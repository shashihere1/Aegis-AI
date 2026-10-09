"""Aegis control plane: registry, identity/STS, approvals, discovery, SOC and evidence (plan §7.3)."""

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aegis import telemetry
from aegis.common.crypto import SigningKey
from aegis.common.settings import Settings
from aegis.control import (
    approvals,
    discovery,
    evidence,
    evidence_reports,
    identity_sync,
    internal,
    investigations,
    model_controls,
    ownership,
    policies,
    registry,
    risk,
    siem,
    signin,
    soc,
    tools_registry,
)
from aegis.control.context import ControlContext, load_taxonomy
from aegis.control.db import Database
from aegis.control.identity import idp as idp_module
from aegis.control.identity import oidc_provider, sts
from aegis.control.identity.agent_identity import AgentIdentityProvider, build_agent_identity
from aegis.control.identity.oidc import IdentityUnavailable, OidcConfig, OidcVerifier
from aegis.control.identity.people import PersonDirectory
from aegis.control.identity.users import UserAuthenticator
from aegis.hotstore import HotStore, make_hotstore

log = logging.getLogger("aegis.control")


def network_client(url: str) -> httpx.AsyncClient:
    """A client for a provider reached over the network. trust_env is off for a provider on this machine, so a
    corporate proxy variable cannot capture loopback calls."""
    loopback = urlsplit(url).hostname in {"127.0.0.1", "localhost", "::1"}
    return httpx.AsyncClient(timeout=10, trust_env=not loopback)


def create_app(
    settings: Settings,
    http: httpx.AsyncClient,
    hotstore: HotStore | None = None,
    agent_identity: AgentIdentityProvider | None = None,
    gateway_service_public_pem: str = "",
) -> FastAPI:
    if settings.siem_enabled:
        siem.validate_destination(settings.siem_url)
        siem.connector_token(settings)
    context = ControlContext(
        settings=settings,
        db=Database(settings.database_url, settings.database_schema),
        idp=idp_module.DevIdp(
            f"{settings.control_url}/idp",
            SigningKey.ensure(settings.idp_key_path, "idp-1"),
            settings.identity_state_dir,
        ),
        sts_key=SigningKey.ensure(settings.signing_key_path, "sts-1"),
        hotstore=hotstore or make_hotstore(settings.hotstore_url),
        http=http,
        taxonomy=load_taxonomy(),
        evidence_key=SigningKey.ensure(settings.evidence_key_file, "evidence-1"),
    )
    # Public-key fingerprints only (never the private key). Persistent keys keep the same fingerprint
    # across restarts; an ephemeral one changes every start, which is the signal it is dev-only.
    log.info(
        "signing keys ready: sts fingerprint=%s (%s), idp fingerprint=%s (%s), evidence fingerprint=%s (%s)",
        context.sts_key.fingerprint,
        "persistent" if settings.signing_key_path else "ephemeral",
        context.idp.key.fingerprint,
        "persistent" if settings.idp_key_path else "ephemeral",
        context.evidence_key.fingerprint,
        "persistent" if settings.evidence_key_file else "ephemeral",
    )
    oidc_config = OidcConfig.from_settings(settings)
    own_http: httpx.AsyncClient | None = None
    if oidc_config:
        if oidc_config.builtin:
            context.builtin_oidc = oidc_provider.BuiltinOidc(settings, oidc_config, context.idp.personas)
        # A provider served by this process is reached through the shared in-process client; any other
        # provider (Keycloak, Entra...) over the network, honouring the usual proxy environment variables.
        own_http = None if oidc_config.builtin else network_client(oidc_config.issuer)
        context.oidc = OidcVerifier(oidc_config, own_http or http)
    context.people = PersonDirectory(settings.person_links, context.idp, context.db)
    context.users = UserAuthenticator(context.idp, settings, context.oidc, context.people)
    use_keycloak = settings.agent_idp == "keycloak" and agent_identity is None
    agent_http = network_client(settings.keycloak_url) if use_keycloak else None
    context.agent_identity = agent_identity or build_agent_identity(settings, context.idp, agent_http)
    context.telemetry = telemetry.Telemetry(context.db)
    # The Gateway authenticates its internal calls by signing with its private key; we verify with the
    # public half only (no shared secret). Supplied in-process in the demo, or loaded from a PEM in Azure.
    context.gateway_service_public_pem = gateway_service_public_pem or (
        Path(settings.gateway_service_public_key_path).read_text(encoding="utf-8")
        if settings.gateway_service_public_key_path
        else ""
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await context.db.create_all()
        await policies.initialize(context)
        await policies.sync_opa_on_startup(context)  # OPA runs the approved Rego from the database, not stale files
        await sts.rehydrate_revocations(context)
        await context.telemetry.start()
        if (
            settings.evidence_automation_enabled
            and settings.evidence_key_file
            and ":memory:" not in settings.database_url
        ):
            context.evidence_task = asyncio.create_task(evidence_reports.run_scheduler(context))
        # An in-memory SQLite database shares one connection, so a background transaction would interleave with
        # request writes (same rule as telemetry); there, campaigns are run on demand through the API instead.
        if (settings.attestation_interval_days > 0 or settings.attestation_auto_enforce) and ":memory:" not in (
            settings.database_url
        ):
            context.attestation_task = asyncio.create_task(ownership.run_scheduler(context))
        if settings.agent_idp != "dev":
            try:  # a provider that is down at start-up must not stop the control plane; calls fail closed (503)
                report = await identity_sync.reconcile(context)
                log.info("identity reconcile: %s", {k: v for k, v in report.items() if v})
            except IdentityUnavailable as exc:
                log.warning("identity provider unavailable at start-up: %s", exc)
        background = []
        if settings.siem_enabled and ":memory:" not in settings.database_url:
            background.append(asyncio.create_task(siem.run_worker(context)))
        if settings.discovery_scan_interval:
            background.append(asyncio.create_task(discovery.scan_periodically(context)))
        try:
            yield
        finally:
            for task in background:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            if context.evidence_task is not None:
                context.evidence_task.cancel()
                await asyncio.gather(context.evidence_task, return_exceptions=True)
            if context.attestation_task is not None:
                context.attestation_task.cancel()
                await asyncio.gather(context.attestation_task, return_exceptions=True)
            await context.telemetry.stop()
            await context.db.engine.dispose()
            for client in (own_http, agent_http):
                if client is not None:
                    await client.aclose()

    app = FastAPI(title="Aegis AI control plane", version="0.1.0", lifespan=lifespan)
    app.state.ctx = context
    for module in (
        idp_module,
        sts,
        registry,
        tools_registry,
        approvals,
        discovery,
        soc,
        evidence,
        evidence_reports,
        internal,
        model_controls,
        siem,
        policies,
        investigations,
        risk,
        telemetry,
        signin,
        oidc_provider,
        identity_sync,
    ):
        app.include_router(module.router())
    app.add_middleware(telemetry.TraceMiddleware, telemetry=context.telemetry, service="aegis.control")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        max_age=600,
    )

    @app.exception_handler(IdentityUnavailable)
    async def identity_unavailable(request: Request, exc: IdentityUnavailable):
        # Fail closed. The detail (which may name internal hosts) goes to the log, not to the caller.
        log.error("identity provider problem on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse({"detail": "the identity provider is unavailable"}, status_code=503)

    @app.get("/health")
    async def health():
        return {"status": "ok", "database": context.db.engine.dialect.name}

    return app
