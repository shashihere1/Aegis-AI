"""Aegis control plane: registry, identity/STS, approvals, discovery, SOC and evidence (plan §7.3)."""

import logging
from contextlib import asynccontextmanager
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
    identity_sync,
    internal,
    investigations,
    model_controls,
    policies,
    registry,
    risk,
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
    context = ControlContext(
        settings=settings,
        db=Database(settings.database_url, settings.database_schema),
        idp=idp_module.DevIdp(
            f"{settings.control_url}/idp",
            SigningKey.load_or_generate(settings.idp_key_path, "idp-1"),
            settings.identity_state_dir,
        ),
        sts_key=SigningKey.load_or_generate(settings.signing_key_path, "sts-1"),
        hotstore=hotstore or make_hotstore(settings.hotstore_url),
        http=http,
        taxonomy=load_taxonomy(),
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
    context.users = UserAuthenticator(context.idp, settings, context.oidc)
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
        await sts.rehydrate_revocations(context)
        await context.telemetry.start()
        if settings.agent_idp != "dev":
            try:  # a provider that is down at start-up must not stop the control plane; calls fail closed (503)
                report = await identity_sync.reconcile(context)
                log.info("identity reconcile: %s", {k: v for k, v in report.items() if v})
            except IdentityUnavailable as exc:
                log.warning("identity provider unavailable at start-up: %s", exc)
        try:
            yield
        finally:
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
        internal,
        model_controls,
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
