"""Aegis control plane: registry, identity/STS, approvals, discovery, SOC and evidence (plan §7.3)."""

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from aegis import telemetry
from aegis.common.crypto import SigningKey
from aegis.common.settings import Settings
from aegis.control import (
    approvals,
    discovery,
    evidence,
    internal,
    investigations,
    model_controls,
    policies,
    registry,
    risk,
    soc,
    tools_registry,
)
from aegis.control.context import ControlContext, load_taxonomy
from aegis.control.db import Database
from aegis.control.identity import idp as idp_module
from aegis.control.identity import sts
from aegis.hotstore import HotStore, make_hotstore


def create_app(settings: Settings, http: httpx.AsyncClient, hotstore: HotStore | None = None) -> FastAPI:
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
    context.telemetry = telemetry.Telemetry(context.db)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await context.db.create_all()
        await policies.initialize(context)
        await sts.rehydrate_revocations(context)
        await context.telemetry.start()
        try:
            yield
        finally:
            await context.telemetry.stop()
            await context.db.engine.dispose()

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
    ):
        app.include_router(module.router())
    app.add_middleware(telemetry.TraceMiddleware, telemetry=context.telemetry, service="aegis.control")

    @app.get("/health")
    async def health():
        return {"status": "ok", "database": context.db.engine.dialect.name}

    return app
