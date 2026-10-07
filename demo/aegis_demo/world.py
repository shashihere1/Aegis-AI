"""Runs the whole system in one process: control plane, Gateway, mock-bank MCP servers and demo agents.

Services talk over HTTP exactly as in a deployment, but requests are routed in-process through one
ASGI app, so no Docker, network or external IdP is needed. The same composite is served by
`python -m aegis_demo.serve` for the browser and API docs.
"""

import asyncio
import random
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.responses import RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from aegis.common.ids import agent_id as new_agent_id
from aegis.common.models import AgentStatus
from aegis.common.settings import REPO_ROOT, Settings
from aegis.control.app import create_app
from aegis.control.identity.idp import Persona
from aegis.control.tables import Agent
from aegis.gateway.app import create_gateway
from aegis.hotstore import MemoryHotStore
from aegis.policy.engine import make_engine
from aegis.sdk import AegisAgent
from aegis_demo import catalog
from aegis_demo.agents import Ava, kyc_agent_app, payments_agent_app
from aegis_demo.fake_llm import fake_llm_app
from aegis_demo.mcp_servers import SERVERS
from aegis_demo.studio import studio_app

BASE = "http://127.0.0.1:8000"
FAKE_LLM_URL = f"{BASE}/demo/fake-llm/v1"
UI_DIST = REPO_ROOT / "web" / "dist"


class SpaStaticFiles(StaticFiles):
    """Serves the built console; unknown paths fall back to index.html for client-side routing."""

    async def get_response(self, path, scope):
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
            response = None
        if response is None or response.status_code == 404:
            response = await super().get_response("index.html", scope)
        return response


class InProcessTransport(httpx.AsyncBaseTransport):
    """Routes every request to the composite ASGI app (set after the apps are built)."""

    def __init__(self) -> None:
        self.app = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await httpx.ASGITransport(app=self.app).handle_async_request(request)


@dataclass
class World:
    settings: Settings
    http: httpx.AsyncClient
    control: FastAPI
    gateway: FastAPI
    mounts: dict[str, Mount]
    stack: AsyncExitStack
    kyc_app: FastAPI
    payments_app: FastAPI
    agent_ids: dict[str, str] = field(default_factory=dict)
    sdks: dict[str, AegisAgent] = field(default_factory=dict)
    ava: Ava | None = None
    stop: asyncio.Event = field(default_factory=asyncio.Event)
    background: list[asyncio.Task] = field(default_factory=list)
    spawned: list[asyncio.Task] = field(default_factory=list)

    def spawn(self, coro) -> asyncio.Task:
        """Run a background job (e.g. an agent waiting for an approval); cancelled when the world stops."""
        task = asyncio.create_task(coro)
        self.spawned.append(task)
        return task

    @property
    def ctx(self):
        return self.control.state.ctx

    def token(self, username: str) -> str:
        return self.ctx.idp.login(username)

    async def api(self, username: str, method: str, path: str, **kwargs) -> httpx.Response:
        headers = {"authorization": f"Bearer {self.token(username)}", **kwargs.pop("headers", {})}
        return await self.http.request(method, f"{BASE}{path}", headers=headers, **kwargs)

    async def swap_mcp_server(self, name: str, server) -> None:
        """Replace a running MCP server with a new version (used to demonstrate a rug pull)."""
        app = server.streamable_http_app()
        started = asyncio.Event()

        async def hold() -> None:  # the MCP session manager must start and stop in the same task
            async with app.router.lifespan_context(app):
                started.set()
                await self.stop.wait()

        self.background.append(asyncio.create_task(hold()))
        await started.wait()
        mount = self.mounts[name]
        mount._base_app = mount.app = app


def _ok(response: httpx.Response) -> dict:
    if response.status_code >= 400:
        raise RuntimeError(f"{response.request.method} {response.request.url} -> {response.status_code}: "
                           f"{response.text}")
    return response.json()


async def bootstrap(w: World) -> None:
    """Set up the demo bank through the public API, with the right persona for each step."""
    for username, name, roles, entitlements in catalog.PERSONAS:
        w.ctx.idp.add_persona(Persona(username, name, roles, entitlements))

    for server_id in SERVERS:
        vendor = "third-party" if server_id == "fx-rates" else "internal"
        _ok(await w.api("priya.raman", "POST", "/v1/mcp/servers", json={
            "id": server_id, "url": f"{BASE}/demo/mcp/{server_id}/mcp", "owner": "niels.vandijk", "vendor": vendor}))
        _ok(await w.api("priya.raman", "POST", f"/v1/mcp/servers/{server_id}/import"))
    for tool_id, classification in catalog.TOOL_CLASSIFICATION.items():
        _ok(await w.api("priya.raman", "PUT", f"/v1/tools/{tool_id}/classification", json=classification))
        if not tool_id.startswith("fx-rates."):  # the poisoned third-party tool stays unapproved
            _ok(await w.api("fatima.elamrani", "POST", f"/v1/tools/{tool_id}/approve"))

    endpoints = {"kyc-agent": f"{BASE}/demo/agents/kyc/", "payments-agent": f"{BASE}/demo/agents/payments/"}
    for key, manifest in catalog.AGENTS.items():
        body = {**manifest, "owner": "niels.vandijk", "sponsor": "retail.ops.head", "environment": "PRD",
                "cloud": "azure", "endpoint_url": endpoints.get(key)}
        w.agent_ids[key] = _ok(await w.api("priya.raman", "POST", "/v1/agents", json=body))["id"]
    ava = w.agent_ids["ava"]
    for key in ("kyc-agent", "payments-agent"):
        _ok(await w.api("priya.raman", "PATCH", f"/v1/agents/{w.agent_ids[key]}", json={"can_receive_from": [ava]}))
    _ok(await w.api("priya.raman", "PATCH", f"/v1/agents/{ava}", json={
        "can_delegate_to": [w.agent_ids["kyc-agent"], w.agent_ids["payments-agent"]]}))

    for key, agent_id in w.agent_ids.items():
        _ok(await w.api("priya.raman", "POST", f"/v1/agents/{agent_id}/submit"))
        creds = _ok(await w.api("sanne.bakker", "POST", f"/v1/agents/{agent_id}/approve",
                                json={"reason": "demo onboarding"}))["credentials"]
        w.sdks[key] = AegisAgent(w.http, BASE, w.settings.gateway_url, creds["client_id"], creds["private_key_pem"])
    w.kyc_app.state.sdk = w.sdks["kyc-agent"]
    w.payments_app.state.sdk = w.sdks["payments-agent"]
    w.ava = Ava(w.sdks["ava"], w.agent_ids["kyc-agent"], w.agent_ids["payments-agent"])


async def seed_registry(w: World, count: int) -> None:
    """Synthetic inventory so the registry shows enterprise scale (the prototype shows 1,247 agents)."""
    rng = random.Random(1247)
    words = ["Claims", "Fraud", "KYC", "Lending", "Treasury", "CloudOps", "HR", "Mortgage", "Payments", "Risk",
             "Compliance", "Marketing", "Support", "Trading", "Audit", "Data", "Onboarding", "Collections"]
    roles = ["Assistant", "Agent", "Copilot", "Analyst", "Bot", "Reviewer", "Router", "Summariser", "Monitor"]
    async with w.ctx.db.sessionmaker() as s:
        for i in range(count):
            s.add(Agent(
                id=new_agent_id(), name=f"{rng.choice(words)}-{rng.choice(roles)}-{i:04d}",
                purpose="Synthetic registry entry for scale testing.", intent_categories=["customer.inquiry.read"],
                owner=rng.choice(["niels.vandijk", "sanne.bakker", "priya.raman"]), sponsor="retail.ops.head",
                registered_by="seed", environment=rng.choice(["DEV", "TST", "ACC", "PRD"]),
                cloud=rng.choice(["azure", "aws", "gcp", "on-prem"]), autonomy=rng.choice(["L0", "L1", "L2", "L3"]),
                max_data_class=rng.choice(["public", "internal", "confidential", "restricted"]),
                status=rng.choices([AgentStatus.ACTIVE, AgentStatus.SUSPENDED, AgentStatus.DRAFT,
                                    AgentStatus.DISCOVERED], [85, 4, 8, 3])[0],
                risk_tier=rng.choice(["low", "medium", "high"]),
            ))
        await s.commit()


@asynccontextmanager
async def running_world(seed: int = 0, **overrides):
    settings = Settings(control_url=BASE, gateway_url=f"{BASE}/gw", database_url="sqlite+aiosqlite:///:memory:",
                        cache_seconds=0, **overrides)
    transport = InProcessTransport()
    http = httpx.AsyncClient(transport=transport, timeout=60.0)
    hotstore = MemoryHotStore()
    control = create_app(settings, http, hotstore)
    gateway = create_gateway(settings, http, hotstore,
                             make_engine(settings.policy_engine, settings.policy_dir, settings.opa_url, http))
    servers = {name: factory().streamable_http_app() for name, factory in SERVERS.items()}
    kyc_app, payments_app = kyc_agent_app(), payments_agent_app()
    mounts = {name: Mount(f"/demo/mcp/{name}", app) for name, app in servers.items()}
    holder: dict = {}
    ui = [Route("/ui", lambda request: RedirectResponse("/ui/")),
          Mount("/ui", SpaStaticFiles(directory=UI_DIST, html=True)),
          Route("/", lambda request: RedirectResponse("/ui/"))] if UI_DIST.exists() else []
    composite = Starlette(routes=[
        Mount("/gw", gateway), *mounts.values(),
        Mount("/demo/agents/kyc", kyc_app), Mount("/demo/agents/payments", payments_app),
        Mount("/demo/fake-llm", fake_llm_app()),
        Mount("/demo/api", studio_app(lambda: holder["world"])),
        *ui,
        Mount("/", control),
    ])
    transport.app = composite
    async with AsyncExitStack() as stack:
        await stack.enter_async_context(control.router.lifespan_context(control))
        for app in servers.values():
            await stack.enter_async_context(app.router.lifespan_context(app))
        world = World(settings, http, control, gateway, mounts, stack, kyc_app, payments_app)
        world.composite = composite
        holder["world"] = world
        await bootstrap(world)
        if seed:
            await seed_registry(world, seed)
        try:
            yield world
        finally:
            world.stop.set()
            for task in world.spawned:
                task.cancel()
            await asyncio.gather(*world.spawned, return_exceptions=True)
            await asyncio.gather(*world.background)
            await http.aclose()
