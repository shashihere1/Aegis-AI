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
from sqlalchemy import select
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
from aegis.control.policies import ManagedEngine
from aegis.control.tables import Agent, McpServer
from aegis.gateway.app import create_gateway
from aegis.hotstore import MemoryHotStore
from aegis.policy.engine import make_engine
from aegis.sdk import AegisAgent
from aegis.telemetry import TraceMiddleware, tracing_headers
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
        mount._base_app = mount.app = TraceMiddleware(app, self.ctx.telemetry, f"aegis.mcp.{name}")


def _ok(response: httpx.Response) -> dict:
    if response.status_code >= 400:
        raise RuntimeError(
            f"{response.request.method} {response.request.url} -> {response.status_code}: {response.text}"
        )
    return response.json()


async def bootstrap(w: World) -> None:
    """Set up the demo bank through the public API, with the right persona for each step."""
    for username, name, roles, entitlements in catalog.PERSONAS:
        w.ctx.idp.add_persona(Persona(username, name, roles, entitlements))

    async with w.ctx.db.sessionmaker() as s:
        existing_servers = set((await s.scalars(select(McpServer.id))).all())
        existing_agents = {a.name: a for a in (await s.scalars(select(Agent))).all()}

    for server_id in SERVERS:
        if server_id in existing_servers:
            continue
        vendor = "third-party" if server_id == "fx-rates" else "internal"
        _ok(
            await w.api(
                "priya.raman",
                "POST",
                "/v1/mcp/servers",
                json={
                    "id": server_id,
                    "url": f"{BASE}/demo/mcp/{server_id}/mcp",
                    "owner": "niels.vandijk",
                    "vendor": vendor,
                },
            )
        )
        _ok(await w.api("priya.raman", "POST", f"/v1/mcp/servers/{server_id}/import"))
    for tool_id, classification in catalog.TOOL_CLASSIFICATION.items():
        if tool_id.split(".")[0] in existing_servers:
            continue
        _ok(await w.api("priya.raman", "PUT", f"/v1/tools/{tool_id}/classification", json=classification))
        if not tool_id.startswith("fx-rates."):  # the poisoned third-party tool stays unapproved
            _ok(await w.api("fatima.elamrani", "POST", f"/v1/tools/{tool_id}/approve"))

    endpoints = {"kyc-agent": f"{BASE}/demo/agents/kyc/", "payments-agent": f"{BASE}/demo/agents/payments/"}
    for key, manifest in catalog.AGENTS.items():
        if manifest["name"] in existing_agents:
            w.agent_ids[key] = existing_agents[manifest["name"]].id
            continue
        body = {
            **manifest,
            "owner": "niels.vandijk",
            "sponsor": "retail.ops.head",
            "environment": "PRD",
            "cloud": "azure",
            "endpoint_url": endpoints.get(key),
        }
        w.agent_ids[key] = _ok(await w.api("priya.raman", "POST", "/v1/agents", json=body))["id"]
    ava = w.agent_ids["ava"]
    for key in ("kyc-agent", "payments-agent"):
        if catalog.AGENTS[key]["name"] not in existing_agents:
            _ok(await w.api("priya.raman", "PATCH", f"/v1/agents/{w.agent_ids[key]}", json={"can_receive_from": [ava]}))
    if catalog.AGENTS["ava"]["name"] not in existing_agents:
        _ok(
            await w.api(
                "priya.raman",
                "PATCH",
                f"/v1/agents/{ava}",
                json={"can_delegate_to": [w.agent_ids["kyc-agent"], w.agent_ids["payments-agent"]]},
            )
        )

    for key, agent_id in w.agent_ids.items():
        existing = existing_agents.get(catalog.AGENTS[key]["name"])
        if existing and existing.idp_client_id:
            creds = {
                "client_id": existing.idp_client_id,
                "private_key_pem": w.ctx.idp.development_private_key(existing.idp_client_id),
            }
            w.ctx.idp.set_enabled(existing.idp_client_id, existing.status == AgentStatus.ACTIVE)
        else:
            if not existing or existing.status == AgentStatus.DRAFT:
                _ok(await w.api("priya.raman", "POST", f"/v1/agents/{agent_id}/submit"))
            creds = _ok(
                await w.api(
                    "sanne.bakker", "POST", f"/v1/agents/{agent_id}/approve", json={"reason": "demo onboarding"}
                )
            )["credentials"]
        w.sdks[key] = AegisAgent(
            w.http,
            BASE,
            w.settings.gateway_url,
            creds["client_id"],
            creds["private_key_pem"],
            telemetry=w.ctx.telemetry,
        )
    w.kyc_app.state.sdk = w.sdks["kyc-agent"]
    w.payments_app.state.sdk = w.sdks["payments-agent"]
    w.ava = Ava(w.sdks["ava"], w.agent_ids["kyc-agent"], w.agent_ids["payments-agent"])


async def seed_registry(w: World, count: int) -> None:
    """Synthetic inventory so the registry shows enterprise scale (the prototype shows 1,247 agents)."""
    rng = random.Random(1247)
    words = [
        "Claims",
        "Fraud",
        "KYC",
        "Lending",
        "Treasury",
        "CloudOps",
        "HR",
        "Mortgage",
        "Payments",
        "Risk",
        "Compliance",
        "Marketing",
        "Support",
        "Trading",
        "Audit",
        "Data",
        "Onboarding",
        "Collections",
    ]
    roles = ["Assistant", "Agent", "Copilot", "Analyst", "Bot", "Reviewer", "Router", "Summariser", "Monitor"]
    async with w.ctx.db.sessionmaker() as s:
        existing_names = set((await s.scalars(select(Agent.name))).all())
        for i in range(count):
            name = f"{rng.choice(words)}-{rng.choice(roles)}-{i:04d}"
            if name in existing_names:
                # Still advance RNG consistently for the remaining generated attributes.
                for choices in (
                    ["niels.vandijk", "sanne.bakker", "priya.raman"],
                    ["DEV", "TST", "ACC", "PRD"],
                    ["azure", "aws", "gcp", "on-prem"],
                    ["L0", "L1", "L2", "L3"],
                    ["public", "internal", "confidential", "restricted"],
                ):
                    rng.choice(choices)
                rng.choices([0, 1, 2, 3], [85, 4, 8, 3])
                rng.choice(["low", "medium", "high"])
                continue
            s.add(
                Agent(
                    id=new_agent_id(),
                    name=name,
                    purpose="Synthetic registry entry for scale testing.",
                    intent_categories=["customer.inquiry.read"],
                    owner=rng.choice(["niels.vandijk", "sanne.bakker", "priya.raman"]),
                    sponsor="retail.ops.head",
                    registered_by="seed",
                    environment=rng.choice(["DEV", "TST", "ACC", "PRD"]),
                    cloud=rng.choice(["azure", "aws", "gcp", "on-prem"]),
                    autonomy=rng.choice(["L0", "L1", "L2", "L3"]),
                    max_data_class=rng.choice(["public", "internal", "confidential", "restricted"]),
                    status=rng.choices(
                        [AgentStatus.ACTIVE, AgentStatus.SUSPENDED, AgentStatus.DRAFT, AgentStatus.DISCOVERED],
                        [85, 4, 8, 3],
                    )[0],
                    risk_tier=rng.choice(["low", "medium", "high"]),
                )
            )
        await s.commit()


@asynccontextmanager
async def running_world(seed: int = 0, **overrides):
    values = dict(
        control_url=BASE, gateway_url=f"{BASE}/gw", database_url="sqlite+aiosqlite:///:memory:", cache_seconds=0
    )
    settings = Settings(**(values | overrides))
    transport = InProcessTransport()

    async def inject_trace(request):
        if "traceparent" not in request.headers:
            request.headers.update(tracing_headers())

    http = httpx.AsyncClient(transport=transport, timeout=60.0, event_hooks={"request": [inject_trace]})
    hotstore = MemoryHotStore()
    control = create_app(settings, http, hotstore)
    gateway = create_gateway(
        settings,
        http,
        hotstore,
        ManagedEngine(
            control.state.ctx, make_engine(settings.policy_engine, settings.policy_dir, settings.opa_url, http)
        ),
        telemetry=control.state.ctx.telemetry,
    )
    servers = {name: factory().streamable_http_app() for name, factory in SERVERS.items()}
    kyc_app, payments_app = kyc_agent_app(), payments_agent_app()
    gateway.add_middleware(TraceMiddleware, telemetry=control.state.ctx.telemetry, service="aegis.gateway")
    for name, app in servers.items():
        app.add_middleware(TraceMiddleware, telemetry=control.state.ctx.telemetry, service=f"aegis.mcp.{name}")
    for name, app in (("kyc", kyc_app), ("payments", payments_app)):
        app.add_middleware(TraceMiddleware, telemetry=control.state.ctx.telemetry, service=f"aegis.agent.{name}")
    mounts = {name: Mount(f"/demo/mcp/{name}", app) for name, app in servers.items()}
    holder: dict = {}
    ui = (
        [
            Route("/ui", lambda request: RedirectResponse("/ui/")),
            Mount("/ui", SpaStaticFiles(directory=UI_DIST, html=True)),
            Route("/", lambda request: RedirectResponse("/ui/")),
        ]
        if UI_DIST.exists()
        else []
    )
    composite = Starlette(
        routes=[
            Mount("/gw", gateway),
            *mounts.values(),
            Mount("/demo/agents/kyc", kyc_app),
            Mount("/demo/agents/payments", payments_app),
            Mount("/demo/fake-llm", fake_llm_app()),
            Mount("/demo/api", studio_app(lambda: holder["world"])),
            *ui,
            Mount("/", control),
        ]
    )
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
