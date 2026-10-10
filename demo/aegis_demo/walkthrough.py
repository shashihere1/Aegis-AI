"""Approved local runtime templates, not an agent builder or arbitrary code loader.

Registration and approval use the ordinary governance APIs under the actual caller's
identity. Only the local development IdP can supply managed private keys. Keys and
resumable tasks stay server-side; a restart requires reconnecting approved instances.
"""

import asyncio
from dataclasses import dataclass

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from aegis.common.hashing import sha256_hex
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.identity.idp import Persona
from aegis.control.identity.oidc import IdentityUnavailable
from aegis.control.ownership import require_management_rights
from aegis.control.tables import Agent, PolicyState, PolicyVersion
from aegis.sdk import AegisAgent
from aegis_demo.agents import payments_agent_app

MARKER = "Managed local security walkthrough v1"
A_INTENTS = ["customer.inquiry.read", "customer.profile.read", "payments.transfer.initiate"]
B_INTENTS = ["payments.transfer.initiate", "payments.status.read"]
A_TOOLS = ["core-banking.get_balance", "crm.get_customer"]
B_TOOLS = ["payments.initiate_transfer", "payments.get_payment_status"]


def endpoint(world, agent_id):
    return f"{world.settings.control_url}/demo/runtime/payments/{agent_id}/"


def fingerprint(agent):
    return sha256_hex(
        {
            k: getattr(agent, k)
            for k in (
                "id",
                "idp_client_id",
                "purpose",
                "intent_categories",
                "capabilities",
                "max_data_class",
                "can_delegate_to",
                "can_receive_from",
                "endpoint_url",
                "owner",
                "environment",
                "framework",
            )
        }
    )


@dataclass(frozen=True)
class RuntimePair:
    coordinator_id: str
    payments_id: str
    sdk: AegisAgent
    payments_sdk: AegisAgent
    payments_app: FastAPI
    fingerprints: tuple[str, str]


async def pair_rows(world, coordinator_id, *, active=False):
    async with world.ctx.db.sessionmaker() as s:
        a = await s.get(Agent, coordinator_id)
        if a is None or a.description != MARKER or len(a.can_delegate_to) != 1:
            raise HTTPException(409, "Select a configured walkthrough coordinator.")
        b = await s.get(Agent, a.can_delegate_to[0])
        if (
            b is None
            or b.description != MARKER
            or a.owner != b.owner
            or b.can_receive_from != [a.id]
            or b.can_delegate_to
            or a.framework != "langgraph"
            or b.framework != "python-mcp"
            or sorted(a.capabilities) != sorted(A_TOOLS)
            or sorted(b.capabilities) != sorted(B_TOOLS)
            or sorted(a.intent_categories) != sorted(A_INTENTS)
            or sorted(b.intent_categories) != sorted(B_INTENTS)
            or any(x.environment not in {"DEV", "TST"} or x.max_data_class != "confidential" for x in (a, b))
            or b.endpoint_url != endpoint(world, b.id)
            or a.endpoint_url is not None
        ):
            raise HTTPException(409, "The pair no longer matches the approved local templates. Review registration.")
        if active and any(x.status != "active" or not x.idp_client_id for x in (a, b)):
            raise HTTPException(409, "Both agents must be independently approved and active.")
        return a, b


async def runtime_pair(world, coordinator_id):
    pair = world.runtime_pairs.get(coordinator_id)
    if pair is None:
        raise HTTPException(409, "Connect the approved pair first; runtime credentials are not restored from history.")
    a, b = await pair_rows(world, coordinator_id, active=True)
    if pair.fingerprints != (fingerprint(a), fingerprint(b)):
        raise HTTPException(409, "Registration changed; reconnect the independently approved pair.")
    return pair


class RegisterPair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name_prefix: str = Field(default="Judge", pattern=r"^[A-Za-z][A-Za-z0-9 -]{2,45}$")
    owner: str = Field(default="niels.vandijk", min_length=3, max_length=120)


class ConnectPair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    coordinator_id: str = Field(pattern=r"^AGT-[A-Z0-9-]+$")


class ApprovePair(ConnectPair):
    reason: str = Field(min_length=10, max_length=1000)


def router(get_world):
    r = APIRouter(prefix="/walkthrough", tags=["security-walkthrough"])
    setup_lock = asyncio.Lock()

    def local_only(w):
        if not w.settings.enable_dev_login or w.ctx.agent_identity.name != "dev-idp":
            raise HTTPException(
                409,
                "Managed local templates require the development IdP. Enterprise runtimes need their own secret store.",
            )

    async def forward(w, request, method, path, body=None):
        response = await w.http.request(
            method,
            f"{w.settings.control_url}{path}",
            headers={"authorization": request.headers["authorization"]},
            json=body,
        )
        if response.status_code >= 400:
            raise HTTPException(response.status_code, response.json().get("detail", "Governance request refused."))
        return response.json()

    @r.get("/pairs")
    async def pairs(user: Persona = Depends(require_roles("customer", *OPERATORS))):
        w = get_world()
        if not set(user.roles).intersection(OPERATORS) and user.username != "jan.devries":
            raise HTTPException(403, "The connected walkthrough is restricted to Jan's synthetic account.")
        async with w.ctx.db.sessionmaker() as s:
            rows = list(await s.scalars(select(Agent).where(Agent.description == MARKER).order_by(Agent.name)))
            state = await s.get(PolicyState, "tool-call")
            version = await s.get(PolicyVersion, state.active_version) if state else None
        by_id = {a.id: a for a in rows}
        items = []
        for a in rows:
            if a.framework != "langgraph" or len(a.can_delegate_to) != 1:
                continue
            b = by_id.get(a.can_delegate_to[0])
            if b:
                items.append(
                    {
                        "coordinator_id": a.id,
                        "payments_id": b.id,
                        "name": a.name,
                        "coordinator_status": a.status,
                        "payments_status": b.status,
                        "connected": a.id in w.runtime_pairs,
                        "owner": a.owner,
                    }
                )
        return {
            "items": items,
            "payment_threshold_eur": version.configuration["thresholds"]["payments"]["hitl_amount_eur"]
            if version
            else None,
            "development_identity": w.ctx.agent_identity.name == "dev-idp",
        }

    @r.post("/register", status_code=201)
    async def register(
        body: RegisterPair,
        request: Request,
        user: Persona = Depends(require_roles("agent-developer", "agent-owner", "admin")),
    ):
        w = get_world()
        local_only(w)
        # Explicit setup action only: no bootstrap seeding and no automatic approval.
        async with setup_lock:
            rows = []
            for suffix, framework, intents, tools in (
                ("Coordinator", "langgraph", A_INTENTS, A_TOOLS),
                ("Payments", "python-mcp", B_INTENTS, B_TOOLS),
            ):
                name = f"{body.name_prefix}-{suffix}"
                async with w.ctx.db.sessionmaker() as s:
                    existing = await s.scalar(select(Agent).where(Agent.name == name))
                if existing:
                    if (
                        existing.registered_by != user.username
                        or existing.owner != body.owner
                        or existing.description != MARKER
                    ):
                        raise HTTPException(
                            409, "That name belongs to another registration. Choose a different prefix."
                        )
                    rows.append({"id": existing.id, "status": existing.status})
                    continue
                row = await forward(
                    w,
                    request,
                    "POST",
                    "/v1/agents",
                    {
                        "name": name,
                        "owner": body.owner,
                        "sponsor": "retail.ops.head",
                        "purpose": "Coordinate governed synthetic account inquiries and customer-confirmed transfers."
                        if suffix == "Coordinator"
                        else "Execute governed synthetic payments; no real settlement.",
                        "framework": framework,
                        "intent_categories": intents,
                        "capabilities": tools,
                        "environment": "DEV",
                        "cloud": "on-prem",
                        "autonomy": "L1",
                        "max_data_class": "confidential",
                        "customer_facing": suffix == "Coordinator",
                    },
                )
                await forward(w, request, "PATCH", f"/v1/agents/{row['id']}", {"description": MARKER})
                rows.append(row)
            a, b = rows
            for row, changes in (
                (a, {"can_delegate_to": [b["id"]]}),
                (b, {"can_receive_from": [a["id"]], "endpoint_url": endpoint(w, b["id"])}),
            ):
                if row["status"] == "draft":
                    await forward(w, request, "PATCH", f"/v1/agents/{row['id']}", changes)
            await pair_rows(w, a["id"])
            for row in rows:
                if row["status"] == "draft":
                    await forward(w, request, "POST", f"/v1/agents/{row['id']}/submit")
            return {"coordinator_id": a["id"], "payments_id": b["id"], "approval_required": True}

    @r.post("/connect")
    async def connect(
        body: ConnectPair,
        request: Request,
        user: Persona = Depends(require_roles("agent-developer", "agent-owner", "admin")),
    ):
        w = get_world()
        local_only(w)
        async with setup_lock:
            a, b = await pair_rows(w, body.coordinator_id, active=True)
            async with w.ctx.db.sessionmaker() as s:
                for agent in (a, b):
                    await require_management_rights(
                        w.ctx,
                        s,
                        user,
                        agent,
                        "connect its local runtime",
                        any_agent_roles=("admin",),
                        registrant_may=True,
                    )
            old = w.runtime_pairs.get(a.id)
            if old and old.fingerprints == (fingerprint(a), fingerprint(b)):
                return {"coordinator_id": a.id, "payments_id": b.id, "connected": True}
            if any(run.get("coordinator_id") == a.id for run in w.live_runs.values()):
                raise HTTPException(
                    409, "Finish or cancel this coordinator's runs before replacing its runtime binding."
                )
            sdks = []
            for agent in (a, b):
                try:
                    private_key = await w.ctx.agent_identity.development_private_key(agent.idp_client_id)
                except IdentityUnavailable:
                    raise HTTPException(
                        409,
                        "No protected local development key is available for this identity. "
                        "Configure persistent development identity storage before connecting.",
                    ) from None
                credentials = {
                    "client_id": agent.idp_client_id,
                    "private_key_pem": private_key,
                    "token_endpoint": w.ctx.agent_identity.token_endpoint,
                    "assertion_audience": w.ctx.agent_identity.assertion_audience,
                }
                sdks.append(
                    AegisAgent.from_credentials(
                        w.http, w.settings.control_url, w.settings.gateway_url, credentials, telemetry=w.ctx.telemetry
                    )
                )
            app = payments_agent_app()
            app.state.sdk = sdks[1]
            pair = RuntimePair(a.id, b.id, *sdks, app, (fingerprint(a), fingerprint(b)))
            # Never overwrite defaults or an existing specialist's pending approvals.
            if old and old.payments_app.state.pending:
                raise HTTPException(409, "Finish or cancel pending delegated work before reconnecting.")
            w.runtime_pairs[a.id] = pair
            async with w.ctx.db.sessionmaker() as s:
                await ledger.append(
                    s,
                    "agent.runtime_connected",
                    user.username,
                    a.id,
                    {"payments_agent_id": b.id, "templates": ["langgraph-azure", "sdk-mcp"]},
                )
                await s.commit()
            return {"coordinator_id": a.id, "payments_id": b.id, "connected": True}

    @r.post("/approve")
    async def approve(body: ApprovePair, request: Request, user: Persona = Depends(require_roles("risk-approver"))):
        w = get_world()
        local_only(w)
        async with setup_lock:
            a, b = await pair_rows(w, body.coordinator_id)
            for agent in (a, b):
                if agent.status not in {"pending_approval", "active"}:
                    raise HTTPException(409, "Submit both draft agents for independent review first.")
            for agent in (a, b):
                if agent.status == "pending_approval":
                    # Existing registry endpoint enforces separation of duties and provisions identity.
                    # Its private-key response stays inside this server, not in browser storage.
                    await forward(w, request, "POST", f"/v1/agents/{agent.id}/approve", {"reason": body.reason})
            return {"coordinator_id": a.id, "payments_id": b.id, "approved": True}

    return r


def runtime_app(get_world):
    app = FastAPI(title="Managed local Payments instances")

    @app.post("/payments/{agent_id}/")
    async def payments(agent_id: str, request: Request):
        w = get_world()
        pair = next((p for p in w.runtime_pairs.values() if p.payments_id == agent_id), None)
        if pair is None:
            raise HTTPException(404, "No connected specialist instance.")
        await runtime_pair(w, pair.coordinator_id)
        return await pair.payments_app.state.handle_message(request)

    return app
