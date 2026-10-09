"""Keep the identity provider and the registry in agreement (plan §8.3).

Aegis decides which agents may act; the identity provider decides who can sign in. If the two drift apart (the
provider was unreachable during a suspension, a realm was recreated, an agent was deleted), this finds it and, for
enabled/disabled mismatches, repairs it. It never creates identities, because that would mean issuing a new private key.
"""

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

from aegis.common.models import AgentStatus
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import ControlContext
from aegis.control.identity.idp import Persona
from aegis.control.identity.oidc import IdentityUnavailable
from aegis.control.tables import Agent

log = logging.getLogger("aegis.identity")


async def reconcile(c: ControlContext, actor: str = "system") -> dict:
    report: dict = {
        "provider": c.agent_identity.name,
        "checked": 0,
        "enabled": [],
        "disabled": [],
        "missing": [],  # in the registry but not in the provider: re-approve the agent to issue a new identity
        "orphaned": [],  # managed by Aegis in the provider, but the registry has no such agent
        "errors": [],
    }
    clients = {client.client_id: client for client in await c.agent_identity.list_clients()}
    async with c.db.sessionmaker() as s:
        agents = (await s.scalars(select(Agent).where(Agent.idp_client_id.is_not(None)))).all()
        known_agents = set((await s.scalars(select(Agent.id))).all())
        for agent in agents:
            report["checked"] += 1
            client = clients.get(agent.idp_client_id)
            if client is None:
                report["missing"].append(agent.idp_client_id)
                continue
            should_be_enabled = agent.status == AgentStatus.ACTIVE
            if client.enabled == should_be_enabled:
                continue
            try:
                await c.agent_identity.set_enabled(agent.idp_client_id, should_be_enabled)
            except IdentityUnavailable as exc:
                report["errors"].append({"client_id": agent.idp_client_id, "error": str(exc)})
                continue
            report["enabled" if should_be_enabled else "disabled"].append(agent.idp_client_id)
        report["orphaned"] = sorted(
            client.client_id for client in clients.values() if client.agent_id and client.agent_id not in known_agents
        )
        if any(report[key] for key in ("enabled", "disabled", "missing", "orphaned", "errors")):
            await ledger.append(s, "identity.reconciled", actor, c.agent_identity.name, report)
            await s.commit()
    if report["errors"]:
        log.error("identity reconcile could not repair: %s", report["errors"])
    return report


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/identity", tags=["identity"])

    @r.get("/status", dependencies=[Depends(require_roles(*OPERATORS))])
    async def status(request: Request):
        c: ControlContext = request.app.state.ctx
        async with c.db.sessionmaker() as s:
            with_identity = await s.scalar(
                select(func.count()).select_from(Agent).where(Agent.idp_client_id.is_not(None))
            )
        return {**await c.agent_identity.status(), "agents_with_identity": with_identity}

    @r.post("/reconcile")
    async def run(request: Request, user: Persona = Depends(require_roles("admin", "security-approver"))):
        return await reconcile(request.app.state.ctx, f"user:{user.username}")

    return r
