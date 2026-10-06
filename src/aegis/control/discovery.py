"""Shadow-agent discovery (plan §8.2, flow F7). Sources: Gateway traffic and IdP scan."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.ids import agent_id as new_agent_id
from aegis.common.ids import new_id
from aegis.common.models import AgentCreate, AgentStatus
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import ControlContext, session
from aegis.control.identity.idp import Persona
from aegis.control.tables import Agent, Alert, DiscoveryFinding


def finding_dict(f: DiscoveryFinding) -> dict:
    return {"id": f.id, "fingerprint": f.fingerprint, "sources": f.sources, "evidence": f.evidence[-5:],
            "suggested_owner": f.suggested_owner, "hits": f.hits, "first_seen": f.first_seen,
            "last_seen": f.last_seen, "status": f.status, "agent_id": f.agent_id}


async def record_signal(s: AsyncSession, source: str, fingerprint: str, evidence: dict,
                        suggested_owner: str | None = None) -> DiscoveryFinding:
    """Correlate signals from different sources into one finding per fingerprint."""
    finding = (await s.execute(select(DiscoveryFinding).where(DiscoveryFinding.fingerprint == fingerprint))
               ).scalar_one_or_none()
    if finding is None:
        finding = DiscoveryFinding(id=new_id("fnd"), fingerprint=fingerprint, sources=[source], evidence=[],
                                   suggested_owner=suggested_owner)
        s.add(finding)
        s.add(Alert(id=new_id("alr"), rule_id="DET-07", severity="medium", title=f"Unregistered agent activity: "
                    f"{fingerprint}", evidence={"source": source, **evidence}))
        await ledger.append(s, "discovery.finding", source, fingerprint, evidence)
    elif source not in finding.sources:
        finding.sources = [*finding.sources, source]
    finding.evidence = [*finding.evidence[-19:], {"source": source, **evidence}]
    finding.hits += 1
    finding.last_seen = datetime.now(UTC)
    finding.suggested_owner = finding.suggested_owner or suggested_owner
    return finding


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/discovery", tags=["discovery"])

    @r.get("/findings", dependencies=[Depends(require_roles(*OPERATORS))])
    async def findings(s: AsyncSession = Depends(session)):
        rows = (await s.execute(select(DiscoveryFinding).order_by(DiscoveryFinding.last_seen.desc()))).scalars()
        return [finding_dict(f) for f in rows]

    @r.post("/scan")
    async def scan(request: Request, s: AsyncSession = Depends(session),
                   user: Persona = Depends(require_roles("soc-analyst", "admin"))):
        """IdP scan: identities that exist in the IdP but are not governed by the registry."""
        c: ControlContext = request.app.state.ctx
        found = []
        for client in c.idp.list_clients():
            if client.agent_id is None:
                finding = await record_signal(s, "idp", f"idp-client:{client.client_id}",
                                              {"client_id": client.client_id, "name": client.name})
                found.append(finding.fingerprint)
        await s.commit()
        return {"found": found}

    @r.post("/findings/{finding_id}/claim", status_code=201)
    async def claim(finding_id: str, body: AgentCreate, request: Request, s: AsyncSession = Depends(session),
                    user: Persona = Depends(require_roles("agent-developer", "agent-owner"))):
        finding = await s.get(DiscoveryFinding, finding_id)
        if finding is None or finding.status != "open":
            raise HTTPException(409, "finding is not open")
        agent = Agent(id=new_agent_id(), registered_by=user.username, status=AgentStatus.DRAFT,
                      description=f"Claimed from discovery finding {finding.fingerprint}", **body.model_dump())
        s.add(agent)
        finding.status, finding.agent_id = "claimed", agent.id
        if finding.fingerprint.startswith("idp-client:"):
            # The unmanaged identity is disabled; the agent gets a governed identity once approved.
            request.app.state.ctx.idp.set_enabled(finding.fingerprint.removeprefix("idp-client:"), False)
        await ledger.append(s, "discovery.claimed", f"user:{user.username}", finding.fingerprint,
                            {"agent_id": agent.id})
        await s.commit()
        return {"finding": finding_dict(finding), "agent_id": agent.id}

    @r.post("/findings/{finding_id}/quarantine")
    async def quarantine(finding_id: str, request: Request, s: AsyncSession = Depends(session),
                         user: Persona = Depends(require_roles("soc-analyst"))):
        finding = await s.get(DiscoveryFinding, finding_id)
        if finding is None:
            raise HTTPException(404, "unknown finding")
        c: ControlContext = request.app.state.ctx
        await c.hotstore.block_fingerprint(finding.fingerprint)
        if finding.fingerprint.startswith("idp-client:"):
            c.idp.set_enabled(finding.fingerprint.removeprefix("idp-client:"), False)
        finding.status = "quarantined"
        await ledger.append(s, "discovery.quarantined", f"user:{user.username}", finding.fingerprint, {})
        await s.commit()
        return finding_dict(finding)

    return r
