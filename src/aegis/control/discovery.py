"""Shadow-agent discovery (plan §8.2, flow F7). Sources: Gateway traffic and a scan of the identity provider
(the built-in IdP or Keycloak) for identities the registry does not govern. The scan runs on demand and, when
`discovery_scan_interval` is set, on a schedule."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.ids import agent_id as new_agent_id
from aegis.common.ids import new_id
from aegis.common.models import AgentCreate, AgentStatus
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import ControlContext, session
from aegis.control.identity.agent_identity import IdentityNotFound
from aegis.control.identity.idp import Persona
from aegis.control.tables import Agent, Alert, DiscoveryFinding

log = logging.getLogger("aegis.discovery")

SCHEDULER = "system:scheduler"


def finding_dict(f: DiscoveryFinding) -> dict:
    return {"id": f.id, "fingerprint": f.fingerprint, "sources": f.sources, "evidence": f.evidence[-5:],
            "suggested_owner": f.suggested_owner, "hits": f.hits, "first_seen": f.first_seen,
            "last_seen": f.last_seen, "status": f.status, "agent_id": f.agent_id}


async def record_signal(s: AsyncSession, source: str, fingerprint: str, evidence: dict,
                        suggested_owner: str | None = None, count_hit: bool = True) -> DiscoveryFinding:
    """Correlate signals from different sources into one finding per fingerprint.

    `count_hit=False` (scheduled re-scans) refreshes last_seen without inflating hits and evidence."""
    finding = (await s.execute(select(DiscoveryFinding).where(DiscoveryFinding.fingerprint == fingerprint))
               ).scalar_one_or_none()
    new = finding is None
    if new:
        finding = DiscoveryFinding(id=new_id("fnd"), fingerprint=fingerprint, sources=[source], evidence=[],
                                   suggested_owner=suggested_owner, hits=0)
        s.add(finding)
        s.add(Alert(id=new_id("alr"), rule_id="DET-07", severity="medium", title=f"Unregistered agent activity: "
                    f"{fingerprint}", evidence={"source": source, **evidence}))
        await ledger.append(s, "discovery.finding", source, fingerprint, evidence)
    elif source not in finding.sources:
        finding.sources = [*finding.sources, source]
    if new or count_hit:
        finding.evidence = [*finding.evidence[-19:], {"source": source, **evidence}]
        finding.hits += 1
    finding.last_seen = datetime.now(UTC)
    finding.suggested_owner = finding.suggested_owner or suggested_owner
    return finding


async def run_idp_scan(c: ControlContext, actor: str, trigger: str) -> dict:
    """Flag identities that exist in the IdP but are not governed by the registry. Used by the button and the timer.

    The lock serialises a manual and a scheduled scan, which could otherwise both insert the same new finding."""
    started = datetime.now(UTC)
    async with c.discovery_lock:
        try:
            async with c.db.sessionmaker() as s:
                known_agents = set((await s.scalars(select(Agent.id))).all())
                existing = set((await s.scalars(select(DiscoveryFinding.fingerprint))).all())
                clients = await c.agent_identity.list_clients()
                found = []
                for client in clients:
                    # Ungoverned: no agent behind it, or it names an agent the registry has never heard of.
                    if client.agent_id is None or client.agent_id not in known_agents:
                        finding = await record_signal(s, "idp", f"idp-client:{client.client_id}",
                                                      {"client_id": client.client_id, "name": client.name},
                                                      count_hit=trigger != "scheduled")
                        found.append(finding.fingerprint)
                await s.commit()
        except Exception as exc:
            # Only the error type is kept: provider messages can name internal hosts.
            c.discovery_status["last_run"] = {"at": started.isoformat(), "trigger": trigger, "actor": actor,
                                              "ok": False, "error": type(exc).__name__}
            raise
    result = {"found": found, "checked": len(clients), "new": len([f for f in found if f not in existing])}
    c.discovery_status["last_run"] = {"at": started.isoformat(), "trigger": trigger, "actor": actor, "ok": True,
                                      "checked": result["checked"], "ungoverned": len(found), "new": result["new"]}
    return result


async def scan_periodically(c: ControlContext) -> None:
    """Background loop: scan now, then every `discovery_scan_interval` seconds. A failed scan never stops the loop."""
    interval = c.settings.discovery_scan_interval
    while True:
        try:
            report = await run_idp_scan(c, SCHEDULER, "scheduled")
            if report["new"]:
                log.info("scheduled identity-provider scan: %d new ungoverned identities", report["new"])
        except Exception as exc:
            log.warning("scheduled identity-provider scan failed: %s", exc)
        c.discovery_status["next_run_at"] = (datetime.now(UTC) + timedelta(seconds=interval)).isoformat()
        await asyncio.sleep(interval)


async def disable_identity(c: ControlContext, fingerprint: str) -> None:
    """Switch off an ungoverned identity. One that has already vanished from the provider is the desired end state."""
    try:
        await c.agent_identity.set_enabled(fingerprint.removeprefix("idp-client:"), False)
    except IdentityNotFound:
        pass


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/discovery", tags=["discovery"])

    @r.get("/findings", dependencies=[Depends(require_roles(*OPERATORS))])
    async def findings(s: AsyncSession = Depends(session)):
        rows = (await s.execute(select(DiscoveryFinding).order_by(DiscoveryFinding.last_seen.desc()))).scalars()
        return [finding_dict(f) for f in rows]

    @r.get("/status", dependencies=[Depends(require_roles(*OPERATORS))])
    async def status(request: Request):
        c: ControlContext = request.app.state.ctx
        interval = c.settings.discovery_scan_interval
        return {
            "sources": {"gateway": "active", "idp": "scheduled" if interval else "manual",
                        "otel": "planned", "repo": "planned", "cloud": "planned"},
            "idp_scan": {"automatic": interval > 0, "interval_seconds": interval,
                         "last_run": c.discovery_status.get("last_run"),
                         "next_run_at": c.discovery_status.get("next_run_at") if interval else None},
        }

    @r.post("/scan")
    async def scan(request: Request, user: Persona = Depends(require_roles("soc-analyst", "admin"))):
        """IdP scan on demand: identities that exist in the IdP but are not governed by the registry."""
        return await run_idp_scan(request.app.state.ctx, f"user:{user.username}", "manual")

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
            await disable_identity(request.app.state.ctx, finding.fingerprint)
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
            await disable_identity(c, finding.fingerprint)
        finding.status = "quarantined"
        await ledger.append(s, "discovery.quarantined", f"user:{user.username}", finding.fingerprint, {})
        await s.commit()
        return finding_dict(finding)

    return r
