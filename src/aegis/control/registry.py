"""Agent registry, lifecycle and re-attestation (plan §8.1, §8.2, flow F1)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.ids import agent_id as new_agent_id
from aegis.common.ids import new_id
from aegis.common.models import LIFECYCLE, MATERIAL_FIELDS, AgentCreate, AgentPatch, AgentStatus
from aegis.control import ledger
from aegis.control.auth import OPERATORS, current_user, require_roles
from aegis.control.context import ControlContext, session
from aegis.control.identity import sts
from aegis.control.identity.agent_identity import IdentityNotFound
from aegis.control.identity.idp import Persona
from aegis.control.tables import Agent, Alert, Tool

# Each factor is normalized to 0-100, then weighted, so the weights are a legible statement of what
# matters most (tool criticality and autonomy dominate; capability breadth is a minor tiebreaker).
AUTONOMY_SCORE = {"L0": 0, "L1": 30, "L2": 65, "L3": 100}
DATA_SCORE = {"public": 0, "internal": 30, "confidential": 70, "restricted": 100}
SIDE_EFFECT_SCORE = {"read": 0, "write": 35, "financial": 75, "destructive": 100}
WEIGHTS = {"autonomy": 0.30, "tool_criticality": 0.30, "data_class": 0.20, "exposure": 0.15, "capability_breadth": 0.05}
HIGH_AUTONOMY = {"L2", "L3"}
HIGH_CRITICALITY = {"financial", "destructive"}
COMPOUNDING_BONUS = 15  # an autonomous agent holding a financial/destructive tool is worse than the parts imply


def risk_tier(score: int) -> str:
    return "low" if score < 30 else "medium" if score < 55 else "high" if score < 80 else "critical"


async def inherent_risk(s: AsyncSession, agent: Agent) -> tuple[int, dict]:
    """Explainable 0-100 score: weighted autonomy + tool criticality + data class + exposure + capability
    breadth, plus a compounding bonus when high autonomy meets a financial/destructive tool (plan §8.1)."""
    tools = (await s.execute(select(Tool).where(Tool.id.in_(agent.capabilities or ["-"])))).scalars().all()
    side_effects = [(t.classification or {}).get("side_effect", "read") for t in tools]
    egress = [(t.classification or {}).get("egress", "none") for t in tools]
    worst_effect = max(side_effects, key=lambda x: SIDE_EFFECT_SCORE.get(x, 100), default="read")
    factors = {
        "autonomy": AUTONOMY_SCORE.get(agent.autonomy, 100),
        "tool_criticality": SIDE_EFFECT_SCORE.get(worst_effect, 100),
        "data_class": DATA_SCORE.get(agent.max_data_class, 100),
        "exposure": min(100, (50 if agent.customer_facing else 0) + (30 if agent.environment == "PRD" else 0)
                        + (20 if "external" in egress else 0)),
        "capability_breadth": min(100, len(agent.capabilities or []) * 8),
    }
    parts = {k: round(v * WEIGHTS[k]) for k, v in factors.items()}
    compounding = COMPOUNDING_BONUS if agent.autonomy in HIGH_AUTONOMY and worst_effect in HIGH_CRITICALITY else 0
    if compounding:
        parts["compounding"] = compounding
    return min(100, sum(parts.values())), parts


def to_dict(a: Agent) -> dict:
    return {
        "id": a.id, "name": a.name, "description": a.description, "purpose": a.purpose,
        "intent_categories": a.intent_categories, "owner": a.owner, "sponsor": a.sponsor,
        "registered_by": a.registered_by, "business_unit": a.business_unit, "environment": a.environment,
        "cloud": a.cloud, "framework": a.framework, "autonomy": a.autonomy, "max_data_class": a.max_data_class,
        "customer_facing": a.customer_facing, "capabilities": a.capabilities,
        "can_delegate_to": a.can_delegate_to, "can_receive_from": a.can_receive_from, "max_depth": a.max_depth,
        "endpoint_url": a.endpoint_url, "inherent_risk": a.inherent_risk, "risk_tier": a.risk_tier,
        "status": a.status, "idp_client_id": a.idp_client_id, "orphaned": a.orphaned,
        "attestation_due": a.attestation_due, "created_at": a.created_at, "last_active_at": a.last_active_at,
    }


async def transition(s: AsyncSession, agent: Agent, target: AgentStatus, actor: str, reason: str = "") -> None:
    current = AgentStatus(agent.status)
    if target not in LIFECYCLE[current]:
        raise HTTPException(409, f"illegal lifecycle transition {current} -> {target}")
    agent.status = target
    await ledger.append(s, f"agent.{target}", actor, agent.id, {"from": current, "reason": reason})


async def load(s: AsyncSession, agent_id: str) -> Agent:
    agent = await s.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, "agent not found")
    return agent


class Reason(BaseModel):
    reason: str = ""


class CampaignRequest(BaseModel):
    due_in_days: int = 14


class LeaverEvent(BaseModel):
    username: str


def router() -> APIRouter:
    r = APIRouter(prefix="/v1", tags=["registry"])

    @r.post("/agents", status_code=201)
    async def register(body: AgentCreate, s: AsyncSession = Depends(session),
                       user: Persona = Depends(require_roles("agent-developer", "admin"))):
        if (await s.execute(select(Agent).where(Agent.name == body.name))).scalar_one_or_none():
            raise HTTPException(409, "an agent with this name already exists")
        agent = Agent(id=new_agent_id(), registered_by=user.username, status=AgentStatus.DRAFT,
                      **body.model_dump())
        agent.inherent_risk, _ = await inherent_risk(s, agent)
        agent.risk_tier = risk_tier(agent.inherent_risk)
        s.add(agent)
        await ledger.append(s, "agent.registered", f"user:{user.username}", agent.id,
                            {"name": agent.name, "risk_tier": agent.risk_tier})
        await s.commit()
        return to_dict(agent)

    @r.get("/agents", dependencies=[Depends(require_roles(*OPERATORS))])
    async def list_agents(status: str | None = None, environment: str | None = None, cloud: str | None = None,
                          data_class: str | None = None, q: str | None = None, attestation: str | None = None,
                          limit: int = 50, offset: int = 0, s: AsyncSession = Depends(session)):
        query = select(Agent)
        if attestation == "due":
            query = query.where(Agent.attestation_due.is_not(None))
        elif attestation == "orphaned":
            query = query.where(Agent.orphaned.is_(True))
        if status:
            query = query.where(Agent.status == status)
        if environment:
            query = query.where(Agent.environment == environment)
        if cloud:
            query = query.where(Agent.cloud == cloud)
        if data_class:
            query = query.where(Agent.max_data_class == data_class)
        if q:
            like = f"%{q}%"
            query = query.where(or_(Agent.name.ilike(like), Agent.id.ilike(like), Agent.owner.ilike(like)))
        total = (await s.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
        # Most recently active first, so live agents surface above the rest of the inventory.
        rows = (await s.execute(query.order_by(Agent.last_active_at.desc().nulls_last(), Agent.name)
                                .limit(min(limit, 200)).offset(offset))).scalars()
        return {"total": total, "items": [to_dict(a) for a in rows]}

    @r.get("/agents/stats", dependencies=[Depends(require_roles(*OPERATORS))])
    async def stats(s: AsyncSession = Depends(session)):
        by_status = dict((await s.execute(select(Agent.status, func.count()).group_by(Agent.status))).all())
        open_alerts = (await s.execute(select(func.count()).where(Alert.status == "new"))).scalar_one()
        due = (await s.execute(select(func.count()).where(Agent.attestation_due.is_not(None)))).scalar_one()
        return {"total": sum(by_status.values()), "by_status": by_status,
                "shadow": by_status.get(AgentStatus.DISCOVERED, 0) + by_status.get(AgentStatus.QUARANTINED, 0),
                "pending_attestation": due, "active_alerts": open_alerts}

    @r.get("/agents/{agent_id}", dependencies=[Depends(require_roles(*OPERATORS))])
    async def get_agent(agent_id: str, s: AsyncSession = Depends(session)):
        agent = await load(s, agent_id)
        _, parts = await inherent_risk(s, agent)
        return {**to_dict(agent), "risk_breakdown": parts}

    @r.get("/agents/{agent_id}/passport", dependencies=[Depends(require_roles(*OPERATORS))])
    async def passport(agent_id: str, request: Request, s: AsyncSession = Depends(session)):
        """A signed, portable statement of who the agent is and what it is for."""
        agent = await load(s, agent_id)
        c: ControlContext = request.app.state.ctx
        body = {k: v for k, v in to_dict(agent).items()
                if k in {"id", "name", "purpose", "intent_categories", "owner", "sponsor", "environment",
                         "autonomy", "max_data_class", "risk_tier", "status", "capabilities"}}
        now = int(datetime.now(UTC).timestamp())
        return {"passport": body, "jws": c.sts_key.sign({"iss": c.sts_issuer, "sub": agent.id, "iat": now,
                                                          "exp": now + 3600, "passport": body})}

    @r.patch("/agents/{agent_id}")
    async def update(agent_id: str, body: AgentPatch, request: Request, s: AsyncSession = Depends(session),
                     user: Persona = Depends(require_roles("agent-developer", "agent-owner", "admin"))):
        agent = await load(s, agent_id)
        changes = body.model_dump(exclude_none=True)
        for key, value in changes.items():
            setattr(agent, key, value)
        if MATERIAL_FIELDS & changes.keys() and agent.status == AgentStatus.ACTIVE:
            # Material change: purpose, scope, tools or data class need re-approval (plan §8.1),
            # and mandates issued under the old definition stop working immediately.
            await transition(s, agent, AgentStatus.PENDING_APPROVAL, f"user:{user.username}", "material change")
            radius = await sts.blast_radius(s, agent.id)
            await sts.revoke_tree(request.app.state.ctx, s, radius["mandates"], "material change",
                                  f"user:{user.username}")
        agent.inherent_risk, _ = await inherent_risk(s, agent)
        agent.risk_tier = risk_tier(agent.inherent_risk)
        await ledger.append(s, "agent.updated", f"user:{user.username}", agent.id, {"fields": sorted(changes)})
        await s.commit()
        return to_dict(agent)

    @r.post("/agents/{agent_id}/submit")
    async def submit(agent_id: str, s: AsyncSession = Depends(session),
                     user: Persona = Depends(require_roles("agent-developer", "agent-owner", "admin"))):
        agent = await load(s, agent_id)
        await transition(s, agent, AgentStatus.PENDING_APPROVAL, f"user:{user.username}")
        await s.commit()
        return to_dict(agent)

    @r.post("/agents/{agent_id}/approve")
    async def approve(agent_id: str, body: Reason, request: Request, s: AsyncSession = Depends(session),
                      user: Persona = Depends(require_roles("risk-approver"))):
        agent = await load(s, agent_id)
        if user.username in (agent.registered_by, agent.owner):
            raise HTTPException(403, "SOD-001: the registrant or owner cannot approve their own agent")
        c: ControlContext = request.app.state.ctx
        await transition(s, agent, AgentStatus.ACTIVE, f"user:{user.username}", body.reason)
        credentials = None
        event = "identity.provisioned"
        if agent.idp_client_id is not None:
            try:
                await c.agent_identity.set_enabled(agent.idp_client_id, True)
            except IdentityNotFound:  # the provider lost it (e.g. the realm was recreated): issue a new identity
                agent.idp_client_id, event = None, "identity.reprovisioned"
        if agent.idp_client_id is None:
            # A provider failure raises 503 before anything is committed, so the agent stays pending approval.
            issued = await c.agent_identity.provision(agent.id, agent.name)
            agent.idp_client_id = issued.client_id
            credentials = issued.credentials()
            await ledger.append(s, event, f"user:{user.username}", agent.id,
                                {"client_id": issued.client_id, "idp": issued.provider})
        await s.commit()
        # The private key is returned exactly once, for the agent runtime's secret store.
        return {"agent": to_dict(agent), "credentials": credentials}

    @r.post("/agents/{agent_id}/reject")
    async def reject(agent_id: str, body: Reason, s: AsyncSession = Depends(session),
                     user: Persona = Depends(require_roles("risk-approver"))):
        agent = await load(s, agent_id)
        await transition(s, agent, AgentStatus.DRAFT, f"user:{user.username}", body.reason)
        await s.commit()
        return to_dict(agent)

    @r.get("/agents/{agent_id}/blast-radius", dependencies=[Depends(require_roles(*OPERATORS))])
    async def preview_blast_radius(agent_id: str, s: AsyncSession = Depends(session)):
        await load(s, agent_id)
        return await sts.blast_radius(s, agent_id)

    @r.post("/agents/{agent_id}/suspend")
    async def suspend(agent_id: str, body: Reason, request: Request, s: AsyncSession = Depends(session),
                      user: Persona = Depends(require_roles("soc-analyst", "risk-approver", "agent-owner"))):
        agent = await load(s, agent_id)
        if AgentStatus.SUSPENDED not in LIFECYCLE[AgentStatus(agent.status)]:
            raise HTTPException(409, f"cannot suspend an agent in state {agent.status}")
        radius = await sts.suspend_agent(request.app.state.ctx, s, agent_id, body.reason or "manual suspension",
                                         f"user:{user.username}")
        await s.commit()
        return {"agent": to_dict(agent), "blast_radius": radius}

    @r.post("/agents/{agent_id}/resume")
    async def resume(agent_id: str, body: Reason, request: Request, s: AsyncSession = Depends(session),
                     user: Persona = Depends(require_roles("risk-approver"))):
        agent = await load(s, agent_id)
        await transition(s, agent, AgentStatus.ACTIVE, f"user:{user.username}", body.reason)
        c: ControlContext = request.app.state.ctx
        if agent.idp_client_id:
            try:
                await c.agent_identity.set_enabled(agent.idp_client_id, True)
            except IdentityNotFound as exc:
                raise HTTPException(409, "this agent's identity no longer exists; approve the agent again") from exc
        # Old mandates stay revoked; only new mandates can be issued again.
        await c.hotstore.clear("agent", agent_id)
        await s.commit()
        return to_dict(agent)

    @r.post("/agents/{agent_id}/retire")
    async def retire(agent_id: str, body: Reason, request: Request, s: AsyncSession = Depends(session),
                     user: Persona = Depends(require_roles("agent-owner", "admin"))):
        agent = await load(s, agent_id)
        if agent.status == AgentStatus.ACTIVE:
            await sts.suspend_agent(request.app.state.ctx, s, agent_id, "retired", f"user:{user.username}")
        await transition(s, agent, AgentStatus.RETIRED, f"user:{user.username}", body.reason)
        await s.commit()
        return to_dict(agent)

    # ---- re-attestation (plan §8.2) ----

    @r.post("/attestations/campaign")
    async def campaign(body: CampaignRequest, s: AsyncSession = Depends(session),
                       user: Persona = Depends(require_roles("risk-approver", "admin"))):
        due = datetime.now(UTC) + timedelta(days=body.due_in_days)
        agents = (await s.execute(select(Agent).where(Agent.status == AgentStatus.ACTIVE))).scalars().all()
        for agent in agents:
            agent.attestation_due = due
        await ledger.append(s, "attestation.campaign", f"user:{user.username}", "all-active",
                            {"agents": len(agents), "due": due.isoformat()})
        await s.commit()
        return {"agents": len(agents), "due": due}

    @r.post("/agents/{agent_id}/attest")
    async def attest(agent_id: str, s: AsyncSession = Depends(session), user: Persona = Depends(current_user)):
        agent = await load(s, agent_id)
        if user.username != agent.owner:
            raise HTTPException(403, "only the agent's owner can attest")
        agent.attestation_due, agent.orphaned = None, False
        await ledger.append(s, "attestation.confirmed", f"user:{user.username}", agent.id, {})
        await s.commit()
        return to_dict(agent)

    @r.post("/attestations/enforce")
    async def enforce(request: Request, s: AsyncSession = Depends(session),
                      user: Persona = Depends(require_roles("risk-approver", "admin"))):
        now = datetime.now(UTC)
        overdue = [a for a in (await s.execute(select(Agent).where(Agent.status == AgentStatus.ACTIVE,
                                                                     Agent.attestation_due.is_not(None)))).scalars()
                   if a.attestation_due.replace(tzinfo=UTC) <= now]
        for agent in overdue:
            await sts.suspend_agent(request.app.state.ctx, s, agent.id, "attestation overdue",
                                    f"user:{user.username}")
        await s.commit()
        return {"suspended": [a.id for a in overdue]}

    @r.post("/idp-events/leaver")
    async def leaver(body: LeaverEvent, request: Request, s: AsyncSession = Depends(session),
                     user: Persona = Depends(require_roles("admin"))):
        """An owner left the bank: their agents become orphaned and must be re-attested now (DET-12)."""
        c: ControlContext = request.app.state.ctx
        if body.username in c.idp.personas:
            c.idp.mark_leaver(body.username)
        agents = (await s.execute(select(Agent).where(Agent.owner == body.username,
                                                      Agent.status == AgentStatus.ACTIVE))).scalars().all()
        for agent in agents:
            agent.orphaned, agent.attestation_due = True, datetime.now(UTC)
            s.add(Alert(id=new_id("alr"), rule_id="DET-12", severity="medium", agent_id=agent.id,
                        title=f"Agent {agent.name} is orphaned: owner {body.username} left",
                        evidence={"owner": body.username, "sponsor": agent.sponsor}))
        await ledger.append(s, "identity.leaver", f"user:{user.username}", body.username,
                            {"orphaned_agents": [a.id for a in agents]})
        await s.commit()
        return {"orphaned": [a.id for a in agents]}

    return r
