"""Control-plane API used by the Gateway (data plane). Not exposed through public ingress."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.ids import new_id
from aegis.control import approvals, ledger, risk, soc
from aegis.control.auth import require_internal
from aegis.control.context import session
from aegis.control.tables import Agent, Alert, Approval, DecisionRecord, McpServer, Tool, Usage


class DecisionIn(BaseModel):
    mandate_id: str | None = None
    root_id: str | None = None
    agent_id: str | None = None
    subject: str | None = None
    action: str
    decision: str
    reasons: list[dict] = Field(default_factory=list)
    obligations: list[dict] = Field(default_factory=list)
    policy_version: str = ""
    input_snapshot: dict = Field(default_factory=dict)
    data_class: str | None = None
    trace_id: str | None = None
    latency_ms: float = 0.0


class ApprovalIn(BaseModel):
    mandate_id: str
    agent_id: str
    tool: str
    arguments: dict
    reasons: list[dict] = Field(default_factory=list)


class UsageIn(BaseModel):
    agent_id: str
    mandate_id: str | None = None
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_eur: float = 0.0
    latency_ms: float = 0.0


def router() -> APIRouter:
    r = APIRouter(prefix="/internal", tags=["internal"], dependencies=[Depends(require_internal)])

    @r.get("/agents/{agent_id}")
    async def agent(agent_id: str, request: Request, s: AsyncSession = Depends(session)):
        a = await s.get(Agent, agent_id)
        if a is None:
            raise HTTPException(404, "unknown agent")
        score = await risk.compute(s, a)
        if (
            score.tier == "critical"
            and a.status == "active"
            and request.app.state.ctx.settings.auto_suspend_on_critical
        ):
            await soc.raise_alert(
                request.app.state.ctx,
                s,
                "DET-13",
                "critical",
                "Adaptive risk reached the critical tier",
                a.id,
                {"score": score.score, "signals": score.breakdown["signals"]},
            )
        await risk.persist(s, score)
        await s.commit()
        ranks = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        effective_tier = max((a.risk_tier, score.tier), key=lambda t: ranks[t])
        return {
            "id": a.id,
            "name": a.name,
            "status": a.status,
            "risk_tier": effective_tier,
            "env": a.environment,
            "risk_score": score.score,
            "autonomy": a.autonomy,
            "owner": a.owner,
            "endpoint_url": a.endpoint_url,
            "can_delegate_to": a.can_delegate_to,
            "can_receive_from": a.can_receive_from,
        }

    @r.get("/servers/{server_id}")
    async def server(server_id: str, s: AsyncSession = Depends(session)):
        m = await s.get(McpServer, server_id)
        if m is None or m.status != "active":
            raise HTTPException(404, "unknown or inactive MCP server")
        return {"id": m.id, "url": m.url}

    @r.get("/tools")
    async def tools(server: str, s: AsyncSession = Depends(session)):
        rows = (await s.execute(select(Tool).where(Tool.server_id == server))).scalars()
        return [
            {
                "id": t.id,
                "name": t.name,
                "status": t.status,
                "approved_hash": t.approved_hash,
                "classification": t.classification,
            }
            for t in rows
        ]

    @r.post("/decisions")
    async def decision(body: DecisionIn, request: Request, s: AsyncSession = Depends(session)):
        record = DecisionRecord(id=new_id("dec"), **body.model_dump())
        s.add(record)
        await ledger.append(
            s,
            f"decision.{body.decision}",
            f"agent:{body.agent_id}",
            body.action,
            {
                "decision_id": record.id,
                "mandate": body.mandate_id,
                "rules": [r.get("rule") for r in body.reasons],
                "policy_version": body.policy_version,
            },
        )
        await soc.on_decision(request.app.state.ctx, s, record)
        agent_row = await s.get(Agent, body.agent_id) if body.agent_id else None
        if agent_row:
            score = await risk.compute(s, agent_row)
            candidates = []
            if score.baseline["status"] == "ready":
                if score.baseline["robust_z_score"] > 3.5:
                    candidates.append(("DET-08", "medium", "Call rate exceeded the observed agent baseline"))
                if score.baseline["new_tools"]:
                    candidates.append(("DET-09", "low", "First-time tool use relative to observed history"))
            for rule, severity, title in candidates:
                recent = (
                    await s.scalars(
                        select(Alert).where(
                            Alert.agent_id == agent_row.id,
                            Alert.rule_id == rule,
                            Alert.ts >= datetime.now(UTC) - timedelta(minutes=5),
                        )
                    )
                ).first()
                if not recent:
                    await soc.raise_alert(
                        request.app.state.ctx,
                        s,
                        rule,
                        severity,
                        title,
                        agent_row.id,
                        {"decision": record.id, "baseline": score.baseline},
                    )
            await risk.persist(s, score)
        await s.commit()
        return {"id": record.id}

    @r.post("/events")
    async def event(body: dict, request: Request, s: AsyncSession = Depends(session)):
        await soc.on_event(request.app.state.ctx, s, body)
        await s.commit()
        return {"ok": True}

    @r.post("/approvals")
    async def create_approval(body: ApprovalIn, request: Request, s: AsyncSession = Depends(session)):
        approval = await approvals.create(request.app.state.ctx, s, body.model_dump())
        await s.commit()
        return {"id": approval.id, "status": approval.status, "action_hash": approval.action_hash}

    @r.get("/approvals/{approval_id}")
    async def get_approval(approval_id: str, s: AsyncSession = Depends(session)):
        a = await s.get(Approval, approval_id)
        if a is None:
            raise HTTPException(404, "unknown approval")
        await approvals.refresh_expiry(a)
        await s.commit()
        return {"id": a.id, "status": a.status, "action_hash": a.action_hash, "mandate_id": a.mandate_id}

    @r.post("/approvals/{approval_id}/consume")
    async def consume(approval_id: str, s: AsyncSession = Depends(session)):
        a = await s.get(Approval, approval_id)
        if a is None or a.status != "approved":
            raise HTTPException(409, "approval is not available")
        a.status = "consumed"  # single use
        await ledger.append(s, "approval.consumed", f"agent:{a.agent_id}", a.id, {"tool": a.tool})
        await s.commit()
        return {"id": a.id, "status": a.status}

    @r.post("/usage")
    async def usage(body: UsageIn, s: AsyncSession = Depends(session)):
        s.add(Usage(**body.model_dump()))
        await s.commit()
        return {"ok": True}

    return r
