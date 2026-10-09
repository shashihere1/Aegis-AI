"""Human-in-the-loop approvals bound to one exact action (plan §8.8, flow F5)."""

from datetime import UTC, datetime, timedelta

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common import crypto
from aegis.common.hashing import action_hash
from aegis.common.ids import new_id
from aegis.control import ledger
from aegis.control.auth import require_roles
from aegis.control.context import ControlContext, session
from aegis.control.identity.idp import Persona
from aegis.control.tables import Agent, Approval, Mandate


def approval_dict(a: Approval) -> dict:
    return {"id": a.id, "status": a.status, "tool": a.tool, "arguments": a.arguments, "intent": a.intent,
            "subject": a.subject, "chain": a.chain, "agent_id": a.agent_id, "mandate_id": a.mandate_id,
            "reasons": a.reasons, "approver": a.approver, "justification": a.justification,
            "created_at": a.created_at, "expires_at": a.expires_at, "action_hash": a.action_hash}


async def refresh_expiry(a: Approval) -> Approval:
    if a.status == "pending" and a.expires_at.replace(tzinfo=UTC) <= datetime.now(UTC):
        a.status = "expired"
    return a


async def create(c: ControlContext, s: AsyncSession, data: dict) -> Approval:
    digest = action_hash(data["tool"], data["arguments"], data["mandate_id"])
    existing = (await s.execute(select(Approval).where(Approval.action_hash == digest,
                                                       Approval.status == "pending"))).scalar_one_or_none()
    if existing:
        return existing
    mandate = await s.get(Mandate, data["mandate_id"])
    approval = Approval(
        id=new_id("apr"), action_hash=digest, mandate_id=data["mandate_id"], agent_id=data["agent_id"],
        subject=mandate.subject if mandate else data.get("subject", ""), chain=mandate.chain if mandate else [],
        tool=data["tool"], arguments=data["arguments"], intent=mandate.intent if mandate else "",
        reasons=data.get("reasons", []),
        expires_at=datetime.now(UTC) + timedelta(seconds=c.settings.approval_ttl),
    )
    s.add(approval)
    await ledger.append(s, "approval.requested", f"agent:{data['agent_id']}", approval.id,
                        {"tool": approval.tool, "reasons": approval.reasons})
    return approval


class DecisionBody(BaseModel):
    justification: str = ""


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/approvals", tags=["approvals"])

    @r.get("", dependencies=[Depends(require_roles("risk-approver", "soc-analyst", "auditor"))])
    async def list_approvals(status: str | None = "pending", s: AsyncSession = Depends(session)):
        query = select(Approval).order_by(Approval.created_at.desc())
        rows = [await refresh_expiry(a) for a in (await s.execute(query)).scalars()]
        await s.commit()
        names = dict((await s.execute(select(Agent.id, Agent.name).where(
            Agent.id.in_({x for a in rows for x in a.chain})))).all())
        return [{**approval_dict(a), "chain_names": [names.get(x, x) for x in a.chain]}
                for a in rows if status in (None, "all", a.status)]

    async def decide(c: ControlContext, approval_id: str, verdict: str, body: DecisionBody, s: AsyncSession,
                     user: Persona):
        approval = await s.get(Approval, approval_id)
        if approval is None:
            raise HTTPException(404, "unknown approval")
        await refresh_expiry(approval)
        if approval.status != "pending":
            raise HTTPException(409, f"approval is {approval.status}")
        owners = {a.owner for a in (await s.execute(select(Agent).where(Agent.id.in_(approval.chain)))).scalars()}
        initiator = approval.subject.removeprefix("user:") if approval.subject.startswith("user:") else None
        involved = ([initiator] if initiator else []) + sorted(owners)
        if any([await c.people.same_person(s, user, name) for name in involved]):
            raise HTTPException(403, "SOD-003: approver cannot be the initiating user or an owner of an agent "
                                     "in the chain")
        approval.status, approval.approver = verdict, user.username
        approval.justification, approval.decided_at = body.justification, datetime.now(UTC)
        await ledger.append(s, f"approval.{verdict}", f"user:{user.username}", approval.id,
                            {"tool": approval.tool, "arguments": approval.arguments,
                             "justification": body.justification})
        await s.commit()
        return approval_dict(approval)

    @r.post("/{approval_id}/approve")
    async def approve(approval_id: str, body: DecisionBody, request: Request, s: AsyncSession = Depends(session),
                      user: Persona = Depends(require_roles("risk-approver"))):
        return await decide(request.app.state.ctx, approval_id, "approved", body, s, user)

    @r.post("/{approval_id}/reject")
    async def reject(approval_id: str, body: DecisionBody, request: Request, s: AsyncSession = Depends(session),
                     user: Persona = Depends(require_roles("risk-approver"))):
        return await decide(request.app.state.ctx, approval_id, "rejected", body, s, user)

    @r.get("/{approval_id}/status")
    async def status(approval_id: str, request: Request, s: AsyncSession = Depends(session)):
        """Polled by the waiting agent; authorised by a mandate from the same task."""
        c: ControlContext = request.app.state.ctx
        try:
            claims = crypto.verify(request.headers.get("authorization", "")[7:], c.sts_key.public_pem,
                                   issuer=c.sts_issuer)
        except jwt.InvalidTokenError as exc:
            raise HTTPException(401, str(exc)) from exc
        approval = await s.get(Approval, approval_id)
        mandate = await s.get(Mandate, approval.mandate_id) if approval else None
        if approval is None or mandate is None or mandate.root_id != claims["aegis"]["root_id"]:
            raise HTTPException(404, "unknown approval")
        await refresh_expiry(approval)
        await s.commit()
        return {"id": approval.id, "status": approval.status}

    return r
