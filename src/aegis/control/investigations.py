"""Analyst assignments, validated case transitions and append-only investigation history."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from aegis.common.ids import new_id
from aegis.control import ledger
from aegis.control.auth import require_roles
from aegis.control.context import ctx, session
from aegis.control.identity.idp import Persona
from aegis.control.tables import Alert, AlertCase, CaseEvent, DecisionRecord, utcnow

TRANSITIONS = {
    "new": {"triage", "investigating", "false_positive"},
    "triage": {"investigating", "resolved", "false_positive"},
    "investigating": {"triage", "resolved", "false_positive"},
    "resolved": {"investigating"},
    "false_positive": {"investigating"},
}


class CaseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    status: Literal["new", "triage", "investigating", "resolved", "false_positive"] | None = None
    assigned_to: str | None = Field(default=None, max_length=120)
    note: str | None = Field(default=None, min_length=3, max_length=4000)
    decision_id: str | None = None


async def update_case(c, s, alert: Alert, body: CaseUpdate, user: Persona) -> dict:
    case = await s.get(AlertCase, alert.id)
    if case is None:
        case = AlertCase(alert_id=alert.id)
        s.add(case)
    detail = {}
    if body.status is not None and body.status != alert.status:
        if body.status not in TRANSITIONS.get(alert.status, set()):
            raise HTTPException(409, f"Invalid transition from {alert.status} to {body.status}")
        if body.status in {"resolved", "false_positive"} and not body.note:
            raise HTTPException(422, "A resolution or false-positive justification is required")
        detail["status"] = {"before": alert.status, "after": body.status}
        alert.status = body.status
    if "assigned_to" in body.model_fields_set:
        if body.assigned_to:
            analyst = c.idp.personas.get(body.assigned_to)
            if not analyst or analyst.status != "active" or "soc-analyst" not in analyst.roles:
                raise HTTPException(422, "Assignee must be an active SOC analyst")
        detail["assignment"] = {"before": case.assigned_to, "after": body.assigned_to}
        case.assigned_to = body.assigned_to
    if body.note:
        detail["note"] = body.note
    if body.decision_id:
        decision = await s.get(DecisionRecord, body.decision_id)
        if decision is None or decision.agent_id != alert.agent_id:
            raise HTTPException(422, "Linked decision must belong to this alert's agent")
        detail["decision_id"] = decision.id
        detail["root_id"] = decision.root_id
        detail["trace_id"] = decision.trace_id
        detail["policy_version"] = decision.policy_version
    if not detail:
        raise HTTPException(422, "Provide an assignment, status change, note or evidence link")
    case.updated_at = utcnow()
    event = CaseEvent(id=new_id("case"), alert_id=alert.id, actor=user.username, kind="case.updated", detail=detail)
    s.add(event)
    await ledger.append(s, "case.updated", user.username, alert.id, {"case_event_id": event.id, **detail})
    await s.commit()
    return {"id": alert.id, "status": alert.status, "assigned_to": case.assigned_to}


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/alerts", tags=["investigations"])

    @r.get("/{alert_id}/case", dependencies=[Depends(require_roles("soc-analyst", "auditor", "admin"))])
    async def get_case(alert_id: str, s=Depends(session)):
        alert = await s.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(404, "Alert not found")
        case = await s.get(AlertCase, alert_id)
        events = (
            await s.scalars(
                select(CaseEvent).where(CaseEvent.alert_id == alert_id).order_by(CaseEvent.ts, CaseEvent.id)
            )
        ).all()
        decisions = (
            await s.scalars(
                select(DecisionRecord)
                .where(DecisionRecord.agent_id == alert.agent_id)
                .order_by(DecisionRecord.ts.desc())
                .limit(30)
            )
        ).all()
        return {
            "alert_id": alert_id,
            "status": alert.status,
            "assigned_to": case.assigned_to if case else None,
            "events": [{"id": e.id, "actor": e.actor, "kind": e.kind, "ts": e.ts, "detail": e.detail} for e in events],
            "decisions": [
                {
                    "id": d.id,
                    "action": d.action,
                    "decision": d.decision,
                    "trace_id": d.trace_id,
                    "root_id": d.root_id,
                    "policy_version": d.policy_version,
                    "ts": d.ts,
                }
                for d in decisions
            ],
        }

    @r.patch("/{alert_id}/case")
    async def patch_case(
        alert_id: str,
        body: CaseUpdate,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("soc-analyst")),
    ):
        alert = (await s.scalars(select(Alert).where(Alert.id == alert_id).with_for_update())).one_or_none()
        if alert is None:
            raise HTTPException(404, "Alert not found")
        return await update_case(c, s, alert, body, user)

    return r
