"""Explainable risk from recorded traffic; no fabricated history or model response."""

import math
from collections import Counter
from datetime import UTC, datetime, timedelta
from statistics import median

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import session
from aegis.control.tables import Agent, AgentRisk, Alert, DecisionRecord, utcnow


def aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def tier(score: int) -> str:
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"


async def compute(s, agent: Agent) -> AgentRisk:
    now = datetime.now(UTC)
    rows = (
        await s.scalars(
            select(DecisionRecord)
            .where(DecisionRecord.agent_id == agent.id, DecisionRecord.ts >= now - timedelta(days=14))
            .order_by(DecisionRecord.ts)
        )
    ).all()
    # Compare current minute to completed active-minute buckets; do not invent quiet historical periods.
    minute = now.replace(second=0, microsecond=0)
    history = [d for d in rows if aware(d.ts) < minute]
    recent = [d for d in rows if aware(d.ts) >= now - timedelta(minutes=5)]
    buckets = Counter(aware(d.ts).replace(second=0, microsecond=0).isoformat() for d in history)
    ready = len(history) >= 20 and len(buckets) >= 5
    baseline_median = median(buckets.values()) if buckets else 0
    mad = median(abs(n - baseline_median) for n in buckets.values()) if buckets else 0
    current_calls = sum(aware(d.ts) >= minute for d in rows)
    z_score = 0.6745 * (current_calls - baseline_median) / max(mad, 1) if ready else None
    known_tools = {d.action for d in history if ":" not in d.action}
    new_tools = sorted({d.action for d in recent if ":" not in d.action} - known_tools) if ready else []
    alerts = (
        await s.scalars(select(Alert).where(Alert.agent_id == agent.id, Alert.ts >= now - timedelta(hours=24)))
    ).all()
    weights = {"DET-01": 20, "DET-02": 35, "DET-03": 20, "DET-04": 12, "DET-05": 15}
    signals = []
    for alert in alerts:
        if alert.status == "false_positive":
            continue
        weight = weights.get(alert.rule_id, 5) * math.exp(-(now - aware(alert.ts)).total_seconds() / 86400)
        signals.append({"source": alert.id, "reason": alert.rule_id, "points": round(weight, 2)})
    denies = sum(d.decision == "deny" for d in recent)
    if denies:
        signals.append({"reason": "Denied calls in the last five minutes", "points": min(10, denies * 2)})
    if ready and z_score is not None and z_score > 3.5:
        signals.append({"reason": "Call-rate deviation from observed baseline", "points": 15})
    if new_tools:
        signals.append({"reason": "First-time tools relative to observed history", "points": 5})
    # The registry's inherent score is 0-100; it supplies at most 40 of the 100 points here (behaviour 40, posture 20).
    inherent = round(min(100, max(0, agent.inherent_risk)) * 0.4)
    behavioural = min(40, round(sum(signal["points"] for signal in signals)))
    posture = min(
        20, (15 if agent.orphaned else 0) + (10 if agent.attestation_due and aware(agent.attestation_due) < now else 0)
    )
    score = inherent + behavioural + posture
    # Pure calculation first. Persist last, after any alert/ledger writes, for consistent lock order.
    row = AgentRisk(agent_id=agent.id, score=score, tier=tier(score))
    row.score, row.tier, row.updated_at = score, tier(score), utcnow()
    row.breakdown = {
        "inherent": inherent,
        "behavioural": behavioural,
        "posture": posture,
        "signals": signals,
        "denied_calls_5m": denies,
    }
    row.baseline = {
        "status": "ready" if ready else "warming_up",
        "history_calls": len(history),
        "observed_minutes": len(buckets),
        "minimum_calls": 20,
        "minimum_minutes": 5,
        "median_calls_per_active_minute": baseline_median,
        "mad": mad,
        "current_minute_calls": current_calls,
        "robust_z_score": round(z_score, 2) if ready else None,
        "new_tools": new_tools,
        "window_days": 14,
        "limitations": "Active-minute baseline; not a trained model or an hour-of-week profile.",
    }
    return row


async def persist(s, row: AgentRisk) -> None:
    """Atomic upsert prevents duplicate first-use rows from concurrent UI / gateway requests."""
    fields = ("agent_id", "score", "tier", "breakdown", "baseline", "updated_at")
    values = {field: getattr(row, field) for field in fields}
    insert = pg_insert if s.bind.dialect.name == "postgresql" else sqlite_insert
    statement = insert(AgentRisk).values(**values)
    await s.execute(
        statement.on_conflict_do_update(
            index_elements=["agent_id"], set_={field: values[field] for field in fields if field != "agent_id"}
        )
    )


def risk_dict(row: AgentRisk) -> dict:
    return {
        "agent_id": row.agent_id,
        "score": row.score,
        "tier": row.tier,
        "breakdown": row.breakdown,
        "baseline": row.baseline,
        "updated_at": row.updated_at,
    }


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/risk", tags=["adaptive risk"], dependencies=[Depends(require_roles(*OPERATORS))])

    @r.get("/{agent_id}")
    async def get_risk(agent_id: str, s=Depends(session)):
        agent = await s.get(Agent, agent_id)
        if agent is None:
            raise HTTPException(404, "Agent not found")
        row = await compute(s, agent)
        await persist(s, row)
        await s.commit()
        return risk_dict(row)

    return r
