"""Python-enforced deployment, processing-footprint, data-class and estimated-budget controls.

OPA is intentionally not involved. PostgreSQL serializes reservations across gateway workers.
Configuration is server-owned; each reservation retains its policy snapshot and version.
"""

import math
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text

from aegis.common.hashing import sha256_hex
from aegis.common.ids import new_id
from aegis.common.models import data_class_rank
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_internal, require_roles
from aegis.control.tables import Agent, BudgetNotice, DecisionRecord, LlmReservation, Mandate, Usage


def policy(settings) -> dict:
    return {
        "engine": "python-model-controls",
        "deployment": settings.azure_openai_deployment,
        "processing_scope": settings.llm_processing_scope,
        "allowed_processing_scope": settings.llm_allowed_processing_scope,
        "max_data_class": settings.llm_max_data_class,
        "daily_budget_eur": settings.llm_daily_budget_eur,
        "input_eur_per_1k": settings.llm_price_in_per_1k,
        "output_eur_per_1k": settings.llm_price_out_per_1k,
        "budget_enforcement": "deny-before-provider",
        "budget_warning_ratio": 0.8,
    }


def policy_error(settings, deployment: str, data_class: str) -> str | None:
    if not settings.azure_openai_deployment or deployment != settings.azure_openai_deployment:
        return "The requested deployment is not allowlisted."
    scope = settings.llm_processing_scope
    allowed = settings.llm_allowed_processing_scope
    # 'global' explicitly permits broader processing; regional permission never permits global.
    if scope == "unknown" or (allowed != "global" and scope != allowed):
        return "Declared model processing scope is unknown or outside the permitted geography."
    if data_class_rank(data_class) > data_class_rank(settings.llm_max_data_class):
        return "The Mandate's data ceiling exceeds this model's permitted data class."
    return None


async def budget_status(ctx, agent_id: str) -> dict:
    today = datetime.now(UTC).date().isoformat()
    async with ctx.db.sessionmaker() as s:
        total = await s.scalar(
            select(func.coalesce(func.sum(LlmReservation.charged_eur), 0)).where(
                LlmReservation.agent_id == agent_id,
                LlmReservation.day == today,
            )
        )
        holds = await s.scalar(
            select(func.count())
            .select_from(LlmReservation)
            .where(
                LlmReservation.agent_id == agent_id,
                LlmReservation.day == today,
                LlmReservation.status == "reserved",
            )
        )
        decisions = list(
            await s.scalars(
                select(DecisionRecord).where(
                    DecisionRecord.agent_id == agent_id,
                    DecisionRecord.action == "llm.chat",
                    DecisionRecord.decision == "deny",
                    DecisionRecord.ts >= datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0),
                )
            )
        )
    return {
        "day_utc": today,
        "used_or_reserved_eur": round(total, 6),
        "outstanding_holds": holds,
        "remaining_estimate_eur": round(max(0, ctx.settings.llm_daily_budget_eur - total), 6),
        "daily_budget_eur": ctx.settings.llm_daily_budget_eur,
        "blocked_requests": sum(any(r.get("rule") == "LLM-BUDGET" for r in d.reasons) for d in decisions),
        "state": "exhausted"
        if total >= ctx.settings.llm_daily_budget_eur
        else "warning"
        if total >= 0.8 * ctx.settings.llm_daily_budget_eur
        else "within_budget",
        "note": "Configured estimates, not Azure billing. Uncertain calls retain their holds.",
    }


async def warn_budget(ctx, s, row):
    """Budget lock is held by the caller; the warning and notice commit with the reservation/settlement."""
    from aegis.control.soc import raise_alert

    config = row.policy_snapshot
    await s.flush()
    total = await s.scalar(
        select(func.coalesce(func.sum(LlmReservation.charged_eur), 0)).where(
            LlmReservation.agent_id == row.agent_id, LlmReservation.day == row.day
        )
    )
    notice_id = f"{row.agent_id}:{row.day}:{row.policy_version}"
    if total < 0.8 * config["daily_budget_eur"] or await s.get(BudgetNotice, notice_id):
        return
    mandate = await s.get(Mandate, row.mandate_id)
    alert = await raise_alert(
        ctx,
        s,
        "DET-16",
        "medium",
        "Estimated model budget reached 80%",
        row.agent_id,
        {
            "mandate_id": row.mandate_id,
            "root_id": mandate.root_id if mandate else None,
            "policy_version": row.policy_version,
            "day_utc": row.day,
            "used_or_reserved_eur": round(total, 6),
            "daily_budget_eur": config["daily_budget_eur"],
        },
    )
    s.add(BudgetNotice(id=notice_id, agent_id=row.agent_id, alert_id=alert.id))


class Reserve(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str
    mandate_id: str
    deployment: str
    data_class: str
    input_bound_tokens: int = Field(ge=1, le=1000000)
    output_bound_tokens: int = Field(ge=1, le=8192)


class Settle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(max_length=200)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    latency_ms: float = Field(ge=0, allow_inf_nan=False)


def router() -> APIRouter:
    r = APIRouter()

    @r.get("/v1/model-budgets", dependencies=[Depends(require_roles(*OPERATORS))])
    async def budgets(request: Request):
        ctx = request.app.state.ctx
        async with ctx.db.sessionmaker() as s:
            agents = list(await s.scalars(select(Agent).order_by(Agent.name).limit(200)))
        return {
            "policy": policy(ctx.settings),
            "items": [{"agent_id": a.id, "agent_name": a.name, **await budget_status(ctx, a.id)} for a in agents],
        }

    @r.post("/internal/llm/reserve", dependencies=[Depends(require_internal)])
    async def reserve(body: Reserve, request: Request):
        ctx = request.app.state.ctx
        settings = ctx.settings
        snapshot = policy(settings)
        version = sha256_hex(snapshot)
        reason = policy_error(settings, body.deployment, body.data_class)
        if reason:
            return {
                "allowed": False,
                "rule": "LLM-MODEL-POLICY",
                "message": reason,
                "policy_version": version,
                "policy": snapshot,
            }
        amount = (
            math.ceil(
                (
                    body.input_bound_tokens * settings.llm_price_in_per_1k
                    + body.output_bound_tokens * settings.llm_price_out_per_1k
                )
                * 1000
            )
            / 1000000
        )
        today = datetime.now(UTC).date().isoformat()
        # SQLite is only supported in a single-process demo. PG's transaction lock also covers other workers.
        async with ctx.llm_budget_lock, ctx.db.sessionmaker() as s:
            if s.bind.dialect.name == "postgresql":
                await s.execute(text("SELECT pg_advisory_xact_lock(724356913)"))
            used = await s.scalar(
                select(func.coalesce(func.sum(LlmReservation.charged_eur), 0)).where(
                    LlmReservation.agent_id == body.agent_id,
                    LlmReservation.day == today,
                )
            )
            if used + amount > settings.llm_daily_budget_eur:
                return {
                    "allowed": False,
                    "rule": "LLM-BUDGET",
                    "message": "Daily estimated agent budget exhausted.",
                    "policy_version": version,
                    "policy": snapshot,
                    "budget": {
                        "used_or_reserved_eur": round(used, 6),
                        "daily_budget_eur": settings.llm_daily_budget_eur,
                        "requested_estimate_eur": amount,
                    },
                }
            reservation = LlmReservation(
                id=new_id("llm"),
                agent_id=body.agent_id,
                mandate_id=body.mandate_id,
                deployment=body.deployment,
                day=today,
                reserved_eur=amount,
                charged_eur=amount,
                policy_version=version,
                policy_snapshot=snapshot,
            )
            s.add(reservation)
            await warn_budget(ctx, s, reservation)
            await ledger.append(
                s,
                "llm.budget_reserved",
                body.agent_id,
                reservation.id,
                {"mandate_id": body.mandate_id, "estimated_eur": amount, "policy": snapshot, "policy_version": version},
            )
            await s.commit()
            return {"allowed": True, "reservation_id": reservation.id, "policy_version": version}

    @r.post("/internal/llm/{reservation_id}/settle", dependencies=[Depends(require_internal)])
    async def settle(reservation_id: str, body: Settle, request: Request):
        ctx = request.app.state.ctx
        async with ctx.llm_budget_lock, ctx.db.sessionmaker() as s:
            if s.bind.dialect.name == "postgresql":
                await s.execute(text("SELECT pg_advisory_xact_lock(724356913)"))
            row = await s.get(LlmReservation, reservation_id)
            if row is None:
                return {"settled": False}
            if row.status == "settled":
                return {"settled": True, "cost_eur": row.charged_eur}
            config = row.policy_snapshot
            cost = round(
                (body.input_tokens * config["input_eur_per_1k"] + body.output_tokens * config["output_eur_per_1k"])
                / 1000,
                6,
            )
            row.status, row.charged_eur = "settled", cost
            await warn_budget(ctx, s, row)
            s.add(
                Usage(
                    agent_id=row.agent_id,
                    mandate_id=row.mandate_id,
                    model=body.model,
                    input_tokens=body.input_tokens,
                    output_tokens=body.output_tokens,
                    cost_eur=cost,
                    latency_ms=body.latency_ms,
                )
            )
            await ledger.append(
                s,
                "llm.budget_settled",
                row.agent_id,
                row.id,
                {"cost_estimate_eur": cost, "input_tokens": body.input_tokens, "output_tokens": body.output_tokens},
            )
            await s.commit()
            return {"settled": True, "cost_eur": cost}

    return r
