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
from aegis.control.auth import require_internal
from aegis.control.tables import LlmReservation, Usage


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
    return {
        "day_utc": today,
        "used_or_reserved_eur": round(total, 6),
        "outstanding_holds": holds,
        "remaining_estimate_eur": round(max(0, ctx.settings.llm_daily_budget_eur - total), 6),
        "note": "Configured estimates, not Azure billing. Uncertain calls retain their holds.",
    }


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
    r = APIRouter(prefix="/internal/llm", dependencies=[Depends(require_internal)])

    @r.post("/reserve")
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
            await ledger.append(
                s,
                "llm.budget_reserved",
                body.agent_id,
                reservation.id,
                {"mandate_id": body.mandate_id, "estimated_eur": amount, "policy": snapshot, "policy_version": version},
            )
            await s.commit()
            return {"allowed": True, "reservation_id": reservation.id, "policy_version": version}

    @r.post("/{reservation_id}/settle")
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
