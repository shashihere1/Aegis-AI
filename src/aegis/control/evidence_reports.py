"""Durable report artifacts and scheduled generation. No Azure, email, or regulatory submission calls.

Due-slot row locks and unique job keys prevent duplicate reports across workers/restarts. Artifact,
checkpoint, audit event and schedule advancement commit together. The source database is never reset.
"""

import asyncio
import hashlib
import logging
import uuid
import zipfile
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import defer

from aegis.control import attestation, evidence, ledger
from aegis.control.auth import require_roles
from aegis.control.context import ControlContext, ctx
from aegis.control.evidence_controls import CATALOG, control_coverage, executive_summary
from aegis.control.evidence_scope import moment
from aegis.control.evidence_verify import verify_pack
from aegis.control.identity.idp import Persona
from aegis.control.tables import EvidenceReport, EvidenceSchedule, LedgerCheckpoint, LedgerEntry

log = logging.getLogger("aegis.evidence")
WORKER = "system:evidence-reporter"
Framework = Literal["all", "eu-ai-act", "dora", "gdpr", "iso-42001", "nist-ai-rmf"]


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    start: date | None = Field(default=None, alias="from")
    end: date | None = Field(default=None, alias="to")
    agent_id: str | None = Field(default=None, min_length=1, max_length=20)
    root_id: str | None = Field(default=None, min_length=1, max_length=40)
    framework: Framework = "all"

    @model_validator(mode="after")
    def dates(self):
        evidence.period_bounds(self.start, self.end)
        return self


class ScheduleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=120)
    scope: Scope = Field(default_factory=Scope)
    interval_hours: Literal[1, 24, 168] = 24

    @model_validator(mode="after")
    def relative_window(self):
        if self.scope.start or self.scope.end:
            raise ValueError("Schedules use a rolling interval, not fixed dates")
        return self


class Toggle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    note: str = Field(min_length=10, max_length=2000)


def metadata(row: EvidenceReport) -> dict:
    return jsonable_encoder(
        {
            key: getattr(row, key)
            for key in (
                "id",
                "schedule_id",
                "generated_by",
                "generated_at",
                "status",
                "scope",
                "summary",
                "sha256",
                "key_fingerprint",
                "error_code",
                "reviewed_by",
                "reviewed_at",
                "review_note",
            )
        }
    )


def schedule_record(row: EvidenceSchedule) -> dict:
    return jsonable_encoder(
        {
            key: getattr(row, key)
            for key in (
                "id",
                "name",
                "created_by",
                "scope",
                "interval_hours",
                "enabled",
                "next_run_at",
                "created_at",
            )
        }
    )


async def prepare(c: ControlContext, w, actor: str, scope: Scope, *, lower=None, upper=None):
    kwargs = dict(
        agent_id=scope.agent_id,
        root_id=scope.root_id,
        framework=scope.framework,
        lower=lower,
        upper=upper,
        signing_key=c.evidence_key,
    )
    if w.bind.dialect.name == "postgresql":
        async with c.db.sessionmaker() as read:
            pack = await evidence.snapshot(read, actor, evidence._source(c), scope.start, scope.end, **kwargs)
    else:
        # In-memory SQLite shares one connection: do not interleave independent read transactions.
        pack = await evidence.snapshot(w, actor, evidence._source(c), scope.start, scope.end, **kwargs)
    if not pack["integrity"]["ok"]:
        raise HTTPException(409, f"Audit ledger verification failed at entry {pack['integrity']['broken_at_seq']}")
    checkpoint = await attestation.record_checkpoint(
        w, c.evidence_key, actor, evidence._issuer(c), pack["integrity"]["entries"], pack["integrity"]["tip"]
    )
    pack["records"]["checkpoints"].append(attestation.checkpoint_record(checkpoint))
    pack["counts"]["checkpoints"] += 1
    body = evidence.build_zip(pack, c.evidence_key, checkpoint.id, evidence._key_mode(c), evidence._issuer(c))
    verify_pack(body, expected_key=c.evidence_key.fingerprint)
    coverage = control_coverage(pack)
    return body, {
        "period": pack["period"],
        "scope": pack["scope"],
        "counts": pack["counts"],
        "integrity": pack["integrity"],
        "coverage": coverage,
        "executive_summary": executive_summary(pack, coverage),
        "summary_method": "deterministic",
    }


async def save_report(c, w, actor, scope, *, schedule_id=None, job_key=None, lower=None, upper=None):
    body, summary = await prepare(c, w, actor, scope, lower=lower, upper=upper)
    report_id = "rpt_" + uuid.uuid4().hex
    row = EvidenceReport(
        id=report_id,
        job_key=job_key or report_id,
        schedule_id=schedule_id,
        generated_by=actor,
        status="ready",
        scope=summary["scope"],
        summary=summary,
        sha256=hashlib.sha256(body).hexdigest(),
        key_fingerprint=c.evidence_key.fingerprint,
        artifact=body,
    )
    w.add(row)
    await ledger.append(
        w,
        "evidence.exported",
        actor,
        report_id,
        {
            "schedule_id": schedule_id,
            "scope": summary["scope"],
            "period": summary["period"],
            "pack_sha256": row.sha256,
            "key_fingerprint": row.key_fingerprint,
        },
    )
    await w.flush()
    return row


async def generate_report(c: ControlContext, actor: str, scope: Scope):
    async with c.evidence_lock, c.db.sessionmaker() as w, w.begin():
        row = await save_report(c, w, actor, scope)
        return metadata(row), row.artifact


async def scheduled_cycle(c: ControlContext, now: datetime | None = None) -> list[dict]:
    if (
        not c.settings.evidence_automation_enabled
        or not c.settings.evidence_key_file
        or ":memory:" in c.settings.database_url
    ):
        return []
    now = now or datetime.now(UTC)
    output = []
    async with c.evidence_lock, c.db.sessionmaker() as w, w.begin():
        rows = (
            await w.scalars(
                select(EvidenceSchedule)
                .where(EvidenceSchedule.enabled.is_(True), EvidenceSchedule.next_run_at <= now)
                .order_by(EvidenceSchedule.next_run_at)
                .limit(5)
                .with_for_update(skip_locked=True)
            )
        ).all()
        for schedule in rows:
            due = moment(schedule.next_run_at)
            slot = f"{schedule.id}:{due.isoformat()}"
            interval = timedelta(hours=schedule.interval_hours)
            # Advance one slot at a time: downtime does not erase unreported intervals.
            try:
                async with w.begin_nested():
                    owner = c.idp.personas.get(schedule.created_by)
                    if owner and (owner.status != "active" or "auditor" not in owner.roles):
                        raise HTTPException(403, "Schedule owner no longer has auditor access")
                    row = await save_report(
                        c,
                        w,
                        WORKER,
                        Scope.model_validate(schedule.scope),
                        schedule_id=schedule.id,
                        job_key=slot,
                        lower=due - interval,
                        upper=due,
                    )
            except Exception as exc:
                # Persist a failed slot without SQL errors, arguments or credentials; never create a valid-looking ZIP.
                code = (
                    "audit_integrity_failed"
                    if isinstance(exc, HTTPException) and exc.status_code == 409
                    else (
                        "scope_or_owner_unavailable" if isinstance(exc, HTTPException) else "report_generation_failed"
                    )
                )
                row = EvidenceReport(
                    id="rpt_" + uuid.uuid4().hex,
                    job_key=slot,
                    schedule_id=schedule.id,
                    generated_by=WORKER,
                    status="failed",
                    scope=schedule.scope,
                    summary={"period_start": (due - interval).isoformat(), "period_end": due.isoformat()},
                    error_code=code,
                )
                w.add(row)
                await ledger.append(
                    w, "evidence.generation_failed", WORKER, row.id, {"schedule_id": schedule.id, "error_code": code}
                )
            schedule.next_run_at = due + interval
            await w.flush()
            output.append(metadata(row))
    return output


async def automatic_checkpoint(c: ControlContext, now: datetime | None = None):
    if (
        not c.settings.evidence_automation_enabled
        or not c.settings.evidence_key_file
        or ":memory:" in c.settings.database_url
    ):
        return
    now = now or datetime.now(UTC)
    async with c.evidence_lock, c.db.sessionmaker() as w, w.begin():
        # This lock serializes checkpoint timers across PostgreSQL workers and the ledger append path.
        if w.bind.dialect.name == "postgresql":
            from sqlalchemy import text

            await w.execute(text("SELECT pg_advisory_xact_lock(724356912)"))
        latest = await w.scalar(select(LedgerCheckpoint).order_by(LedgerCheckpoint.id.desc()).limit(1))
        if latest and (now - moment(latest.ts)).total_seconds() < c.settings.evidence_checkpoint_seconds:
            return
        entries = (await w.scalars(select(LedgerEntry).order_by(LedgerEntry.seq))).all()
        checkpoints = (await w.scalars(select(LedgerCheckpoint).order_by(LedgerCheckpoint.id))).all()
        integrity = evidence.source_integrity(entries, checkpoints, c.evidence_key)
        if not integrity["ok"]:
            raise HTTPException(409, "Cannot checkpoint a ledger with failed source integrity")
        checkpoint = await attestation.create_checkpoint(w, c.evidence_key, WORKER, evidence._issuer(c))
        await ledger.append(
            w,
            "ledger.checkpoint",
            WORKER,
            f"checkpoint:{checkpoint.id}",
            {"entries": checkpoint.entries, "tip": checkpoint.tip, "key_fingerprint": checkpoint.key_fingerprint},
        )


async def run_scheduler(c: ControlContext, first_delay: float | None = None):
    await asyncio.sleep(c.settings.evidence_check_seconds if first_delay is None else first_delay)
    while True:
        try:
            await scheduled_cycle(c)
            await automatic_checkpoint(c)
        except Exception as exc:
            log.error("Evidence scheduler pass failed (%s); next pass will retry", type(exc).__name__)
        await asyncio.sleep(c.settings.evidence_check_seconds)


def attachment(body: bytes, report_id: str) -> Response:
    return Response(
        body,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="aegis-evidence-{report_id}.zip"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


def validate_saved_artifact(row: EvidenceReport):
    if row.status != "ready" or row.artifact is None:
        raise HTTPException(409, "This report failed generation and has no downloadable artifact")
    if hashlib.sha256(row.artifact).hexdigest() != row.sha256:
        raise HTTPException(409, "Stored artifact hash mismatch")
    try:
        verify_pack(row.artifact, expected_key=row.key_fingerprint)
    except (ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        raise HTTPException(409, "Stored report signature or integrity check failed") from exc


def router():
    r = APIRouter(prefix="/v1/evidence", tags=["evidence"])
    auditor = require_roles("auditor")

    @r.get("/controls")
    async def controls(_: Persona = Depends(auditor)):
        return CATALOG

    @r.post("/reports", status_code=201)
    async def create_report(scope: Scope, user: Persona = Depends(auditor), c: ControlContext = Depends(ctx)):
        result, _ = await generate_report(c, user.username, scope)
        return result

    @r.get("/reports")
    async def reports(
        limit: int = Query(30, ge=1, le=200), _: Persona = Depends(auditor), c: ControlContext = Depends(ctx)
    ):
        async with c.db.sessionmaker() as s:
            rows = (
                await s.scalars(
                    select(EvidenceReport)
                    .options(defer(EvidenceReport.artifact))
                    .order_by(EvidenceReport.generated_at.desc(), EvidenceReport.id)
                    .limit(limit)
                )
            ).all()
            return [metadata(row) for row in rows]

    @r.get("/reports/{report_id}/download")
    async def download(report_id: str, _: Persona = Depends(auditor), c: ControlContext = Depends(ctx)):
        async with c.db.sessionmaker() as s:
            row = await s.get(EvidenceReport, report_id)
            if row is None:
                raise HTTPException(404, "Unknown evidence report")
            validate_saved_artifact(row)
            return attachment(row.artifact, row.id)

    @r.post("/reports/{report_id}/review")
    async def review(report_id: str, body: Review, user: Persona = Depends(auditor), c: ControlContext = Depends(ctx)):
        async with c.evidence_lock, c.db.sessionmaker() as s, s.begin():
            row = await s.scalar(select(EvidenceReport).where(EvidenceReport.id == report_id).with_for_update())
            if row is None:
                raise HTTPException(404, "Unknown evidence report")
            if row.status != "ready":
                raise HTTPException(409, "Only a generated report can be reviewed")
            if row.reviewed_at:
                raise HTTPException(409, "An auditor review is already recorded")
            validate_saved_artifact(row)
            row.reviewed_by, row.reviewed_at, row.review_note = user.username, datetime.now(UTC), body.note
            await ledger.append(
                s, "evidence.reviewed", user.username, row.id, {"pack_sha256": row.sha256, "note": body.note}
            )
            return metadata(row)

    @r.get("/schedules")
    async def schedules(_: Persona = Depends(auditor), c: ControlContext = Depends(ctx)):
        async with c.db.sessionmaker() as s:
            return [
                schedule_record(row)
                for row in (
                    await s.scalars(select(EvidenceSchedule).order_by(EvidenceSchedule.created_at.desc()))
                ).all()
            ]

    @r.post("/schedules", status_code=201)
    async def create_schedule(body: ScheduleInput, user: Persona = Depends(auditor), c: ControlContext = Depends(ctx)):
        if not c.settings.evidence_automation_enabled or ":memory:" in c.settings.database_url:
            raise HTTPException(409, "Automatic schedules require automation enabled and a persistent database")
        if not c.settings.evidence_key_file:
            raise HTTPException(409, "Automatic schedules require a persistent evidence signing key")
        # Validate identifiers before storing a schedule that would fail on every run.
        async with c.db.sessionmaker() as s:
            preview = await evidence.snapshot(
                s,
                user.username,
                evidence._source(c),
                agent_id=body.scope.agent_id,
                root_id=body.scope.root_id,
                framework=body.scope.framework,
                signing_key=c.evidence_key,
            )
            if not preview["integrity"]["ok"]:
                raise HTTPException(409, "Cannot schedule reports for a ledger with failed integrity")
        async with c.evidence_lock, c.db.sessionmaker() as s, s.begin():
            row = EvidenceSchedule(
                id="sch_" + uuid.uuid4().hex,
                name=body.name,
                created_by=user.username,
                scope=body.scope.model_dump(mode="json", by_alias=True),
                interval_hours=body.interval_hours,
                next_run_at=datetime.now(UTC),
            )
            s.add(row)
            await ledger.append(
                s,
                "evidence.schedule_created",
                user.username,
                row.id,
                {"scope": row.scope, "interval_hours": row.interval_hours},
            )
            await s.flush()
            return schedule_record(row)

    @r.patch("/schedules/{schedule_id}")
    async def toggle(
        schedule_id: str, body: Toggle, user: Persona = Depends(auditor), c: ControlContext = Depends(ctx)
    ):
        async with c.evidence_lock, c.db.sessionmaker() as s, s.begin():
            row = await s.scalar(select(EvidenceSchedule).where(EvidenceSchedule.id == schedule_id).with_for_update())
            if row is None:
                raise HTTPException(404, "Unknown evidence schedule")
            row.enabled = body.enabled
            await ledger.append(s, "evidence.schedule_updated", user.username, row.id, {"enabled": row.enabled})
            return schedule_record(row)

    @r.post("/schedules/run")
    async def run_due(_: Persona = Depends(auditor), c: ControlContext = Depends(ctx)):
        return await scheduled_cycle(c)

    return r
