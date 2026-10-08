"""Approved, immutable policy configurations and side-effect-free historical replay.

The local Python PDP supports configuration changes, not arbitrary Rego execution.
"""

import asyncio
import json
from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from aegis.common.hashing import sha256_hex
from aegis.common.ids import new_id
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import ControlContext, ctx, session
from aegis.control.identity.idp import Persona
from aegis.control.tables import DecisionRecord, PolicyState, PolicyVersion, utcnow
from aegis.policy import engine as engine_module
from aegis.policy.engine import PythonEngine, policy_version


class PaymentThreshold(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    hitl_amount_eur: float = Field(ge=0, le=1_000_000)


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payments: PaymentThreshold


class PolicyConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    thresholds: Thresholds
    redact_entities: list[str] = Field(min_length=1, max_length=4)
    approval_side_effects_high_risk: list[str] = Field(min_length=1, max_length=2)

    def checked(self) -> dict:
        if not set(self.redact_entities) <= {"BSN", "IBAN_CODE", "EMAIL_ADDRESS", "PHONE_NUMBER"}:
            raise HTTPException(422, "Unsupported redaction entity")
        if not set(self.approval_side_effects_high_risk) <= {"financial", "destructive"}:
            raise HTTPException(422, "Unsupported high-risk side effect")
        return self.model_dump()


class Draft(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=3, max_length=120)
    justification: str = Field(min_length=5, max_length=2000)
    configuration: PolicyConfiguration


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    justification: str = Field(min_length=5, max_length=2000)


class Activation(Review):
    expected_active_version: str


class Replay(BaseModel):
    limit: int = Field(default=200, ge=1, le=1000)


def rules_hash(policy_dir: str) -> str:
    # Captures the code actually evaluated, not just the displayed Rego.
    return sha256_hex(Path(engine_module.__file__).read_text("utf-8"))


def version_dict(row: PolicyVersion) -> dict:
    return {
        field: getattr(row, field)
        for field in (
            "id",
            "name",
            "configuration",
            "content_hash",
            "rules_hash",
            "author",
            "approver",
            "status",
            "justification",
            "simulation",
            "created_at",
            "approved_at",
        )
    }


async def initialize(c: ControlContext) -> None:
    async with c.db.sessionmaker() as s:
        if await s.get(PolicyState, "tool-call"):
            return
        data = json.loads((Path(c.settings.policy_dir) / "data.json").read_text("utf-8"))
        data = PolicyConfiguration.model_validate(data).checked()
        version = policy_version(c.settings.policy_dir)
        s.add(
            PolicyVersion(
                id=version,
                name="Initial checked-in policy",
                configuration=data,
                content_hash=sha256_hex(data),
                rules_hash=rules_hash(c.settings.policy_dir),
                author="bootstrap",
                approver="bootstrap",
                status="active",
                justification="Initial repository configuration",
                approved_at=utcnow(),
            )
        )
        s.add(PolicyState(id="tool-call", active_version=version))
        await ledger.append(s, "policy.initialized", "bootstrap", version, {"content_hash": sha256_hex(data)})
        await s.commit()


class ManagedEngine:
    """Read the committed active version for each decision; activation needs no restart."""

    def __init__(self, c: ControlContext, fallback):
        self.c, self.fallback = c, fallback
        self.version = fallback.version

    async def evaluate(self, policy_input: dict) -> dict:
        if self.c.settings.policy_engine != "python":
            return await self.fallback.evaluate(policy_input)
        async with self.c.db.sessionmaker() as s:
            state = await s.get(PolicyState, "tool-call")
            version = await s.get(PolicyVersion, state.active_version)
            if version.content_hash != sha256_hex(version.configuration):
                raise RuntimeError("Active policy configuration hash does not verify")
            if version.rules_hash != rules_hash(self.c.settings.policy_dir):
                raise RuntimeError("Policy evaluator code changed; an approved matching policy version is required")
            self.version = version.id
            return PythonEngine(self.c.settings.policy_dir, version.configuration, version.id).decide(policy_input)


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/policies", tags=["policy governance"], dependencies=[Depends(require_roles(*OPERATORS))])
    mutation_lock = asyncio.Lock()

    async def load(s, version_id: str) -> PolicyVersion:
        row = (
            await s.scalars(select(PolicyVersion).where(PolicyVersion.id == version_id).with_for_update())
        ).one_or_none()
        if row is None:
            raise HTTPException(404, "Policy version not found")
        if row.content_hash != sha256_hex(row.configuration):
            raise HTTPException(409, "Policy configuration hash does not verify")
        return row

    def editable(c: ControlContext):
        if c.settings.policy_engine != "python":
            raise HTTPException(409, "Configuration lifecycle currently supports the Python PDP only")

    @r.get("/versions")
    async def versions(s=Depends(session)):
        state = await s.get(PolicyState, "tool-call")
        rows = (await s.scalars(select(PolicyVersion).order_by(PolicyVersion.created_at.desc()))).all()
        return {"active_version": state.active_version, "versions": [version_dict(v) for v in rows]}

    @r.post("/versions", status_code=201)
    async def create(
        body: Draft, c=Depends(ctx), s=Depends(session), user: Persona = Depends(require_roles("policy-author"))
    ):
        editable(c)
        data = body.configuration.checked()
        row = PolicyVersion(
            id=new_id("pol"),
            name=body.name,
            configuration=data,
            content_hash=sha256_hex(data),
            rules_hash=rules_hash(c.settings.policy_dir),
            author=user.username,
            status="draft",
            justification=body.justification,
        )
        s.add(row)
        await ledger.append(
            s, "policy.drafted", user.username, row.id, {"content_hash": row.content_hash, "name": row.name}
        )
        await s.commit()
        return version_dict(row)

    @r.post("/{version_id}/replay")
    async def replay(
        version_id: str,
        body: Replay,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("policy-author", "policy-approver")),
    ):
        editable(c)
        row = await load(s, version_id)
        if row.status not in {"draft", "submitted"}:
            raise HTTPException(409, "Replay is available only for a draft or submitted version")
        if row.rules_hash != rules_hash(c.settings.policy_dir):
            raise HTTPException(409, "Evaluator code changed; create and replay a new draft")
        candidate = PythonEngine(c.settings.policy_dir, row.configuration, row.id)
        records = (await s.scalars(select(DecisionRecord).order_by(DecisionRecord.ts.desc()).limit(body.limit))).all()
        results, skipped, transitions = [], 0, Counter()
        for record in records:
            snapshot = record.input_snapshot
            if not all(k in snapshot for k in ("subject", "resource", "action", "context")):
                skipped += 1
                continue
            old = await s.get(PolicyVersion, record.policy_version)
            if old is None or old.rules_hash != row.rules_hash or old.content_hash != sha256_hex(old.configuration):
                skipped += 1
                continue
            before = PythonEngine(c.settings.policy_dir, old.configuration, old.id).decide(snapshot)
            after = candidate.decide(snapshot)
            changed_fields = [k for k in ("decision", "reasons", "obligations") if before[k] != after[k]]
            changed = bool(changed_fields)
            if changed:
                transitions[f"{before['decision']} → {after['decision']}"] += 1
            results.append(
                {
                    "decision_id": record.id,
                    "action": record.action,
                    "recorded_outcome": record.decision,
                    "before": before["decision"],
                    "after": after["decision"],
                    "changed": changed,
                    "changed_fields": changed_fields,
                    "before_obligations": before["obligations"],
                    "after_obligations": after["obligations"],
                    "before_reasons": before["reasons"],
                    "reasons": after["reasons"],
                }
            )
        report = {
            "evaluated": len(results),
            "skipped": skipped,
            "changed": sum(transitions.values()),
            "transitions": dict(transitions),
            "results": results,
            "content_hash": row.content_hash,
            "rules_hash": row.rules_hash,
            "generated_at": utcnow().isoformat(),
            "limitations": "Policy-only replay of recorded context; "
            "no tools, payments, rate counters or approvals are executed.",
        }
        row.simulation = report
        await ledger.append(
            s,
            "policy.replayed",
            user.username,
            row.id,
            {"evaluated": report["evaluated"], "changed": report["changed"], "skipped": skipped},
        )
        await s.commit()
        return report

    @r.post("/{version_id}/submit")
    async def submit(
        version_id: str, c=Depends(ctx), s=Depends(session), user: Persona = Depends(require_roles("policy-author"))
    ):
        editable(c)
        row = await load(s, version_id)
        if row.author != user.username or row.status != "draft":
            raise HTTPException(409, "Only the author can submit their draft")
        if not row.simulation or row.simulation.get("content_hash") != row.content_hash:
            raise HTTPException(409, "Run replay before submitting the policy")
        row.status = "submitted"
        await ledger.append(s, "policy.submitted", user.username, row.id, {"content_hash": row.content_hash})
        await s.commit()
        return version_dict(row)

    @r.post("/{version_id}/approve")
    async def approve(
        version_id: str,
        body: Review,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("policy-approver")),
    ):
        editable(c)
        row = await load(s, version_id)
        if row.author == user.username:
            raise HTTPException(403, "Segregation of duties: authors cannot approve their own policy")
        if row.status != "submitted" or row.rules_hash != rules_hash(c.settings.policy_dir):
            raise HTTPException(409, "Policy is not submitted or evaluator code has changed")
        row.status, row.approver, row.approved_at = "approved", user.username, utcnow()
        row.simulation = {
            **row.simulation,
            "review": {
                "outcome": "approved",
                "actor": user.username,
                "justification": body.justification,
                "at": row.approved_at.isoformat(),
            },
        }
        await ledger.append(s, "policy.approved", user.username, row.id, {"justification": body.justification})
        await s.commit()
        return version_dict(row)

    @r.post("/{version_id}/reject")
    async def reject(
        version_id: str,
        body: Review,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("policy-approver")),
    ):
        editable(c)
        row = await load(s, version_id)
        if row.author == user.username:
            raise HTTPException(403, "Segregation of duties: authors cannot review their own policy")
        if row.status != "submitted":
            raise HTTPException(409, "Only a submitted version can be rejected")
        row.status = "rejected"
        row.simulation = {
            **row.simulation,
            "review": {
                "outcome": "rejected",
                "actor": user.username,
                "justification": body.justification,
                "at": utcnow().isoformat(),
            },
        }
        await ledger.append(
            s,
            "policy.rejected",
            user.username,
            row.id,
            {"justification": body.justification, "content_hash": row.content_hash},
        )
        await s.commit()
        return version_dict(row)

    async def switch(version_id: str, body: Activation, rollback: bool, c, s, user):
        editable(c)
        async with mutation_lock:
            state = (await s.scalars(select(PolicyState).where(PolicyState.id == "tool-call").with_for_update())).one()
            if state.active_version != body.expected_active_version:
                raise HTTPException(409, "Active policy changed; refresh and review before retrying")
            row = await load(s, version_id)
            if row.author == user.username:
                raise HTTPException(403, "Policy authors cannot activate or roll back their own version")
            allowed = {"superseded"} if rollback else {"approved"}
            if row.status not in allowed or not row.approver:
                raise HTTPException(
                    409, "Only an approved version can be activated; rollback requires a previously active version"
                )
            if row.rules_hash != rules_hash(c.settings.policy_dir):
                raise HTTPException(409, "Evaluator code does not match this version")
            previous = await load(s, state.active_version)
            previous.status, row.status = "superseded", "active"
            state.active_version, state.updated_at = row.id, utcnow()
            await ledger.append(
                s,
                "policy.rolled_back" if rollback else "policy.activated",
                user.username,
                row.id,
                {
                    "previous_version": previous.id,
                    "justification": body.justification,
                    "content_hash": row.content_hash,
                },
            )
            await s.commit()
            return {"active_version": row.id, "previous_version": previous.id}

    @r.post("/{version_id}/activate")
    async def activate(
        version_id: str,
        body: Activation,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("policy-approver")),
    ):
        return await switch(version_id, body, False, c, s, user)

    @r.post("/{version_id}/rollback")
    async def rollback(
        version_id: str,
        body: Activation,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("policy-approver")),
    ):
        return await switch(version_id, body, True, c, s, user)

    return r
