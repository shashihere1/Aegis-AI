"""Policy versions: approved, immutable configuration AND Rego, with checks, replay, review, activation and rollback.

Works with every policy engine (python, rego, opa): each decision evaluates the active approved version and is stamped
with its id. A version carries its own Rego (``PolicyBundle``); the rego and opa engines run exactly those modules, so
editing a file on disk changes nothing until a version that imports it is approved and activated. The python engine is
a fixed mirror of the repository Rego, so on it a version can change configuration but not rules.

A rule change passes automatic checks before it can be saved, its replay compares old and new rules on recorded
traffic, the reviewer sees the Rego diff, and it needs a security sign-off from a second person on top of the policy
approval (so does a configuration change whose replay shows any decision becoming more permissive).
"""

import asyncio
import difflib
import json
import logging
import time
from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.hashing import sha256_hex
from aegis.common.ids import new_id
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import ControlContext, ctx, session
from aegis.control.identity.idp import Persona
from aegis.control.tables import DecisionRecord, PolicyBundle, PolicyState, PolicyVersion, utcnow
from aegis.policy import engine as engine_module
from aegis.policy import engines as engines_module
from aegis.policy.engine import policy_version
from aegis.policy.engines import (
    OpaEngine,
    PolicyUnavailable,
    RegoEngine,
    evaluator,
    forget_opa_verification,
    normalize,
    rego_available,
    rego_sources,
)
from aegis.policy.rules_check import MAX_CASES, MAX_MODULES, bundle_hash, check_rules, repository_cases_file

log = logging.getLogger("aegis.control.policies")
RANK = {"deny": 0, "require_approval": 1, "allow": 2}
HEAL_RETRY_SECONDS = 10.0
# The checked-in policy is reviewed in Git and tested in CI (`opa check`, `opa test`); start-up does not re-run checks.
REPOSITORY_CHECKS = {"passed": True, "skipped": "the checked-in repository policy, reviewed in Git and tested in CI"}


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


class RulesProposal(BaseModel):
    """New Rego for a draft: file name -> module text, and optionally new test cases (else the active ones)."""

    model_config = ConfigDict(extra="forbid")
    modules: dict[str, str] = Field(min_length=1, max_length=MAX_MODULES)
    cases: list[dict] | None = Field(default=None, max_length=MAX_CASES)


class Draft(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=3, max_length=120)
    justification: str = Field(min_length=5, max_length=2000)
    configuration: PolicyConfiguration
    rules: RulesProposal | None = None  # edited in the app
    import_repository: bool = False  # take the Rego (and cases) from the repository files, after Git review


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    justification: str = Field(min_length=5, max_length=2000)


class Activation(Review):
    expected_active_version: str


class Replay(BaseModel):
    limit: int = Field(default=200, ge=1, le=1000)


def rules_hash(policy_dir: str, engine: str = "python", sources: dict[str, str] | None = None) -> str:
    """Fingerprint of the evaluator that turns a configuration into decisions; approved versions are bound to it.

    python: the Python engine's source (unchanged, so existing approved versions stay valid).
    rego / opa: the engine kind, the version's Rego and the adapter code that feeds it. Changing the Rego, or switching
    engine, therefore needs a newly approved version, exactly like editing the Python engine does.
    """
    if engine == "python":
        return sha256_hex(Path(engine_module.__file__).read_text("utf-8"))
    return sha256_hex(
        {
            "engine": engine,
            "rego": sources if sources is not None else rego_sources(policy_dir),
            "adapter": Path(engines_module.__file__).read_text("utf-8"),
        }
    )


def repository_bundle(policy_dir: str) -> tuple[dict[str, str], list[dict]]:
    """The Rego and test cases as checked in to the repository (reviewed in Git)."""
    cases_file = repository_cases_file(policy_dir)
    cases = json.loads(cases_file.read_text("utf-8")) if cases_file.is_file() else []
    return rego_sources(policy_dir), cases


def bundle_verifies(bundle: PolicyBundle) -> bool:
    return bundle.bundle_hash == bundle_hash(bundle.modules, bundle.cases)


def security_review(row: PolicyVersion, bundle: PolicyBundle | None, active: PolicyBundle | None) -> dict:
    """Whether this version needs a security sign-off on top of the policy approval, and why."""
    rules_changed = bundle is not None and (active is None or bundle.modules != active.modules)
    loosened = int((row.simulation or {}).get("more_permissive") or 0)
    return {"required": rules_changed or loosened > 0, "rules_changed": rules_changed, "more_permissive": loosened}


def version_dict(row: PolicyVersion, bundle: PolicyBundle | None = None, active: PolicyBundle | None = None) -> dict:
    result = {
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
    result["rules"] = (
        None
        if bundle is None
        else {
            "origin": bundle.origin,
            "base_version": bundle.base_version,
            "bundle_hash": bundle.bundle_hash,
            "modules": sorted(bundle.modules),
            "cases": len(bundle.cases),
            "checks": bundle.checks,
            "security": {
                **security_review(row, bundle, active),
                "approver": bundle.security_approver,
                "justification": bundle.security_justification,
                "at": bundle.security_approved_at,
            },
        }
    )
    return result


def loosened(before: dict, after: dict) -> bool:
    """True when the new verdict lets more through: a higher decision, or weaker obligations on the same decision."""
    if before["decision"] != after["decision"]:
        return RANK[after["decision"]] > RANK[before["decision"]]
    if after["decision"] == "deny":
        return False

    def redacted(verdict):
        return {e for o in verdict["obligations"] if o["type"] == "redact" for e in o["entities"]}

    def limits(verdict):
        return {o["key"]: o["limit"] for o in verdict["obligations"] if o["type"] == "rate_limit"}

    if not redacted(before) <= redacted(after):
        return True
    after_limits = limits(after)
    return any(key not in after_limits or after_limits[key] > limit for key, limit in limits(before).items())


def rules_diff(before: dict[str, str], after: dict[str, str]) -> list[dict]:
    files = []
    for name in sorted(set(before) | set(after)):
        old, new = before.get(name), after.get(name)
        status = "added" if old is None else "removed" if new is None else "unchanged" if old == new else "changed"
        lines = (
            []
            if status == "unchanged"
            else list(
                difflib.unified_diff(
                    (old or "").splitlines(), (new or "").splitlines(), f"a/{name}", f"b/{name}", lineterm=""
                )
            )
        )
        body = lines[2:]
        files.append(
            {
                "file": name,
                "status": status,
                "added_lines": sum(1 for line in body if line.startswith("+")),
                "removed_lines": sum(1 for line in body if line.startswith("-")),
                "diff": "\n".join(lines),
            }
        )
    return files


def configuration_diff(before: dict, after: dict) -> list[dict]:
    def flat(value, prefix=""):
        if isinstance(value, dict):
            items = {}
            for key, inner in value.items():
                items.update(flat(inner, f"{prefix}.{key}" if prefix else str(key)))
            return items
        return {prefix: value}

    old, new = flat(before), flat(after)
    return [
        {"path": path, "before": old.get(path), "after": new.get(path)}
        for path in sorted(set(old) | set(new))
        if old.get(path) != new.get(path)
    ]


async def initialize(c: ControlContext) -> None:
    """Create the first version from the repository, or record the Rego of versions saved before rules were versioned
    (only where the repository Rego provably is what they were approved for)."""
    st = c.settings
    async with c.db.sessionmaker() as s:
        modules, cases = repository_bundle(st.policy_dir)
        state = await s.get(PolicyState, "tool-call")
        if state is None:
            data = json.loads((Path(st.policy_dir) / "data.json").read_text("utf-8"))
            data = PolicyConfiguration.model_validate(data).checked()
            version = policy_version(st.policy_dir)
            s.add(
                PolicyVersion(
                    id=version,
                    name="Initial checked-in policy",
                    configuration=data,
                    content_hash=sha256_hex(data),
                    rules_hash=rules_hash(st.policy_dir, st.policy_engine, modules),
                    author="bootstrap",
                    approver="bootstrap",
                    status="active",
                    justification="Initial repository configuration",
                    approved_at=utcnow(),
                )
            )
            s.add(new_bundle(version, modules, cases, "repository", None, REPOSITORY_CHECKS))
            s.add(PolicyState(id="tool-call", active_version=version))
            await ledger.append(
                s,
                "policy.initialized",
                "bootstrap",
                version,
                {"content_hash": sha256_hex(data), "bundle_hash": bundle_hash(modules, cases)},
            )
            await s.commit()
            return
        recorded = set((await s.scalars(select(PolicyBundle.version_id))).all())
        expected = rules_hash(st.policy_dir, st.policy_engine, modules)
        missing = (await s.scalars(select(PolicyVersion).where(PolicyVersion.id.not_in(recorded or {""})))).all()
        backfilled = [row.id for row in missing if row.rules_hash == expected]
        for version_id in backfilled:
            s.add(new_bundle(version_id, modules, cases, "backfilled", None, REPOSITORY_CHECKS))
        if backfilled:
            await ledger.append(s, "policy.rules_backfilled", "bootstrap", "policy", {"versions": backfilled})
            await s.commit()


def new_bundle(version_id, modules, cases, origin, base_version, checks) -> PolicyBundle:
    return PolicyBundle(
        version_id=version_id,
        modules=modules,
        cases=cases,
        bundle_hash=bundle_hash(modules, cases),
        origin=origin,
        base_version=base_version,
        checks=checks,
    )


def bound_evaluator(c: ControlContext, configuration: dict, version_id: str, sources: dict[str, str] | None = None):
    """The configured engine, bound to one approved configuration and the version id it stamps on decisions."""
    st = c.settings
    return evaluator(
        st.policy_engine,
        st.policy_dir,
        configuration,
        version_id,
        http=c.http,
        opa_url=st.opa_url,
        opa_timeout=st.opa_timeout_seconds,
        opa_token=st.opa_token,
        sources=sources,
    )


def opa_engine(c: ControlContext, modules: dict[str, str]) -> OpaEngine:
    engine = bound_evaluator(c, {}, "sync", modules)
    if not isinstance(engine, OpaEngine):
        raise HTTPException(409, "Pushing Rego to OPA needs AEGIS_POLICY_ENGINE=opa")
    return engine


async def push_to_opa(c: ControlContext, modules: dict[str, str]) -> dict:
    """Make OPA run these modules. Raises PolicyUnavailable when OPA cannot be reached or refuses them."""
    forget_opa_verification()  # nobody may keep trusting OPA's previous policy while it changes
    try:
        return await opa_engine(c, modules).sync_policy()
    finally:
        forget_opa_verification()


async def sync_opa_on_startup(c: ControlContext) -> None:
    """Start-up: make OPA run the active version (it may have restarted empty, or loaded other files)."""
    if c.settings.policy_engine != "opa" or not c.settings.opa_push_policy:
        return
    async with c.db.sessionmaker() as s:
        state = await s.get(PolicyState, "tool-call")
        bundle = await s.get(PolicyBundle, state.active_version) if state else None
        if bundle is None or not bundle_verifies(bundle):
            log.warning("OPA start-up sync skipped: the active policy version has no verified Rego")
            return
        try:
            plan = await push_to_opa(c, bundle.modules)
        except PolicyUnavailable as exc:
            log.warning("could not push the approved policy to OPA at start-up (decisions fail closed): %s", exc)
            return
        if plan["removed"] or plan["replaced"] or plan["added"]:
            await ledger.append(s, "policy.opa_synced", "system:startup", state.active_version, plan)
            await s.commit()


class ManagedEngine:
    """Read the committed active version for each decision; activation needs no restart. Works with every engine."""

    def __init__(self, c: ControlContext):
        self.c = c  # engines reach OPA through c.http, the control plane's client
        self.version = policy_version(c.settings.policy_dir)
        self._modules: dict[str, dict[str, str]] = {}  # version id -> its verified Rego (versions are immutable)
        self._heal_after = 0.0

    async def _active_modules(self, s: AsyncSession, version_id: str) -> dict[str, str]:
        modules = self._modules.get(version_id)
        if modules is None:
            bundle = await s.get(PolicyBundle, version_id)
            if bundle is None:
                raise RuntimeError(
                    "The active policy version has no recorded Rego; import the rules into a new version"
                )
            if not bundle_verifies(bundle):
                raise RuntimeError("The active policy's Rego hash does not verify")
            modules = self._modules[version_id] = dict(bundle.modules)
        return modules

    async def _heal_opa(self, engine: OpaEngine) -> None:
        """An OPA that restarted empty gets the approved policy back. Anything else that differs is NOT overwritten
        here (it may be tampering): the decision fails closed and a person pushes the policy explicitly."""
        if time.monotonic() < self._heal_after:
            return
        try:
            await engine.verify_policy()
            return
        except PolicyUnavailable:
            self._heal_after = time.monotonic() + HEAL_RETRY_SECONDS
        try:
            if await engine.runs_no_policy():
                plan = await engine.sync_policy()
                log.warning("OPA had no policy loaded (restarted?); pushed the approved policy back: %s", plan)
        except PolicyUnavailable:
            pass  # evaluate() fails closed below with the real reason

    async def evaluate(self, policy_input: dict) -> dict:
        settings = self.c.settings
        async with self.c.db.sessionmaker() as s:
            state = await s.get(PolicyState, "tool-call")
            version = await s.get(PolicyVersion, state.active_version)
            if version.content_hash != sha256_hex(version.configuration):
                raise RuntimeError("Active policy configuration hash does not verify")
            # The Rego that is checked against the approval is exactly the Rego handed to the engine.
            sources = await self._active_modules(s, version.id) if settings.policy_engine != "python" else None
            if version.rules_hash != rules_hash(settings.policy_dir, settings.policy_engine, sources):
                raise RuntimeError(
                    f"The active policy version was not approved for the current evaluator ({settings.policy_engine}, "
                    "or its Rego or code changed); approve a policy version for it"
                )
            self.version = version.id  # for receipts that are not decisions (a2a, /health); decisions carry their own
            engine = bound_evaluator(self.c, version.configuration, version.id, sources)
            if isinstance(engine, OpaEngine) and settings.opa_push_policy:
                await self._heal_opa(engine)
            verdict = await engine.evaluate(policy_input)
            return normalize(verdict, version.id)


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

    async def bundle_of(s, version_id: str, required: bool = True) -> PolicyBundle | None:
        bundle = await s.get(PolicyBundle, version_id)
        if bundle is None:
            if required:
                raise HTTPException(409, "This version's Rego was never recorded; import the rules into a new version")
            return None
        if not bundle_verifies(bundle):
            raise HTTPException(409, "Policy rules hash does not verify")
        return bundle

    async def active_bundle(s) -> tuple[str, PolicyBundle | None]:
        state = await s.get(PolicyState, "tool-call")
        return state.active_version, await bundle_of(s, state.active_version, required=False)

    async def describe(s, row: PolicyVersion) -> dict:
        _, active = await active_bundle(s)
        return version_dict(row, await bundle_of(s, row.id, required=False), active)

    def editable(c: ControlContext):
        if c.settings.policy_engine == "rego" and not rego_available():
            raise HTTPException(409, "policy_engine=rego needs the regopy package installed")

    @r.get("/versions")
    async def versions(s=Depends(session)):
        state = await s.get(PolicyState, "tool-call")
        rows = (await s.scalars(select(PolicyVersion).order_by(PolicyVersion.created_at.desc()))).all()
        bundles = {b.version_id: b for b in (await s.scalars(select(PolicyBundle))).all()}
        active = bundles.get(state.active_version)
        return {
            "active_version": state.active_version,
            "versions": [version_dict(v, bundles.get(v.id), active) for v in rows],
        }

    @r.get("/repository")
    async def repository(c=Depends(ctx), s=Depends(session)):
        """Does the Rego checked in to the repository differ from the Rego that runs? (Import it to propose it.)"""
        modules, cases = repository_bundle(c.settings.policy_dir)
        active_id, active = await active_bundle(s)
        return {
            "active_version": active_id,
            "differs": active is None or modules != active.modules,
            "cases_differ": active is None or cases != active.cases,
            "files": [
                {k: f[k] for k in ("file", "status", "added_lines", "removed_lines")}
                for f in rules_diff(active.modules if active else {}, modules)
            ],
        }

    @r.get("/{version_id}/rules")
    async def rules(version_id: str, s=Depends(session)):
        bundle = await bundle_of(s, version_id)
        return {k: getattr(bundle, k) for k in ("version_id", "modules", "cases", "bundle_hash", "origin", "checks")}

    @r.get("/{version_id}/diff")
    async def diff(version_id: str, against: str | None = None, s=Depends(session)):
        """What activating this version would change: the Rego diff, the configuration diff and the cases."""
        row = await load(s, version_id)
        bundle = await bundle_of(s, version_id)
        against = against or (await s.get(PolicyState, "tool-call")).active_version
        base = await load(s, against)
        base_bundle = await bundle_of(s, against, required=False)
        return {
            "version": row.id,
            "against": base.id,
            "rules": rules_diff(base_bundle.modules if base_bundle else {}, bundle.modules),
            "configuration": configuration_diff(base.configuration, row.configuration),
            "cases": {
                "before": len(base_bundle.cases) if base_bundle else 0,
                "after": len(bundle.cases),
                "changed": base_bundle is None or base_bundle.cases != bundle.cases,
            },
        }

    @r.post("/versions", status_code=201)
    async def create(
        body: Draft, c=Depends(ctx), s=Depends(session), user: Persona = Depends(require_roles("policy-author"))
    ):
        editable(c)
        st = c.settings
        data = body.configuration.checked()
        if body.rules is not None and body.import_repository:
            raise HTTPException(422, "Propose new rules or import them from the repository, not both")
        active_id, active = await active_bundle(s)
        if body.import_repository:
            modules, cases = repository_bundle(st.policy_dir)
            cases = cases or (active.cases if active else [])
            origin = "repository"
        elif body.rules is not None:
            modules = {name: text.replace("\r\n", "\n") for name, text in body.rules.modules.items()}
            cases = body.rules.cases if body.rules.cases is not None else (active.cases if active else [])
            origin = "edited"
        elif active is not None:
            modules, cases, origin = dict(active.modules), list(active.cases), "inherited"
        else:
            raise HTTPException(
                409, "The active version's Rego was never recorded; import the rules from the repository"
            )
        rules_changed = active is None or modules != active.modules
        if st.policy_engine == "python":
            # The python engine can only ever run the repository rules it mirrors; nothing to check beyond that.
            if modules != repository_bundle(st.policy_dir)[0]:
                raise HTTPException(
                    409,
                    "Rule changes need AEGIS_POLICY_ENGINE=rego or opa: the python engine is a fixed copy of the "
                    "repository rules and cannot run other Rego",
                )
            checks = {"passed": True, "skipped": "the python engine runs the repository rules it mirrors"}
        elif rules_changed or active is None or cases != active.cases:
            if not rego_available():
                raise HTTPException(409, "Checking a Rego change needs the regopy package installed")
            checks = await asyncio.to_thread(check_rules, st.policy_dir, modules, cases)
            if not checks["passed"]:
                raise HTTPException(
                    422, {"message": "The proposed rules failed the automatic checks", "checks": checks}
                )
        else:
            checks = {"passed": True, "skipped": "rules and test cases are unchanged from the active version"}
        row = PolicyVersion(
            id=new_id("pol"),
            name=body.name,
            configuration=data,
            content_hash=sha256_hex(data),
            rules_hash=rules_hash(st.policy_dir, st.policy_engine, modules),
            author=user.username,
            status="draft",
            justification=body.justification,
        )
        bundle = new_bundle(row.id, modules, cases, origin, active_id, checks)
        s.add_all([row, bundle])
        await ledger.append(
            s,
            "policy.drafted",
            user.username,
            row.id,
            {
                "content_hash": row.content_hash,
                "name": row.name,
                "bundle_hash": bundle.bundle_hash,
                "rules_origin": origin,
                "rules_changed": rules_changed,
            },
        )
        await s.commit()
        return version_dict(row, bundle, active)

    @r.post("/{version_id}/replay")
    async def replay(
        version_id: str,
        body: Replay,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("policy-author", "policy-approver")),
    ):
        editable(c)
        st = c.settings
        row = await load(s, version_id)
        if row.status not in {"draft", "submitted"}:
            raise HTTPException(409, "Replay is available only for a draft or submitted version")
        bundle = await bundle_of(s, row.id)
        if row.rules_hash != rules_hash(st.policy_dir, st.policy_engine, bundle.modules):
            raise HTTPException(409, "Evaluator code changed; create and replay a new draft")
        _, active = await active_bundle(s)
        running = active.modules if active else None
        records = (await s.scalars(select(DecisionRecord).order_by(DecisionRecord.ts.desc()).limit(body.limit))).all()
        results, skipped, transitions, engines_used = [], 0, Counter(), set()
        known: dict[str, tuple[PolicyVersion | None, PolicyBundle | None]] = {}

        def engine_for(version: PolicyVersion, modules: dict[str, str]):
            """OPA when it runs these exact modules (it runs the active ones); otherwise the same Rego in-process."""
            if st.policy_engine == "python" or (st.policy_engine == "opa" and modules == bundle.modules == running):
                return bound_evaluator(c, version.configuration, version.id, modules), st.policy_engine
            if not rego_available():
                return None, None
            return RegoEngine(st.policy_dir, version.configuration, version.id, sources=modules), "rego"

        for record in records:
            snapshot = record.input_snapshot
            if not all(k in snapshot for k in ("subject", "resource", "action", "context")):
                skipped += 1
                continue
            if record.policy_version not in known:
                old = await s.get(PolicyVersion, record.policy_version)
                old_bundle = await s.get(PolicyBundle, record.policy_version)
                known[record.policy_version] = (old, old_bundle)
            old, old_bundle = known[record.policy_version]
            if (
                old is None
                or old.content_hash != sha256_hex(old.configuration)
                or old_bundle is None
                or not bundle_verifies(old_bundle)
                or (st.policy_engine == "python" and old.rules_hash != row.rules_hash)
            ):
                skipped += 1
                continue
            before_engine, before_kind = engine_for(old, old_bundle.modules)
            after_engine, after_kind = engine_for(row, bundle.modules)
            if before_engine is None or after_engine is None:
                skipped += 1
                continue
            try:  # policy-only evaluation; an OPA query is read-only, nothing is executed
                before = normalize(await before_engine.evaluate(snapshot), old.id)
                after = normalize(await after_engine.evaluate(snapshot), row.id)
            except PolicyUnavailable as exc:  # no evidence is better than evidence from a broken evaluator
                raise HTTPException(503, f"The policy engine is unavailable, so no replay was stored: {exc}") from exc
            except Exception:  # a recorded input the engine cannot evaluate is reported as skipped, not as a change
                skipped += 1
                continue
            engines_used.update({before_kind, after_kind})
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
                    "more_permissive": loosened(before, after),
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
            "more_permissive": sum(1 for item in results if item["more_permissive"]),
            "rules_changed": running is None or bundle.modules != running,
            "evaluated_with": sorted(engines_used),
            "transitions": dict(transitions),
            "results": results,
            "content_hash": row.content_hash,
            "rules_hash": row.rules_hash,
            "bundle_hash": bundle.bundle_hash,
            "generated_at": utcnow().isoformat(),
            "limitations": "Policy-only replay of recorded context; no tools, payments, rate counters or approvals are "
            "executed. Only recorded traffic is compared, so a rule change could still loosen decisions that never "
            "occurred: that is why every rule change also needs a security sign-off.",
        }
        row.simulation = report
        await ledger.append(
            s,
            "policy.replayed",
            user.username,
            row.id,
            {
                "evaluated": report["evaluated"],
                "changed": report["changed"],
                "skipped": skipped,
                "more_permissive": report["more_permissive"],
            },
        )
        await s.commit()
        return report

    @r.post("/{version_id}/submit")
    async def submit(
        version_id: str, c=Depends(ctx), s=Depends(session), user: Persona = Depends(require_roles("policy-author"))
    ):
        editable(c)
        row = await load(s, version_id)
        if row.status != "draft" or not await c.people.same_person(s, user, row.author):
            raise HTTPException(409, "Only the author can submit their draft")
        bundle = await bundle_of(s, row.id)
        simulation = row.simulation or {}
        if simulation.get("content_hash") != row.content_hash or simulation.get("bundle_hash") != bundle.bundle_hash:
            raise HTTPException(409, "Run replay before submitting the policy")
        if bundle.checks.get("passed") is not True:
            raise HTTPException(409, "The rules have not passed the automatic checks")
        row.status = "submitted"
        await ledger.append(
            s,
            "policy.submitted",
            user.username,
            row.id,
            {"content_hash": row.content_hash, "bundle_hash": bundle.bundle_hash},
        )
        await s.commit()
        return await describe(s, row)

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
        if await c.people.same_person(s, user, row.author):
            raise HTTPException(403, "Segregation of duties: authors cannot approve their own policy")
        bundle = await bundle_of(s, row.id)
        if bundle.security_approver and await c.people.same_person(s, user, bundle.security_approver):
            raise HTTPException(
                403, "Segregation of duties: the security sign-off and the policy approval must come from two people"
            )
        st = c.settings
        if row.status != "submitted" or row.rules_hash != rules_hash(st.policy_dir, st.policy_engine, bundle.modules):
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
        return await describe(s, row)

    @r.post("/{version_id}/security-approve")
    async def security_approve(
        version_id: str,
        body: Review,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("security-approver")),
    ):
        """The second sign-off a rule change (or a loosening configuration change) needs before activation."""
        editable(c)
        row = await load(s, version_id)
        if row.status not in {"submitted", "approved"}:
            raise HTTPException(409, "Only a submitted or approved version can be signed off")
        bundle = await bundle_of(s, row.id)
        _, active = await active_bundle(s)
        review = security_review(row, bundle, active)
        if not review["required"]:
            raise HTTPException(
                409, "This version changes no rules and loosens no replayed decision: no sign-off needed"
            )
        if await c.people.same_person(s, user, row.author):
            raise HTTPException(403, "Segregation of duties: authors cannot sign off their own policy")
        if row.approver and await c.people.same_person(s, user, row.approver):
            raise HTTPException(
                403, "Segregation of duties: the security sign-off and the policy approval must come from two people"
            )
        if bundle.security_approver:
            raise HTTPException(409, f"Already signed off by {bundle.security_approver}")
        bundle.security_approver, bundle.security_approved_at = user.username, utcnow()
        bundle.security_justification = body.justification
        await ledger.append(
            s,
            "policy.security_approved",
            user.username,
            row.id,
            {"justification": body.justification, "bundle_hash": bundle.bundle_hash, **review},
        )
        await s.commit()
        return version_dict(row, bundle, active)

    @r.post("/{version_id}/reject")
    async def reject(
        version_id: str,
        body: Review,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("policy-approver", "security-approver")),
    ):
        editable(c)
        row = await load(s, version_id)
        if await c.people.same_person(s, user, row.author):
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
        return await describe(s, row)

    async def switch(version_id: str, body: Activation, rollback: bool, c, s, user):
        editable(c)
        st = c.settings
        async with mutation_lock:
            state = (await s.scalars(select(PolicyState).where(PolicyState.id == "tool-call").with_for_update())).one()
            if state.active_version != body.expected_active_version:
                raise HTTPException(409, "Active policy changed; refresh and review before retrying")
            row = await load(s, version_id)
            if await c.people.same_person(s, user, row.author):
                raise HTTPException(403, "Policy authors cannot activate or roll back their own version")
            allowed = {"superseded"} if rollback else {"approved"}
            if row.status not in allowed or not row.approver:
                raise HTTPException(
                    409, "Only an approved version can be activated; rollback requires a previously active version"
                )
            bundle = await bundle_of(s, row.id)
            if row.rules_hash != rules_hash(st.policy_dir, st.policy_engine, bundle.modules):
                raise HTTPException(409, "Evaluator code does not match this version")
            previous = await load(s, state.active_version)
            previous_bundle = await bundle_of(s, previous.id, required=False)
            # A rollback returns to a version that was fully approved when it ran; a new version needs every sign-off.
            if (
                not rollback
                and security_review(row, bundle, previous_bundle)["required"]
                and not bundle.security_approver
            ):
                raise HTTPException(
                    409,
                    "SEC-001: this version changes rules or loosens decisions; a security approver must sign it off",
                )
            payload = {
                "previous_version": previous.id,
                "justification": body.justification,
                "content_hash": row.content_hash,
                "bundle_hash": bundle.bundle_hash,
                "rules_diff": [
                    {k: f[k] for k in ("file", "status", "added_lines", "removed_lines")}
                    for f in rules_diff(previous_bundle.modules if previous_bundle else {}, bundle.modules)
                    if f["status"] != "unchanged"
                ],
            }
            pushing = st.policy_engine == "opa" and st.opa_push_policy
            if pushing and (previous_bundle is None or previous_bundle.modules != bundle.modules):
                try:
                    payload["opa"] = await push_to_opa(c, bundle.modules)
                except PolicyUnavailable as exc:
                    if previous_bundle is not None:  # put the previous policy back; decisions fail closed meanwhile
                        try:
                            await push_to_opa(c, previous_bundle.modules)
                        except PolicyUnavailable:
                            log.error("OPA refused the new policy and the previous one could not be restored")
                    raise HTTPException(503, f"OPA did not accept the policy, so nothing was activated: {exc}") from exc
            previous.status, row.status = "superseded", "active"
            state.active_version, state.updated_at = row.id, utcnow()
            await ledger.append(
                s, "policy.rolled_back" if rollback else "policy.activated", user.username, row.id, payload
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

    @r.post("/opa/sync")
    async def sync_opa(
        body: Review,
        c=Depends(ctx),
        s=Depends(session),
        user: Persona = Depends(require_roles("policy-approver", "security-approver", "admin")),
    ):
        """Push the active version's Rego to OPA, replacing whatever it runs (after a restart or a suspected change)."""
        if c.settings.policy_engine != "opa":
            raise HTTPException(409, "Pushing Rego to OPA needs AEGIS_POLICY_ENGINE=opa")
        active_id, active = await active_bundle(s)
        if active is None:
            raise HTTPException(
                409, "The active version's Rego was never recorded; import the rules into a new version"
            )
        try:
            plan = await push_to_opa(c, active.modules)
        except PolicyUnavailable as exc:
            raise HTTPException(503, f"OPA did not accept the policy: {exc}") from exc
        await ledger.append(
            s, "policy.opa_synced", user.username, active_id, {**plan, "justification": body.justification}
        )
        await s.commit()
        return {"active_version": active_id, **plan}

    return r
