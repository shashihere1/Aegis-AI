"""Authenticated live-agent runs. History is durable; resumable Mandates stay in memory only.

The local console is a single-process demonstration. A restart interrupts pending runs; it never
replays a write or reconstitutes a bearer token from database history.
"""

import asyncio
import logging
import time
from typing import Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from aegis.common.banking import SERVERS as BANK_SERVERS
from aegis.common.hashing import sha256_hex
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.identity.idp import Persona
from aegis.control.model_controls import budget_status, policy, policy_error
from aegis.control.soc import agent_names, lineage_graph
from aegis.control.tables import Agent, AgentRun, Alert, Approval, DecisionRecord, Mandate, Tool
from aegis.sdk import AegisDenied, LlmCallError
from aegis_demo.agent_runtime import MODES, ExecutionUncertain, LiveAva, framework_status
from aegis_demo.walkthrough import runtime_pair

OPEN = {"running", "confirmation_required", "approval_required"}
log = logging.getLogger(__name__)


class StartRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID
    mode: Literal["inquiry", "documents", "address", "transfer"]
    message: str = Field(min_length=3, max_length=1500)
    confirm_synthetic_external_call: Literal[True]
    coordinator_id: str | None = Field(default=None, pattern=r"^AGT-[A-Z0-9-]+$")
    walkthrough_case: Literal["normal", "delegation_widening"] = "normal"
    auto_resume: bool = False


class ContinueRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["confirm", "resume_approval", "cancel"]


async def interrupt_history(world):
    async with world.ctx.db.sessionmaker() as s:
        for row in await s.scalars(select(AgentRun).where(AgentRun.status.in_(OPEN))):
            row.status = "interrupted"
            row.snapshot = {
                **row.snapshot,
                "status": "interrupted",
                "resumable": False,
                "reply": "Server restarted; this run cannot resume. Check receipts before any new write.",
            }
        await s.commit()


def router(get_world) -> APIRouter:
    r = APIRouter(prefix="/agent", tags=["live-agent"])
    active: dict = {}
    admission = asyncio.Lock()
    monitor_job = None

    async def save(run):
        w = get_world()
        snapshot = {k: run[k] for k in ("id", "subject", "mode", "status", "reply", "events", "root_id", "pending")}
        snapshot["resumable"] = run["status"] in ("confirmation_required", "approval_required")
        snapshot["request_hash"] = run["request_hash"]
        snapshot.update({k: run.get(k) for k in ("coordinator_id", "payments_id", "walkthrough_case", "auto_resume")})
        async with w.ctx.db.sessionmaker() as s:
            row = await s.get(AgentRun, run["id"])
            if row is None:
                row = AgentRun(id=run["id"], subject=run["subject"], status=run["status"], snapshot=snapshot)
                s.add(row)
                await ledger.append(
                    s,
                    "agent.run_started",
                    run["subject"],
                    run["id"],
                    {
                        "mode": run["mode"],
                        "synthetic_external_call_confirmed": True,
                        "coordinator_id": run.get("coordinator_id"),
                        "payments_id": run.get("payments_id"),
                        "walkthrough_case": run.get("walkthrough_case"),
                    },
                )
            else:
                row.status, row.snapshot = run["status"], snapshot
            await s.commit()

    async def close(run):
        if run.get("task"):
            try:
                if not run.get("stop_reason"):
                    # A kill switch may have published revocation before its DB transaction commits.
                    # Do not race that governance outcome with ordinary task-completion cleanup.
                    await run["task"].complete()
            except AegisDenied, httpx.HTTPError:
                run["events"].append(
                    {
                        "kind": "warning",
                        "label": "Mandate closure could not be confirmed; "
                        "expiry/revocation still applies. Check Access Control.",
                    }
                )
            w = get_world()
            apps = [w.payments_app, *(pair.payments_app for pair in w.runtime_pairs.values())]
            for app in apps:
                for approval_id, (pending_task, _) in list(app.state.pending.items()):
                    if pending_task.root_id == run["task"].root_id:
                        app.state.pending.pop(approval_id, None)
            async with w.ctx.db.sessionmaker() as s:
                mandate_ids = select(Mandate.id).where(Mandate.root_id == run["task"].root_id)
                cancelled = []
                for approval in await s.scalars(
                    select(Approval).where(
                        Approval.mandate_id.in_(mandate_ids),
                        Approval.status == "pending",
                    )
                ):
                    approval.status = "cancelled"
                    cancelled.append(approval.id)
                if cancelled:
                    await ledger.append(
                        s,
                        "agent.pending_approvals_cancelled",
                        run["subject"],
                        run["id"],
                        {"approval_ids": cancelled, "reason": "Live agent run closed"},
                    )
                    await s.commit()

    async def work(run, token=None):
        w = get_world()

        async def emit(event):
            run["events"].append(event)
            await save(run)

        try:
            if token is not None:
                pair = run.get("pair")
                sdk = pair.sdk if pair else w.sdks["ava"]
                task = await sdk.start_task(run["message"], token, intent_categories=MODES[run["mode"]])
                run["task"], run["root_id"] = task, task.root_id

                if run.get("walkthrough_case") == "delegation_widening":
                    run["events"].append(
                        {
                            "kind": "delegation",
                            "label": "Requested extra purpose: payments.status.read",
                            "arguments": {"from": pair.coordinator_id, "to": pair.payments_id},
                        }
                    )
                    await save(run)
                    try:
                        unexpected = await pair.payments_sdk.accept_delegation(
                            task.token, intent_categories=[*MODES["transfer"], "payments.status.read"]
                        )
                    except AegisDenied as exc:
                        async with w.ctx.db.sessionmaker() as s:
                            decision = await s.scalar(
                                select(DecisionRecord)
                                .where(
                                    DecisionRecord.root_id == task.root_id,
                                    DecisionRecord.action == "sts.token_exchange",
                                )
                                .order_by(DecisionRecord.ts.desc())
                                .limit(1)
                            )
                            alerts = list(await s.scalars(select(Alert).where(Alert.agent_id == pair.coordinator_id)))
                            alert = next(
                                (a for a in alerts if decision and a.evidence.get("decision") == decision.id), None
                            )
                            children = list(
                                await s.scalars(select(Mandate.id).where(Mandate.parent_id == task.mandate_id))
                            )
                        verified = (
                            "DLG-004" in exc.rules and decision is not None and alert is not None and not children
                        )
                        run["status"] = "blocked" if verified else "failed"
                        run["reply"] = (
                            "DLG-004: delegation permission widening denied. No child credential issued; "
                            "no bank tool called. A linked SOC alert records the real rejection."
                            if verified
                            else "The expected correlated DLG-004 proof was not obtained. Inspect Activity."
                        )
                        run["events"].append(
                            {
                                "kind": "denial",
                                "label": str(exc),
                                "result": {
                                    "decision_id": decision.id if decision else None,
                                    "alert_id": alert.id if alert else None,
                                    "rules": exc.rules,
                                    "child_credentials_issued": len(children),
                                    "bank_tools_called": False,
                                },
                            }
                        )
                        return
                    else:
                        await unexpected.complete()
                        run["status"], run["reply"] = (
                            "failed",
                            "Security test unexpectedly received a child credential. No bank tool was called.",
                        )
                        return
                ids = {"ava": pair.coordinator_id, "payments-agent": pair.payments_id} if pair else None
                runtime = LiveAva(w, task, run["mode"], emit, agent_ids=ids)
                await runtime.prepare()
                run["runtime"], run["state"] = runtime, runtime.initial(run["message"])
            run["state"] = await run["runtime"].run(run["state"])
            state = run["state"]
            run["status"], run["reply"] = state["status"], state["reply"]
            run["pending"] = {**(state["next_call"] or {}), "approval_id": state["approval_id"]}
        except asyncio.CancelledError:
            run["status"] = "stopped" if run.get("stop_reason") else "cancelled"
            run["reply"] = run.get("stop_reason") or "Run cancelled. Check verified receipts before a new write."
        except LlmCallError as exc:
            run["status"], run["reply"] = "blocked", f"{exc.code}: {exc}"
            await emit(
                {
                    "kind": "denial",
                    "label": f"Model request blocked: {exc.code}",
                    "result": {"rule": exc.code, "message": str(exc)},
                }
            )
        except ExecutionUncertain as exc:
            run["status"], run["reply"] = "uncertain", str(exc)
        except AegisDenied as exc:
            run["status"], run["reply"] = "blocked", str(exc)
        except ValidationError:
            run["status"], run["reply"] = (
                "blocked",
                "Model arguments failed strict validation. No invalid operation was run.",
            )
        except httpx.HTTPError:
            run["status"], run["reply"] = (
                "uncertain",
                "A request failed. It may have executed; inspect receipts. No automatic retry.",
            )
        except Exception as exc:
            # Do not leak SDK errors, cloud responses, prompts or credentials through the browser.
            run["status"], run["reply"] = (
                "failed",
                f"The workflow could not finish ({type(exc).__name__}). Inspect Activity; no automatic retry.",
            )
        finally:
            if run["status"] not in OPEN:
                await close(run)
            await save(run)
            if run["status"] not in OPEN:
                active.pop(run["id"], None)

    async def stop_run(run, reason, status="stopped"):
        run["stop_reason"] = reason
        job = run["job"]
        if not job.done():
            job.cancel()
            await asyncio.gather(job, return_exceptions=True)
        else:
            run["status"], run["reply"] = status, reason
            await close(run)
            await save(run)
            active.pop(run["id"], None)

    async def resume_run(run, *, automatic=False):
        if run["status"] != "approval_required" or not run["job"].done():
            raise HTTPException(409, "This run is not waiting for approval; no duplicate execution was started.")
        if not run["state"]["confirmed"]:
            raise HTTPException(409, "Customer confirmation is required before risk approval can resume a write.")
        approval = await run["task"].wait_for_approval(run["state"]["approval_id"], timeout=0)
        if approval != "approved":
            raise HTTPException(409, f"Approval is {approval}; nothing was resumed. You may cancel the run.")
        run["events"].append(
            {
                "kind": "approval",
                "label": "Approval accepted; continuing the same confirmed action",
                "approval_id": run["state"]["approval_id"],
                "runtime": "automatic" if automatic else "manual",
            }
        )
        run["state"]["status"], run["status"] = "running", "running"
        await save(run)
        run["job"] = get_world().spawn(work(run))

    async def monitor():
        w = get_world()
        while not w.stop.is_set():
            try:
                async with admission:
                    for run in list(active.values()):
                        if run["status"] not in OPEN or not run.get("task"):
                            continue
                        task = run["task"]
                        ids = task.claims["aegis"].get("chain", [])
                        if run.get("payments_id"):
                            ids = [*ids, run["payments_id"]]
                        reason = await w.ctx.hotstore.revoked(
                            [("mdt", task.mandate_id), ("root", task.root_id), ("jti", task.claims["jti"])]
                            + [("agent", agent_id) for agent_id in ids]
                        )
                        if not reason:
                            async with w.ctx.db.sessionmaker() as s:
                                agents = list(await s.scalars(select(Agent).where(Agent.id.in_(ids))))
                            if len(agents) != len(set(ids)) or any(a.status != "active" for a in agents):
                                reason = "A bound agent is no longer active or requires renewed approval"
                        if reason:
                            await stop_run(
                                run,
                                f"Governance stopped this task: {reason}. Delegated work cannot continue. "
                                "Check receipts; previously committed operations are not undone.",
                            )
                            continue
                        if time.time() >= task.claims["exp"]:
                            await stop_run(run, "Mandate expired; pending work will not resume.", "expired")
                            continue
                        if run["status"] == "approval_required" and run["job"].done() and run.get("auto_resume"):
                            approval = await task.wait_for_approval(run["state"]["approval_id"], timeout=0)
                            if approval == "approved":
                                await resume_run(run, automatic=True)
                            elif approval in {"rejected", "cancelled", "expired", "consumed"}:
                                await stop_run(
                                    run, f"Approval {approval}; the pending action will not execute.", "blocked"
                                )
            except asyncio.CancelledError:
                raise
            except Exception:
                # Monitoring failures never bypass authorization or retry an uncertain payment.
                log.exception("Agent lifecycle monitor failed; execution remains gateway-authorized")
            try:
                await asyncio.wait_for(w.stop.wait(), timeout=0.25)
            except TimeoutError:
                pass

    async def owned(run_id, user):
        async with get_world().ctx.db.sessionmaker() as s:
            row = await s.get(AgentRun, str(run_id))
            if row is None or (row.subject != user.username and not set(user.roles).intersection(OPERATORS)):
                raise HTTPException(404, "Run not found.")
            return row.snapshot

    @r.get("/status")
    async def status(user: Persona = Depends(require_roles("customer", *OPERATORS)), coordinator_id: str | None = None):
        w = get_world()
        pair = await runtime_pair(w, coordinator_id) if coordinator_id else None
        config = policy(w.settings)
        frameworks = framework_status()
        error = policy_error(w.settings, w.settings.azure_openai_deployment, "confidential")
        azure = w.gateway.state.azure_upstream
        azure_ready = False
        if azure:
            try:
                azure.configuration()
                azure_ready = True
            except Exception:
                pass
        async with w.ctx.db.sessionmaker() as s:
            review = (
                list(
                    (
                        await s.scalars(
                            select(Tool.id)
                            .where(Tool.server_id.in_(BANK_SERVERS), Tool.status != "approved")
                            .order_by(Tool.id)
                        )
                    ).all()
                )
                if w.bank
                else []
            )
        return {
            "ready": azure_ready and all(frameworks.values()) and error is None,
            "frameworks": frameworks,
            "policy": config,
            "policy_error": error,
            "azure_configured": azure_ready,
            "budget": await budget_status(w.ctx, pair.coordinator_id if pair else w.agent_ids["ava"]),
            "synthetic_bank": True,
            "passwordless_demo_identity": w.settings.enable_dev_login,
            "bank_storage": w.ctx.db.engine.dialect.name if w.bank else "offline-fixtures",
            "bank_tools_requiring_review": review,
            "opa_used_for_llm": False,
        }

    @r.get("/runs")
    async def history(user: Persona = Depends(require_roles("customer", *OPERATORS))):
        async with get_world().ctx.db.sessionmaker() as s:
            query = select(AgentRun).order_by(AgentRun.updated_at.desc()).limit(50)
            if not set(user.roles).intersection(OPERATORS):
                query = query.where(AgentRun.subject == user.username)
            return [row.snapshot for row in await s.scalars(query)]

    @r.get("/runs/{run_id}")
    async def get_run(run_id: UUID, user: Persona = Depends(require_roles("customer", *OPERATORS))):
        return await owned(run_id, user)

    @r.get("/runs/{run_id}/proof")
    async def proof(run_id: UUID, user: Persona = Depends(require_roles("customer", *OPERATORS))):
        from aegis.control.siem import delivery_dict
        from aegis.control.tables import SiemDelivery

        snapshot = await owned(run_id, user)
        root_id = snapshot.get("root_id")
        if not root_id:
            return {"graph": {"nodes": [], "edges": []}, "alerts": [], "decisions": []}
        async with get_world().ctx.db.sessionmaker() as s:
            mandates = list(await s.scalars(select(Mandate).where(Mandate.root_id == root_id)))
            decisions = list(
                await s.scalars(
                    select(DecisionRecord).where(DecisionRecord.root_id == root_id).order_by(DecisionRecord.ts)
                )
            )
            approvals = list(await s.scalars(select(Approval).where(Approval.mandate_id.in_([m.id for m in mandates]))))
            names = await agent_names(
                s,
                [
                    *[m.agent_id for m in mandates],
                    *[d.input_snapshot.get("delegation", {}).get("target_agent_id") for d in decisions],
                ],
            )
            alerts = list(await s.scalars(select(Alert).where(Alert.agent_id.in_([m.agent_id for m in mandates]))))
            deliveries = {
                d.alert_id: delivery_dict(d)
                for d in await s.scalars(select(SiemDelivery).where(SiemDelivery.alert_id.in_([a.id for a in alerts])))
            }
        return {
            "graph": lineage_graph(mandates, decisions, approvals, names, False),
            "decisions": [
                {
                    "id": d.id,
                    "decision": d.decision,
                    "action": d.action,
                    "reasons": d.reasons,
                    "subject": d.subject,
                    "agent_id": d.agent_id,
                    "root_id": d.root_id,
                    "trace_id": d.trace_id,
                }
                for d in decisions
            ],
            "alerts": [
                {
                    "id": a.id,
                    "rule_id": a.rule_id,
                    "title": a.title,
                    "reasons": a.evidence.get("reasons", []),
                    "forwarding": deliveries.get(a.id),
                }
                for a in alerts
                if a.evidence.get("root_id") == root_id
            ],
        }

    @r.post("/runs", status_code=202)
    async def start(body: StartRun, request: Request, user: Persona = Depends(require_roles("customer"))):
        nonlocal monitor_job
        if user.username != "jan.devries":
            raise HTTPException(403, "The live demo is restricted to Jan's synthetic bank account.")
        w = get_world()
        if body.walkthrough_case != "normal" and (not body.coordinator_id or body.mode != "transfer"):
            raise HTTPException(422, "The bounded delegation challenge requires a connected pair and a transfer task.")
        w.live_runs = active
        if body.coordinator_id and body.mode not in {"inquiry", "transfer"}:
            raise HTTPException(
                422, "The two-agent templates support inquiries and transfers; use default Ava for KYC/address tasks."
            )
        request_hash = sha256_hex(body.model_dump(mode="json"))
        async with admission:
            async with w.ctx.db.sessionmaker() as s:
                existing = await s.get(AgentRun, str(body.request_id))
                if existing:
                    if existing.subject != user.username:
                        raise HTTPException(409, "Request ID unavailable.")
                    if existing.snapshot.get("request_hash") != request_hash:
                        raise HTTPException(
                            409,
                            "This request ID belongs to a different submission. "
                            "Inspect its run before starting another task.",
                        )
                    return existing.snapshot
                # One open task per customer prevents overlapping writes and model requests.
                pending = await s.scalar(
                    select(AgentRun.id).where(AgentRun.subject == user.username, AgentRun.status.in_(OPEN)).limit(1)
                )
                if pending:
                    raise HTTPException(409, "Finish or cancel your existing run before starting another.")
            pair = await runtime_pair(w, body.coordinator_id) if body.coordinator_id else None
            config = await status(user, body.coordinator_id)
            if body.walkthrough_case == "normal" and not config["ready"]:
                raise HTTPException(503, config["policy_error"] or "Azure/framework configuration is not ready.")
            run = {
                "id": str(body.request_id),
                "subject": user.username,
                "mode": body.mode,
                "status": "running",
                "reply": "",
                "events": [],
                "root_id": None,
                "pending": {},
                "message": body.message,
                "request_hash": request_hash,
                "coordinator_id": pair.coordinator_id if pair else w.agent_ids["ava"],
                "payments_id": pair.payments_id if pair else w.agent_ids["payments-agent"],
                "walkthrough_case": body.walkthrough_case,
                "auto_resume": body.auto_resume,
                "pair": pair,
            }
            await save(run)
            active[run["id"]] = run
            run["job"] = w.spawn(work(run, request.headers["authorization"][7:]))
            if monitor_job is None or monitor_job.done():
                monitor_job = w.spawn(monitor())
            return await owned(body.request_id, user)

    @r.post("/runs/{run_id}/continue", status_code=202)
    async def continue_run(run_id: UUID, body: ContinueRun, user: Persona = Depends(require_roles("customer"))):
        async with admission:
            snapshot = await owned(run_id, user)
            if snapshot["subject"] != user.username:
                raise HTTPException(403, "Only the initiating customer can continue this run.")
            run = active.get(str(run_id))
            if run is None:
                raise HTTPException(409, "This run is not resumable. It will not be replayed.")
            if body.action == "cancel":
                if not run["job"].done():
                    run["job"].cancel()
                    await asyncio.gather(run["job"], return_exceptions=True)
                    if run["status"] == "running":
                        run["status"], run["reply"] = "cancelled", "Run cancelled; check receipts before another write."
                        await close(run)
                        await save(run)
                        active.pop(str(run_id), None)
                else:
                    run["status"], run["reply"] = "cancelled", "Run cancelled; pending actions will not execute."
                    await close(run)
                    await save(run)
                    active.pop(str(run_id), None)
                return await owned(run_id, user)
            expected = "confirmation_required" if body.action == "confirm" else "approval_required"
            if run["status"] != expected or not run["job"].done():
                raise HTTPException(409, "The run is not waiting for this action; no duplicate execution was started.")
            if time.time() >= run["task"].claims["exp"]:
                run["status"], run["reply"] = "expired", "Mandate expired. The pending action was not resumed."
                await close(run)
                await save(run)
                active.pop(str(run_id), None)
                raise HTTPException(409, run["reply"])
            if body.action == "resume_approval":
                await resume_run(run)
                return await owned(run_id, user)
            else:
                async with get_world().ctx.db.sessionmaker() as s:
                    await ledger.append(
                        s,
                        "agent.action_confirmed",
                        user.username,
                        run["root_id"],
                        {"run_id": run["id"], "operation": run["state"]["next_call"]},
                    )
                    await s.commit()
            run["state"]["confirmed"], run["state"]["status"] = True, "running"
            run["status"] = "running"
            await save(run)
            run["job"] = get_world().spawn(work(run))
            return await owned(run_id, user)

    return r
