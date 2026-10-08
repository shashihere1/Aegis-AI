"""Authenticated live-agent runs. History is durable; resumable Mandates stay in memory only.

The local console is a single-process demonstration. A restart interrupts pending runs; it never
replays a write or reconstitutes a bearer token from database history.
"""

import asyncio
import time
from typing import Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from aegis.common.hashing import sha256_hex
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.identity.idp import Persona
from aegis.control.model_controls import budget_status, policy, policy_error
from aegis.control.tables import AgentRun, Approval, Mandate
from aegis.sdk import AegisDenied, LlmCallError
from aegis_demo.agent_runtime import MODES, LiveAva, framework_status

OPEN = {"running", "confirmation_required", "approval_required"}


class StartRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID
    mode: Literal["inquiry", "documents", "address", "transfer"]
    message: str = Field(min_length=3, max_length=1500)
    confirm_synthetic_external_call: Literal[True]


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

    async def save(run):
        w = get_world()
        snapshot = {k: run[k] for k in ("id", "subject", "mode", "status", "reply", "events", "root_id", "pending")}
        snapshot["resumable"] = run["status"] in ("confirmation_required", "approval_required")
        snapshot["request_hash"] = run["request_hash"]
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
                    {"mode": run["mode"], "synthetic_external_call_confirmed": True},
                )
            else:
                row.status, row.snapshot = run["status"], snapshot
            await s.commit()

    async def close(run):
        if run.get("task"):
            try:
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
            for approval_id, (pending_task, _) in list(w.payments_app.state.pending.items()):
                if pending_task.root_id == run["task"].root_id:
                    w.payments_app.state.pending.pop(approval_id, None)
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
        try:
            if token is not None:
                task = await w.sdks["ava"].start_task(run["message"], token, intent_categories=MODES[run["mode"]])
                run["task"], run["root_id"] = task, task.root_id

                async def emit(event):
                    run["events"].append(event)
                    await save(run)

                runtime = LiveAva(w, task, run["mode"], emit)
                await runtime.prepare()
                run["runtime"], run["state"] = runtime, runtime.initial(run["message"])
            run["state"] = await run["runtime"].run(run["state"])
            state = run["state"]
            run["status"], run["reply"] = state["status"], state["reply"]
            run["pending"] = {**(state["next_call"] or {}), "approval_id": state["approval_id"]}
        except asyncio.CancelledError:
            run["status"], run["reply"] = "cancelled", "Run cancelled. Check verified receipts before a new write."
        except LlmCallError as exc:
            run["status"], run["reply"] = "blocked", f"{exc.code}: {exc}"
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

    async def owned(run_id, user):
        async with get_world().ctx.db.sessionmaker() as s:
            row = await s.get(AgentRun, str(run_id))
            if row is None or (row.subject != user.username and not set(user.roles).intersection(OPERATORS)):
                raise HTTPException(404, "Run not found.")
            return row.snapshot

    @r.get("/status")
    async def status(user: Persona = Depends(require_roles("customer", *OPERATORS))):
        w = get_world()
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
        return {
            "ready": azure_ready and all(frameworks.values()) and error is None,
            "frameworks": frameworks,
            "policy": config,
            "policy_error": error,
            "azure_configured": azure_ready,
            "budget": await budget_status(w.ctx, w.agent_ids["ava"]),
            "synthetic_bank": True,
            "passwordless_demo_identity": True,
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

    @r.post("/runs", status_code=202)
    async def start(body: StartRun, request: Request, user: Persona = Depends(require_roles("customer"))):
        if user.username != "jan.devries":
            raise HTTPException(403, "The live demo is restricted to Jan's synthetic bank account.")
        w = get_world()
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
            config = await status(user)
            if not config["ready"]:
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
            }
            await save(run)
            active[run["id"]] = run
            run["job"] = w.spawn(work(run, request.headers["authorization"][7:]))
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
                approval = await run["task"].wait_for_approval(run["state"]["approval_id"], timeout=0)
                if approval != "approved":
                    raise HTTPException(409, f"Approval is {approval}; nothing was resumed. You may cancel the run.")
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
