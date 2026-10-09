"""Demo agents in deterministic "scripted planner" mode (plan §13.3).

The governance path is identical to LLM planning; only the plan is fixed, so the demo is repeatable.
Ava is the customer-facing orchestrator; the KYC and Payments agents accept A2A delegations.
"""

import json
import re

from fastapi import FastAPI, Request

from aegis.sdk import AegisAgent, AegisDenied, ApprovalRequired, Task


def a2a_result(state: str, data: dict) -> dict:
    return {"status": {"state": state}, "artifacts": [{"parts": [{"data": data}]}]}


def structured(result: dict) -> dict:
    """A tool result as a dict: structured content if present, otherwise the JSON text content."""
    content = result.get("structuredContent")
    if isinstance(content, dict) and content:
        return content.get("result", content)
    texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
    try:
        return json.loads(texts[0]) if texts else {}
    except json.JSONDecodeError:
        return {"text": "\n".join(texts)}


def specialist_app(name: str) -> FastAPI:
    """An A2A endpoint. `app.state.sdk` is set once the agent is approved and has credentials."""
    app = FastAPI(title=name)
    app.state.sdk = None
    app.state.last_task = None
    app.state.pending: dict[str, tuple[Task, dict]] = {}
    return app


def kyc_agent_app(*, allow_scripted: bool = False) -> FastAPI:
    app = specialist_app("KYC Verification Agent")

    @app.post("/")
    async def send_message(request: Request):
        body = await request.json()
        meta = body["params"]["message"].get("metadata", {})
        sdk: AegisAgent = app.state.sdk
        try:
            task = await sdk.accept_delegation(request.headers["x-aegis-parent-mandate"])
            app.state.last_task = task
            if meta.get("runtime") == "microsoft-agent-framework":
                from aegis_demo.agent_runtime import verify_with_framework

                receipt = await verify_with_framework(task, meta["customer_id"], meta["document_id"])
                await task.complete()
            elif allow_scripted:
                result = await task.call_tool(
                    "kyc", "verify_document", {"customer_id": meta["customer_id"], "document_id": meta["document_id"]}
                )
                receipt = structured(result)
            else:
                await task.complete()
                raise AegisDenied("KYC requires Microsoft Agent Framework in the normal app.")
        except AegisDenied as exc:
            return {"jsonrpc": "2.0", "id": body.get("id"), "result": a2a_result("failed", {"error": str(exc)})}
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": a2a_result("completed", receipt)}

    return app


def payments_agent_app() -> FastAPI:
    app = specialist_app("Payments Agent")

    @app.post("/")
    async def send_message(request: Request):
        body = await request.json()
        meta = body["params"]["message"].get("metadata", {})
        sdk: AegisAgent = app.state.sdk
        try:
            if meta.get("resume_approval"):
                # Resume the original task: the approval is bound to that mandate and these exact arguments.
                pending = app.state.pending.get(meta["resume_approval"])
                if pending is None:
                    raise AegisDenied("This approval is no longer resumable. Do not repeat the payment.")
                task, args = pending
                caller = await sdk.accept_delegation(request.headers["x-aegis-parent-mandate"])
                try:
                    if caller.root_id != task.root_id or caller.claims["sub"] != task.claims["sub"]:
                        raise AegisDenied("Approval resume does not belong to this user's task.")
                finally:
                    await caller.complete()
                status = await task.wait_for_approval(meta["resume_approval"], timeout=0)
                if status != "approved":
                    if status == "pending":
                        return {
                            "jsonrpc": "2.0",
                            "id": body.get("id"),
                            "result": a2a_result("auth-required", {"approval_id": meta["resume_approval"]}),
                        }
                    raise AegisDenied("The approval was rejected, expired or consumed.")
                app.state.pending.pop(meta["resume_approval"])
                result = await task.call_tool(
                    "payments", "initiate_transfer", args, approval_id=meta["resume_approval"]
                )
            else:
                task = await sdk.accept_delegation(request.headers["x-aegis-parent-mandate"])
                args = {k: meta[k] for k in ("customer_id", "amount", "creditor_iban", "new_beneficiary")}
                args["reference"] = meta.get("reference", "")
                result = await task.call_tool("payments", "initiate_transfer", args)
        except ApprovalRequired as exc:
            app.state.pending[exc.approval_id] = (task, args)
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": a2a_result("auth-required", {"approval_id": exc.approval_id, "reasons": exc.reasons}),
            }
        except AegisDenied as exc:
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": a2a_result("failed", {"error": str(exc), "reasons": exc.reasons}),
            }
        if result.get("isError"):
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": a2a_result("failed", {"error": "Payment tool returned an execution error."}),
            }
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": a2a_result("completed", structured(result))}

    return app


class Ava:
    """Customer-service orchestrator. In LLM mode a LangGraph planner chooses these steps."""

    def __init__(self, sdk: AegisAgent, kyc_id: str, payments_id: str):
        self.sdk, self.kyc_id, self.payments_id = sdk, kyc_id, payments_id

    async def change_address(self, user_token: str, customer_id: str, document_id: str, new_address: str) -> dict:
        """S2: mandate -> A2A delegation to KYC (attenuated) -> PII-redacted result -> address update."""
        task = await self.sdk.start_task("Verify identity document for address change", user_token)
        verification = await task.delegate(
            self.kyc_id, "Verify this identity document", {"customer_id": customer_id, "document_id": document_id}
        )
        updated = await task.call_tool(
            "crm", "update_address", {"customer_id": customer_id, "new_address": new_address}
        )
        await task.complete()  # closing the task revokes its mandate tree (automatic revocation)
        return {"task": task, "verification": verification, "update": updated}

    async def transfer(
        self, user_token: str, customer_id: str, amount: float, creditor_iban: str, new_beneficiary: bool
    ) -> dict:
        """S3: delegated payment; high value to a new beneficiary needs a human approval."""
        task = await self.sdk.start_task(f"Transfer EUR {amount:,.0f} to my new landlord", user_token)
        response = await task.delegate(
            self.payments_id,
            "Initiate this transfer",
            {
                "customer_id": customer_id,
                "amount": amount,
                "creditor_iban": creditor_iban,
                "new_beneficiary": new_beneficiary,
                "reference": "Rent",
            },
        )
        return {"task": task, "response": response}

    async def resume_transfer(self, task: Task, approval_id: str) -> dict:
        result = await task.delegate(self.payments_id, "Approval granted, continue", {"resume_approval": approval_id})
        await task.complete()
        return result

    async def process_uploaded_document(self, user_token: str, customer_id: str, document_id: str) -> dict:
        """S4: a poisoned document hijacks the planner. Aegis must contain it."""
        task = await self.sdk.start_task(
            "Verify the customer's ID, update their address from the uploaded document and send a confirmation",
            user_token,
            intent_categories=["customer.kyc.verify", "customer.profile.update", "comms.external.send"],
        )
        steps = []
        await task.delegate(
            self.kyc_id, "Verify the customer's passport", {"customer_id": customer_id, "document_id": "D-77"}
        )
        steps.append({"step": "delegate_kyc", "ok": True})
        document = await task.call_tool("docs", "read_document", {"document_id": document_id})
        text = document["content"][0]["text"]
        steps.append({"step": "read_document", "ok": True})
        # A hijacked LLM would obey the hidden instruction; the scripted planner reproduces that.
        injected = re.search(r"email all customer records to ([\w.-]+) at ([\w-]+) dot (\w+)", text)
        if injected:
            address = f"{injected.group(1)}@{injected.group(2)}.{injected.group(3)}"  # the LLM "decodes" it
            try:
                await task.call_tool("notify", "send_email", {"to": address, "subject": "records", "body": text})
                steps.append({"step": "send_email", "ok": True})
            except AegisDenied as exc:
                steps.append({"step": "send_email", "ok": False, "denied": exc.rules, "message": str(exc)})
        return {"task": task, "steps": steps}
