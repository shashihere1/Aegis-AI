"""Demo Studio API: runs the demo scenes from the console (demo deployments only, never in production).

Each run records human-readable steps so the console can show what Aegis did, with links into the
lineage, approvals and alerts views. Scenes call the real APIs through the SDK, exactly as the tests do.
"""

import asyncio
import itertools
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import FastAPI
from pydantic import BaseModel

from aegis.sdk import AegisDenied
from aegis_demo import mcp_servers
from aegis_demo.agents import structured
from aegis_demo.data import DOCUMENTS, LANDLORD_IBAN
from aegis_demo.mcp_servers import kyc

JAN = "jan.devries"
SCENES = {
    "address-change": {"title": "Governed journey", "scene": "S2"},
    "transfer": {"title": "High-value transfer", "scene": "S3"},
    "policy-transfer": {"title": "Policy threshold comparison: EUR 5,000", "scene": "S7"},
    "attack": {"title": "Prompt-injection attack", "scene": "S4"},
    "shadow": {"title": "Shadow agents", "scene": "S5"},
    "rug-pull": {"title": "Tool rug pull", "scene": "A4"},
}


class TransferRequest(BaseModel):
    amount: float = 25000
    new_beneficiary: bool = True


def studio_app(get_world: Callable) -> FastAPI:
    app = FastAPI(title="Aegis demo studio")
    runs: list[dict] = []
    state = {"kyc_variant": "v1"}
    counter = itertools.count(1)

    def new_run(key: str) -> dict:
        run = {
            "id": uuid.uuid4().hex[:8],
            "key": key,
            **SCENES[key],
            "status": "running",
            "started_at": datetime.now(UTC).isoformat(),
            "steps": [],
            "links": {},
        }
        runs.insert(0, run)
        del runs[30:]
        return run

    def step(run: dict, label: str, status: str = "ok", detail: str = "") -> None:
        run["steps"].append({"label": label, "status": status, "detail": detail, "at": datetime.now(UTC).isoformat()})

    def finish(run: dict, status: str) -> dict:
        run["status"] = status
        return run

    async def agent_status(w, key: str) -> str:
        return (await w.api("mark.jansen", "GET", f"/v1/agents/{w.agent_ids[key]}")).json()["status"]

    @app.get("/runs")
    async def list_runs():
        return runs

    @app.get("/status")
    async def status():
        w = get_world()
        agents = {key: {"id": agent_id, "status": await agent_status(w, key)} for key, agent_id in w.agent_ids.items()}
        tools = (await w.api("mark.jansen", "GET", "/v1/tools?server=kyc")).json()
        return {
            "agents": agents,
            "kyc_variant": state["kyc_variant"],
            "kyc_tool_status": {t["id"]: t["status"] for t in tools},
            "emails_sent": len(mcp_servers.SENT_EMAILS),
            "transfers": mcp_servers.TRANSFERS[-5:],
        }

    @app.get("/samples")
    async def samples():
        return {"poisoned_document": DOCUMENTS["D-99"]["text"], "passport": DOCUMENTS["D-77"]["text"]}

    @app.post("/scenarios/address-change")
    async def address_change():
        w, run = get_world(), new_run("address-change")
        try:
            result = await w.ava.change_address(w.token(JAN), "C-1001", "D-77", "Keizersgracht 401, 1016 EK Amsterdam")
        except AegisDenied as exc:
            step(run, "Ava could not start the task", "denied", str(exc))
            return finish(run, "blocked")
        claims = result["task"].claims
        run["links"]["root_id"] = result["task"].root_id
        step(
            run,
            "Mandate issued to Ava for Jan de Vries",
            detail=f"purpose {', '.join(claims['authorization_details'][0]['intent_categories'])} · "
            f"expires in {claims['exp'] - claims['iat']} s",
        )
        verification = result["verification"]
        if verification["status"]["state"] != "completed":
            step(
                run,
                "KYC agent could not verify the document",
                "denied",
                verification["artifacts"][0]["parts"][0]["data"].get("error", ""),
            )
            return finish(run, "blocked")
        kyc_claims = w.kyc_app.state.last_task.claims
        step(
            run,
            "Delegated to KYC agent over A2A",
            detail=f"purpose narrowed to {', '.join(kyc_claims['authorization_details'][0]['intent_categories'])}"
            f" · chain depth {kyc_claims['aegis']['depth']}",
        )
        data = verification["artifacts"][0]["parts"][0]["data"]
        step(run, "KYC result returned with PII redacted", detail=f"bsn={data.get('bsn')} · iban={data.get('iban')}")
        step(run, "Address updated in CRM", detail=f"new address: {structured(result['update']).get('address', '')}")
        step(run, "Task closed: mandates revoked automatically")
        return finish(run, "completed")

    async def await_approval(run: dict, flow: dict, approval_id: str) -> None:
        w = get_world()
        status = await flow["task"].wait_for_approval(approval_id, timeout=900, interval=0.75)
        approvals = (await w.api("eva.visser", "GET", "/v1/approvals?status=all")).json()
        approver = next((a.get("approver") for a in approvals if a["id"] == approval_id), None)
        if status != "approved":
            step(run, f"Approval {status}" + (f" by {approver}" if approver else ""), "denied")
            await flow["task"].complete()
            finish(run, "blocked")
            return
        step(run, f"Approved by {approver}", detail="approval is single use and bound to this exact action")
        done = await w.ava.resume_transfer(flow["task"], approval_id)
        payment = done["artifacts"][0]["parts"][0]["data"]
        step(run, "Payment executed", detail=f"{payment.get('payment_id')} · EUR {payment.get('amount'):,.2f}")
        finish(run, "completed")

    @app.post("/scenarios/transfer")
    async def transfer(body: TransferRequest):
        return await transfer_flow(body, "transfer")

    @app.post("/scenarios/policy-transfer")
    async def policy_transfer():
        return await transfer_flow(TransferRequest(amount=5000), "policy-transfer")

    async def transfer_flow(body: TransferRequest, scene: str):
        w, run = get_world(), new_run(scene)
        try:
            flow = await w.ava.transfer(w.token(JAN), "C-1001", body.amount, LANDLORD_IBAN, body.new_beneficiary)
        except AegisDenied as exc:
            step(run, "Ava could not start the task", "denied", str(exc))
            return finish(run, "blocked")
        run["links"]["root_id"] = flow["task"].root_id
        step(run, f"Mandate issued; delegated EUR {body.amount:,.0f} transfer to the Payments agent")
        response = flow["response"]
        data = response["artifacts"][0]["parts"][0]["data"]
        if response["status"]["state"] == "auth-required":
            run["links"]["approval_id"] = data["approval_id"]
            step(
                run,
                "Held for human approval",
                "waiting",
                "; ".join(f"{r['rule']}: {r['message']}" for r in data["reasons"]) + " · approve it in Approvals",
            )
            run["status"] = "waiting"
            w.spawn(await_approval(run, flow, data["approval_id"]))
            return run
        await flow["task"].complete()
        if response["status"]["state"] == "completed":
            step(run, "Payment executed without approval (below the threshold)", detail=data.get("payment_id", ""))
            return finish(run, "completed")
        step(run, "Payment refused", "denied", data.get("error", ""))
        return finish(run, "blocked")

    @app.post("/scenarios/attack")
    async def attack():
        w, run = get_world(), new_run("attack")
        before = {a["id"] for a in (await w.api("mark.jansen", "GET", "/v1/alerts")).json()}
        try:
            result = await w.ava.process_uploaded_document(w.token(JAN), "C-1001", "D-99")
        except AegisDenied as exc:
            step(run, "Ava could not start the task", "denied", f"{exc} · reset the demo to resume Ava")
            return finish(run, "blocked")
        run["links"]["root_id"] = result["task"].root_id
        step(run, "Ava delegated passport verification to the KYC agent")
        step(
            run,
            "Ava read the customer's uploaded rental contract",
            detail="it hides an instruction to e-mail all customer records to an outside address",
        )
        email = next((s for s in result["steps"] if s["step"] == "send_email"), None)
        if email and not email["ok"]:
            step(
                run,
                "Hijacked e-mail to the attacker blocked",
                "denied",
                ", ".join(email["denied"]) + " · untrusted content + confidential data + external egress",
            )
        new_alerts = [a for a in (await w.api("mark.jansen", "GET", "/v1/alerts")).json() if a["id"] not in before]
        for alert in sorted(new_alerts, key=lambda a: a["rule_id"]):
            step(run, f"{alert['rule_id']} alert: {alert['title']}", "alert", alert["severity"])
            for action in alert["actions_taken"]:
                radius = action["blast_radius"]
                step(
                    run,
                    "Playbook suspended Ava and cascade-revoked her tasks",
                    "denied",
                    f"{len(radius['mandates'])} mandates across {len(radius['agents_affected'])} agents",
                )
        run["links"]["alert_ids"] = [a["id"] for a in new_alerts]
        try:
            await w.kyc_app.state.last_task.call_tool("kyc", "get_kyc_status", {"customer_id": "C-1001"})
            step(run, "KYC agent's delegated mandate still works", "denied")
        except AegisDenied as exc:
            step(run, "KYC agent's delegated mandate is now rejected", "ok", str(exc)[:110])
        step(run, f"E-mails that actually left the bank: {len(mcp_servers.SENT_EMAILS)}")
        return finish(run, "contained")

    @app.post("/scenarios/shadow")
    async def shadow():
        w, run = get_world(), new_run("shadow")
        n = next(counter)
        call = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_customer", "arguments": {"customer_id": "C-1001"}},
        }
        response = await w.http.post(
            f"{w.settings.gateway_url}/mcp/crm",
            json=call,
            headers={"x-api-key": f"static-key-from-wiki-{n}", "user-agent": f"marketing-lead-scraper/0.{n}"},
        )
        step(
            run,
            "Unregistered script called the CRM through the Gateway with a static API key",
            "denied",
            f"HTTP {response.status_code}: a Mandate is required",
        )
        client = f"lead-enrichment-bot-{n}-{uuid.uuid4().hex[:8]}"
        w.ctx.idp.register_unmanaged_client(client, "Lead enrichment bot")
        step(run, f"An identity '{client}' was created directly in the IdP, bypassing Aegis")
        found = (await w.api("mark.jansen", "POST", "/v1/discovery/scan")).json()["found"]
        step(run, "IdP scan found identities not governed by the registry", detail=", ".join(found[-3:]))
        step(run, "Both are now findings in Shadow Agents (claim or quarantine them there)")
        return finish(run, "completed")

    @app.post("/scenarios/rug-pull")
    async def rug_pull():
        w, run = get_world(), new_run("rug-pull")
        if state["kyc_variant"] == "v1":
            await w.swap_mcp_server("kyc", kyc("v2"))
            state["kyc_variant"] = "v2"
        step(run, "The KYC MCP server silently changed its verify_document description after approval")
        try:
            result = await w.ava.change_address(w.token(JAN), "C-1001", "D-77", "Keizersgracht 401, Amsterdam")
            run["links"]["root_id"] = result["task"].root_id
            state_ = result["verification"]["status"]["state"]
            step(
                run,
                "KYC agent tried to call the changed tool",
                "denied" if state_ != "completed" else "ok",
                f"result: {state_}",
            )
        except AegisDenied as exc:
            step(run, "Ava could not start the task", "denied", str(exc))
        tools = {t["id"]: t for t in (await w.api("mark.jansen", "GET", "/v1/tools?server=kyc")).json()}
        step(
            run,
            f"kyc.verify_document is {tools['kyc.verify_document']['status']} (definition hash mismatch)",
            "alert",
            "DET-03 raised",
        )
        return finish(run, "contained")

    @app.post("/reset")
    async def reset():
        """Make the demo repeatable: resume suspended demo agents and restore the original KYC server."""
        w = get_world()
        done = []
        if state["kyc_variant"] != "v1":
            await w.swap_mcp_server("kyc", kyc("v1"))
            state["kyc_variant"] = "v1"
            await w.api("priya.raman", "POST", "/v1/mcp/servers/kyc/import")
            for tool in (await w.api("mark.jansen", "GET", "/v1/tools?server=kyc")).json():
                if tool["status"] == "quarantined":
                    await w.api("fatima.elamrani", "POST", f"/v1/tools/{tool['id']}/approve")
                    done.append(f"re-approved {tool['id']}")
        for key, agent_id in w.agent_ids.items():
            if await agent_status(w, key) == "suspended":
                await w.api("sanne.bakker", "POST", f"/v1/agents/{agent_id}/resume", json={"reason": "demo reset"})
                done.append(f"resumed {key}")
        await asyncio.sleep(0)
        return {"done": done}

    return app
