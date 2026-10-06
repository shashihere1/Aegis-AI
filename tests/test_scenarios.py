"""End-to-end demo scenes (plan §13.4) and the attack suite (plan §14.3), through the real HTTP APIs."""

import asyncio
import time

import jwt
import pytest

from aegis.sdk import AegisDenied, ApprovalRequired
from aegis_demo import mcp_servers
from aegis_demo.data import CUSTOMERS, LANDLORD_IBAN
from aegis_demo.world import BASE

JAN = "jan.devries"


def rules(alerts: list[dict]) -> set[str]:
    return {a["rule_id"] for a in alerts}


async def test_s1_onboarding_enforces_segregation_of_duties(world):
    world.ctx.idp.add_persona(type(world.ctx.idp.personas["admin"])(
        "olaf.dekker", "Olaf Dekker", ["agent-developer", "risk-approver"]))
    body = {"name": "Mortgage-Advice-Agent", "purpose": "Answer mortgage questions for customers.",
            "intent_categories": ["customer.inquiry.read"], "owner": "niels.vandijk", "sponsor": "retail.ops.head",
            "capabilities": ["core-banking.get_balance"]}
    agent = (await world.api("olaf.dekker", "POST", "/v1/agents", json=body)).json()
    assert agent["status"] == "draft" and agent["risk_tier"] in {"low", "medium", "high", "critical"}
    await world.api("olaf.dekker", "POST", f"/v1/agents/{agent['id']}/submit")

    own = await world.api("olaf.dekker", "POST", f"/v1/agents/{agent['id']}/approve", json={})
    assert own.status_code == 403 and "SOD-001" in own.text

    approved = (await world.api("sanne.bakker", "POST", f"/v1/agents/{agent['id']}/approve", json={})).json()
    assert approved["agent"]["status"] == "active"
    assert approved["credentials"]["private_key_pem"].startswith("-----BEGIN PRIVATE KEY")
    passport = (await world.api("eva.visser", "GET", f"/v1/agents/{agent['id']}/passport")).json()
    assert jwt.decode(passport["jws"], options={"verify_signature": False})["passport"]["id"] == agent["id"]


async def test_s2_governed_journey_with_delegation_and_redaction(world):
    result = await world.ava.change_address(world.token(JAN), "C-1001", "D-77", "Keizersgracht 401, Amsterdam")
    task = result["task"]
    assert set(task.claims["authorization_details"][0]["intent_categories"]) == {
        "customer.kyc.verify", "customer.profile.update"}
    assert task.claims["sub"] == f"user:{JAN}" and task.claims["exp"] - task.claims["iat"] <= 900

    verification = result["verification"]["artifacts"][0]["parts"][0]["data"]
    assert verification["verified"] is True
    assert verification["bsn"] == "<BSN>" and verification["iban"] == "<IBAN_CODE>"
    assert CUSTOMERS["C-1001"]["bsn"] not in str(result["verification"])

    kyc_claims = world.kyc_app.state.last_task.claims
    assert kyc_claims["act"] == {"sub": f"agent:{world.agent_ids['kyc-agent']}",
                                 "act": {"sub": f"agent:{world.agent_ids['ava']}"}}
    assert kyc_claims["aegis"]["chain"] == [world.agent_ids["ava"], world.agent_ids["kyc-agent"]]
    assert kyc_claims["authorization_details"][0]["intent_categories"] == ["customer.kyc.verify"]  # attenuated

    graph = (await world.api("mark.jansen", "GET", f"/v1/lineage/{task.root_id}")).json()
    kinds = {(e["kind"], e.get("decision")) for e in graph["edges"]}
    assert ("initiated", None) in kinds and ("delegated_to", None) in kinds and ("invoked", "allow") in kinds
    assert any(n["id"] == "data:confidential" for n in graph["nodes"])


async def test_s3_high_value_transfer_needs_an_approval_bound_to_the_exact_action(world):
    flow = await world.ava.transfer(world.token(JAN), "C-1001", 25000, LANDLORD_IBAN, True)
    pending = flow["response"]["artifacts"][0]["parts"][0]["data"]
    assert flow["response"]["status"]["state"] == "auth-required"
    approval_id = pending["approval_id"]
    assert pending["reasons"][0]["rule"] == "PAY-010" and not mcp_servers.TRANSFERS

    inbox = (await world.api("sanne.bakker", "GET", "/v1/approvals")).json()
    card = next(a for a in inbox if a["id"] == approval_id)
    assert card["arguments"]["amount"] == 25000 and card["subject"] == f"user:{JAN}" and len(card["chain"]) == 2
    assert (await world.api(JAN, "POST", f"/v1/approvals/{approval_id}/approve", json={})).status_code == 403
    await world.api("sanne.bakker", "POST", f"/v1/approvals/{approval_id}/approve", json={"justification": "rent"})

    task, args = world.payments_app.state.pending[approval_id]
    with pytest.raises(AegisDenied) as tampered:  # A11: reuse the approval for a different amount
        await task.call_tool("payments", "initiate_transfer", {**args, "amount": 45000}, approval_id=approval_id)
    assert "APR-001" in tampered.value.rules

    done = await world.ava.resume_transfer(flow["task"], approval_id)
    assert done["status"]["state"] == "completed" and mcp_servers.TRANSFERS[0]["amount"] == 25000

    history = (await world.api("eva.visser", "GET", "/v1/approvals?status=consumed")).json()
    assert [a["id"] for a in history] == [approval_id]  # single use
    with pytest.raises(AegisDenied, match="revoked"):  # the task was closed, so its mandates are gone
        await task.call_tool("payments", "initiate_transfer", args, approval_id=approval_id)


async def test_approval_is_single_use(world):
    flow = await world.ava.transfer(world.token(JAN), "C-1001", 25000, LANDLORD_IBAN, True)
    approval_id = flow["response"]["artifacts"][0]["parts"][0]["data"]["approval_id"]
    await world.api("sanne.bakker", "POST", f"/v1/approvals/{approval_id}/approve", json={})
    task, args = world.payments_app.state.pending[approval_id]
    await task.call_tool("payments", "initiate_transfer", args, approval_id=approval_id)
    with pytest.raises(ApprovalRequired):
        await task.call_tool("payments", "initiate_transfer", args, approval_id=approval_id)


async def test_small_transfer_needs_no_approval(world):
    flow = await world.ava.transfer(world.token(JAN), "C-1001", 50, LANDLORD_IBAN, True)
    assert flow["response"]["status"]["state"] == "completed"


async def test_s4_injection_is_contained_suspended_and_cascade_revoked(world):
    start = time.perf_counter()
    result = await world.ava.process_uploaded_document(world.token(JAN), "C-1001", "D-99")
    email = next(s for s in result["steps"] if s["step"] == "send_email")
    assert email["ok"] is False and "IFC-001" in email["denied"]
    assert mcp_servers.SENT_EMAILS == []

    alerts = (await world.api("mark.jansen", "GET", "/v1/alerts")).json()
    assert {"DET-01", "DET-02"} <= rules(alerts)
    det02 = next(a for a in alerts if a["rule_id"] == "DET-02")
    assert det02["actions_taken"][0]["action"] == "suspend_agent"
    radius = det02["actions_taken"][0]["blast_radius"]
    assert world.agent_ids["kyc-agent"] in radius["agents_affected"] and len(radius["mandates"]) == 2
    assert time.perf_counter() - start < 5

    ava = (await world.api("mark.jansen", "GET", f"/v1/agents/{world.agent_ids['ava']}")).json()
    assert ava["status"] == "suspended"
    with pytest.raises(AegisDenied, match="revoked"):  # KYC's delegated mandate died in the cascade
        await world.kyc_app.state.last_task.call_tool("kyc", "get_kyc_status", {"customer_id": "C-1001"})
    with pytest.raises(AegisDenied):  # Ava's identity is disabled at the IdP
        await world.sdks["ava"].start_task("Verify identity document", world.token(JAN))
    kyc = (await world.api("mark.jansen", "GET", f"/v1/agents/{world.agent_ids['kyc-agent']}")).json()
    assert kyc["status"] == "active"  # the innocent delegate keeps working

    assert (await world.api("eva.visser", "GET", "/v1/ledger/verify")).json()["ok"] is True


async def test_a6_unauthorised_tools_are_invisible_and_uncallable(world):
    task = await world.sdks["ava"].start_task("Verify identity document for address change", world.token(JAN))
    visible = {t["name"] for t in await task.list_tools("notify")}
    assert visible == {"send_app_message"}  # send_email exists upstream but is outside this purpose
    with pytest.raises(AegisDenied) as denied:
        await task.call_tool("notify", "send_email", {"to": "a@b.example", "subject": "x", "body": "y"})
    assert {"SCP-001", "PUR-001"} <= set(denied.value.rules)


async def test_a10_mandate_cannot_be_used_at_another_resource(world):
    task = await world.sdks["ava"].start_task("Verify identity document for address change", world.token(JAN))
    with pytest.raises(AegisDenied, match="audience"):
        await task.call_tool("payments", "initiate_transfer", {})


async def test_a7_a8_delegation_cannot_widen_or_skip_the_registry(world):
    task = await world.sdks["ava"].start_task("Verify identity document for address change", world.token(JAN))
    with pytest.raises(AegisDenied) as not_delegated:
        await world.sdks["payments-agent"].accept_delegation(task.token)
    assert "DLG-001" in not_delegated.value.rules
    with pytest.raises(AegisDenied) as widened:
        await world.sdks["kyc-agent"].accept_delegation(task.token, intent_categories=["payments.transfer.initiate"])
    assert "DLG-004" in widened.value.rules


async def test_a16_expired_mandate_is_rejected(world):
    agent = world.sdks["ava"]
    response = await agent.http.post(f"{BASE}/sts/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "actor_token": await agent.identity_token(), "subject_token": world.token(JAN), "requested_ttl": 1,
        "authorization_details": '[{"type": "aegis_mandate", "intent": "Verify identity document"}]'})
    from aegis.sdk import Task
    task = Task(agent, response.json()["access_token"])
    await asyncio.sleep(1.2)
    with pytest.raises(AegisDenied, match="expired"):
        await task.list_tools("kyc")


async def test_a17_agent_cannot_exceed_the_user_it_acts_for(world):
    persona = type(world.ctx.idp.personas[JAN])
    world.ctx.idp.add_persona(persona("lisa.bos", "Lisa Bos", ["customer"], ["own_accounts.read"]))
    flow = await world.ava.transfer(world.token("lisa.bos"), "C-1002", 50, LANDLORD_IBAN, True)
    assert flow["response"]["status"]["state"] == "failed"  # payments tool not granted without the entitlement
    assert not mcp_servers.TRANSFERS


async def test_rate_limit_obligation(world):
    states = [(await world.ava.transfer(world.token(JAN), "C-1001", 10, LANDLORD_IBAN, False))["response"]
              ["status"]["state"] for _ in range(6)]
    assert states == ["completed"] * 5 + ["failed"]
    limited = (await world.api("mark.jansen", "GET", "/v1/decisions?decision=rate_limited")).json()
    assert len(limited) == 1


async def test_a4_rug_pull_quarantines_the_tool(world):
    from aegis_demo.mcp_servers import kyc
    await world.swap_mcp_server("kyc", kyc("v2"))
    result = await world.ava.change_address(world.token(JAN), "C-1001", "D-77", "Keizersgracht 401, Amsterdam")
    assert result["verification"]["status"]["state"] == "failed"
    tools = {t["id"]: t for t in (await world.api("mark.jansen", "GET", "/v1/tools?server=kyc")).json()}
    assert tools["kyc.verify_document"]["status"] == "quarantined"
    assert "DET-03" in rules((await world.api("mark.jansen", "GET", "/v1/alerts")).json())


async def test_a3_poisoned_tool_cannot_be_approved_without_override(world):
    tools = {t["id"]: t for t in (await world.api("mark.jansen", "GET", "/v1/tools?server=fx-rates")).json()}
    assert tools["fx-rates.get_rate"]["poisoning_findings"]
    refused = await world.api("fatima.elamrani", "POST", "/v1/tools/fx-rates.get_rate/approve")
    assert refused.status_code == 409


async def test_a12_shadow_agent_is_discovered_and_quarantined(world):
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "get_customer", "arguments": {"customer_id": "C-1001"}}}
    headers = {"x-api-key": "static-key-from-a-wiki-page", "user-agent": "marketing-lead-scraper/0.3"}
    first = await world.http.post(f"{BASE}/gw/mcp/crm", json=call, headers=headers)
    assert first.status_code == 401 and "resource_metadata" in first.headers["www-authenticate"]

    world.ctx.idp.register_unmanaged_client("marketing-lead-scraper", "Marketing lead scraper")
    await world.api("mark.jansen", "POST", "/v1/discovery/scan")
    findings = (await world.api("mark.jansen", "GET", "/v1/discovery/findings")).json()
    assert {f["sources"][0] for f in findings} == {"gateway", "idp"}
    assert "DET-07" in rules((await world.api("mark.jansen", "GET", "/v1/alerts")).json())

    gateway_finding = next(f for f in findings if f["sources"] == ["gateway"])
    await world.api("mark.jansen", "POST", f"/v1/discovery/findings/{gateway_finding['id']}/quarantine")
    assert (await world.http.post(f"{BASE}/gw/mcp/crm", json=call, headers=headers)).status_code == 403

    idp_finding = next(f for f in findings if f["sources"] == ["idp"])
    claim = await world.api("niels.vandijk", "POST", f"/v1/discovery/findings/{idp_finding['id']}/claim", json={
        "name": "Marketing-Lead-Scraper", "purpose": "Draft marketing campaigns from CRM leads.",
        "intent_categories": ["marketing.campaign.draft"], "owner": "niels.vandijk", "sponsor": "marketing.head"})
    assert claim.status_code == 201
    claimed = (await world.api("niels.vandijk", "GET", f"/v1/agents/{claim.json()['agent_id']}")).json()
    assert claimed["status"] == "draft"


async def test_material_change_requires_reapproval_and_revokes_mandates(world):
    task = await world.sdks["ava"].start_task("Verify identity document for address change", world.token(JAN))
    ava = world.agent_ids["ava"]
    patched = await world.api("priya.raman", "PATCH", f"/v1/agents/{ava}",
                              json={"capabilities": ["docs.read_document"]})
    assert patched.json()["status"] == "pending_approval"
    with pytest.raises(AegisDenied, match="revoked"):
        await task.list_tools("docs")


async def test_leaver_orphans_agents(world):
    await world.api("admin", "POST", "/v1/idp-events/leaver", json={"username": "niels.vandijk"})
    agents = (await world.api("mark.jansen", "GET", "/v1/agents")).json()["items"]
    assert all(a["orphaned"] for a in agents if a["owner"] == "niels.vandijk")
    assert "DET-12" in rules((await world.api("mark.jansen", "GET", "/v1/alerts")).json())


async def test_llm_proxy_records_tokens_and_cost(world):
    task = await world.sdks["ava"].start_task("Verify identity document for address change", world.token(JAN))
    reply = await task.chat([{"role": "user", "content": "Summarise the customer's request in one line."}])
    assert reply["choices"][0]["message"]["content"]
    usage = (await world.api("mark.jansen", "GET", "/v1/usage")).json()
    assert usage[0]["agent_id"] == world.agent_ids["ava"] and usage[0]["input_tokens"] > 0
    assert usage[0]["cost_eur"] > 0


async def test_every_decision_is_evidence(world):
    await world.ava.change_address(world.token(JAN), "C-1001", "D-77", "Keizersgracht 401, Amsterdam")
    entries = (await world.api("eva.visser", "GET", "/v1/ledger?limit=500")).json()
    types = {e["event_type"] for e in entries}
    assert {"agent.active", "identity.provisioned", "mandate.issued", "decision.allow", "tool.approved"} <= types
    assert (await world.api("eva.visser", "GET", "/v1/ledger/verify")).json()["ok"] is True
