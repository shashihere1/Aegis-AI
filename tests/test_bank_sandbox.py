"""Real banking persistence/security checks; no Azure calls or external identity provisioning."""

import asyncio
import json
import os
import re
import uuid
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import func, select, text

from aegis.common.banking import upstream_headers
from aegis.common.settings import Settings
from aegis.control import ledger
from aegis.control.bank_tables import (
    BankAccount,
    BankDocument,
    BankEntry,
    BankOperation,
    BankPayment,
    RegistrySeedArchive,
)
from aegis.control.db import Database
from aegis.control.tables import Agent
from aegis.sdk import AegisDenied, ApprovalRequired, Task
from aegis_demo.agents import structured
from aegis_demo.bank import Bank, Execution, money
from aegis_demo.data import LANDLORD_IBAN
from aegis_demo.registry_cleanup import cleanup, restore
from aegis_demo.world import BASE, FAKE_LLM_URL, running_world, seed_registry

ACTOR = Execution("user:jan.devries", "mdt_sandbox_test", "mdt_sandbox_child", "AGT-TEST")


@pytest.fixture(params=["sqlite", "postgresql"])
async def bank(request, tmp_path):
    dialect = request.param
    admin = None
    schema = ""
    if dialect == "postgresql":
        if os.getenv("AEGIS_TEST_POSTGRES") != "1":
            pytest.skip("Opt-in isolated local PostgreSQL tests")
        url = Settings.from_env().database_url
        assert url.startswith("postgresql+asyncpg://")
        schema = "aegis_bank_test_" + uuid.uuid4().hex
        assert re.fullmatch(r"aegis_bank_test_[a-f0-9]{32}", schema)
        admin = Database(url)
        async with admin.engine.begin() as conn:
            await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    else:
        url = f"sqlite+aiosqlite:///{tmp_path / 'bank.sqlite'}"
    db = Database(url, schema)
    try:
        await db.create_all()
        repository = Bank(db)
        await repository.seed()
        yield repository
    finally:
        await db.engine.dispose()
        if admin:
            async with admin.engine.begin() as conn:
                await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            await admin.engine.dispose()


async def counts(bank):
    async with bank.db.sessionmaker() as s:
        return tuple(
            [
                await s.scalar(select(func.count()).select_from(model))
                for model in (BankPayment, BankEntry, BankOperation)
            ]
        )


async def test_transaction_duplicate_and_restart(bank):
    args = ("C-1001", 100.25, LANDLORD_IBAN, False, "Rent", ACTOR)
    results = await asyncio.gather(*(bank.transfer(*args) for _ in range(4)))
    assert len({r["payment_id"] for r in results}) == 1
    assert sum(not r.get("replayed", False) for r in results) == 1
    assert await counts(bank) == (1, 2, 1)
    assert (await bank.balance("C-1001", ACTOR))["balance_eur"] == 48150.50
    async with bank.db.sessionmaker() as s:
        assert await s.scalar(select(func.sum(BankEntry.amount))) == Decimal("0.00")
        landlord = await s.scalar(select(BankAccount).where(BankAccount.iban == LANDLORD_IBAN))
        assert landlord.balance == Decimal("100.25")
    # A separate repository/connection pool simulates restart: seeding never resets money.
    reopened_db = Database(bank.db.engine.url.render_as_string(hide_password=False), bank.db.schema)
    reopened = Bank(reopened_db)
    try:
        await reopened.seed()
        assert (await reopened.snapshot(ACTOR.subject))["balance_eur"] == 48150.50
        assert (await reopened.transfer(*args))["payment_id"] == results[0]["payment_id"]
        with pytest.raises(ValueError, match="different arguments"):
            await reopened.transfer("C-1001", 90, LANDLORD_IBAN, False, "Rent", ACTOR)
    finally:
        if reopened_db:
            await reopened_db.engine.dispose()


async def test_concurrent_overspend_and_rollback(bank):
    actors = [Execution(ACTOR.subject, f"mdt_concurrent_{n}", ACTOR.mandate_id, ACTOR.agent_id) for n in range(2)]
    outcomes = await asyncio.gather(
        *(bank.transfer("C-1001", 30000, LANDLORD_IBAN, False, "", a) for a in actors), return_exceptions=True
    )
    assert sum(isinstance(o, dict) for o in outcomes) == 1
    assert sum(isinstance(o, ValueError) for o in outcomes) == 1
    assert (await bank.snapshot(ACTOR.subject))["balance_eur"] == 18250.75
    assert await counts(bank) == (1, 2, 1)
    with pytest.raises(ValueError, match="existing synthetic"):
        await bank.transfer("C-1001", 100, "NL00UNKN0000000000", False, "", ACTOR)
    assert await counts(bank) == (1, 2, 1)


async def test_ownership_and_same_task_document_requirement(bank):
    with pytest.raises(ValueError, match="owned"):
        await bank.balance("C-1002", ACTOR)
    with pytest.raises(ValueError, match="same task"):
        await bank.update_address("C-1001", "New synthetic address", ACTOR)
    assert not (await bank.verify("C-1001", "D-99", ACTOR))["verified"]
    actor = Execution(ACTOR.subject, "mdt_valid_document", ACTOR.mandate_id, ACTOR.agent_id)
    receipt = await bank.verify("C-1001", "D-77", actor)
    assert receipt["verified"] and receipt["verification_kind"] == "synthetic-record-check"
    await bank.update_address("C-1001", "New synthetic address", actor)
    await bank.seed()
    assert (await bank.snapshot(ACTOR.subject))["address"] == "New synthetic address"
    async with bank.db.sessionmaker() as s, s.begin():
        doc = await s.get(BankDocument, "D-77")
        from datetime import date

        doc.expires_on = date(2000, 1, 1)
    expired = Execution(ACTOR.subject, "mdt_expired", ACTOR.mandate_id, ACTOR.agent_id)
    assert not (await bank.verify("C-1001", "D-77", expired))["verified"]


async def test_audit_failure_rolls_back_money_payment_entries_and_idempotency(bank, monkeypatch):
    async def failed_append(*args, **kwargs):
        raise RuntimeError("Injected offline audit failure")

    with monkeypatch.context() as patch:
        patch.setattr(ledger, "append", failed_append)
        with pytest.raises(RuntimeError, match="audit failure"):
            await bank.transfer("C-1001", 100, LANDLORD_IBAN, False, "", ACTOR)
    assert await counts(bank) == (0, 0, 0)
    assert (await bank.snapshot(ACTOR.subject))["balance_eur"] == 48250.75
    receipt = await bank.transfer("C-1001", 100, LANDLORD_IBAN, False, "", ACTOR)
    assert receipt["balance_after_eur"] == 48150.75


@pytest.mark.parametrize("amount", [True, 0, -1, float("nan"), float("inf"), 1.001, 1000000000])
def test_invalid_money(amount):
    with pytest.raises(ValueError):
        money(amount)


def test_broker_credential_not_sent_to_registry_redirects():
    settings = Settings(bank_sandbox_enabled=True, control_url=BASE)
    expected = f"{BASE}/demo/mcp/payments/mcp"
    assert upstream_headers(
        settings,
        "payments",
        expected,
        {"aegis": {"root_id": "r", "mandate_id": "m"}, "sub": ACTOR.subject, "azp": ACTOR.agent_id},
    )
    for url in (expected + "/", expected + "?redirect=1", "https://attacker.example/mcp"):
        assert not upstream_headers(settings, "payments", url, {})


async def test_normal_world_no_scripted_routes_and_gateway_receipts():
    async with running_world() as w:
        assert w.ava is None and len(w.agent_ids) == 4
        assert set(w.mounts) == {"core-banking", "payments", "kyc", "docs", "crm", "aegis-investigate"}
        for path in ("/demo/api/scenarios/transfer", "/demo/fake-llm/v1/chat/completions"):
            assert (await w.http.post(BASE + path, json={})).status_code == 404
        direct = await w.http.post(
            f"{BASE}/demo/mcp/payments/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "initiate_transfer", "arguments": {}},
            },
        )
        assert direct.status_code == 403
        assert (await w.api("jan.devries", "GET", "/demo/api/bank/account")).status_code == 200
        assert (await w.api("priya.raman", "GET", "/demo/api/bank/account")).status_code == 403
        task = await w.sdks["ava"].start_task(
            "Read own balance",
            w.token("jan.devries"),
            intent_categories=["customer.inquiry.read"],
            tools=["core-banking.get_balance"],
        )
        result = structured(await task.call_tool("core-banking", "get_balance", {"customer_id": "C-1001"}))
        assert result["balance_eur"] == 48250.75
        await task.complete()


async def test_gateway_approval_does_not_move_funds_until_execution():
    async with running_world() as w:
        task = await w.sdks["payments-agent"].start_task(
            "Pay synthetic rent",
            w.token("jan.devries"),
            intent_categories=["payments.transfer.initiate"],
            tools=["payments.initiate_transfer"],
        )
        args = {
            "customer_id": "C-1001",
            "amount": 25000,
            "creditor_iban": LANDLORD_IBAN,
            "new_beneficiary": True,
            "reference": "Rent",
        }
        with pytest.raises(ApprovalRequired) as needed:
            await task.call_tool("payments", "initiate_transfer", args)
        aid = needed.value.approval_id
        assert await counts(w.bank) == (0, 0, 0)
        assert (await w.api("jan.devries", "POST", f"/v1/approvals/{aid}/approve", json={})).status_code == 403
        assert (
            await w.api(
                "sanne.bakker",
                "POST",
                f"/v1/approvals/{aid}/approve",
                json={"justification": "Authorized synthetic rent"},
            )
        ).status_code == 200
        assert await counts(w.bank) == (0, 0, 0)
        receipt = structured(await task.call_tool("payments", "initiate_transfer", args, approval_id=aid))
        assert receipt["status"] == "accepted" and receipt["balance_after_eur"] == 23250.75
        assert await counts(w.bank) == (1, 2, 1)
        with pytest.raises((AegisDenied, ApprovalRequired)):
            await task.call_tool("payments", "initiate_transfer", args, approval_id=aid)
        assert await counts(w.bank) == (1, 2, 1)
        await task.complete()


async def test_targeted_registry_cleanup_preserves_agents_and_history():
    async with running_world() as w:
        await seed_registry(w, 5)
        preview = await cleanup(w.ctx.db)
        assert preview["eligible"] == 5 and preview["removed"] == 0
        result = await cleanup(w.ctx.db, apply=True)
        assert result["removed"] == 5
        async with w.ctx.db.sessionmaker() as s:
            assert await s.scalar(select(func.count()).select_from(Agent)) == 4
            assert await s.scalar(select(func.count()).select_from(RegistrySeedArchive)) == 5
        assert (await restore(w.ctx.db, result["batch_id"]))["restored"] == 5
        assert (await restore(w.ctx.db, result["batch_id"]))["restored"] == 0


async def test_ui_api_langgraph_maf_confirmation_and_durable_address(monkeypatch, bank):
    pytest.importorskip("langgraph")
    pytest.importorskip("agent_framework")
    delegations = []
    delegate = Task.delegate

    async def observe(task, *args, **kwargs):
        response = await delegate(task, *args, **kwargs)
        delegations.append(response)
        return response

    monkeypatch.setattr(Task, "delegate", observe)
    config = dict(
        database_url=bank.db.engine.url.render_as_string(hide_password=False),
        database_schema=bank.db.schema,
        azure_openai_endpoint="https://offline-test.openai.azure.com",
        azure_openai_api_key="offline-test-key",
        azure_openai_deployment="offline-test",
        llm_processing_scope="global",
        llm_allowed_processing_scope="global",
    )
    async with running_world(**config) as w:
        azure = w.gateway.state.azure_upstream
        await azure.http.aclose()
        selections = iter(
            [
                ("verify_document", {"document_id": "D-77"}),
                ("update_address", {"new_address": "A persistent synthetic address"}),
            ]
        )

        def offline_response(request):
            name, arguments = next(selections)
            return httpx.Response(
                200,
                json={
                    "id": "offline-completion",
                    "model": "offline-test",
                    "choices": [
                        {
                            "finish_reason": "tool_calls",
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "offline-call",
                                        "type": "function",
                                        "function": {"name": name, "arguments": json.dumps(arguments)},
                                    }
                                ],
                            },
                        }
                    ],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 20},
                },
            )

        azure.http = httpx.AsyncClient(transport=httpx.MockTransport(offline_response))

        async def wait(run_id):
            for _ in range(200):
                run = (await w.api("jan.devries", "GET", f"/demo/api/agent/runs/{run_id}")).json()
                if run["status"] != "running":
                    return run
                await asyncio.sleep(0.01)
            pytest.fail("Offline UI workflow did not finish")

        response = await w.api(
            "jan.devries",
            "POST",
            "/demo/api/agent/runs",
            json={
                "request_id": str(uuid.uuid4()),
                "mode": "address",
                "message": "Verify D-77 and change my synthetic address",
                "confirm_synthetic_external_call": True,
            },
        )
        assert response.status_code == 202, response.text
        run_id = response.json()["id"]
        run = await wait(run_id)
        assert run["status"] == "confirmation_required", run["reply"] + json.dumps(delegations)
        assert (await w.bank.snapshot(ACTOR.subject))["address"] != "A persistent synthetic address"
        assert any(e.get("runtime") == "microsoft-agent-framework" for e in run["events"])
        confirmed = await w.api(
            "jan.devries", "POST", f"/demo/api/agent/runs/{run_id}/continue", json={"action": "confirm"}
        )
        assert confirmed.status_code == 202, confirmed.text
        result = await wait(run_id)
        assert result["status"] == "completed", result
        assert (await w.bank.snapshot(ACTOR.subject))["address"] == "A persistent synthetic address"
        assert await counts(w.bank) == (0, 0, 2)


@pytest.mark.parametrize("model_behavior", ["proposal", "text_only", "missing_details", "mismatched_receipt"])
async def test_ui_transfer_review_then_2000_policy_approval_or_safe_no_action(bank, model_behavior, monkeypatch):
    """Exercise UI HTTP -> LangGraph -> gateway -> durable bank with only offline model responses."""
    pytest.importorskip("langgraph")
    requests = []
    args = {"amount": 5000.0, "creditor_iban": LANDLORD_IBAN, "new_beneficiary": True, "reference": "Rent"}
    selections = iter(
        [
            ("get_balance", {}),
            ("initiate_transfer", args)
            if model_behavior in ("proposal", "mismatched_receipt")
            else (None, "Please confirm you want to proceed with the transfer.")
            if model_behavior == "text_only"
            else ("explain_without_action", {"reason": "missing_details", "message": "Please specify an amount."}),
        ]
    )

    def offline_response(request):
        body = json.loads(request.content)
        requests.append(body)
        assert body["tool_choice"] == "required" and body["parallel_tool_calls"] is False
        name, arguments = next(selections)
        message = {"role": "assistant", "content": None if name else arguments}
        if name:
            message["tool_calls"] = [
                {
                    "id": "offline-call",
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(arguments)},
                }
            ]
        return httpx.Response(
            200,
            json={
                "id": "offline-completion",
                "model": "offline-test",
                "choices": [{"finish_reason": "tool_calls" if name else "stop", "message": message}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async with running_world(
        database_url=bank.db.engine.url.render_as_string(hide_password=False),
        database_schema=bank.db.schema,
        azure_openai_endpoint="https://offline-test.openai.azure.com",
        azure_openai_api_key="offline-test-key",
        azure_openai_deployment="offline-test",
        llm_processing_scope="global",
        llm_allowed_processing_scope="global",
    ) as w:
        azure = w.gateway.state.azure_upstream
        await azure.http.aclose()
        azure.http = httpx.AsyncClient(transport=httpx.MockTransport(offline_response))
        if model_behavior == "mismatched_receipt":
            transfer = w.bank.transfer

            async def incorrect_receipt(*args, **kwargs):
                result = await transfer(*args, **kwargs)
                return {**result, "verification_hash": "offline-corrupted-receipt"}

            monkeypatch.setattr(w.bank, "transfer", incorrect_receipt)

        # Use the same author/independent-approver activation path as the UI, in this isolated test database.
        original = (await w.api("mark.jansen", "GET", "/v1/policies/versions")).json()["active_version"]
        configuration = (await w.api("mark.jansen", "GET", "/v1/policies")).json()["data"]
        configuration["thresholds"]["payments"]["hitl_amount_eur"] = 2000
        draft = await w.api(
            "priya.raman",
            "POST",
            "/v1/policies/versions",
            json={
                "name": "Offline transfer approval",
                "configuration": configuration,
                "justification": "Test EUR 2000",
            },
        )
        assert draft.status_code == 201, draft.text
        version_id = draft.json()["id"]
        for action in ("replay", "submit", "approve", "activate"):
            body = (
                {}
                if action == "replay"
                else None
                if action == "submit"
                else {
                    "justification": "Independently reviewed for offline testing",
                    **({"expected_active_version": original} if action == "activate" else {}),
                }
            )
            who = "priya.raman" if action in ("replay", "submit") else "fatima.elamrani"
            result = await w.api(who, "POST", f"/v1/policies/{version_id}/{action}", json=body)
            assert result.status_code == 200, result.text

        async def wait(run_id):
            for _ in range(300):
                run = (await w.api("jan.devries", "GET", f"/demo/api/agent/runs/{run_id}")).json()
                if run["status"] != "running":
                    return run
                await asyncio.sleep(0.01)
            pytest.fail("Offline transfer workflow did not pause/finish")

        started = await w.api(
            "jan.devries",
            "POST",
            "/demo/api/agent/runs",
            json={
                "request_id": str(uuid.uuid4()),
                "mode": "transfer",
                "message": "Transfer EUR 5,000 to the demo landlord as a new beneficiary, reference Rent."
                if model_behavior != "missing_details"
                else "Transfer to the demo landlord, but I have not chosen an amount.",
                "confirm_synthetic_external_call": True,
            },
        )
        assert started.status_code == 202, started.text
        run_id = started.json()["id"]
        run = await wait(run_id)
        assert len(requests) == 2 and await counts(w.bank) == (0, 0, 0)
        assert (await w.bank.snapshot(ACTOR.subject))["balance_eur"] == 48250.75

        if model_behavior not in ("proposal", "mismatched_receipt"):
            assert run["status"] == "not_executed" and run["resumable"] is False, run
            assert not run["pending"].get("name") and not run["pending"].get("approval_id")
            refused = await w.api(
                "jan.devries", "POST", f"/demo/api/agent/runs/{run_id}/continue", json={"action": "confirm"}
            )
            assert refused.status_code == 409
            assert await counts(w.bank) == (0, 0, 0)
            return

        assert run["status"] == "confirmation_required" and run["resumable"] is True, run
        assert run["pending"]["name"] == "initiate_transfer" and run["pending"]["arguments"] == args
        confirmed = await w.api(
            "jan.devries", "POST", f"/demo/api/agent/runs/{run_id}/continue", json={"action": "confirm"}
        )
        assert confirmed.status_code == 202, confirmed.text
        run = await wait(run_id)
        assert run["status"] == "approval_required", run
        assert await counts(w.bank) == (0, 0, 0)  # Customer confirmation never substitutes for risk approval.
        approval_id = run["pending"]["approval_id"]
        assert any(e["kind"] == "approval" and any(r["rule"] == "PAY-010" for r in e["reasons"]) for e in run["events"])
        assert (await w.api("jan.devries", "POST", f"/v1/approvals/{approval_id}/approve", json={})).status_code == 403
        approved = await w.api(
            "sanne.bakker",
            "POST",
            f"/v1/approvals/{approval_id}/approve",
            json={
                "justification": "Approve the exact synthetic rent transfer",
            },
        )
        assert approved.status_code == 200, approved.text
        assert await counts(w.bank) == (0, 0, 0)  # Approval alone also does not execute it.
        resumed = await w.api(
            "jan.devries", "POST", f"/demo/api/agent/runs/{run_id}/continue", json={"action": "resume_approval"}
        )
        assert resumed.status_code == 202, resumed.text
        run = await wait(run_id)
        if model_behavior == "mismatched_receipt":
            assert run["status"] == "uncertain" and not run["resumable"], run
            assert (await w.bank.snapshot(ACTOR.subject))["balance_eur"] == 43250.75
            assert await counts(w.bank) == (1, 2, 1) and len(requests) == 2
            refused = await w.api(
                "jan.devries", "POST", f"/demo/api/agent/runs/{run_id}/continue", json={"action": "confirm"}
            )
            assert refused.status_code == 409 and await counts(w.bank) == (1, 2, 1)
            return
        assert run["status"] == "completed", json.dumps(run)
        receipts = [e["result"] for e in run["events"] if e["kind"] == "tool" and e["label"] == "initiate_transfer"]
        assert len(receipts) == 1 and receipts[0]["amount"] == 5000 and receipts[0]["payment_id"]
        assert receipts[0]["creditor_iban"] == "<IBAN_CODE>" and receipts[0]["verification_hash"]
        assert (await w.bank.snapshot(ACTOR.subject))["balance_eur"] == 43250.75
        assert await counts(w.bank) == (1, 2, 1) and len(requests) == 2


async def test_upgrade_quarantines_changed_tools_without_silent_reapproval(tmp_path):
    options = {
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'upgrade.sqlite'}",
        "identity_state_dir": str(tmp_path / "identities"),
    }
    async with running_world(offline_fixtures=True, llm_upstream_url=FAKE_LLM_URL, **options):
        pass
    async with running_world(**options) as w:
        status = (await w.api("jan.devries", "GET", "/demo/api/agent/status")).json()
        assert set(status["bank_tools_requiring_review"]) == {
            "payments.initiate_transfer",
            "kyc.verify_document",
            "kyc.get_kyc_status",
        }
        servers = (await w.api("priya.raman", "GET", "/v1/mcp/servers")).json()
        assert all(server["status"] == "retired" for server in servers if server["id"] in {"notify", "fx-rates"})
        assert (await w.api("priya.raman", "POST", "/v1/tools/kyc.verify_document/approve")).status_code == 403
        for tool in status["bank_tools_requiring_review"]:
            approved = await w.api("fatima.elamrani", "POST", f"/v1/tools/{tool}/approve")
            assert approved.status_code == 200, approved.text
        assert not (await w.api("jan.devries", "GET", "/demo/api/agent/status")).json()["bank_tools_requiring_review"]


async def test_normal_bank_detects_injection_and_blocks_unverified_or_revoked_calls():
    async with running_world() as w:
        task = await w.sdks["ava"].start_task(
            "Read a synthetic rental contract",
            w.token("jan.devries"),
            intent_categories=["customer.kyc.verify", "customer.profile.update"],
            tools=["docs.read_document", "crm.update_address"],
        )
        await task.call_tool("docs", "read_document", {"document_id": "D-99"})
        alerts = (await w.api("mark.jansen", "GET", "/v1/alerts")).json()
        assert any(alert["rule_id"] == "DET-01" for alert in alerts)
        result = await task.call_tool(
            "crm", "update_address", {"customer_id": "C-1001", "new_address": "Unsafe request"}
        )
        assert result.get("isError")  # Internal tainted calls are not all forbidden; the bank requires same-task KYC.
        assert await counts(w.bank) == (0, 0, 0)
        await task.complete()
        with pytest.raises(AegisDenied):
            await task.call_tool("docs", "read_document", {"document_id": "D-77"})
