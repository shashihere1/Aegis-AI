"""Connected judge journey using real local enforcement/banking and offline Azure HTTP fixtures.

No live Azure request, corporate DB write or external identity provisioning is made.
"""

import asyncio
import json
import re
import time
import uuid
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import func, select

from aegis.control.bank_tables import BankPayment
from aegis.control.identity.idp import Persona
from aegis.control.tables import Agent, Alert, Approval, DecisionRecord, Mandate
from aegis.sdk import AegisDenied
from aegis_demo.bank import Bank
from aegis_demo.data import LANDLORD_IBAN
from aegis_demo.world import running_world

pytest.importorskip("langgraph")
pytest.importorskip("agent_framework")


@pytest.fixture
async def journey(tmp_path):
    ready = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()
    model_started = asyncio.Event()
    block_model = asyncio.Event()
    requests = []

    async def offline_response(request):
        body = json.loads(request.content)
        requests.append(body)
        messages = body["messages"]
        prompt = next(m["content"] for m in messages if m["role"] == "user")
        if "Hold this inquiry" in prompt:
            model_started.set()
            await block_model.wait()
        has_balance = any(m["role"] == "tool" for m in messages)
        if not has_balance:
            name, arguments = "get_balance", {}
        elif "Transfer EUR" in prompt:
            name = "initiate_transfer"
            arguments = {
                "amount": 5000.0,
                "creditor_iban": LANDLORD_IBAN,
                "new_beneficiary": True,
                "reference": re.search(r"reference ([A-Za-z0-9-]+)", prompt).group(1),
            }
        else:
            name, arguments = None, None
        message = {"role": "assistant", "content": None if name else "Verified synthetic account inquiry."}
        if name:
            message["tool_calls"] = [
                {
                    "id": "offline-selection",
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(arguments)},
                }
            ]
        return httpx.Response(
            200,
            json={
                "id": "offline-completion",
                "model": "offline-test",
                "choices": [{"message": message, "finish_reason": "tool_calls" if name else "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )

    async def owner():
        async with running_world(
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'journey.sqlite'}",
            identity_state_dir=str(tmp_path / "identity"),
            azure_openai_endpoint="https://offline-test.openai.azure.com",
            azure_openai_api_key="offline-test-key",
            azure_openai_deployment="offline-test",
            llm_processing_scope="global",
            llm_allowed_processing_scope="global",
        ) as w:
            await w.gateway.state.azure_upstream.http.aclose()
            w.gateway.state.azure_upstream.http = httpx.AsyncClient(transport=httpx.MockTransport(offline_response))
            original = ok(await w.api("mark.jansen", "GET", "/v1/policies/versions"))["active_version"]
            configuration = ok(await w.api("mark.jansen", "GET", "/v1/policies"))["data"]
            configuration["thresholds"]["payments"]["hitl_amount_eur"] = 2000
            version = ok(
                await w.api(
                    "priya.raman",
                    "POST",
                    "/v1/policies/versions",
                    json={
                        "name": "Isolated walkthrough test policy",
                        "configuration": configuration,
                        "justification": "Test independent approval at EUR 2000",
                    },
                )
            )["id"]
            for action in ("replay", "submit", "approve", "activate"):
                payload = (
                    {}
                    if action == "replay"
                    else None
                    if action == "submit"
                    else {
                        "justification": "Independently reviewed in disposable test database",
                        **({"expected_active_version": original} if action == "activate" else {}),
                    }
                )
                who = "priya.raman" if action in {"replay", "submit"} else "fatima.elamrani"
                ok(await w.api(who, "POST", f"/v1/policies/{version}/{action}", json=payload))
            w.model_requests, w.model_started = requests, model_started
            ready.set_result(w)
            await stop.wait()

    task = asyncio.create_task(owner())
    await asyncio.wait({task, ready}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        task.result()
    try:
        yield ready.result()
    finally:
        stop.set()
        await task


def ok(response):
    assert response.status_code < 400, response.text
    return response.json()


async def register_pair(w, prefix="Judge"):
    pair = ok(
        await w.api(
            "priya.raman",
            "POST",
            "/demo/api/walkthrough/register",
            json={"name_prefix": prefix, "owner": "niels.vandijk"},
        )
    )
    ok(
        await w.api(
            "sanne.bakker",
            "POST",
            "/demo/api/walkthrough/approve",
            json={"coordinator_id": pair["coordinator_id"], "reason": "Independent template review complete"},
        )
    )
    connected = ok(
        await w.api(
            "priya.raman", "POST", "/demo/api/walkthrough/connect", json={"coordinator_id": pair["coordinator_id"]}
        )
    )
    assert connected["connected"]
    assert "private_key" not in json.dumps(connected)
    return pair


async def submit(w, pair, mode="transfer", case="normal", message=None, request_id=None, auto_resume=True):
    request_id = request_id or str(uuid.uuid4())
    body = {
        "request_id": request_id,
        "coordinator_id": pair["coordinator_id"],
        "mode": mode,
        "walkthrough_case": case,
        "auto_resume": auto_resume,
        "confirm_synthetic_external_call": True,
        "message": message
        or f"Transfer EUR 5,000 to the demo landlord as a new beneficiary, reference Test-{request_id[:8]}.",
    }
    return body, await w.api("jan.devries", "POST", "/demo/api/agent/runs", json=body)


async def until(w, run_id, expected, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = ok(await w.api("jan.devries", "GET", f"/demo/api/agent/runs/{run_id}"))
        if row["status"] in expected:
            return row
        if row["status"] not in {"running", "confirmation_required", "approval_required"}:
            pytest.fail(f"Unexpected final state: {row}")
        await asyncio.sleep(0.03)
    pytest.fail(f"Run did not reach {expected}: {row}")


async def payment_count(w):
    async with w.ctx.db.sessionmaker() as s:
        return await s.scalar(select(func.count()).select_from(BankPayment))


async def test_bank_assistant_pair_status_challenge_proof_and_budget_denial(journey):
    from aegis.control.tables import SiemDelivery

    w = journey
    pair = await register_pair(w, "Assistant")
    w.ctx.settings.siem_enabled = True  # outbox only; no background/external receiver in this isolated fixture
    w.ctx.settings.siem_token = "offline-siembearer-" + "x" * 40
    status = ok(
        await w.api("jan.devries", "GET", "/demo/api/agent/status", params={"coordinator_id": pair["coordinator_id"]})
    )
    assert status["budget"]["daily_budget_eur"] == 1
    body, response = await submit(
        w,
        pair,
        case="delegation_widening",
        message="Test whether Payments can request payments.status.read beyond the permissions of this payment task.",
    )
    ok(response)
    denied = await until(w, body["request_id"], {"blocked"})
    assert not w.model_requests and await payment_count(w) == 0
    proof = ok(await w.api("jan.devries", "GET", f"/demo/api/agent/runs/{denied['id']}/proof"))
    assert proof["alerts"][0]["rule_id"] == "DET-15" and proof["alerts"][0]["forwarding"]["status"] == "pending"
    w.ctx.settings.llm_daily_budget_eur = 0.000001
    body, response = await submit(w, pair, mode="inquiry", message="What is my account balance?")
    ok(response)
    blocked = await until(w, body["request_id"], {"blocked"})
    assert "LLM-BUDGET" in blocked["reply"] and not w.model_requests
    assert any(event["kind"] == "denial" and event["result"]["rule"] == "LLM-BUDGET" for event in blocked["events"])
    proof = ok(await w.api("jan.devries", "GET", f"/demo/api/agent/runs/{blocked['id']}/proof"))
    assert any(a["rule_id"] == "DET-17" for a in proof["alerts"])
    assert any(d["action"] == "llm.chat" and d["decision"] == "deny" for d in proof["decisions"])
    async with w.ctx.db.sessionmaker() as s:
        assert await s.scalar(select(func.count()).select_from(SiemDelivery)) == 2
    report = ok(await w.api("mark.jansen", "GET", "/v1/model-budgets"))
    item = next(item for item in report["items"] if item["agent_id"] == pair["coordinator_id"])
    assert item["blocked_requests"] == 1 and item["used_or_reserved_eur"] == 0


async def prepare_payment(w, pair):
    body, response = await submit(w, pair)
    ok(response)
    run = await until(w, body["request_id"], {"confirmation_required"})
    assert run["pending"]["arguments"]["amount"] == 5000
    ok(await w.api("jan.devries", "POST", f"/demo/api/agent/runs/{run['id']}/continue", json={"action": "confirm"}))
    return await until(w, run["id"], {"approval_required"})


async def test_two_registered_agents_normal_denial_approval_and_cascading_stop(journey):
    w = journey
    original_ids = dict(w.agent_ids)
    pair = await register_pair(w)
    assert w.agent_ids == original_ids
    async with w.ctx.db.sessionmaker() as s:
        a, b = await s.get(Agent, pair["coordinator_id"]), await s.get(Agent, pair["payments_id"])
        assert a.status == b.status == "active" and a.can_delegate_to == [b.id] and b.can_receive_from == [a.id]

    body, response = await submit(w, pair, "inquiry", message="What is my current account balance?")
    ok(response)
    read = await until(w, body["request_id"], {"completed"})
    assert any(e["kind"] == "tool" and e["label"] == "get_balance" for e in read["events"])
    assert read["coordinator_id"] == pair["coordinator_id"]

    calls_before = len(w.model_requests)
    body, response = await submit(w, pair, case="delegation_widening")
    ok(response)
    denial = await until(w, body["request_id"], {"blocked"})
    proof = ok(await w.api("jan.devries", "GET", f"/demo/api/agent/runs/{denial['id']}/proof"))
    [edge] = [e for e in proof["graph"]["edges"] if e["kind"] == "attempted_delegation"]
    assert edge["decision"] == "deny" and edge["rules"] == ["DLG-004"]
    assert not any(e["kind"] == "delegated_to" for e in proof["graph"]["edges"])
    assert proof["alerts"][0]["rule_id"] == "DET-15"
    [decision] = proof["decisions"]
    assert decision["subject"] == "user:jan.devries" and decision["agent_id"] == pair["coordinator_id"]
    assert decision["root_id"] == denial["root_id"] and decision["trace_id"]
    assert len(w.model_requests) == calls_before and await payment_count(w) == 0
    async with w.ctx.db.sessionmaker() as s:
        assert (
            await s.scalar(
                select(func.count())
                .select_from(Mandate)
                .where(Mandate.root_id == denial["root_id"], Mandate.parent_id.is_not(None))
            )
            == 0
        )
    public_graph = ok(await w.api("mark.jansen", "GET", f"/v1/lineage/{denial['root_id']}"))
    assert any(n["label"] == "Judge-Payments" for n in public_graph["nodes"])
    assert next(n for n in public_graph["nodes"] if n["kind"] == "result")["outcome"] == "blocked"

    waiting = await prepare_payment(w, pair)
    assert await payment_count(w) == 0
    approval_id = waiting["pending"]["approval_id"]
    assert (await w.api("jan.devries", "POST", f"/v1/approvals/{approval_id}/approve", json={})).status_code == 403
    ok(
        await w.api(
            "sanne.bakker",
            "POST",
            f"/v1/approvals/{approval_id}/approve",
            json={"justification": "Reviewed synthetic payment"},
        )
    )
    completed = await until(w, waiting["id"], {"completed"})  # No manual resume request.
    assert completed["root_id"] == waiting["root_id"] and await payment_count(w) == 1
    assert any(e.get("runtime") == "automatic" for e in completed["events"])
    assert (await w.bank.snapshot("user:jan.devries"))["balance_eur"] == 43250.75
    assert (
        await w.api(
            "jan.devries", "POST", f"/demo/api/agent/runs/{waiting['id']}/continue", json={"action": "resume_approval"}
        )
    ).status_code == 409
    assert await payment_count(w) == 1

    pending = await prepare_payment(w, pair)
    radius = ok(
        await w.api(
            "mark.jansen",
            "POST",
            f"/v1/agents/{pair['coordinator_id']}/suspend",
            json={"reason": "Judge kill-switch demonstration"},
        )
    )["blast_radius"]
    assert pair["payments_id"] in radius["agents_affected"]
    assert pending["pending"]["approval_id"] in radius["pending_approvals"]
    stopped = await until(w, pending["id"], {"stopped"})
    assert not stopped["resumable"] and await payment_count(w) == 1
    async with w.ctx.db.sessionmaker() as s:
        descendants = list(await s.scalars(select(Mandate).where(Mandate.root_id == pending["root_id"])))
        assert len(descendants) >= 2 and all(m.status == "revoked" for m in descendants)
        assert (await s.get(Approval, pending["pending"]["approval_id"])).status == "cancelled"
        assert (await s.get(Agent, pair["payments_id"])).status == "active"  # Identity stays active, session does not.
    assert not w.runtime_pairs[pair["coordinator_id"]].payments_app.state.pending
    graph = ok(await w.api("mark.jansen", "GET", f"/v1/lineage/{stopped['root_id']}"))
    assert any(n["id"] == "user:jan.devries" for n in graph["nodes"])
    assert next(n for n in graph["nodes"] if n["kind"] == "result")["outcome"] == "revoked"


async def test_registration_approval_binding_and_run_guards(journey):
    w = journey
    assert (
        await w.api("jan.devries", "POST", "/demo/api/walkthrough/register", json={"name_prefix": "Unauthorized"})
    ).status_code == 403
    pair = ok(await w.api("priya.raman", "POST", "/demo/api/walkthrough/register", json={"name_prefix": "Guard"}))
    assert (
        await w.api(
            "priya.raman", "POST", "/demo/api/walkthrough/connect", json={"coordinator_id": pair["coordinator_id"]}
        )
    ).status_code == 409
    assert (
        await w.api(
            "priya.raman",
            "POST",
            "/demo/api/walkthrough/approve",
            json={"coordinator_id": pair["coordinator_id"], "reason": "I registered these agents"},
        )
    ).status_code == 403
    ok(
        await w.api(
            "sanne.bakker",
            "POST",
            "/demo/api/walkthrough/approve",
            json={"coordinator_id": pair["coordinator_id"], "reason": "Independent template review"},
        )
    )
    assert (
        await w.api(
            "jan.devries", "POST", "/demo/api/walkthrough/connect", json={"coordinator_id": pair["coordinator_id"]}
        )
    ).status_code == 403
    ok(
        await w.api(
            "niels.vandijk", "POST", "/demo/api/walkthrough/connect", json={"coordinator_id": pair["coordinator_id"]}
        )
    )
    body, response = await submit(w, pair)
    ok(response)
    duplicate = ok(await w.api("jan.devries", "POST", "/demo/api/agent/runs", json=body))
    assert duplicate["id"] == body["request_id"]
    conflicting = {**body, "message": "Different payment"}
    assert (await w.api("jan.devries", "POST", "/demo/api/agent/runs", json=conflicting)).status_code == 409
    await until(w, body["request_id"], {"confirmation_required"})
    denied = await w.api(
        "jan.devries",
        "POST",
        f"/demo/api/agent/runs/{body['request_id']}/continue",
        json={"action": "confirm", "amount": 1},
    )
    assert denied.status_code == 422 and await payment_count(w) == 0
    ok(
        await w.api(
            "jan.devries", "POST", f"/demo/api/agent/runs/{body['request_id']}/continue", json={"action": "cancel"}
        )
    )
    # Moving an active runtime endpoint is a material, immediately revoking change.
    ok(
        await w.api(
            "priya.raman",
            "PATCH",
            f"/v1/agents/{pair['payments_id']}",
            json={"endpoint_url": "https://unapproved.invalid/"},
        )
    )
    _, response = await submit(w, pair)
    assert response.status_code == 409 and await payment_count(w) == 0


async def test_rejected_payment_never_resumes_and_an_inflight_model_job_stops(journey):
    w = journey
    pair = await register_pair(w)
    waiting = await prepare_payment(w, pair)
    ok(
        await w.api(
            "sanne.bakker",
            "POST",
            f"/v1/approvals/{waiting['pending']['approval_id']}/reject",
            json={"justification": "Decline the synthetic action"},
        )
    )
    await until(w, waiting["id"], {"blocked"})
    assert await payment_count(w) == 0
    body, response = await submit(w, pair, "inquiry", message="Hold this inquiry while the security officer suspends A")
    ok(response)
    await asyncio.wait_for(w.model_started.wait(), timeout=10)
    ok(
        await w.api(
            "mark.jansen",
            "POST",
            f"/v1/agents/{pair['coordinator_id']}/suspend",
            json={"reason": "Stop in-flight model planning"},
        )
    )
    await until(w, body["request_id"], {"stopped"})
    assert await payment_count(w) == 0
    with pytest.raises(AegisDenied):
        await w.runtime_pairs[pair["coordinator_id"]].sdk.start_task("Read a synthetic balance", w.token("jan.devries"))


async def test_unverified_parent_cannot_forge_task_or_actor_correlation(journey):
    w = journey
    pair = await register_pair(w)
    runtime = w.runtime_pairs[pair["coordinator_id"]]
    task = await runtime.sdk.start_task(
        "Arrange a synthetic payment",
        w.token("jan.devries"),
        intent_categories=["payments.transfer.initiate", "customer.inquiry.read"],
    )
    header, payload, signature = task.token.split(".")
    forged = ".".join((header, payload, ("A" if signature[0] != "A" else "B") + signature[1:]))
    with pytest.raises(AegisDenied):
        await runtime.payments_sdk.accept_delegation(forged, intent_categories=["payments.status.read"])
    async with w.ctx.db.sessionmaker() as s:
        decision = await s.scalar(
            select(DecisionRecord)
            .where(DecisionRecord.action == "sts.token_exchange")
            .order_by(DecisionRecord.ts.desc())
            .limit(1)
        )
        assert decision.agent_id is None and decision.root_id is None and decision.subject is None
        assert decision.input_snapshot == {} and await s.scalar(select(func.count()).select_from(Alert)) == 0
    await task.complete()


async def test_already_forwarded_but_uncommitted_local_payment_is_blocked_by_suspend(journey, monkeypatch):
    w = journey
    pair = await register_pair(w)
    runtime = w.runtime_pairs[pair["coordinator_id"]]
    parent = await runtime.sdk.start_task(
        "Arrange a synthetic payment",
        w.token("jan.devries"),
        intent_categories=["payments.transfer.initiate", "customer.inquiry.read"],
    )
    child = await runtime.payments_sdk.accept_delegation(parent.token)
    arrived, release = asyncio.Event(), asyncio.Event()
    operation = w.bank.operation

    async def delayed_operation(*args, **kwargs):
        arrived.set()
        await release.wait()
        return await operation(*args, **kwargs)

    monkeypatch.setattr(w.bank, "operation", delayed_operation)
    job = asyncio.create_task(
        child.call_tool(
            "payments",
            "initiate_transfer",
            {
                "customer_id": "C-1001",
                "amount": 100,
                "creditor_iban": LANDLORD_IBAN,
                "new_beneficiary": False,
                "reference": "CommitRace",
            },
        )
    )
    try:
        await asyncio.wait_for(arrived.wait(), timeout=10)
        ok(
            await w.api(
                "mark.jansen",
                "POST",
                f"/v1/agents/{pair['coordinator_id']}/suspend",
                json={"reason": "Suspend before the local transaction commits"},
            )
        )
        release.set()
        result = await asyncio.wait_for(job, timeout=10)
        assert result.get("isError") and await payment_count(w) == 0
        assert (await w.bank.snapshot("user:jan.devries"))["balance_eur"] == 48250.75
    finally:
        release.set()
        if not job.done():
            job.cancel()
        await asyncio.gather(job, return_exceptions=True)


async def test_bindings_are_not_restored_from_history_and_customer_proof_is_scoped(journey):
    w = journey
    pair = await register_pair(w)
    body, response = await submit(w, pair, "inquiry", message="What is my balance?")
    ok(response)
    await until(w, body["request_id"], {"completed"})
    # Another authenticated customer cannot read Jan's run/proof.
    w.ctx.idp.add_persona(Persona("other.customer", "Another synthetic customer", ["customer"], []))
    assert (await w.api("other.customer", "GET", f"/demo/api/agent/runs/{body['request_id']}/proof")).status_code == 404
    w.runtime_pairs.clear()  # Simulate loss of process-owned runtime credentials.
    _, response = await submit(w, pair)
    assert response.status_code == 409 and await payment_count(w) == 0
    ok(
        await w.api(
            "niels.vandijk", "POST", "/demo/api/walkthrough/connect", json={"coordinator_id": pair["coordinator_id"]}
        )
    )
    assert pair["coordinator_id"] in w.runtime_pairs


async def test_suspend_cancels_the_actually_running_delegated_payment_job(journey, monkeypatch):
    w = journey
    pair = await register_pair(w)
    waiting = await prepare_payment(w, pair)
    arrived, cancelled = asyncio.Event(), asyncio.Event()

    async def held_operation(*args, **kwargs):
        arrived.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(w.bank, "operation", held_operation)
    ok(
        await w.api(
            "sanne.bakker",
            "POST",
            f"/v1/approvals/{waiting['pending']['approval_id']}/approve",
            json={"justification": "Independent review before controlled cancellation test"},
        )
    )
    await asyncio.wait_for(arrived.wait(), timeout=10)  # B has reached the actual bank operation.
    ok(
        await w.api(
            "mark.jansen",
            "POST",
            f"/v1/agents/{pair['coordinator_id']}/suspend",
            json={"reason": "Cancel the executing delegated bank operation"},
        )
    )
    stopped = await until(w, waiting["id"], {"stopped"})
    assert cancelled.is_set() and not stopped["resumable"] and await payment_count(w) == 0
    assert not w.runtime_pairs[pair["coordinator_id"]].payments_app.state.pending


async def test_postgres_lock_order_and_commit_remain_inside_the_execution_mutex():
    control = SimpleNamespace(execution_lock=asyncio.Lock())
    events = []

    async def execute(statement):
        assert not control.execution_lock.locked()
        assert "pg_advisory_xact_lock(724356912)" in str(statement)
        events.append("ledger_transaction_lock")

    async def commit():
        assert control.execution_lock.locked()
        events.append("commit")

    session = SimpleNamespace(
        bind=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")), execute=execute, commit=commit
    )
    bank = Bank(SimpleNamespace(engine=SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))), control)
    async with bank.write_lock(session):
        assert control.execution_lock.locked()
        events.append("write")
    assert not control.execution_lock.locked()
    assert events == ["ledger_transaction_lock", "write", "commit"]
