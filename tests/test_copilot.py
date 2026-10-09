"""Offline regression fixtures only. No external Azure, bank or identity service is contacted."""

import json
from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import select

from aegis.common.investigation import ENTITLEMENT, INTENT, SERVER, TOOLS, upstream_headers
from aegis.common.settings import Settings
from aegis.control.investigation import InvestigationData, InvestigationQuery
from aegis.control.tables import Agent, Alert, Approval, CopilotRun, DecisionRecord, Mandate, TraceSpan, Usage, utcnow
from aegis.guard.detectors import scan_text, scan_tool_description
from aegis.sdk import AegisDenied
from aegis_demo.agents import structured
from aegis_demo.copilot import SYSTEM, Investigator, interrupt_copilot_history, validate_answer
from aegis_demo.testing import BASE, running_world


def completion(name=None, args=None, answer=None):
    message = {"role": "assistant", "content": json.dumps(answer) if answer is not None else None}
    if name:
        message["tool_calls"] = [
            {
                "id": "offline-call",
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps({"query": args or {}}),
                },
            }
        ]
    return {
        "id": "offline-completion",
        "model": "gpt-4.1-mini",
        "choices": [{"message": message, "finish_reason": "tool_calls" if name else "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130},
    }


async def seed_block(world):
    async with world.ctx.db.sessionmaker() as s:
        s.add(
            DecisionRecord(
                id="dec_offline_block",
                agent_id=world.agent_ids["ava"],
                subject="user:jan.devries",
                action="mcp:notify.send_email",
                decision="deny",
                policy_version="offline-policy",
                reasons=[
                    {"rule": "IFC-001", "message": "External egress blocked after untrusted confidential content"}
                ],
                data_class="confidential",
                trace_id="a" * 32,
                input_snapshot={"api_key": "should-never-leave-the-database", "prompt": "raw prompt omitted"},
            )
        )
        s.add(
            Alert(
                id="alr_offline",
                rule_id="DET-02",
                severity="critical",
                agent_id=world.agent_ids["ava"],
                title="Exfiltration attempt blocked",
                evidence={"secret": "private-alert-payload"},
            )
        )
        s.add(
            TraceSpan(
                span_id="b" * 16,
                trace_id="a" * 32,
                name="mcp tools/call",
                service="aegis.gateway",
                start_ns=1,
                end_ns=1000001,
                status="ERROR",
                attributes={"password": "private-span-attribute"},
            )
        )
        await s.commit()


@pytest.mark.parametrize("user", ["jan.devries", "priya.raman", "admin", "niels.vandijk", "sanne.bakker"])
async def test_only_investigators_can_use_api(world, user):
    for path in ("status", "runs", "evidence/decision/dec_offline_block"):
        assert (await world.api(user, "GET", f"/demo/api/copilot/{path}")).status_code == 403
    response = await world.api(
        user,
        "POST",
        "/demo/api/copilot/ask",
        json={
            "request_id": str(uuid4()),
            "question": "Why was Ava blocked?",
            "confirm_synthetic_external_call": True,
        },
    )
    assert response.status_code == 403


async def test_anonymous_and_direct_upstream_are_blocked(world):
    assert (await world.http.get(f"{BASE}/demo/api/copilot/status")).status_code == 401
    for headers in (
        {},
        world.internal_headers(),
        {"authorization": f"Bearer {world.token('mark.jansen')}"},
    ):
        response = await world.http.post(
            f"{BASE}/demo/mcp/{SERVER}/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        assert response.status_code == 401


async def test_no_consent_no_azure_and_no_fake_fallback(world):
    assert not (await world.api("mark.jansen", "GET", "/demo/api/copilot/status")).json()["ready"]
    body = {"request_id": str(uuid4()), "question": "Why was Ava blocked?"}
    assert (await world.api("mark.jansen", "POST", "/demo/api/copilot/ask", json=body)).status_code == 422
    body["confirm_synthetic_external_call"] = True
    assert (await world.api("mark.jansen", "POST", "/demo/api/copilot/ask", json=body)).status_code == 503
    assert (await world.api("mark.jansen", "GET", "/demo/api/copilot/runs")).json() == []


async def test_role_derived_entitlement_and_real_governed_read(world):
    await seed_block(world)
    for user in ("mark.jansen", "eva.visser"):
        verified = await world.ctx.users.authenticate(world.token(user))
        assert ENTITLEMENT in verified.entitlements
        task = await world.sdks["investigation-copilot"].start_task(
            "Investigate", user_token=world.token(user), intent_categories=[INTENT]
        )
        assert all(scope == "llm.chat" or scope.startswith(f"{SERVER}.") for scope in task.scopes)
        assert {t["name"] for t in await task.list_tools(SERVER)} == set(TOOLS)
        receipt = await task.call_tool(SERVER, "search_decisions", {"query": {"agent": "Ava", "decision": "deny"}})
        assert structured(receipt)["records"][0]["ref"] == "decision:dec_offline_block"
        assert "should-never-leave" not in json.dumps(receipt)
        with pytest.raises(AegisDenied):
            await task.call_tool("crm", "update_address", {"customer_id": "C-1001", "new_address": "Not allowed"})
        await task.complete()
    assert ENTITLEMENT not in (await world.ctx.users.authenticate(world.token("jan.devries"))).entitlements
    with pytest.raises(AegisDenied):
        await world.sdks["investigation-copilot"].start_task(
            "Investigate", user_token=world.token("jan.devries"), intent_categories=[INTENT]
        )


async def test_projections_omit_payloads_restricted_rows_and_false_time_inference(world):
    await seed_block(world)
    async with world.ctx.db.sessionmaker() as s:
        s.add(
            DecisionRecord(
                id="dec_restricted",
                action="secret",
                decision="deny",
                data_class="restricted",
                agent_id=world.agent_ids["ava"],
                reasons=[{"message": "sensitive"}],
            )
        )
        s.add(
            DecisionRecord(
                id="dec_old",
                action="old",
                decision="deny",
                data_class="internal",
                agent_id=world.agent_ids["ava"],
                ts=utcnow() - timedelta(days=5),
            )
        )
        await s.commit()
    data = InvestigationData(world.ctx)
    result = await data.read("search_decisions", InvestigationQuery(agent="Ava", decision="deny", limit=1))
    assert [r["id"] for r in result["records"]] == ["dec_offline_block"]
    assert await data.source("decision", "dec_restricted") is None
    assert (await data.source("decision", "dec_old"))["id"] == "dec_old"
    for name, query in (
        ("list_alerts", InvestigationQuery(agent="Ava")),
        ("get_trace_timeline", InvestigationQuery(trace_id="a" * 32)),
    ):
        text = json.dumps(await data.read(name, query))
        assert "private-alert-payload" not in text and "private-span-attribute" not in text
    with pytest.raises(ValueError):
        await data.read("get_trace_timeline", InvestigationQuery(agent="Ava"))
    with pytest.raises(ValidationError):
        InvestigationQuery.model_validate({"sql": "DROP TABLE agents"})
    with pytest.raises(ValidationError):
        InvestigationQuery(hours=745)
    with pytest.raises(ValidationError):
        InvestigationQuery(limit=1000)


async def test_approval_filter_is_typed_and_amount_is_not_raw_arguments(world):
    async with world.ctx.db.sessionmaker() as s:
        s.add(
            Approval(
                id="apr_offline",
                agent_id=world.agent_ids["ava"],
                action_hash="x" * 64,
                mandate_id="mdt_offline",
                subject="user:jan.devries",
                tool="payments.initiate_transfer",
                approver="sanne.bakker",
                status="approved",
                expires_at=utcnow() + timedelta(minutes=10),
                arguments={"amount": 25000, "creditor_iban": "NL91ABNA0417164300", "secret": "private"},
            )
        )
        await s.commit()
    result = await InvestigationData(world.ctx).read(
        "search_approvals", InvestigationQuery(approver="sanne.bakker", min_amount_eur=10000.0)
    )
    assert result["records"][0]["facts"]["amount_eur"] == 25000
    assert "creditor_iban" not in json.dumps(result)


def test_credential_is_never_sent_to_untrusted_destinations():
    settings = Settings(control_url=BASE)
    assert settings.investigation_token != Settings().investigation_token
    assert settings.investigation_token not in repr(settings)
    expected = f"{BASE}/demo/mcp/{SERVER}/mcp"
    assert upstream_headers(settings, SERVER, expected)
    for url in (
        "https://attacker.example/mcp",
        expected + "?redirect=1",
        expected + "/",
        expected.replace("8000", "8001"),
    ):
        assert upstream_headers(settings, SERVER, url) == {}
    assert upstream_headers(settings, "other-server", expected) == {}


def test_system_and_tool_descriptions_do_not_trigger_our_guard():
    assert not scan_text(SYSTEM).injection
    for description in TOOLS.values():
        assert not scan_tool_description(description).injection


def test_unretrieved_citations_and_uncited_statements_are_rejected():
    source = {"decision:dec_test": {"id": "dec_test"}}
    assert validate_answer(
        json.dumps(
            {
                "statements": [{"text": "Blocked under the recorded rule.", "citations": ["decision:dec_test"]}],
                "unknowns": [],
            }
        ),
        source,
    )
    for citations in ([], ["decision:invented"], ["https://attacker.example"]):
        with pytest.raises((ValueError, ValidationError)):
            validate_answer(
                json.dumps({"statements": [{"text": "An unsupported claim.", "citations": citations}], "unknowns": []}),
                source,
            )


class OfflineTask:
    def __init__(self, responses, records=None):
        self.responses = list(responses)
        self.records = records or []
        self.last_chat_metadata = {"x-aegis-llm-provider": "azure-openai"}  # Unit fixture only.
        self.executed = []
        self.requests = []

    async def list_tools(self, server):
        return [{"name": name} for name in TOOLS]

    async def chat(self, messages, **kwargs):
        self.requests.append({"messages": messages, **kwargs})
        return self.responses.pop(0)

    async def call_tool(self, server, name, args):
        self.executed.append((server, name, args))
        return {"structuredContent": {"records": self.records, "truncated": False}}


async def test_model_cannot_choose_writes_or_run_without_real_provider():
    task = OfflineTask([completion("suspend_agent")])
    with pytest.raises(AegisDenied):
        await Investigator(task, Settings()).run("Suspend Ava")
    assert task.executed == []
    task = OfflineTask([completion("search_decisions")])
    task.last_chat_metadata = {"x-aegis-llm-provider": "configured-upstream"}
    with pytest.raises(AegisDenied):
        await Investigator(task, Settings()).run("Why was Ava blocked?")
    assert task.executed == []


async def test_no_evidence_is_explicit_not_an_invented_answer():
    task = OfflineTask([completion("search_decisions", {"agent": "No such agent"}), completion()])
    result = await Investigator(task, Settings()).run("Why was a nonexistent agent blocked?")
    assert not result["answer"]["statements"] and "cannot establish" in result["answer"]["unknowns"][0]
    assert len(task.requests) == 2


async def test_full_api_via_gateway_offline_citations_budget_dedupe_and_history():
    # Replace the outbound Azure HTTP client before asking. No network request can leave this fixture.
    config = {
        "azure_openai_endpoint": "https://offline-resource.openai.azure.com",
        "azure_openai_api_key": "offline-placeholder",
        "azure_openai_deployment": "aegis-chat",
        "llm_processing_scope": "global",
        "llm_allowed_processing_scope": "global",
    }
    async with running_world(**config) as world:
        await seed_block(world)
        azure = world.gateway.state.azure_upstream
        await azure.http.aclose()
        requests = []

        def respond(request):
            body = json.loads(request.content)
            requests.append(body)
            assert "authorization" not in request.headers
            assert "should-never-leave" not in request.content.decode()
            if "response_format" in body:
                reply = completion(
                    answer={
                        "statements": [
                            {
                                "text": "Ava's email was denied under IFC-001.",
                                "citations": ["decision:dec_offline_block"],
                            }
                        ],
                        "unknowns": ["Execution traces were not retrieved."],
                    }
                )
            elif len(requests) == 1:
                reply = completion("search_decisions", {"agent": "Ava", "decision": "deny"})
            else:
                reply = completion()
            return httpx.Response(200, json=reply, headers={"apim-request-id": "offline-request"})

        azure.http = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        body = {"request_id": str(uuid4()), "question": "Why was Ava blocked?", "confirm_synthetic_external_call": True}
        response = await world.api("mark.jansen", "POST", "/demo/api/copilot/ask", json=body)
        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "completed", result
        assert result["mandate_completed"]
        assert result["sources"][0]["ref"] == "decision:dec_offline_block"
        assert result["sources"][0]["href"] == "/copilot?evidence=decision:dec_offline_block"
        assert len(requests) == 3 and all(
            len(json.dumps(body)) <= world.settings.llm_max_request_chars for body in requests
        )
        repeated = await world.api("mark.jansen", "POST", "/demo/api/copilot/ask", json=body)
        assert repeated.json() == result and len(requests) == 3
        body["question"] = "A different question with the same request ID."
        assert (await world.api("mark.jansen", "POST", "/demo/api/copilot/ask", json=body)).status_code == 409
        assert (await world.api("eva.visser", "POST", "/demo/api/copilot/ask", json=body)).status_code == 409
        assert (await world.api("eva.visser", "GET", "/demo/api/copilot/runs")).json() == []
        assert len((await world.api("mark.jansen", "GET", "/demo/api/copilot/runs")).json()) == 1
        async with world.ctx.db.sessionmaker() as s:
            assert len((await s.scalars(select(Usage))).all()) == 3
            assert (await s.scalar(select(Mandate).where(Mandate.root_id == result["root_id"]))).status == "completed"
            assert (await s.get(Agent, world.agent_ids["ava"])).status == "active"


async def test_running_history_is_interrupted_on_restart(world):
    async with world.ctx.db.sessionmaker() as s:
        s.add(
            CopilotRun(
                id=str(uuid4()),
                subject="mark.jansen",
                request_hash="x" * 64,
                status="running",
                snapshot={"status": "running"},
            )
        )
        await s.commit()
    await interrupt_copilot_history(world)
    async with world.ctx.db.sessionmaker() as s:
        assert (await s.scalar(select(CopilotRun))).status == "interrupted"
