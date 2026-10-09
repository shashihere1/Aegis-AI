"""End-to-end lineage: user -> agents -> tools -> data -> approvals -> result, per task and across tasks."""

import json

import httpx
import pytest

from aegis.control.soc import call_outcome
from aegis.control.tables import DecisionRecord
from aegis_demo.data import LANDLORD_IBAN

JAN = "jan.devries"


def node(graph: dict, kind: str) -> list[dict]:
    return [n for n in graph["nodes"] if n["kind"] == kind]


def result_of(graph: dict) -> dict:
    [result] = node(graph, "result")
    return result


async def lineage(world, root_id: str) -> dict:
    return (await world.api("mark.jansen", "GET", f"/v1/lineage/{root_id}")).json()


async def test_completed_journey_ends_in_a_result_node(world):
    result = await world.ava.change_address(world.token(JAN), "C-1001", "D-77", "Keizersgracht 401, Amsterdam")
    graph = await lineage(world, result["task"].root_id)

    end = result_of(graph)
    assert end["outcome"] == "completed" and end["label"] == "Completed"
    assert end["calls"].get("executed", 0) >= 2 and "executed" in end["detail"]
    tools = node(graph, "tool")
    assert tools and all(t["outcome"] == "executed" for t in tools)
    into_result = [e for e in graph["edges"] if e["kind"] == "resulted_in"]
    assert into_result and all(e["to"] == end["id"] for e in into_result)
    assert any(e["from"] == "data:confidential" for e in into_result)  # the path continues past the data class


async def test_approval_is_drawn_and_the_result_follows_it(world):
    flow = await world.ava.transfer(world.token(JAN), "C-1001", 25000, LANDLORD_IBAN, True)
    approval_id = flow["response"]["artifacts"][0]["parts"][0]["data"]["approval_id"]
    root_id = flow["task"].root_id

    waiting = await lineage(world, root_id)
    assert result_of(waiting)["outcome"] == "waiting"
    [pending] = node(waiting, "approval")
    assert pending["approval_status"] == "pending" and pending["label"] == "Awaiting approval"

    await world.api("sanne.bakker", "POST", f"/v1/approvals/{approval_id}/approve", json={"justification": "rent"})
    await world.ava.resume_transfer(flow["task"], approval_id)

    done = await lineage(world, root_id)
    [approval] = node(done, "approval")
    assert approval["id"] == f"approval:{approval_id}"
    assert approval["approver"] == "sanne.bakker" and approval["label"] == "Approved by sanne.bakker · used"
    transfer = next(t for t in node(done, "tool") if t["label"] == "payments.initiate_transfer")
    assert transfer["outcomes"] == {"awaiting_approval": 1, "executed": 1} and transfer["outcome"] == "executed"
    assert {"from": transfer["id"], "to": approval["id"], "kind": "approval"}.items() <= next(
        e for e in done["edges"] if e["kind"] == "approval").items()
    assert result_of(done)["outcome"] == "completed"
    assert any(e["from"] == approval["id"] and e["kind"] == "resulted_in" for e in done["edges"])

    text = json.dumps(done)  # the graph says what happened, never the data itself
    assert LANDLORD_IBAN not in text and "25000" not in text and "rent" not in text


async def test_contained_attack_shows_a_revoked_result_with_its_reason(world):
    result = await world.ava.process_uploaded_document(world.token(JAN), "C-1001", "D-99")
    graph = await lineage(world, result["task"].root_id)
    end = result_of(graph)
    assert end["outcome"] == "revoked" and end["label"] == "Revoked"
    assert "denied" in end["detail"]
    email = next(t for t in node(graph, "tool") if t["label"] == "notify.send_email")
    assert email["outcome"] == "denied"
    assert next(e for e in graph["edges"] if e["to"] == email["id"])["decisions"] == {"deny": 1}


def fail_core_banking(world, monkeypatch, behaviour):
    """Intercept only the Gateway's upstream tools/call to core-banking; everything else is untouched."""
    original = world.http.post

    async def post(url, *args, **kwargs):
        body = kwargs.get("json") or {}
        if "/demo/mcp/core-banking/" in str(url) and body.get("method") == "tools/call":
            return behaviour(str(url), body)
        return await original(url, *args, **kwargs)

    monkeypatch.setattr(world.http, "post", post)


async def balance_task(world):
    return await world.sdks["ava"].start_task(
        "Read my account balance", world.token(JAN), intent_categories=["customer.inquiry.read"]
    )


async def test_tool_error_from_the_bank_system_is_a_failed_result(world, monkeypatch):
    def tool_error(url, body):
        payload = {"jsonrpc": "2.0", "id": body.get("id"),
                   "result": {"content": [{"type": "text", "text": "core banking unavailable"}], "isError": True}}
        return httpx.Response(200, json=payload, request=httpx.Request("POST", url))

    fail_core_banking(world, monkeypatch, tool_error)
    task = await balance_task(world)
    await task.call_tool("core-banking", "get_balance", {"customer_id": "C-1001"})
    await task.complete()

    graph = await lineage(world, task.root_id)
    tool = next(t for t in node(graph, "tool") if t["label"] == "core-banking.get_balance")
    assert tool["outcome"] == "tool_error"
    assert not node(graph, "data")  # nothing was actually read
    assert result_of(graph)["outcome"] == "failed" and "1 tool error" in result_of(graph)["detail"]


async def test_upstream_failure_is_recorded_instead_of_vanishing(world, monkeypatch):
    def unreachable(url, body):
        raise httpx.ConnectError("connection refused", request=httpx.Request("POST", url))

    fail_core_banking(world, monkeypatch, unreachable)
    task = await balance_task(world)
    with pytest.raises(Exception):
        await task.call_tool("core-banking", "get_balance", {"customer_id": "C-1001"})

    decisions = (await world.api("mark.jansen", "GET", f"/v1/decisions?root_id={task.root_id}")).json()
    [call] = [d for d in decisions if d["action"] == "core-banking.get_balance"]
    assert call["decision"] == "allow" and call["outcome"] == "failed"
    assert result_of(await lineage(world, task.root_id))["outcome"] == "failed"
    await task.complete()


def test_records_from_before_outcomes_were_stored_are_not_guessed():
    old = DecisionRecord(action="core-banking.get_balance", decision="allow", input_snapshot={"subject": {}})
    assert call_outcome(old) == "not_recorded"
    assert call_outcome(DecisionRecord(action="x", decision="deny", input_snapshot={})) == "denied"
    assert call_outcome(DecisionRecord(action="x", decision="require_approval", input_snapshot={})) == "awaiting_approval"


async def test_cross_task_view_merges_tasks_with_counts(world):
    for _ in range(2):
        flow = await world.ava.transfer(world.token(JAN), "C-1001", 50, LANDLORD_IBAN, True)
        assert flow["response"]["status"]["state"] == "completed"
    await world.ava.change_address(world.token(JAN), "C-1001", "D-77", "Keizersgracht 401, Amsterdam")

    graph = (await world.api("mark.jansen", "GET", f"/v1/lineage?subject=user:{JAN}&hours=1")).json()
    assert graph["tasks"] == 3 and graph["truncated"] is False
    assert [n["id"] for n in node(graph, "user")] == [f"user:{JAN}"]
    end = result_of(graph)
    assert sum(end["task_outcomes"].values()) == 3 and end["id"] == "result:tasks"

    transfer = next(e for e in graph["edges"] if e["kind"] == "invoked" and e["to"] == "tool:payments.initiate_transfer")
    decisions = (await world.api("mark.jansen", "GET", f"/v1/decisions?subject=user:{JAN}&hours=1&limit=500")).json()
    assert transfer["count"] == len([d for d in decisions if d["action"] == "payments.initiate_transfer"]) == 2
    initiated = next(e for e in graph["edges"] if e["kind"] == "initiated")
    assert initiated["count"] == 3

    capped = (await world.api("mark.jansen", "GET", f"/v1/lineage?subject=user:{JAN}&hours=1&limit=1")).json()
    assert capped["tasks"] == 1 and capped["truncated"] is True

    kyc = world.agent_ids["kyc-agent"]
    by_agent = (await world.api("mark.jansen", "GET", f"/v1/lineage?agent_id={kyc}&hours=1")).json()
    assert by_agent["tasks"] == 1 and f"agent:{kyc}" in {n["id"] for n in node(by_agent, "agent")}


async def test_cross_task_view_is_empty_not_an_error_and_staff_only(world):
    empty = (await world.api("mark.jansen", "GET", "/v1/lineage?subject=user:nobody&hours=1")).json()
    assert empty == {"scope": {"subject": "user:nobody", "agent_id": None, "hours": 1, "limit": 50},
                     "tasks": 0, "truncated": False, "nodes": [], "edges": []}
    assert (await world.api(JAN, "GET", "/v1/lineage?hours=1")).status_code == 403
    assert (await world.api("mark.jansen", "GET", "/v1/lineage?hours=0")).status_code == 422
