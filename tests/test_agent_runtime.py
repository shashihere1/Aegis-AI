"""Optional-runtime unit coverage with fixture completions only. Never calls Azure."""

import json
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from aegis.common.settings import Settings
from aegis.sdk import AegisDenied
from aegis_demo.agent_runtime import LiveAva, TransferArgs, verify_with_framework
from aegis_demo.agents import a2a_result
from aegis_demo.data import LANDLORD_IBAN

pytest.importorskip("langgraph")
pytest.importorskip("agent_framework")


def completion(name=None, args=None, content="The tool returned a synthetic result."):
    message = {"role": "assistant", "content": None if name else content}
    if name:
        message["tool_calls"] = [
            {"id": "offline-call", "type": "function", "function": {"name": name, "arguments": json.dumps(args or {})}}
        ]
    return {
        "choices": [{"message": message, "finish_reason": "tool_calls" if name else "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


class OfflineTask:
    """Records calls locally; an Azure provider header is a unit fixture, not a live claim."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.claims = {"exp": time.time() + 300}
        self.scopes = ["a2a:kyc", "a2a:payments"]
        self.last_chat_metadata = {"x-aegis-llm-provider": "azure-openai"}
        self.executed = []
        self.delegations = []
        self.approval_responses = []

    async def list_tools(self, server):
        return [{"name": n} for n in ("get_balance", "get_customer", "read_document", "update_address")]

    async def chat(self, messages, **kwargs):
        return self.responses.pop(0)

    async def call_tool(self, server, name, arguments):
        self.executed.append((server, name, arguments))
        return {"structuredContent": {"result": {"verified": True, "balance_eur": 48250.75}}}

    async def delegate(self, agent, text, metadata):
        self.delegations.append(metadata)
        return self.approval_responses.pop(0)


async def live(mode, task):
    world = SimpleNamespace(settings=Settings(), agent_ids={"kyc-agent": "kyc", "payments-agent": "payments"})
    events = []

    async def emit(event):
        events.append(event)

    runtime = LiveAva(world, task, mode, emit)
    await runtime.prepare()
    return runtime, events


async def test_langgraph_selected_balance_binds_customer():
    task = OfflineTask([completion("get_balance"), completion()])
    runtime, events = await live("inquiry", task)
    result = await runtime.run(runtime.initial("Read my synthetic balance"))
    assert result["status"] == "completed"
    assert task.executed == [("core-banking", "get_balance", {"customer_id": "C-1001"})]
    assert len([e for e in events if e["kind"] == "model"]) == 2


async def test_model_cannot_supply_other_customer_or_arbitrary_operation():
    for response in (completion("get_balance", {"customer_id": "C-1002"}), completion("execute_shell")):
        task = OfflineTask([response])
        runtime, _ = await live("inquiry", task)
        with pytest.raises((AegisDenied, ValidationError)):
            await runtime.run(runtime.initial("Read my balance"))
        assert task.executed == []


async def test_address_without_verification_is_refused():
    task = OfflineTask([completion("update_address", {"new_address": "A synthetic address"})])
    runtime, _ = await live("address", task)
    with pytest.raises(AegisDenied, match="KYC"):
        await runtime.run(runtime.initial("Update my address"))
    assert task.executed == []


async def test_payment_confirmation_and_approval_preserve_exact_arguments():
    args = {"amount": 25000.0, "creditor_iban": LANDLORD_IBAN, "new_beneficiary": True, "reference": "Rent"}
    task = OfflineTask([completion("initiate_transfer", args)])
    task.approval_responses = [
        a2a_result("auth-required", {"approval_id": "offline-approval"}),
        a2a_result(
            "completed", {**args, "customer_id": "C-1001", "payment_id": "offline-payment", "status": "accepted"}
        ),
    ]
    runtime, _ = await live("transfer", task)
    state = await runtime.run(runtime.initial("Pay the synthetic landlord"))
    assert state["status"] == "confirmation_required" and not task.delegations
    state["confirmed"], state["status"] = True, "running"
    state = await runtime.run(state)
    assert state["status"] == "approval_required"
    assert task.delegations == [{**args, "customer_id": "C-1001"}]
    state["status"] = "running"
    state = await runtime.run(state)
    assert state["status"] == "completed"
    assert task.delegations[-1] == {"resume_approval": "offline-approval"}


async def test_real_maf_executor_chain_returns_tool_receipt():
    task = OfflineTask([])
    result = await verify_with_framework(task, "C-1001", "D-77")
    assert result["verified"] is True and result["runtime"] == "microsoft-agent-framework"
    assert task.executed == [("kyc", "verify_document", {"customer_id": "C-1001", "document_id": "D-77"})]


def test_payment_validation_rejects_invalid_iban_and_negative_amount():
    from pydantic import ValidationError

    for amount, iban in ((-1, LANDLORD_IBAN), (5, "NL00ABNA0123456789")):
        with pytest.raises(ValidationError):
            TransferArgs(amount=amount, creditor_iban=iban, new_beneficiary=True, reference="test")
