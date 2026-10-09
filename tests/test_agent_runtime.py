"""Optional-runtime unit coverage with fixture completions only. Never calls Azure."""

import json
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from aegis.common.settings import Settings
from aegis.sdk import AegisDenied
from aegis_demo.agent_runtime import (
    ExecutionUncertain,
    LiveAva,
    TransferArgs,
    matches_change_receipt,
    verify_with_framework,
)
from aegis_demo.agents import a2a_result
from aegis_demo.bank import digest, money, receipt_hash
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
        self.root_id = "offline-root"
        self.scopes = ["a2a:kyc", "a2a:payments"]
        self.last_chat_metadata = {"x-aegis-llm-provider": "azure-openai"}
        self.executed = []
        self.delegations = []
        self.approval_responses = []
        self.chat_requests = []

    async def list_tools(self, server):
        return [{"name": n} for n in ("get_balance", "get_customer", "read_document", "update_address")]

    async def chat(self, messages, **kwargs):
        self.chat_requests.append({"messages": messages, **kwargs})
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
    assert all(request["tool_choice"] == "auto" for request in task.chat_requests)


async def test_transfer_balance_then_proposal_pauses_without_moving_money():
    args = {"amount": 25000.0, "creditor_iban": LANDLORD_IBAN, "new_beneficiary": True, "reference": "Rent"}
    task = OfflineTask([completion("get_balance"), completion("initiate_transfer", args)])
    runtime, events = await live("transfer", task)
    state = await runtime.run(runtime.initial("Transfer EUR 25,000 to the demo landlord as a new beneficiary, Rent"))
    assert state["status"] == "confirmation_required"
    assert state["next_call"]["arguments"] == args and state["confirmed"] is False
    assert task.executed == [("core-banking", "get_balance", {"customer_id": "C-1001"})]
    assert not task.delegations
    assert any(e["kind"] == "proposal" and e["label"] == "initiate_transfer" for e in events)
    for request in task.chat_requests:
        assert request["tool_choice"] == "required" and request["parallel_tool_calls"] is False
        names = {tool["function"]["name"] for tool in request["tools"]}
        assert names == {"get_balance", "initiate_transfer", "explain_without_action"}


async def test_text_only_confirmation_after_balance_is_not_a_completed_transfer():
    # Reproduce the screenshot: balance receipt, then plain "Please confirm" and no transfer call.
    task = OfflineTask(
        [completion("get_balance"), completion(content="Please confirm you want to transfer EUR 25,000.")]
    )
    runtime, events = await live("transfer", task)
    state = await runtime.run(runtime.initial("Transfer EUR 25,000 to the demo landlord"))
    assert state["status"] == "not_executed" and state["next_call"] is None
    assert "nothing to confirm" in state["reply"]
    assert "Please confirm" not in state["reply"]
    assert len(task.chat_requests) == 2  # No automatic paid re-planning retry.
    assert len(task.executed) == 1 and not task.delegations
    assert any(e["kind"] == "warning" for e in events)


@pytest.mark.parametrize("mode", ["transfer", "address"])
@pytest.mark.parametrize("reason", ["missing_details", "information_only", "declined", "unavailable"])
async def test_required_selection_has_a_nonexecuting_exit(mode, reason):
    task = OfflineTask(
        [completion("explain_without_action", {"reason": reason, "message": "Please specify the details."})]
    )
    runtime, _ = await live(mode, task)
    state = await runtime.run(runtime.initial("I have a question or an incomplete request"))
    assert state["status"] == "not_executed" and state["next_call"] is None
    assert "No change was prepared or executed" in state["reply"]
    assert not task.executed and not task.delegations
    assert task.chat_requests[0]["tool_choice"] == "required"


async def test_no_action_selection_cannot_smuggle_confirmation_or_payment_arguments():
    task = OfflineTask(
        [
            completion(
                "explain_without_action",
                {
                    "reason": "missing_details",
                    "message": "Need an amount",
                    "confirmed": True,
                    "amount": 25000,
                },
            )
        ]
    )
    runtime, _ = await live("transfer", task)
    with pytest.raises(ValidationError):
        await runtime.run(runtime.initial("Pay someone"))
    assert not task.executed and not task.delegations


async def test_explanation_control_function_is_not_available_in_inquiry_mode():
    task = OfflineTask([completion("explain_without_action", {"reason": "information_only", "message": "Question"})])
    runtime, _ = await live("inquiry", task)
    with pytest.raises(AegisDenied, match="allowlist"):
        await runtime.run(runtime.initial("Balance"))
    assert not task.executed and not task.delegations


@pytest.mark.parametrize("mode", ["transfer", "address"])
async def test_plaintext_write_claim_cannot_complete_a_change(mode):
    task = OfflineTask([completion(content="I have completed your change.")])
    runtime, _ = await live(mode, task)
    state = await runtime.run(runtime.initial("A synthetic change request"))
    assert state["status"] == "not_executed"
    assert state["next_call"] is None and state["write_executed"] is False
    assert "I have completed" not in state["reply"]
    assert not task.executed and not task.delegations


async def test_required_selection_cannot_bypass_task_scope():
    args = {"amount": 25000.0, "creditor_iban": LANDLORD_IBAN, "new_beneficiary": True, "reference": "Rent"}
    task = OfflineTask([completion("initiate_transfer", args)])
    task.scopes = []
    runtime, _ = await live("transfer", task)
    with pytest.raises(AegisDenied, match="allowlist"):
        await runtime.run(runtime.initial("Transfer EUR 25,000"))
    assert not task.delegations
    assert "initiate_transfer" not in {tool["function"]["name"] for tool in task.chat_requests[0]["tools"]}


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
            "completed",
            {
                **args,
                "customer_id": "C-1001",
                "payment_id": "offline-payment",
                "status": "accepted",
                "creditor_iban": "<IBAN_CODE>",
                "verification_hash": receipt_hash(
                    task.root_id,
                    "payments.initiate_transfer",
                    digest(
                        {
                            "customer_id": "C-1001",
                            **args,
                            "amount": str(money(args["amount"])),
                        }
                    ),
                ),
            },
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


@pytest.mark.parametrize(
    "tool,args",
    [
        (
            "payments.initiate_transfer",
            {"amount": 25.5, "creditor_iban": LANDLORD_IBAN, "new_beneficiary": True, "reference": "Rént"},
        ),
        ("crm.update_address", {"new_address": "Synthetic address with email jan@example.com"}),
    ],
)
async def test_change_receipts_bind_original_arguments_and_task_without_unmasking_pii(tool, args):
    from aegis.guard.pii import redact

    expected = {"customer_id": "C-1001", **args}
    if tool == "payments.initiate_transfer":
        expected["amount"] = str(money(args["amount"]))
    result = {
        "customer_id": "C-1001",
        **args,
        "verification_hash": receipt_hash("original-task", tool, digest(expected)),
    }
    redacted, count = redact(result)
    assert count and matches_change_receipt(redacted, tool, args, "original-task")
    assert not matches_change_receipt(redacted, tool, args, "another-task")
    changed = {
        **args,
        **(
            {"reference": "Different reference"}
            if tool.startswith("payments")
            else {"new_address": "Different address"}
        ),
    }
    assert not matches_change_receipt(redacted, tool, changed, "original-task")
    assert not matches_change_receipt({**redacted, "customer_id": "C-1002"}, tool, args, "original-task")
    assert not matches_change_receipt({**redacted, "verification_hash": "tampered"}, tool, args, "original-task")


async def test_mismatched_payment_receipt_is_uncertain_and_never_retried():
    args = {"amount": 25.0, "creditor_iban": LANDLORD_IBAN, "new_beneficiary": True, "reference": "Rent"}
    task = OfflineTask([completion("initiate_transfer", args)])
    task.approval_responses = [
        a2a_result(
            "completed",
            {
                **args,
                "customer_id": "C-1001",
                "status": "accepted",
                "payment_id": "offline-payment",
                "verification_hash": "does-not-match",
            },
        )
    ]
    runtime, _ = await live("transfer", task)
    state = await runtime.run(runtime.initial("Transfer EUR 25 to the synthetic landlord"))
    state["status"], state["confirmed"] = "running", True
    with pytest.raises(ExecutionUncertain, match="uncertain"):
        await runtime.run(state)
    assert len(task.delegations) == 1 and len(task.chat_requests) == 1


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
