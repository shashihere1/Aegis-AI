"""Differential testing: thousands of generated inputs through the Python mirror and the authoritative Rego (regopy).

- Well-formed inputs: the two engines must agree exactly (decision, reasons, messages, obligations).
- Malformed or hostile inputs: the Rego must never be more permissive than the Python mirror. "Permissive" orders
  deny (or an engine error, which the gateway turns into a deny) < require_approval < allow, and an engine that allows
  must not drop an obligation (redaction, rate limit) the other one imposes.

The generator is seeded, so a failure is reproducible; the failing input is printed.
"""

import copy
import json
import random

import pytest
from policy_cases import POLICY_DIR

from aegis.policy.engine import PythonEngine
from aegis.policy.engines import PolicyUnavailable, RegoRuntime, normalize, rego_available

pytestmark = pytest.mark.skipif(not rego_available(), reason="regopy not installed")

CLASSES = ["public", "internal", "confidential", "restricted"]
TOOLS = [
    "kyc.verify_document",
    "payments.initiate_transfer",
    "notify.send_email",
    "crm.get_customer",
    "core.delete_account",
]
CATEGORIES = ["customer.kyc.verify", "payments.transfer.initiate", "comms.external.send", "customer.inquiry.read"]
ENTITLEMENTS = ["own_kyc", "payments.approve", "own_accounts.read"]
STRICTNESS = {"deny": 0, "require_approval": 1, "allow": 2}


def subset(rng: random.Random, items: list) -> list:
    return [x for x in items if rng.random() < 0.5]


def well_formed(rng: random.Random) -> tuple[dict, dict]:
    tool = rng.choice(TOOLS)
    args: dict = {}
    if tool == "payments.initiate_transfer":
        args = {
            "amount": rng.choice([0, 1, 9999.99, 10000, 10000.01, 25000, 49999, 50000, 50001, 1_000_000]),
            "new_beneficiary": rng.choice([True, False]),
        }
    policy_input = {
        "subject": {
            "type": "agent",
            "id": f"AGT-{rng.randint(1, 9)}",
            "properties": {
                "status": rng.choice(["active", "active", "active", "suspended", "retired"]),
                "risk_tier": rng.choice(["low", "medium", "high", "critical"]),
                "env": rng.choice(["DEV", "TST", "ACC", "PRD"]),
            },
        },
        "action": {"name": "tools/call", "properties": {"tool": tool, "args": args}},
        "resource": {
            "type": "mcp_tool",
            "id": tool,
            "properties": {
                "intent_tags": subset(rng, CATEGORIES) or [rng.choice(CATEGORIES)],
                "side_effect": rng.choice(["read", "write", "financial", "destructive"]),
                "egress": rng.choice(["none", "internal", "external"]),
                "returns_data_class": rng.choice(CLASSES),
                "rate_limit_per_min": rng.choice([None, None, 0, 1, 5, 60]),
                "required_entitlement": rng.choice([None, None, *ENTITLEMENTS]),
                "status": rng.choice(["approved", "approved", "approved", "quarantined", "pending"]),
                "pinned": rng.choice([True, True, True, False]),
            },
        },
        "context": {
            "mandate": {
                "scopes": subset(rng, TOOLS) + (["pii.unmasked"] if rng.random() < 0.2 else []),
                "intent_categories": subset(rng, CATEGORIES),
                "max_data_class": rng.choice(CLASSES),
                "entitlements": subset(rng, ENTITLEMENTS),
            },
            "session": {"tainted": rng.choice([True, False]), "max_data_class_read": rng.choice(CLASSES)},
            "approval": rng.choice([None, None, {"status": "approved"}, {"status": "mismatch"}, {"status": "pending"}]),
        },
    }
    # Bias towards inputs that pass the scope checks, so the approval and obligation rules are exercised too.
    if rng.random() < 0.6:
        mandate = policy_input["context"]["mandate"]
        mandate["scopes"] = sorted(set(mandate["scopes"]) | {tool})
        mandate["intent_categories"] = sorted(
            set(mandate["intent_categories"]) | set(policy_input["resource"]["properties"]["intent_tags"][:1])
        )
    data = {
        "thresholds": {"payments": {"hitl_amount_eur": rng.choice([0, 10000, 50000, 999999.5])}},
        "redact_entities": subset(rng, ["BSN", "IBAN_CODE", "EMAIL_ADDRESS", "PHONE_NUMBER"]) or ["BSN"],
        "approval_side_effects_high_risk": subset(rng, ["financial", "destructive"]) or ["financial"],
    }
    return policy_input, data


ODD_VALUES = [None, "", "25000", "secret", True, False, 0, -1, 1.5, [], ["x"], {}, {"a": 1}]
PATHS = [
    ("subject",),
    ("subject", "id"),
    ("subject", "properties"),
    ("subject", "properties", "status"),
    ("subject", "properties", "risk_tier"),
    ("subject", "properties", "env"),
    ("action", "properties", "tool"),
    ("action", "properties", "args"),
    ("action", "properties", "args", "amount"),
    ("action", "properties", "args", "new_beneficiary"),
    ("resource", "properties"),
    ("resource", "properties", "status"),
    ("resource", "properties", "pinned"),
    ("resource", "properties", "intent_tags"),
    ("resource", "properties", "returns_data_class"),
    ("resource", "properties", "side_effect"),
    ("resource", "properties", "egress"),
    ("resource", "properties", "rate_limit_per_min"),
    ("resource", "properties", "required_entitlement"),
    ("context",),
    ("context", "mandate"),
    ("context", "mandate", "scopes"),
    ("context", "mandate", "intent_categories"),
    ("context", "mandate", "max_data_class"),
    ("context", "mandate", "entitlements"),
    ("context", "session", "tainted"),
    ("context", "session", "max_data_class_read"),
    ("context", "approval"),
]


def mutate(rng: random.Random, policy_input: dict) -> dict:
    value = copy.deepcopy(policy_input)
    for _ in range(rng.randint(1, 3)):
        path = rng.choice(PATHS)
        target = value
        for key in path[:-1]:
            if not isinstance(target, dict) or not isinstance(target.get(key), dict):
                break
            target = target[key]
        else:
            if rng.random() < 0.35:
                target.pop(path[-1], None)
            else:
                target[path[-1]] = copy.deepcopy(rng.choice(ODD_VALUES))
    return value


def python_verdict(policy_input: dict, data: dict) -> dict | None:
    try:
        return normalize(PythonEngine(POLICY_DIR, data).decide(copy.deepcopy(policy_input)), "v")
    except Exception:  # the gateway turns an engine error into a recorded deny
        return None


RUNTIME = None


def rego_verdict(policy_input: dict, data: dict) -> dict | None:
    global RUNTIME
    if RUNTIME is None or RUNTIME.broken:
        RUNTIME = RegoRuntime(POLICY_DIR)
    try:
        return normalize(RUNTIME.query({**policy_input, "policy_data": data}), "v")
    except PolicyUnavailable:
        return None


def comparable(verdict: dict) -> dict:
    return json.loads(json.dumps({k: v for k, v in verdict.items() if k != "policy_version"}))


def strictness(verdict: dict | None) -> int:
    return 0 if verdict is None else STRICTNESS[verdict["decision"]]


def obligations_kept(looser: dict, stricter: dict) -> bool:
    """When the Rego allows, it must impose every obligation the Python mirror imposes."""
    return all(o in looser["obligations"] for o in stricter["obligations"])


@pytest.mark.parametrize("seed", range(6))
def test_well_formed_inputs_agree_exactly(seed):
    rng = random.Random(1000 + seed)
    for n in range(400):
        policy_input, data = well_formed(rng)
        python, rego = python_verdict(policy_input, data), rego_verdict(policy_input, data)
        assert python is not None and rego is not None, (
            f"engine failed on a well-formed input #{n}: {json.dumps(policy_input)}"
        )
        assert comparable(rego) == comparable(python), (
            f"seed {seed} input #{n}\nINPUT {json.dumps(policy_input)}\nDATA {json.dumps(data)}\n"
            f"PYTHON {json.dumps(comparable(python))}\nREGO   {json.dumps(comparable(rego))}"
        )


@pytest.mark.parametrize("seed", range(6))
def test_malformed_inputs_never_make_the_rego_more_permissive(seed):
    rng = random.Random(2000 + seed)
    for n in range(400):
        base, data = well_formed(rng)
        policy_input = mutate(rng, base)
        python, rego = python_verdict(policy_input, data), rego_verdict(policy_input, data)
        detail = (
            f"seed {seed} input #{n}\nINPUT {json.dumps(policy_input)}\nDATA {json.dumps(data)}\n"
            f"PYTHON {json.dumps(python and comparable(python))}\nREGO   {json.dumps(rego and comparable(rego))}"
        )
        assert strictness(rego) <= strictness(python), "the Rego is more permissive than the Python mirror\n" + detail
        if rego is not None and python is not None and rego["decision"] == python["decision"] != "deny":
            assert obligations_kept(rego, python), "the Rego dropped an obligation\n" + detail


def test_a_reused_interpreter_gives_the_same_answers_as_a_fresh_one():
    """One regopy interpreter serves every decision; earlier inputs must never leak into later answers."""
    rng = random.Random(77)
    shared = RegoRuntime(POLICY_DIR)
    samples = [well_formed(rng) for _ in range(60)]
    for policy_input, data in samples:
        shared.query({**policy_input, "policy_data": data})
    for policy_input, data in samples[:25]:
        fresh = RegoRuntime(POLICY_DIR).query({**policy_input, "policy_data": data})
        again = shared.query({**policy_input, "policy_data": data})
        assert comparable(normalize(again, "v")) == comparable(normalize(fresh, "v"))


def test_the_governed_data_always_wins_over_policy_data_smuggled_into_the_input():
    from policy_cases import TRANSFER, case

    from aegis.policy.engines import RegoEngine

    forged = case(TRANSFER, policy_data={"thresholds": {"payments": {"hitl_amount_eur": 10**9}}})
    governed = {
        "thresholds": {"payments": {"hitl_amount_eur": 10000}},
        "redact_entities": ["BSN"],
        "approval_side_effects_high_risk": ["financial"],
    }
    verdict = RegoEngine(POLICY_DIR, governed).decide(forged)  # the caller tried to lift the threshold to 1e9
    assert verdict["decision"] == "require_approval" and [r["rule"] for r in verdict["reasons"]] == ["PAY-010"]
