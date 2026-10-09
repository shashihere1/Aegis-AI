"""Shared policy cases: one source of truth for the Python, Rego (regopy) and OPA tests, and for the Rego unit tests.

    python tests/policy_cases.py --write     # regenerate config/policies/tool_call_test.rego after changing cases

tests/test_policy.py checks that the generated file is up to date, so the Rego unit tests that `opa test` runs in CI
always describe exactly the cases the Python and regopy tests verify locally.
"""

import copy
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POLICY_DIR = str(REPO / "config" / "policies")
REGO_TEST_FILE = Path(POLICY_DIR) / "tool_call_test.rego"

BASE = {
    "subject": {
        "type": "agent",
        "id": "AGT-1",
        "properties": {"status": "active", "risk_tier": "medium", "env": "PRD", "autonomy": "L1"},
    },
    "action": {"name": "tools/call", "properties": {"tool": "kyc.verify_document", "args": {}}},
    "resource": {
        "type": "mcp_tool",
        "id": "kyc.verify_document",
        "properties": {
            "intent_tags": ["customer.kyc.verify"],
            "side_effect": "write",
            "egress": "none",
            "returns_data_class": "confidential",
            "rate_limit_per_min": None,
            "untrusted_content": False,
            "required_entitlement": "own_kyc",
            "status": "approved",
            "pinned": True,
        },
    },
    "context": {
        "user": {"id": "user:jan"},
        "mandate": {
            "id": "mdt_1",
            "scopes": ["kyc.verify_document"],
            "intent_categories": ["customer.kyc.verify"],
            "max_data_class": "confidential",
            "entitlements": ["own_kyc"],
            "chain": ["AGT-1"],
            "depth": 0,
        },
        "session": {"tainted": False, "max_data_class_read": "public", "external_egress": False},
        "approval": None,
    },
}


def case(*bases: dict, **changes):
    """A copy of BASE with changes applied. `a__b__c=value` sets value["a"]["b"]["c"]; dict bases are applied first."""
    value = copy.deepcopy(BASE)
    merged: dict = {}
    for base in bases:
        merged.update(base)
    merged.update(changes)
    for path, new in merged.items():
        target = value
        keys = path.split("__")
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = copy.deepcopy(new)
    return value


MANDATE = BASE["context"]["mandate"]
TOOL = BASE["resource"]["properties"]

TRANSFER = dict(
    action__properties={"tool": "payments.initiate_transfer", "args": {"amount": 25000, "new_beneficiary": True}},
    resource__properties={
        "intent_tags": ["payments.transfer.initiate"],
        "side_effect": "financial",
        "egress": "internal",
        "returns_data_class": "confidential",
        "rate_limit_per_min": 5,
        "required_entitlement": None,
        "status": "approved",
        "pinned": True,
    },
    context__mandate={
        "id": "mdt_2",
        "scopes": ["payments.initiate_transfer"],
        "intent_categories": ["payments.transfer.initiate"],
        "max_data_class": "confidential",
        "entitlements": [],
        "chain": ["AGT-1"],
        "depth": 1,
    },
)
EMAIL = dict(
    action__properties={"tool": "notify.send_email", "args": {"to": "x@evil.example"}},
    resource__properties={
        "intent_tags": ["comms.external.send"],
        "side_effect": "write",
        "egress": "external",
        "returns_data_class": "internal",
        "rate_limit_per_min": None,
        "required_entitlement": None,
        "status": "approved",
        "pinned": True,
    },
    context__mandate={
        "id": "mdt_3",
        "scopes": ["notify.send_email"],
        "intent_categories": ["comms.external.send"],
        "max_data_class": "confidential",
        "entitlements": [],
        "chain": ["AGT-1"],
        "depth": 0,
    },
)
DELETE = dict(
    action__properties={"tool": "core.delete_account", "args": {"account": "NL00"}},
    resource__properties={**TOOL, "side_effect": "destructive", "intent_tags": ["customer.kyc.verify"]},
    context__mandate={**MANDATE, "scopes": ["core.delete_account"]},
)
GOVERNED_50K = {
    "thresholds": {"payments": {"hitl_amount_eur": 50000}},
    "redact_entities": ["BSN"],
    "approval_side_effects_high_risk": ["financial", "destructive"],
}

# name -> (input, expected decision, expected rule ids). Every engine must produce exactly this.
CASES = {
    "allow_with_redaction": (case(), "allow", set()),
    "inactive_agent": (
        case(subject__properties={"status": "suspended", "risk_tier": "medium", "env": "PRD"}),
        "deny",
        {"AGT-001"},
    ),
    "critical_risk_agent": (
        case(subject__properties={"status": "active", "risk_tier": "critical", "env": "PRD"}),
        "deny",
        {"RSK-001"},
    ),
    "outside_scope_and_purpose": (
        case(context__mandate={**MANDATE, "scopes": [], "intent_categories": ["payments.transfer.initiate"]}),
        "deny",
        {"SCP-001", "PUR-001"},
    ),
    "missing_entitlement": (case(context__mandate={**MANDATE, "entitlements": []}), "deny", {"ENT-001"}),
    "above_data_ceiling": (case(context__mandate={**MANDATE, "max_data_class": "internal"}), "deny", {"DAT-001"}),
    "unpinned_tool": (case(resource__properties={**TOOL, "pinned": False}), "deny", {"TOOL-001"}),
    "high_value_transfer": (case(TRANSFER), "require_approval", {"PAY-010"}),
    "transfer_at_threshold": (
        case(
            TRANSFER,
            action__properties={
                "tool": "payments.initiate_transfer",
                "args": {"amount": 10000, "new_beneficiary": True},
            },
        ),
        "allow",
        set(),
    ),
    "transfer_to_known_beneficiary": (
        case(
            TRANSFER,
            action__properties={
                "tool": "payments.initiate_transfer",
                "args": {"amount": 25000, "new_beneficiary": False},
            },
        ),
        "allow",
        set(),
    ),
    "approved_transfer": (case(TRANSFER, context__approval={"status": "approved"}), "allow", set()),
    "mismatched_approval": (case(TRANSFER, context__approval={"status": "mismatch"}), "deny", {"APR-001"}),
    "high_risk_agent_financial": (
        case(
            TRANSFER,
            subject__properties={"status": "active", "risk_tier": "high", "env": "PRD"},
            action__properties={
                "tool": "payments.initiate_transfer",
                "args": {"amount": 100, "new_beneficiary": False},
            },
        ),
        "require_approval",
        {"RSK-002"},
    ),
    "destructive_in_production": (case(DELETE), "require_approval", {"DES-001"}),
    "destructive_in_test": (
        case(DELETE, subject__properties={"status": "active", "risk_tier": "medium", "env": "TST"}),
        "allow",
        set(),
    ),
    "unmasked_pii_scope": (
        case(context__mandate={**MANDATE, "scopes": ["kyc.verify_document", "pii.unmasked"]}),
        "allow",
        set(),
    ),
    "clean_egress": (case(EMAIL), "allow", set()),
    "lethal_trifecta": (
        case(
            EMAIL, context__session={"tainted": True, "max_data_class_read": "confidential", "external_egress": False}
        ),
        "deny",
        {"IFC-001"},
    ),
    "governed_threshold_raised": (case(TRANSFER, policy_data=GOVERNED_50K), "allow", set()),
}

# Malformed or hostile inputs the Rego must refuse. In most of them it is deliberately STRICTER than the Python
# mirror (which may coerce or accept them); it must never be looser.
REGO_STRICTER = {
    "transfer_amount_as_text": (
        case(
            TRANSFER,
            action__properties={
                "tool": "payments.initiate_transfer",
                "args": {"amount": "25000", "new_beneficiary": True},
            },
        ),
        {"ARG-001"},
    ),
    "transfer_amount_as_boolean": (
        case(
            TRANSFER,
            action__properties={
                "tool": "payments.initiate_transfer",
                "args": {"amount": True, "new_beneficiary": True},
            },
        ),
        {"ARG-001"},
    ),
    "unknown_data_ceiling": (case(context__mandate={**MANDATE, "max_data_class": "top-secret"}), {"DAT-001"}),
    "scopes_given_as_text": (
        case(context__mandate={**MANDATE, "scopes": "kyc.verify_document pii.unmasked"}),
        {"SCP-001"},
    ),
    "tool_name_not_text": (case(action__properties={"tool": ["kyc.verify_document"], "args": {}}), {"INP-001"}),
    "missing_subject_id": (
        case(subject={"type": "agent", "properties": BASE["subject"]["properties"]}),
        {"INP-001"},
    ),
    "missing_agent_status": (case(subject__properties={"risk_tier": "medium", "env": "PRD"}), {"AGT-001"}),
}


def python_inputs(policy_input: dict) -> tuple[dict, dict | None]:
    """Split a case for the Python engine, which takes governed data as a constructor argument, not in the input."""
    data = policy_input.get("policy_data")
    return {k: v for k, v in policy_input.items() if k != "policy_data"}, data


def _rego_set(values) -> str:
    return "{" + ", ".join(json.dumps(v) for v in sorted(values)) + "}" if values else "set()"


def render_rego_tests(obligation_types: dict[str, set[str]]) -> str:
    lines = [
        "# GENERATED by tests/policy_cases.py from the shared policy cases - do not edit by hand.",
        "# Run with:  opa test config/policies -v   (CI does; python -m aegis_demo.opa_setup test locally)",
        "package aegis.tool_call_test",
        "",
        "import rego.v1",
        "",
        "import data.aegis.tool_call",
        "",
    ]
    for name, (policy_input, decision, rules) in CASES.items():
        lines += [
            f"test_{name} if {{",
            f"\td := tool_call.decision with input as {json.dumps(policy_input, sort_keys=True)}",
            f'\td.decision == "{decision}"',
            f"\t{{r.rule | some r in d.reasons}} == {_rego_set(rules)}",
            f"\t{{o.type | some o in d.obligations}} == {_rego_set(obligation_types[name])}",
            "}",
            "",
        ]
    for name, (policy_input, rules) in REGO_STRICTER.items():
        lines += [
            f"test_stricter_{name} if {{",
            f"\td := tool_call.decision with input as {json.dumps(policy_input, sort_keys=True)}",
            '\td.decision == "deny"',
            f"\t({_rego_set(rules)} & {{r.rule | some r in d.reasons}}) == {_rego_set(rules)}",
            "}",
            "",
        ]
    return "\n".join(lines).rstrip("\n") + "\n"


def expected_obligation_types() -> dict[str, set[str]]:
    sys.path.insert(0, str(REPO / "src"))
    from aegis.policy.engine import PythonEngine

    types = {}
    for name, (policy_input, _decision, _rules) in CASES.items():
        clean, data = python_inputs(policy_input)
        result = PythonEngine(POLICY_DIR, data).decide(clean)
        types[name] = {o["type"] for o in result["obligations"]}
    return types


if __name__ == "__main__":
    if "--write" in sys.argv:
        REGO_TEST_FILE.write_text(render_rego_tests(expected_obligation_types()), encoding="utf-8")
        print(f"wrote {REGO_TEST_FILE}")
    else:
        print(render_rego_tests(expected_obligation_types()))
