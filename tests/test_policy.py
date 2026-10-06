"""PDP rules. The same cases run against OPA (the authoritative Rego) when an `opa` binary is available."""

import copy
import json
import shutil
import subprocess

import pytest

from aegis.common.settings import REPO_ROOT
from aegis.policy.engine import PythonEngine

POLICY_DIR = str(REPO_ROOT / "config" / "policies")
ENGINE = PythonEngine(POLICY_DIR)

BASE = {
    "subject": {"type": "agent", "id": "AGT-1", "properties": {"status": "active", "risk_tier": "medium",
                                                                "env": "PRD", "autonomy": "L1"}},
    "action": {"name": "tools/call", "properties": {"tool": "kyc.verify_document", "args": {}}},
    "resource": {"type": "mcp_tool", "id": "kyc.verify_document", "properties": {
        "intent_tags": ["customer.kyc.verify"], "side_effect": "write", "egress": "none",
        "returns_data_class": "confidential", "rate_limit_per_min": None, "untrusted_content": False,
        "required_entitlement": "own_kyc", "status": "approved", "pinned": True}},
    "context": {
        "user": {"id": "user:jan"},
        "mandate": {"id": "mdt_1", "scopes": ["kyc.verify_document"], "intent_categories": ["customer.kyc.verify"],
                    "max_data_class": "confidential", "entitlements": ["own_kyc"], "chain": ["AGT-1"], "depth": 0},
        "session": {"tainted": False, "max_data_class_read": "public", "external_egress": False},
        "approval": None,
    },
}


def case(**changes):
    value = copy.deepcopy(BASE)
    for path, new in changes.items():
        target = value
        keys = path.split("__")
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = new
    return value


TRANSFER = dict(
    action__properties={"tool": "payments.initiate_transfer",
                        "args": {"amount": 25000, "new_beneficiary": True}},
    resource__properties={"intent_tags": ["payments.transfer.initiate"], "side_effect": "financial",
                          "egress": "internal", "returns_data_class": "confidential", "rate_limit_per_min": 5,
                          "required_entitlement": None, "status": "approved", "pinned": True},
    context__mandate={"id": "mdt_2", "scopes": ["payments.initiate_transfer"],
                      "intent_categories": ["payments.transfer.initiate"], "max_data_class": "confidential",
                      "entitlements": [], "chain": ["AGT-1"], "depth": 1},
)
EMAIL = dict(
    action__properties={"tool": "notify.send_email", "args": {"to": "x@evil.example"}},
    resource__properties={"intent_tags": ["comms.external.send"], "side_effect": "write", "egress": "external",
                          "returns_data_class": "internal", "rate_limit_per_min": None,
                          "required_entitlement": None, "status": "approved", "pinned": True},
    context__mandate={"id": "mdt_3", "scopes": ["notify.send_email"], "intent_categories": ["comms.external.send"],
                      "max_data_class": "confidential", "entitlements": [], "chain": ["AGT-1"], "depth": 0},
)

CASES = {
    "allow_with_redaction": (case(), "allow", set()),
    "inactive_agent": (case(subject__properties={"status": "suspended", "risk_tier": "medium", "env": "PRD"}),
                       "deny", {"AGT-001"}),
    "outside_scope_and_purpose": (case(context__mandate={**BASE["context"]["mandate"], "scopes": [],
                                                          "intent_categories": ["payments.transfer.initiate"]}),
                                  "deny", {"SCP-001", "PUR-001"}),
    "missing_entitlement": (case(context__mandate={**BASE["context"]["mandate"], "entitlements": []}),
                            "deny", {"ENT-001"}),
    "above_data_ceiling": (case(context__mandate={**BASE["context"]["mandate"], "max_data_class": "internal"}),
                           "deny", {"DAT-001"}),
    "unpinned_tool": (case(resource__properties={**BASE["resource"]["properties"], "pinned": False}),
                      "deny", {"TOOL-001"}),
    "high_value_transfer": (case(**TRANSFER), "require_approval", {"PAY-010"}),
    "approved_transfer": (case(**TRANSFER, context__approval={"status": "approved"}), "allow", set()),
    "mismatched_approval": (case(**TRANSFER, context__approval={"status": "mismatch"}), "deny", {"APR-001"}),
    "clean_egress": (case(**EMAIL), "allow", set()),
    "lethal_trifecta": (case(**EMAIL, context__session={"tainted": True, "max_data_class_read": "confidential",
                                                        "external_egress": False}), "deny", {"IFC-001"}),
}


@pytest.mark.parametrize("name", CASES)
def test_python_engine(name):
    policy_input, expected, rules = CASES[name]
    result = ENGINE.decide(policy_input)
    assert result["decision"] == expected
    assert {r["rule"] for r in result["reasons"]} == rules


def test_obligations():
    result = ENGINE.decide(case(**TRANSFER, context__approval={"status": "approved"}))
    types = {o["type"] for o in result["obligations"]}
    assert types == {"redact", "rate_limit"}
    assert result["policy_version"].startswith("rego-")


@pytest.mark.skipif(shutil.which("opa") is None, reason="OPA binary not installed (runs in CI / Azure)")
@pytest.mark.parametrize("name", CASES)
def test_rego_matches_python_engine(name, tmp_path):
    policy_input, expected, rules = CASES[name]
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(policy_input))
    out = subprocess.run(["opa", "eval", "-f", "json", "-d", POLICY_DIR, "-i", str(input_file),
                          "data.aegis.tool_call.decision"], capture_output=True, text=True, check=True)
    result = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
    assert result["decision"] == expected
    assert {r["rule"] for r in result["reasons"]} == rules
