"""PDP rules. The shared cases (tests/policy_cases.py) run through every engine:

- the Python mirror,
- the authoritative Rego in-process via regopy (always, when regopy is installed),
- the same Rego in a real OPA (`opa eval`, `opa test`, `opa check`) when an OPA binary is available - as in CI.
"""

import json
import subprocess

import pytest
from policy_cases import (
    CASES,
    POLICY_DIR,
    REGO_STRICTER,
    REGO_TEST_FILE,
    expected_obligation_types,
    python_inputs,
    render_rego_tests,
)

from aegis.policy.engine import PythonEngine
from aegis.policy.engines import normalize, rego_available
from aegis_demo.opa_setup import find_binary

ENGINE = PythonEngine(POLICY_DIR)
needs_rego = pytest.mark.skipif(not rego_available(), reason="regopy not installed")
OPA = find_binary()
needs_opa = pytest.mark.skipif(OPA is None, reason="no OPA binary (set AEGIS_OPA_BINARY; CI installs one)")


def python_result(policy_input: dict) -> dict:
    clean, data = python_inputs(policy_input)
    return normalize(PythonEngine(POLICY_DIR, data).decide(clean), "v")


def comparable(result: dict) -> dict:
    """Engines may return numbers as 5 or 5.0 and sets in any order; compare what they mean."""
    return json.loads(json.dumps({k: v for k, v in normalize(result, "v").items() if k != "policy_version"}))


@pytest.mark.parametrize("name", CASES)
def test_python_engine(name):
    policy_input, expected, rules = CASES[name]
    result = python_result(policy_input)
    assert result["decision"] == expected
    assert {r["rule"] for r in result["reasons"]} == rules


def test_obligations():
    result = ENGINE.decide(python_inputs(CASES["approved_transfer"][0])[0])
    assert {o["type"] for o in result["obligations"]} == {"redact", "rate_limit"}
    assert result["policy_version"].startswith("rego-")


@needs_rego
@pytest.mark.parametrize("name", CASES)
def test_rego_engine_matches_python_exactly(name):
    from aegis.policy.engines import RegoEngine

    policy_input, expected, rules = CASES[name]
    clean, data = python_inputs(policy_input)
    rego = RegoEngine(POLICY_DIR, data).decide(clean)  # the engine injects the governed data itself
    assert rego["decision"] == expected and {r["rule"] for r in rego["reasons"]} == rules
    assert comparable(rego) == comparable(python_result(policy_input))  # reasons, messages and obligations too


@needs_rego
@pytest.mark.parametrize("name", REGO_STRICTER)
def test_rego_refuses_malformed_or_hostile_input(name):
    from aegis.policy.engines import RegoEngine

    policy_input, rules = REGO_STRICTER[name]
    rego = RegoEngine(POLICY_DIR).decide(policy_input)
    assert rego["decision"] == "deny" and rules <= {r["rule"] for r in rego["reasons"]}


def test_amount_given_as_text_cannot_skip_approval_in_any_engine():
    hostile = REGO_STRICTER["transfer_amount_as_text"][0]
    assert python_result(hostile)["decision"] in {"deny", "require_approval"}  # Python coerces "25000" -> approval
    if rego_available():
        from aegis.policy.engines import RegoEngine

        assert RegoEngine(POLICY_DIR).decide(hostile)["decision"] == "deny"  # Rego refuses outright (ARG-001)


def test_generated_rego_unit_tests_are_up_to_date():
    assert REGO_TEST_FILE.read_text(encoding="utf-8") == render_rego_tests(expected_obligation_types()), (
        "config/policies/tool_call_test.rego is stale: run  python tests/policy_cases.py --write"
    )


@needs_rego
def test_generated_rego_unit_tests_parse():
    import regopy

    interpreter = regopy.Interpreter()
    interpreter.add_module("tool_call", (REGO_TEST_FILE.parent / "tool_call.rego").read_text(encoding="utf-8"))
    interpreter.add_module("tool_call_test", REGO_TEST_FILE.read_text(encoding="utf-8"))  # raises on a syntax error


# ---- real OPA (runs wherever a binary is available, e.g. CI) -------------------------------------


def opa_eval(policy_input: dict, tmp_path) -> dict:
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps(policy_input))
    out = subprocess.run(
        [OPA, "eval", "-f", "json", "-d", POLICY_DIR, "-i", str(input_file), "data.aegis.tool_call.decision"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout)["result"][0]["expressions"][0]["value"]


@needs_opa
@pytest.mark.parametrize("name", CASES)
def test_opa_matches_python_exactly(name, tmp_path):
    policy_input, expected, rules = CASES[name]
    result = opa_eval(policy_input, tmp_path)
    assert result["decision"] == expected and {r["rule"] for r in result["reasons"]} == rules
    assert comparable(result) == comparable(python_result(policy_input))


@needs_opa
@pytest.mark.parametrize("name", REGO_STRICTER)
def test_opa_refuses_malformed_or_hostile_input(name, tmp_path):
    policy_input, rules = REGO_STRICTER[name]
    result = opa_eval(policy_input, tmp_path)
    assert result["decision"] == "deny" and rules <= {r["rule"] for r in result["reasons"]}


@needs_opa
def test_opa_check_and_unit_tests_pass():
    check = subprocess.run([OPA, "check", POLICY_DIR], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    unit = subprocess.run([OPA, "test", POLICY_DIR, "-v"], capture_output=True, text=True)
    assert unit.returncode == 0, unit.stdout + unit.stderr
