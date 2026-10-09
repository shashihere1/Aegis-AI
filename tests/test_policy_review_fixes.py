"""Regression tests for the issues an independent review found in the policy engines (each test names the issue)."""

import asyncio
import json
import math
import shutil

import httpx
import pytest
from fake_opa import FakeOpa
from policy_cases import GOVERNED_50K, POLICY_DIR, TRANSFER, case, python_inputs
from starlette.routing import Mount
from test_policy_engines_world import boot, studio, tool_decisions

from aegis.control.policies import ManagedEngine
from aegis.policy.arguments import MAX_BYTES, argument_problem
from aegis.policy.engines import (
    OpaEngine,
    PolicyUnavailable,
    RegoEngine,
    RegoRuntime,
    forget_opa_verification,
    normalize,
    rego_available,
    rego_fingerprint,
    rego_runtime,
    rego_sources,
)
from aegis.sdk import AegisDenied
from aegis_demo.world import BASE

pytestmark = pytest.mark.skipif(not rego_available(), reason="regopy not installed")
JAN = "jan.devries"


@pytest.fixture(autouse=True)
def fresh_verification():
    forget_opa_verification()
    yield
    forget_opa_verification()


# ---- line endings: a Windows checkout must not make OPA look like it runs different Rego -----------------


async def test_opa_reporting_crlf_rego_is_still_recognised_as_the_approved_policy():
    fake = FakeOpa(POLICY_DIR, line_endings="\r\n")
    assert "\r\n" in fake.modules[0]["raw"]
    engine = OpaEngine("http://opa.test", POLICY_DIR, httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app)))
    verdict = await engine.evaluate(python_inputs(case())[0])
    assert verdict["decision"] == "allow" and fake.decision_calls == 1


def test_the_same_rego_has_the_same_fingerprint_whatever_its_line_endings(tmp_path):
    crlf = tmp_path / "policies"
    shutil.copytree(POLICY_DIR, crlf)
    for rego in crlf.glob("*.rego"):
        rego.write_bytes(rego.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert rego_fingerprint(rego_sources(str(crlf))) == rego_fingerprint(rego_sources(POLICY_DIR))


# ---- the version stamped on a decision is the one that decided -------------------------------------------


async def test_a_decision_keeps_its_own_version_even_if_the_shared_attribute_moves_on(monkeypatch):
    original = ManagedEngine.evaluate

    async def concurrent_activation(self, policy_input):
        verdict = await original(self, policy_input)
        self.version = "pol_activated_meanwhile"  # another request saw a newer version while this one was deciding
        return verdict

    monkeypatch.setattr(ManagedEngine, "evaluate", concurrent_activation)
    world, shutdown = await boot(policy_engine="rego")
    try:
        assert (await studio(world, "scenarios/address-change"))["status"] == "completed"
        active = (await world.api("mark.jansen", "GET", "/v1/policies/versions")).json()["active_version"]
        stamps = {d["policy_version"] for d in await tool_decisions(world)}
        assert stamps == {active}
    finally:
        await shutdown()


# ---- untrusted tool arguments are refused before any engine sees them ---------------------------------------


@pytest.mark.parametrize(
    "arguments, fragment",
    [
        ({"amount": "NaN", "new_beneficiary": True}, "non-finite number written as text"),
        ({"amount": " -Infinity "}, "non-finite number written as text"),
        ({"amount": math.inf}, "not valid JSON"),
        ({"amount": math.nan}, "not valid JSON"),
        ({"amount": math.nextafter(10000.0, math.inf)}, "more precision"),
        ({"amount": 2**60}, "integer too large"),
        ({"note": "x" * (MAX_BYTES + 1)}, "larger than"),
        ({"deep": json.loads("[" * 40 + "]" * 40)}, "nested more than"),
        ({"many": list(range(5000))}, "more than"),
    ],
)
def test_unsafe_arguments_are_refused(arguments, fragment):
    problem = argument_problem(arguments)
    assert problem and fragment in problem


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"amount": 25000, "new_beneficiary": True},
        {"amount": 9999.99},
        {"amount": 0.1},
        {"to": "NL00", "memo": "naninf"},
    ],
)
def test_ordinary_arguments_pass(arguments):
    assert argument_problem(arguments) is None


async def test_the_gateway_refuses_a_nan_amount_even_on_the_default_python_engine(world):
    sdk = world.sdks["payments-agent"]
    task = await sdk.start_task("Initiate a payment transfer for the customer", user_token=world.token(JAN))
    with pytest.raises(AegisDenied) as refused:
        await task.call_tool("payments", "initiate_transfer", {"amount": "NaN", "new_beneficiary": True})
    assert "ARG-002" in refused.value.rules
    recorded = [d for d in await tool_decisions(world) if d["action"] == "payments.initiate_transfer"]
    assert recorded and recorded[0]["decision"] == "deny" and recorded[0]["reasons"][0]["rule"] == "ARG-002"


# ---- an incomplete governed configuration denies instead of silently skipping rules -------------------------


@pytest.mark.parametrize(
    "broken",
    [
        {"redact_entities": ["BSN"], "approval_side_effects_high_risk": []},
        {**GOVERNED_50K, "thresholds": {"payments": {"hitl_amount_eur": "10000"}}},
        {**GOVERNED_50K, "redact_entities": []},
        {**GOVERNED_50K, "redact_entities": [7]},
        {k: v for k, v in GOVERNED_50K.items() if k != "approval_side_effects_high_risk"},
    ],
)
def test_incomplete_governed_configuration_is_refused(broken):
    verdict = RegoEngine(POLICY_DIR, broken).decide(python_inputs(case(TRANSFER))[0])
    assert verdict["decision"] == "deny" and "CFG-001" in {r["rule"] for r in verdict["reasons"]}


# ---- replay never stores evidence from an unavailable engine -------------------------------------------------


async def test_replay_refuses_to_store_a_report_when_opa_is_unavailable():
    fake = FakeOpa(POLICY_DIR)
    world, shutdown = await boot(
        policy_engine="opa", opa_url=f"{BASE}/fake-opa", extra_routes=[Mount("/fake-opa", fake.app)]
    )
    try:
        assert (await studio(world, "scenarios/address-change"))["status"] == "completed"  # some traffic to replay
        configuration = (await world.api("mark.jansen", "GET", "/v1/policies")).json()["data"]
        draft = await world.api(
            "priya.raman",
            "POST",
            "/v1/policies/versions",
            json={"name": "Same again", "configuration": configuration, "justification": "Replay while OPA is down"},
        )
        vid = draft.json()["id"]
        fake.down = True
        forget_opa_verification()
        replay = await world.api("priya.raman", "POST", f"/v1/policies/{vid}/replay", json={})
        assert replay.status_code == 503 and "no replay was stored" in replay.text
        assert (await world.api("priya.raman", "POST", f"/v1/policies/{vid}/submit")).status_code == 409  # no evidence
    finally:
        await shutdown()


# ---- the Rego that runs is exactly the Rego that was checked; interpreters run in parallel safely ----------


def test_the_runtime_evaluates_exactly_the_sources_it_was_given():
    approved = rego_sources(POLICY_DIR)
    edited = {name: text.replace('"PRD"', '"NEVER"') for name, text in approved.items()}  # an unapproved edit
    destructive = python_inputs(
        case(
            action__properties={"tool": "core.delete_account", "args": {}},
            resource__properties={**case()["resource"]["properties"], "side_effect": "destructive"},
            context__mandate={**case()["context"]["mandate"], "scopes": ["core.delete_account"]},
        )
    )[0]
    with_approved = normalize(
        rego_runtime(POLICY_DIR, approved).query({**destructive, "policy_data": GOVERNED_50K}), "v"
    )
    with_edit = normalize(RegoRuntime(POLICY_DIR, edited).query({**destructive, "policy_data": GOVERNED_50K}), "v")
    assert with_approved["decision"] == "require_approval" and with_edit["decision"] == "allow"


async def test_concurrent_decisions_give_the_same_answers_as_sequential_ones():
    engine = RegoEngine(POLICY_DIR, GOVERNED_50K)
    inputs = [
        python_inputs(
            case(
                TRANSFER,
                action__properties={
                    "tool": "payments.initiate_transfer",
                    "args": {"amount": a, "new_beneficiary": True},
                },
            )
        )[0]
        for a in range(0, 100_000, 2_000)
    ]
    sequential = [engine.decide(i) for i in inputs]
    concurrent = await asyncio.gather(*(engine.evaluate(i) for i in inputs))
    assert concurrent == sequential
    assert {v["decision"] for v in sequential} == {"allow", "require_approval"}


def test_policy_unavailable_is_raised_for_input_that_is_not_json():
    with pytest.raises(PolicyUnavailable):
        RegoRuntime(POLICY_DIR).query({"amount": math.nan})
