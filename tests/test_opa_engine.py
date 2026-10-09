"""The OPA client: decisions, the "OPA runs the approved Rego" check, governed data, and every way OPA can fail.

Most tests use a fake OPA that answers with the real Rego (regopy); the last ones start a real OPA server when a
binary is available (CI).
"""

import json
import socket
import subprocess
import time

import httpx
import pytest
from fake_opa import FakeOpa
from policy_cases import CASES, GOVERNED_50K, POLICY_DIR, TRANSFER, case, python_inputs

from aegis.policy.engine import PythonEngine
from aegis.policy.engines import OpaEngine, PolicyUnavailable, forget_opa_verification, normalize, rego_available
from aegis_demo.opa_setup import find_binary, server_command

pytestmark = pytest.mark.skipif(not rego_available(), reason="the fake OPA evaluates the Rego with regopy")
URL = "http://opa.test"


@pytest.fixture(autouse=True)
def fresh_verification():
    forget_opa_verification()
    yield
    forget_opa_verification()


def client(fake: FakeOpa):
    """A factory of OPA engines that talk to the fake server."""
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app))
    return lambda **kw: OpaEngine(URL, POLICY_DIR, http, **kw)


def comparable(verdict: dict) -> dict:
    return json.loads(json.dumps({k: v for k, v in normalize(verdict, "v").items() if k != "policy_version"}))


@pytest.mark.parametrize("name", CASES)
async def test_decisions_through_opa_match_the_python_engine(name):
    fake = FakeOpa(POLICY_DIR)
    policy_input, _expected, _rules = CASES[name]
    clean, data = python_inputs(policy_input)
    verdict = await client(fake)(data=data, version="pol_7").evaluate(clean)
    assert verdict["policy_version"] == "pol_7"  # the governed version that decided, not a local file hash
    assert comparable(verdict) == comparable(PythonEngine(POLICY_DIR, data).decide(clean))


async def test_the_governed_configuration_travels_with_every_decision():
    fake = FakeOpa(POLICY_DIR)
    transfer = python_inputs(case(TRANSFER))[0]
    default = await client(fake)(version="v1").evaluate(transfer)
    governed = await client(fake)(data=GOVERNED_50K, version="v2").evaluate(transfer)
    assert default["decision"] == "require_approval" and governed["decision"] == "allow"
    assert fake.inputs[-1]["policy_data"] == GOVERNED_50K
    smuggled = await client(fake)(data=GOVERNED_50K, version="v2").evaluate(
        {**transfer, "policy_data": {"thresholds": {"payments": {"hitl_amount_eur": 0}}}}
    )
    assert smuggled["decision"] == "allow" and fake.inputs[-1]["policy_data"] == GOVERNED_50K  # caller cannot override


async def test_opa_running_different_rego_is_refused():
    fake = FakeOpa(POLICY_DIR)
    fake.modules[0] = {**fake.modules[0], "raw": fake.modules[0]["raw"].replace('"PRD"', '"NOPE"')}
    with pytest.raises(PolicyUnavailable, match="does not run the approved policy"):
        await client(fake)().evaluate(python_inputs(case())[0])
    assert fake.decision_calls == 0  # it never asked for a decision


async def test_opa_without_the_aegis_policy_is_refused():
    fake = FakeOpa(POLICY_DIR)
    fake.modules = [m for m in fake.modules if m["id"].endswith("_test.rego")]
    with pytest.raises(PolicyUnavailable, match="missing"):
        await client(fake)().evaluate(python_inputs(case())[0])
    fake = FakeOpa(POLICY_DIR)
    fake.no_result = True
    with pytest.raises(PolicyUnavailable, match="no decision"):
        await client(fake)().evaluate(python_inputs(case())[0])


@pytest.mark.parametrize(
    "extra",
    [
        {"id": "/opa/evil.rego", "raw": "package aegis.tool_call\n"},
        {
            "id": "/opa/evil_test.rego",
            "raw": "package aegis.tool_call\nimport rego.v1\n",
        },  # a test-like name is no pass
        {
            "id": "/elsewhere/tool_call_test.rego",
            "raw": "package aegis.tool_call\n",
        },  # our test file's name, other content
    ],
)
async def test_any_module_beyond_the_approved_policy_is_refused(extra):
    fake = FakeOpa(POLICY_DIR)
    fake.modules = [m for m in fake.modules if not m["id"].endswith("_test.rego")] + [extra]
    with pytest.raises(PolicyUnavailable, match="does not run the approved policy"):
        await client(fake)().evaluate(python_inputs(case())[0])
    assert fake.decision_calls == 0


async def test_a_listing_with_duplicate_or_malformed_modules_is_refused():
    fake = FakeOpa(POLICY_DIR)
    fake.modules = fake.modules + [dict(fake.modules[0], id="/other/tool_call.rego")]
    with pytest.raises(PolicyUnavailable, match="two modules"):
        await client(fake)().evaluate(python_inputs(case())[0])
    forget_opa_verification()
    fake = FakeOpa(POLICY_DIR)
    fake.modules = "not a list"
    with pytest.raises(PolicyUnavailable, match="did not list"):
        await client(fake)().evaluate(python_inputs(case())[0])


async def test_the_policy_check_is_cached_and_test_modules_are_ignored():
    fake = FakeOpa(POLICY_DIR)
    assert any(m["id"].endswith("_test.rego") for m in fake.modules)  # loaded test modules do not break the check
    engine = client(fake)()
    for _ in range(5):
        await engine.evaluate(python_inputs(case())[0])
    assert fake.policy_calls == 1 and fake.decision_calls == 5
    forget_opa_verification()
    await engine.evaluate(python_inputs(case())[0])
    assert fake.policy_calls == 2


@pytest.mark.parametrize(
    "breakage, message",
    [
        ({"down": True}, "HTTP 503"),
        ({"not_json": True}, "not JSON"),
        ({"result": {"decision": "permit"}}, "unknown decision"),
        ({"result": {"decision": "deny", "reasons": [], "obligations": []}}, "without a reason"),
        ({"result": {"decision": "allow", "reasons": [], "obligations": [{"type": "teleport"}]}}, "unknown obligation"),
        ({"result": "allow"}, "no decision"),
        ({"result": {"decision": "allow", "reasons": "none", "obligations": []}}, "malformed"),
    ],
)
async def test_anything_but_a_well_formed_decision_is_refused(breakage, message):
    fake = FakeOpa(POLICY_DIR)
    engine = client(fake)()
    await engine.verify_policy()  # get past the policy check so the decision call itself is tested
    for key, value in breakage.items():
        setattr(fake, key, value)
    with pytest.raises(PolicyUnavailable, match=message):
        await engine.evaluate(python_inputs(case())[0])


async def test_a_slow_opa_fails_closed_within_the_timeout():
    fake = FakeOpa(POLICY_DIR)
    fake.delay = 3.0
    started = time.monotonic()
    with pytest.raises(PolicyUnavailable, match="unreachable"):
        await client(fake)(timeout=0.3).evaluate(python_inputs(case())[0])
    assert time.monotonic() - started < 2.0


async def test_an_unreachable_opa_fails_closed():
    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)

    engine = OpaEngine(URL, POLICY_DIR, httpx.AsyncClient(transport=httpx.MockTransport(refuse)))
    with pytest.raises(PolicyUnavailable, match="unreachable"):
        await engine.evaluate(python_inputs(case())[0])


async def test_the_bearer_token_is_sent_when_configured():
    fake = FakeOpa(POLICY_DIR)
    await client(fake)(token="s3cret").evaluate(python_inputs(case())[0])
    assert set(fake.authorizations) == {"Bearer s3cret"}
    fake.authorizations.clear()
    forget_opa_verification()
    await client(fake)().evaluate(python_inputs(case())[0])
    assert set(fake.authorizations) == {""}


# ---- a real OPA server (CI, or wherever a binary is available) --------------------------------------

OPA = find_binary()


@pytest.fixture
def real_opa():
    if OPA is None:
        pytest.skip("no OPA binary (set AEGIS_OPA_BINARY; CI installs one)")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen(server_command(OPA, port), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if httpx.get(f"{url}/health", timeout=0.5).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            raise RuntimeError("OPA did not start")
        yield url
    finally:
        process.terminate()
        process.wait(timeout=10)


async def test_a_real_opa_server_decides_exactly_like_the_python_engine(real_opa):
    async with httpx.AsyncClient() as http:
        for name, (policy_input, expected, rules) in CASES.items():
            clean, data = python_inputs(policy_input)
            verdict = await OpaEngine(real_opa, POLICY_DIR, http, data, "pol_x").evaluate(clean)
            assert verdict["decision"] == expected and {r["rule"] for r in verdict["reasons"]} == rules, name
            assert comparable(verdict) == comparable(PythonEngine(POLICY_DIR, data).decide(clean)), name


async def test_a_real_opa_server_passes_the_loaded_policy_check(real_opa):
    async with httpx.AsyncClient() as http:
        await OpaEngine(real_opa, POLICY_DIR, http).verify_policy()  # raises if OPA's modules differ from ours
