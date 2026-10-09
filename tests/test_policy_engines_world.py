"""The whole system with the Rego engines: the demo journey, the governed policy lifecycle, failing closed, and
switching engines on a running system. `rego` evaluates the real Rego in-process; `opa` talks to a fake OPA server
(the real Rego via regopy) mounted in-process, or to a real OPA when one is available."""

import asyncio
import copy

import pytest
from fake_opa import FakeOpa
from policy_cases import POLICY_DIR
from starlette.routing import Mount
from test_governance import test_policy_changes_replay_approval_activation_and_rollback as governed_lifecycle

from aegis.policy.engines import forget_opa_verification, rego_available
from aegis_demo import data, mcp_servers
from aegis_demo.world import BASE, FAKE_LLM_URL, running_world

pytestmark = pytest.mark.skipif(not rego_available(), reason="regopy not installed")
_CUSTOMERS = copy.deepcopy(data.CUSTOMERS)


async def boot(**overrides):
    """Start a world in its own task (the MCP SDK needs one task to own the lifespan) and return (world, stop)."""
    mcp_servers.SENT_EMAILS.clear()
    mcp_servers.TRANSFERS.clear()
    data.CUSTOMERS.clear()
    data.CUSTOMERS.update(copy.deepcopy(_CUSTOMERS))
    forget_opa_verification()
    ready: asyncio.Future = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()

    async def owner():
        async with running_world(llm_upstream_url=FAKE_LLM_URL, **overrides) as w:
            ready.set_result(w)
            await stop.wait()

    task = asyncio.create_task(owner())
    await asyncio.wait({task, ready}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        task.result()

    async def shutdown():
        stop.set()
        await task

    return ready.result(), shutdown


@pytest.fixture
async def rego_world():
    world, shutdown = await boot(policy_engine="rego")
    yield world
    await shutdown()


@pytest.fixture
async def opa_world():
    fake = FakeOpa(POLICY_DIR)
    world, shutdown = await boot(
        policy_engine="opa", opa_url=f"{BASE}/fake-opa", extra_routes=[Mount("/fake-opa", fake.app)]
    )
    world.fake_opa = fake
    yield world
    await shutdown()


async def studio(world, path: str, body: dict | None = None) -> dict:
    response = await world.http.post(f"{BASE}/demo/api/{path}", json=body or {})
    assert response.status_code == 200, response.text
    return response.json()


async def active_version(world) -> str:
    return (await world.api("mark.jansen", "GET", "/v1/policies/versions")).json()["active_version"]


async def tool_decisions(world) -> list[dict]:
    return [d for d in (await world.api("mark.jansen", "GET", "/v1/decisions")).json() if ":" not in d["action"]]


# ---- rego ---------------------------------------------------------------------------------------------


async def test_the_demo_journey_runs_on_the_real_rego(rego_world):
    assert (await studio(rego_world, "scenarios/address-change"))["status"] == "completed"
    version = await active_version(rego_world)
    decisions = await tool_decisions(rego_world)
    assert decisions and all(d["policy_version"] == version for d in decisions)  # stamped with the governed version
    policies = (await rego_world.api("mark.jansen", "GET", "/v1/policies")).json()
    assert policies["engine"] == "rego"
    health = (await rego_world.http.get(f"{BASE}/gw/health")).json()
    assert health["policy_engine"] == "rego" and health["policy_version"] == version


async def test_the_governed_lifecycle_works_on_the_real_rego(rego_world):
    await governed_lifecycle(rego_world)  # draft -> replay -> approve -> activate -> rollback, all evaluated by Rego


async def test_the_attack_is_still_contained_on_the_real_rego(rego_world):
    run = await studio(rego_world, "scenarios/attack")
    assert run["status"] == "contained" and mcp_servers.SENT_EMAILS == []


# ---- opa (fake server in-process) -----------------------------------------------------------------------


async def test_the_demo_journey_runs_through_opa_with_the_governed_configuration(opa_world):
    assert (await studio(opa_world, "scenarios/address-change"))["status"] == "completed"
    fake = opa_world.fake_opa
    assert fake.decision_calls > 0 and fake.policy_calls >= 1  # it checked OPA's loaded policy, then asked it
    configuration = (await opa_world.api("mark.jansen", "GET", "/v1/policies")).json()["data"]
    assert all(i["policy_data"] == configuration for i in fake.inputs)  # every decision carried the approved data
    version = await active_version(opa_world)
    assert all(d["policy_version"] == version for d in await tool_decisions(opa_world))


async def test_the_governed_lifecycle_works_through_opa(opa_world):
    await governed_lifecycle(opa_world)


async def test_when_opa_is_down_calls_are_refused_and_the_refusal_is_recorded(opa_world):
    opa_world.fake_opa.down = True
    forget_opa_verification()
    run = await studio(opa_world, "scenarios/address-change")
    assert run["status"] == "blocked"
    refused = [d for d in await tool_decisions(opa_world) if d["decision"] == "deny"]
    assert refused and any(r["rule"] == "PDP-001" for d in refused for r in d["reasons"])  # evidence, not a 500
    opa_world.fake_opa.down = False
    assert (await studio(opa_world, "scenarios/address-change"))["status"] == "completed"  # recovers by itself


async def test_an_unexpected_answer_from_opa_is_never_treated_as_allow(opa_world):
    opa_world.fake_opa.result = {"decision": "permit", "reasons": [], "obligations": []}
    run = await studio(opa_world, "scenarios/address-change")
    assert run["status"] == "blocked"
    assert any(r["rule"] == "PDP-001" for d in await tool_decisions(opa_world) for r in d["reasons"])


async def test_opa_running_tampered_rego_is_refused(opa_world):
    fake = opa_world.fake_opa
    fake.modules[0] = {**fake.modules[0], "raw": fake.modules[0]["raw"] + "\n# tampered\n"}
    forget_opa_verification()
    assert (await studio(opa_world, "scenarios/address-change"))["status"] == "blocked"
    assert fake.decision_calls == 0  # no decision was even requested from the untrusted server


# ---- switching engines on a running system ------------------------------------------------------------


async def test_switching_engine_needs_a_newly_approved_version(world):
    """A version approved for one evaluator is not silently trusted by another; the governed path fixes it."""
    assert (await studio(world, "scenarios/address-change"))["status"] == "completed"
    world.ctx.settings.policy_engine = "rego"  # an operator changes AEGIS_POLICY_ENGINE and restarts
    blocked = await studio(world, "scenarios/address-change")
    assert blocked["status"] == "blocked"
    assert any(r["rule"] == "PDP-001" for d in await tool_decisions(world) for r in d["reasons"])

    original = await active_version(world)
    configuration = (await world.api("mark.jansen", "GET", "/v1/policies")).json()["data"]
    draft = await world.api(
        "priya.raman",
        "POST",
        "/v1/policies/versions",
        json={"name": "Approve for Rego", "configuration": configuration, "justification": "Engine change to rego"},
    )
    assert draft.status_code == 201, draft.text
    vid = draft.json()["id"]
    assert (await world.api("priya.raman", "POST", f"/v1/policies/{vid}/replay", json={})).status_code == 200
    assert (await world.api("priya.raman", "POST", f"/v1/policies/{vid}/submit")).status_code == 200
    approve = await world.api(
        "fatima.elamrani",
        "POST",
        f"/v1/policies/{vid}/approve",
        json={"justification": "Reviewed: same configuration, new evaluator"},
    )
    assert approve.status_code == 200, approve.text
    activate = await world.api(
        "fatima.elamrani",
        "POST",
        f"/v1/policies/{vid}/activate",
        json={"expected_active_version": original, "justification": "Run on the Rego engine"},
    )
    assert activate.status_code == 200, activate.text
    assert (await studio(world, "scenarios/address-change"))["status"] == "completed"
    assert (await tool_decisions(world))[0]["policy_version"] == vid
