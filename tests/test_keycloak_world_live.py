"""The whole demo with every agent's identity in a REAL Keycloak (skipped unless the local Keycloak is running).

    python -m aegis_demo.keycloak_setup start
    python -m pytest tests/test_keycloak_world_live.py -q

Only identities created during the test are removed afterwards; anything that was already in Keycloak is left alone.
"""

import asyncio
import copy
import json

import httpx
import pytest

from aegis.common.settings import Settings
from aegis.control.identity.agent_identity import KeycloakAgentIdentity
from aegis_demo import data, mcp_servers
from aegis_demo import keycloak_setup as kc
from aegis_demo.world import BASE, FAKE_LLM_URL, running_world

_CUSTOMERS = copy.deepcopy(data.CUSTOMERS)


def keycloak_settings_or_skip() -> dict:
    path = kc.HOME / "credentials.json"
    if not path.exists() or not kc.ready():
        pytest.skip("local Keycloak is not running (python -m aegis_demo.keycloak_setup start)")
    return {
        "agent_idp": "keycloak",
        "keycloak_url": f"http://127.0.0.1:{kc.PORT}",
        "keycloak_admin_client_secret": json.loads(path.read_text("utf-8"))["control_plane_secret"],
    }


@pytest.fixture
async def live_world():
    config = keycloak_settings_or_skip()
    inspector = KeycloakAgentIdentity(Settings(**config), httpx.AsyncClient(timeout=20, trust_env=False))
    existing = {c.client_id for c in await inspector.list_clients()}
    mcp_servers.SENT_EMAILS.clear()
    mcp_servers.TRANSFERS.clear()
    data.CUSTOMERS.clear()
    data.CUSTOMERS.update(copy.deepcopy(_CUSTOMERS))
    ready: asyncio.Future = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()

    async def owner():
        async with running_world(llm_upstream_url=FAKE_LLM_URL, **config) as w:
            ready.set_result(w)
            await stop.wait()

    task = asyncio.create_task(owner())
    try:
        await asyncio.wait({task, ready}, return_when=asyncio.FIRST_COMPLETED)
        if task.done():
            task.result()
        yield ready.result(), inspector
    finally:
        stop.set()
        await task
        for client in await inspector.list_clients():
            if client.client_id not in existing:
                found = await inspector.admin.find_client(client.client_id)
                await inspector.admin.request("DELETE", f"/clients/{found['id']}")
        await inspector.admin.http.aclose()


async def studio(world, path: str) -> dict:
    response = await world.http.post(f"{BASE}/demo/api/{path}", json={})
    assert response.status_code == 200, response.text
    return response.json()


async def test_demo_agents_hold_real_keycloak_identities_and_the_journey_works(live_world):
    world, keycloak = live_world
    clients = {c.client_id: c for c in await keycloak.list_clients()}
    for agent_id in world.agent_ids.values():
        client = clients[f"agent-{agent_id.lower()}"]
        assert client.agent_id == agent_id and client.enabled
    run = await studio(world, "scenarios/address-change")
    assert run["status"] == "completed"
    assert world.kyc_app.state.last_task.claims["aegis"]["chain"] == [
        world.agent_ids["ava"],
        world.agent_ids["kyc-agent"],
    ]
    assert (await world.api("eva.visser", "GET", "/v1/ledger/verify")).json()["ok"] is True
    status = (await world.api("mark.jansen", "GET", "/v1/identity/status")).json()
    assert status["provider"] == "keycloak" and status["reachable"] is True


async def test_containing_an_attack_disables_the_identity_in_real_keycloak(live_world):
    world, keycloak = live_world
    run = await studio(world, "scenarios/attack")
    assert run["status"] == "contained" and mcp_servers.SENT_EMAILS == []
    ava = {c.client_id: c for c in await keycloak.list_clients()}[world.ava.sdk.client_id]
    assert ava.enabled is False
    reset = await studio(world, "reset")
    assert "resumed ava" in reset["done"]
    assert {c.client_id: c for c in await keycloak.list_clients()}[world.ava.sdk.client_id].enabled is True


async def test_the_shadow_scene_creates_a_real_ungoverned_identity_that_discovery_finds(live_world):
    world, keycloak = live_world
    assert (await studio(world, "scenarios/shadow"))["status"] == "completed"
    found = (await world.api("mark.jansen", "POST", "/v1/discovery/scan")).json()["found"]
    shadow = next(f for f in found if f.startswith("idp-client:lead-enrichment-bot-"))
    governed = {f"idp-client:agent-{a.lower()}" for a in world.agent_ids.values()}
    assert not governed & set(found)
    findings = (await world.api("mark.jansen", "GET", "/v1/discovery/findings")).json()
    target = next(f for f in findings if f["fingerprint"] == shadow)
    assert (
        await world.api("mark.jansen", "POST", f"/v1/discovery/findings/{target['id']}/quarantine")
    ).status_code == 200
    clients = {c.client_id: c for c in await keycloak.list_clients()}
    assert clients[shadow.removeprefix("idp-client:")].enabled is False
