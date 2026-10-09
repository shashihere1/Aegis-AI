"""Agent identities through the whole system: registry, STS, kill switch, discovery and the demo agents, with every
agent's identity held by a (fake) Keycloak instead of the built-in provider."""

import asyncio
import copy

import pytest
from fake_keycloak import CONTROL_PLANE, FakeKeycloak
from starlette.routing import Mount

from aegis.control.identity.agent_identity import KeycloakAgentIdentity
from aegis.sdk import AegisAgent, AegisDenied
from aegis_demo import data, mcp_servers
from aegis_demo.world import BASE, FAKE_LLM_URL, running_world

SECRET = "control-plane-secret"
JAN = "jan.devries"
_CUSTOMERS = copy.deepcopy(data.CUSTOMERS)


@pytest.fixture
async def kc_world():
    mcp_servers.SENT_EMAILS.clear()
    mcp_servers.TRANSFERS.clear()
    data.CUSTOMERS.clear()
    data.CUSTOMERS.update(copy.deepcopy(_CUSTOMERS))
    fake = FakeKeycloak(f"{BASE}/kc", SECRET)
    ready: asyncio.Future = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()

    async def owner():
        async with running_world(
            llm_upstream_url=FAKE_LLM_URL,
            agent_idp="keycloak",
            keycloak_url=f"{BASE}/kc",
            keycloak_admin_client_secret=SECRET,
            agent_identity_factory=lambda settings, http: KeycloakAgentIdentity(settings, http),
            extra_routes=[Mount("/kc", fake.app)],
        ) as w:
            ready.set_result((w, fake))
            await stop.wait()

    task = asyncio.create_task(owner())
    await asyncio.wait({task, ready}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        task.result()
    yield ready.result()
    stop.set()
    await task


async def studio(world, path: str) -> dict:
    response = await world.http.post(f"{BASE}/demo/api/{path}", json={})
    assert response.status_code == 200, response.text
    return response.json()


async def register_agent(world, name: str) -> dict:
    body = {
        "name": name,
        "purpose": "Answer mortgage questions for customers.",
        "intent_categories": ["customer.inquiry.read"],
        "owner": "niels.vandijk",
        "sponsor": "retail.ops.head",
        "capabilities": ["core-banking.get_balance"],
    }
    agent = (await world.api("priya.raman", "POST", "/v1/agents", json=body)).json()
    assert (await world.api("priya.raman", "POST", f"/v1/agents/{agent['id']}/submit")).status_code == 200
    return agent


async def ledger(world) -> list[dict]:
    return (await world.api("eva.visser", "GET", "/v1/ledger?limit=500")).json()


async def test_every_demo_agent_gets_its_own_identity_in_keycloak(kc_world):
    world, fake = kc_world
    registry = {a["name"]: a for a in (await world.api("mark.jansen", "GET", "/v1/agents?q=Ava")).json()["items"]}
    managed = fake.managed()
    assert len(managed) == len(world.agent_ids) == 4  # Ava, KYC, Payments and the read-only investigation Copilot
    assert len({c["clientId"] for c in managed}) == len(world.agent_ids)
    for client in managed:
        assert client["clientAuthenticatorType"] == "client-jwt" and client["publicClient"] is False
        assert client["clientId"] == f"agent-{client['attributes']['aegis.agent_id'].lower()}"
        assert "PRIVATE" not in str(client)
    assert {c["attributes"]["aegis.agent_id"] for c in managed} == set(world.agent_ids.values())
    assert registry  # the registry itself is intact
    for key, agent_id in world.agent_ids.items():
        agent = (await world.api("mark.jansen", "GET", f"/v1/agents/{agent_id}")).json()
        assert agent["idp_client_id"] == f"agent-{agent_id.lower()}" and fake.by_client_id(agent["idp_client_id"])
        assert world.sdks[key].token_endpoint.startswith(f"{BASE}/kc/realms/aegis/")
    types = {e["event_type"]: e["payload"] for e in await ledger(world)}
    assert types["identity.provisioned"]["idp"] == "keycloak"


async def test_the_demo_journey_works_when_agents_sign_in_at_keycloak(kc_world):
    world, fake = kc_world
    before = fake.agent_signins
    run = await studio(world, "scenarios/address-change")
    assert run["status"] == "completed"
    assert fake.agent_signins - before == 2  # Ava, then the delegated KYC agent; Payments was not involved
    kyc_claims = world.kyc_app.state.last_task.claims
    assert kyc_claims["aegis"]["chain"] == [world.agent_ids["ava"], world.agent_ids["kyc-agent"]]  # delegation intact
    assert (await world.api("eva.visser", "GET", "/v1/ledger/verify")).json()["ok"] is True


async def test_the_kill_switch_switches_the_identity_off_in_keycloak(kc_world):
    world, fake = kc_world
    ava = world.ava.sdk
    client = fake.by_client_id(ava.client_id)
    assert client["enabled"] is True and await ava.identity_token()
    suspended = await world.api("mark.jansen", "POST", f"/v1/agents/{world.agent_ids['ava']}/suspend", json={})
    assert suspended.status_code == 200
    assert fake.by_client_id(ava.client_id)["enabled"] is False  # Keycloak will not issue Ava another token
    fresh = AegisAgent(
        world.http,
        BASE,
        world.settings.gateway_url,
        ava.client_id,
        ava._key,
        token_endpoint=ava.token_endpoint,
        assertion_audience=ava.assertion_audience,
    )
    with pytest.raises(AegisDenied, match="identity provider refused"):
        await fresh.identity_token()
    with pytest.raises(AegisDenied):  # and even the token it already holds cannot start a task
        await ava.start_task("Verify identity document", user_token=world.token(JAN))
    resumed = await world.api("sanne.bakker", "POST", f"/v1/agents/{world.agent_ids['ava']}/resume", json={})
    assert resumed.status_code == 200 and fake.by_client_id(ava.client_id)["enabled"] is True
    assert await fresh.identity_token()


async def test_the_attack_scene_contains_the_agent_and_its_identity(kc_world):
    world, fake = kc_world
    run = await studio(world, "scenarios/attack")
    assert run["status"] == "contained" and mcp_servers.SENT_EMAILS == []
    assert fake.by_client_id(world.ava.sdk.client_id)["enabled"] is False
    suspended = next(e for e in await ledger(world) if e["event_type"] == "agent.suspended")
    assert "identity_disable_failed" not in suspended["payload"]


async def test_the_kill_switch_still_works_when_keycloak_is_down_and_reconcile_repairs_it(kc_world):
    world, fake = kc_world
    ava_id = world.agent_ids["ava"]
    client_id = world.ava.sdk.client_id
    fake.fail_admin = True
    suspended = await world.api("mark.jansen", "POST", f"/v1/agents/{ava_id}/suspend", json={})
    assert suspended.status_code == 200  # the control plane did not depend on the provider
    agent = (await world.api("mark.jansen", "GET", f"/v1/agents/{ava_id}")).json()
    assert agent["status"] == "suspended"
    assert fake.by_client_id(client_id)["enabled"] is True  # Keycloak could not be told
    event = next(e for e in await ledger(world) if e["event_type"] == "agent.suspended")
    assert "identity_disable_failed" in event["payload"]  # on the record, not silent

    with pytest.raises(AegisDenied):  # meanwhile the STS refuses a suspended agent anyway
        await world.ava.sdk.start_task("Verify identity document", user_token=world.token(JAN))

    fake.fail_admin = False
    forbidden = await world.api("eva.visser", "POST", "/v1/identity/reconcile")
    assert forbidden.status_code == 403  # an auditor cannot repair identities
    report = (await world.api("admin", "POST", "/v1/identity/reconcile")).json()
    assert report["disabled"] == [client_id] and report["errors"] == []
    assert fake.by_client_id(client_id)["enabled"] is False
    again = (await world.api("admin", "POST", "/v1/identity/reconcile")).json()
    assert again["disabled"] == [] and again["enabled"] == []  # nothing left to repair


async def test_approval_fails_cleanly_when_keycloak_is_down_and_succeeds_when_it_returns(kc_world):
    world, fake = kc_world
    agent = await register_agent(world, "Mortgage-Advice-Agent")
    before = len(fake.managed())
    fake.fail_admin = True
    refused = await world.api("sanne.bakker", "POST", f"/v1/agents/{agent['id']}/approve", json={})
    assert refused.status_code == 503 and refused.json() == {"detail": "the identity provider is unavailable"}
    pending = (await world.api("sanne.bakker", "GET", f"/v1/agents/{agent['id']}")).json()
    assert pending["status"] == "pending_approval" and pending["idp_client_id"] is None  # nothing half-done
    assert len(fake.managed()) == before
    assert not [
        e for e in await ledger(world) if e["subject"] == agent["id"] and e["event_type"] == "identity.provisioned"
    ]

    fake.fail_admin = False
    approved = (await world.api("sanne.bakker", "POST", f"/v1/agents/{agent['id']}/approve", json={})).json()
    assert approved["agent"]["status"] == "active"
    credentials = approved["credentials"]
    assert credentials["token_endpoint"].startswith(f"{BASE}/kc/realms/aegis/")
    assert credentials["assertion_audience"] == f"{BASE}/kc/realms/aegis"
    newcomer = AegisAgent.from_credentials(world.http, BASE, world.settings.gateway_url, credentials)
    assert await newcomer.identity_token()  # the returned key really signs in at Keycloak
    assert fake.by_client_id(credentials["client_id"])["attributes"]["aegis.agent_id"] == agent["id"]


async def test_the_sts_fails_closed_when_the_provider_cannot_be_asked(kc_world):
    world, fake = kc_world
    ava = world.ava.sdk
    await ava.identity_token()  # a valid token is already in hand
    world.ctx.agent_identity._info.clear()  # ... but the client's state must be confirmed again
    fake.fail_admin = True
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "actor_token": await ava.identity_token(),
        "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "authorization_details": '[{"type":"aegis_mandate","intent":"Verify identity document for address change"}]',
    }
    response = await world.http.post(f"{BASE}/sts/token", data=form)
    assert response.status_code == 503 and response.json()["error"] == "temporarily_unavailable"
    fake.fail_admin = False
    assert (await world.http.post(f"{BASE}/sts/token", data=form)).status_code != 503  # recovers by itself


async def test_ungoverned_identities_in_keycloak_are_found_and_quarantined(kc_world):
    world, fake = kc_world
    assert (await studio(world, "scenarios/shadow"))["status"] == "completed"
    fake._add(
        {
            "clientId": "agent-agt-gone-0000",
            "enabled": True,
            "serviceAccountsEnabled": True,
            "attributes": {"aegis.managed": "true", "aegis.agent_id": "AGT-GONE-0000"},
        }
    )  # its agent no longer exists
    found = (await world.api("mark.jansen", "POST", "/v1/discovery/scan")).json()["found"]
    shadow = next(f for f in found if f.startswith("idp-client:lead-enrichment-bot-"))
    assert "idp-client:agent-agt-gone-0000" in found
    assert not [f for f in found if CONTROL_PLANE in f or "aegis-console" in f]
    governed = {f"idp-client:agent-{a.lower()}" for a in world.agent_ids.values()}
    assert not governed & set(found)  # governed agents are not reported as shadow
    findings = (await world.api("mark.jansen", "GET", "/v1/discovery/findings")).json()
    target = next(f for f in findings if f["fingerprint"] == shadow)
    done = await world.api("mark.jansen", "POST", f"/v1/discovery/findings/{target['id']}/quarantine")
    assert done.status_code == 200 and fake.by_client_id(shadow.removeprefix("idp-client:"))["enabled"] is False
    again = (await world.api("mark.jansen", "POST", "/v1/discovery/scan")).json()["found"]
    assert shadow in again  # still listed (disabled), and still a finding to resolve


async def test_reconcile_reports_identities_that_are_missing_or_orphaned(kc_world):
    world, fake = kc_world
    victim = world.ava.sdk.client_id
    del fake.clients[fake.by_client_id(victim)["id"]]  # e.g. the realm was recreated
    fake._add(
        {
            "clientId": "agent-agt-lost-0001",
            "enabled": True,
            "serviceAccountsEnabled": True,
            "attributes": {"aegis.managed": "true", "aegis.agent_id": "AGT-LOST-0001"},
        }
    )
    report = (await world.api("admin", "POST", "/v1/identity/reconcile")).json()
    assert report["missing"] == [victim] and report["orphaned"] == ["agent-agt-lost-0001"] and report["errors"] == []
    await world.api("mark.jansen", "POST", f"/v1/agents/{world.agent_ids['ava']}/suspend", json={})
    resume = await world.api("sanne.bakker", "POST", f"/v1/agents/{world.agent_ids['ava']}/resume", json={})
    assert resume.status_code == 409 and "approve the agent again" in resume.text  # a clear instruction, not a 503


async def test_identity_status_endpoint_and_start_up_resilience(kc_world):
    world, fake = kc_world
    status = (await world.api("mark.jansen", "GET", "/v1/identity/status")).json()
    assert status["provider"] == "keycloak" and status["reachable"] is True
    assert status["agents_with_identity"] == len(world.agent_ids)
    fake.down = True
    down = (await world.api("mark.jansen", "GET", "/v1/identity/status")).json()
    assert down["reachable"] is False and "detail" in down
    assert (await world.api("mark.jansen", "GET", "/v1/agents/stats")).status_code == 200  # the rest keeps working
    assert (await world.http.get(f"{BASE}/health")).status_code == 200
