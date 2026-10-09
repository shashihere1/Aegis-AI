"""The Keycloak agent-identity adapter against a fake Keycloak (no external service needed).

The same behaviour is checked against a real Keycloak in test_keycloak_agent_identity_live.py.
"""

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fake_keycloak import CONTROL_PLANE, FakeKeycloak

from aegis.common import crypto
from aegis.common.settings import Settings
from aegis.control.identity import agent_identity as module
from aegis.control.identity.agent_identity import (
    AGENT_ATTRIBUTE,
    DevAgentIdentity,
    IdentityNotFound,
    KeycloakAgentIdentity,
    build_agent_identity,
)
from aegis.control.identity.idp import ASSERTION_TYPE, DevIdp, client_assertion
from aegis.control.identity.oidc import IdentityUnavailable

URL = "http://kc.test"
SECRET = "control-plane-secret"


def build(fake: FakeKeycloak | None = None, **settings) -> tuple[KeycloakAgentIdentity, FakeKeycloak]:
    fake = fake or FakeKeycloak(URL, SECRET)
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app))
    config = Settings(agent_idp="keycloak", keycloak_url=URL, keycloak_admin_client_secret=SECRET, **settings)
    return KeycloakAgentIdentity(config, http), fake


async def sign_in(fake: FakeKeycloak, issued, key: str | None = None, audience: str | None = None) -> httpx.Response:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app)) as http:
        return await http.post(
            issued.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": issued.client_id,
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": client_assertion(
                    issued.client_id, key or issued.private_key_pem, audience or issued.assertion_audience
                ),
            },
        )


# ---- provisioning ----


async def test_provisioning_registers_only_the_public_key_and_disables_every_other_way_in():
    provider, fake = build()
    issued = await provider.provision("AGT-AAAA-0001", "Ava")
    stored = fake.by_client_id("agent-agt-aaaa-0001")
    assert issued.client_id == stored["clientId"] and issued.provider == "keycloak"
    assert stored["clientAuthenticatorType"] == "client-jwt" and stored["publicClient"] is False
    assert (
        not stored["standardFlowEnabled"]
        and not stored["directAccessGrantsEnabled"]
        and not stored["implicitFlowEnabled"]
    )
    assert stored["serviceAccountsEnabled"] is True and stored["fullScopeAllowed"] is False
    assert stored["defaultClientScopes"] == [] and "secret" not in stored
    jwks = json.loads(stored["attributes"]["jwks.string"])["keys"]
    assert [k["kid"] for k in jwks] == [crypto.key_id(issued.private_key_pem)]
    assert all("d" not in k for k in jwks)  # the private exponent never reaches Keycloak
    assert "PRIVATE" not in json.dumps(stored)
    assert stored["attributes"]["token.endpoint.auth.signing.alg"] == "ES256"
    assert stored["attributes"]["access.token.lifespan"] == "300"
    assert (stored["attributes"]["aegis.managed"], stored["attributes"][AGENT_ATTRIBUTE]) == ("true", "AGT-AAAA-0001")
    (mapper,) = stored["protocolMappers"]
    assert (
        mapper["protocolMapper"] == "oidc-audience-mapper"
        and mapper["config"]["included.custom.audience"] == "aegis-sts"
    )
    assert issued.credentials() == {
        "client_id": "agent-agt-aaaa-0001",
        "private_key_pem": issued.private_key_pem,
        "token_endpoint": f"{URL}/realms/aegis/protocol/openid-connect/token",
        "assertion_audience": f"{URL}/realms/aegis",
    }


async def test_token_lifetime_is_configurable():
    provider, fake = build(agent_token_ttl=120)
    await provider.provision("AGT-AAAA-0002", "Short lived")
    assert fake.by_client_id("agent-agt-aaaa-0002")["attributes"]["access.token.lifespan"] == "120"


async def test_provisioning_twice_rotates_the_key_in_place():
    provider, fake = build()
    first = await provider.provision("AGT-AAAA-0003", "Rotating")
    second = await provider.provision("AGT-AAAA-0003", "Rotating")
    clients = [c for c in fake.clients.values() if c["clientId"] == first.client_id]
    assert len(clients) == 1 and len(clients[0]["protocolMappers"]) == 1
    assert second.private_key_pem != first.private_key_pem
    assert (await sign_in(fake, first)).status_code == 400  # the old key is dead
    assert (await sign_in(fake, second)).status_code == 200


async def test_rotating_a_key_does_not_switch_a_suspended_identity_back_on():
    provider, fake = build()
    first = await provider.provision("AGT-AAAA-0010", "Suspended")
    await provider.set_enabled(first.client_id, False)
    second = await provider.provision("AGT-AAAA-0010", "Suspended")
    assert fake.by_client_id(first.client_id)["enabled"] is False
    assert (await sign_in(fake, second)).status_code == 401  # new key, but the identity stays off
    await provider.set_enabled(first.client_id, True)
    assert (await sign_in(fake, second)).status_code == 200


async def test_a_concurrent_creation_is_resolved_by_updating():
    provider, fake = build()
    await provider.provision("AGT-AAAA-0004", "Racing")
    real, calls = provider.admin.find_client, []

    async def stale_first(client_id):  # the first look says "not there", as if another request just created it
        calls.append(client_id)
        return None if len(calls) == 1 else await real(client_id)

    provider.admin.find_client = stale_first
    issued = await provider.provision("AGT-AAAA-0004", "Racing")
    assert len([c for c in fake.clients.values() if c["clientId"] == issued.client_id]) == 1


async def test_an_unrelated_client_with_the_same_name_is_not_taken_over():
    provider, fake = build()
    fake._add({"clientId": "agent-agt-aaaa-0005", "enabled": True})  # no Aegis agent attribute
    with pytest.raises(IdentityUnavailable, match="unrelated"):
        await provider.provision("AGT-AAAA-0005", "Collision")
    fake.by_client_id("agent-agt-aaaa-0005")["attributes"][AGENT_ATTRIBUTE] = "AGT-SOMEONE-ELSE"
    with pytest.raises(IdentityUnavailable, match="unrelated"):
        await provider.provision("AGT-AAAA-0005", "Collision")


@pytest.mark.parametrize("bad", ["", "has space", "../escape", "a/b", "x" * 200, "-leading"])
async def test_unsafe_names_are_refused_before_anything_is_sent(bad):
    provider, fake = build()
    calls = fake.admin_calls
    with pytest.raises(ValueError):
        await provider.set_enabled(bad, True)
    with pytest.raises(ValueError):
        await provider.register_unmanaged(bad, "x")
    assert fake.admin_calls == calls


# ---- enabling, disabling, listing ----


async def test_set_enabled_changes_only_that_flag_and_protects_other_clients():
    provider, fake = build()
    issued = await provider.provision("AGT-AAAA-0006", "Toggle")
    before = json.dumps(fake.by_client_id(issued.client_id)["attributes"], sort_keys=True)
    await provider.set_enabled(issued.client_id, False)
    stored = fake.by_client_id(issued.client_id)
    assert stored["enabled"] is False and json.dumps(stored["attributes"], sort_keys=True) == before
    assert len(stored["protocolMappers"]) == 1
    await provider.set_enabled(issued.client_id, True)
    assert fake.by_client_id(issued.client_id)["enabled"] is True
    for protected in (CONTROL_PLANE, "aegis-console", "account", "admin-cli"):
        with pytest.raises(IdentityUnavailable, match="protected"):
            await provider.set_enabled(protected, False)
    assert fake.by_client_id(CONTROL_PLANE)["enabled"] is True
    with pytest.raises(IdentityNotFound):
        await provider.set_enabled("agent-agt-missing-0000", True)


async def test_listing_pages_through_everything_and_shows_only_machine_identities():
    provider, fake = build()
    for i in range(250):
        fake._add({"clientId": f"bot-{i:03d}", "enabled": True, "serviceAccountsEnabled": True})
    fake._add({"clientId": "just-a-website", "enabled": True, "publicClient": True})
    await provider.provision("AGT-AAAA-0007", "Governed")
    clients = {c.client_id: c for c in await provider.list_clients()}
    assert len([c for c in clients if c.startswith("bot-")]) == 250  # every page was read
    assert "just-a-website" not in clients
    assert not ({CONTROL_PLANE, "aegis-console", "account", "admin-cli", "broker", "realm-management"} & set(clients))
    assert clients["agent-agt-aaaa-0007"].agent_id == "AGT-AAAA-0007" and clients["bot-000"].agent_id is None
    fake.by_client_id("bot-001")["attributes"] = {AGENT_ATTRIBUTE: "AGT-FORGED"}  # an agent id without the managed flag
    assert {c.client_id: c for c in await provider.list_clients()}["bot-001"].agent_id is None
    fake.by_client_id("bot-002")["enabled"] = False
    assert {c.client_id: c for c in await provider.list_clients()}["bot-002"].enabled is False


async def test_an_unmanaged_identity_has_no_aegis_markers():
    provider, fake = build()
    await provider.register_unmanaged("lead-bot", "Lead bot")
    attributes = fake.by_client_id("lead-bot")["attributes"]
    assert "aegis.managed" not in attributes and AGENT_ATTRIBUTE not in attributes
    assert attributes["use.jwks.string"] == "true"


# ---- checking tokens ----


async def signed_in(provider, fake, agent_id="AGT-BBBB-0001"):
    issued = await provider.provision(agent_id, "Token tests")
    return issued, (await sign_in(fake, issued)).json()["access_token"]


async def test_a_real_sign_in_produces_a_token_aegis_accepts():
    provider, fake = build()
    issued, token = await signed_in(provider, fake)
    assert await provider.verify_token(token) == issued.client_id
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == "aegis-sts" and claims["exp"] - claims["iat"] == 300


async def test_the_assertion_audience_may_be_the_token_endpoint_too():
    provider, fake = build()
    issued = await provider.provision("AGT-BBBB-0002", "Either audience")
    assert (await sign_in(fake, issued, audience=issued.token_endpoint)).status_code == 200
    assert (await sign_in(fake, issued, audience="http://elsewhere")).status_code == 400


async def test_tokens_that_are_not_valid_agent_identities_are_rejected():
    provider, fake = build()
    issued, good = await signed_in(provider, fake)
    client = fake.by_client_id(issued.client_id)
    now = int(time.time())
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    head, body, _signature = good.split(".")
    cases = {
        "wrong audience": fake.issue(client, aud="account"),
        "audience list without aegis-sts": fake.issue(client, aud=["account", "other"]),
        "an ID token": fake.issue(client, typ="ID"),
        "no token type": fake.issue(client, typ=None),
        "expired": fake.issue(client, iat=now - 7200, exp=now - 3600),
        "wrong issuer": fake.issue(client, iss="http://evil.test/realms/aegis"),
        "two different clients": fake.issue(client, client_id="agent-agt-other-0000"),
        "no client at all": fake.issue(client, azp=None, client_id=None),
        "client does not exist": fake.issue({**client, "clientId": "agent-agt-ghost-0000"}),
        "signed by another key": jwt.encode(
            jwt.decode(good, options={"verify_signature": False}),
            other_pem,
            algorithm="RS256",
            headers={"kid": fake.kid},
        ),
        "unknown key id": fake.issue(client).replace(
            head, jwt.utils.base64url_encode(b'{"alg":"RS256","kid":"nope"}').decode(), 1
        ),
        "tampered": f"{head}.{body[:-4]}AAAA.{good.split('.')[2]}",
        "garbage": "not.a.token",
    }
    for name, token in cases.items():
        with pytest.raises(jwt.InvalidTokenError):
            await provider.verify_token(token)
        print("rejected:", name)


async def test_a_disabled_or_removed_identity_is_rejected_even_with_a_valid_token():
    provider, fake = build()
    issued, token = await signed_in(provider, fake)
    assert await provider.verify_token(token) == issued.client_id
    await provider.set_enabled(issued.client_id, False)  # takes effect at once, not after the cache expires
    with pytest.raises(jwt.InvalidTokenError):
        await provider.verify_token(token)
    await provider.set_enabled(issued.client_id, True)
    assert await provider.verify_token(token) == issued.client_id
    stored = fake.by_client_id(issued.client_id)
    stored["serviceAccountsEnabled"] = False  # no longer a machine identity
    provider._info.clear()
    with pytest.raises(jwt.InvalidTokenError):
        await provider.verify_token(token)
    stored["serviceAccountsEnabled"] = True
    del fake.clients[stored["id"]]
    provider._info.clear()
    with pytest.raises(jwt.InvalidTokenError):
        await provider.verify_token(token)


async def test_the_enabled_state_is_cached_briefly(monkeypatch):
    provider, fake = build()
    issued, token = await signed_in(provider, fake)
    await provider.verify_token(token)
    calls = fake.admin_calls
    for _ in range(5):
        await provider.verify_token(token)
    assert fake.admin_calls == calls  # served from the short-lived cache
    provider._info[issued.client_id] = (0.0, provider._info[issued.client_id][1])  # expired
    fake.by_client_id(issued.client_id)["enabled"] = False  # changed behind Aegis's back
    with pytest.raises(jwt.InvalidTokenError):
        await provider.verify_token(token)


async def test_a_keycloak_outage_is_unavailable_not_valid():
    provider, fake = build()
    _issued, token = await signed_in(provider, fake)
    provider._info.clear()
    fake.fail_admin = True
    with pytest.raises(IdentityUnavailable):
        await provider.verify_token(token)  # cannot confirm the client: fail closed


# ---- talking to Keycloak safely ----


async def test_the_admin_token_is_reused_and_refreshed_once_when_it_expires():
    provider, fake = build()
    for i in range(5):
        await provider.provision(f"AGT-CCCC-{i:04d}", "Many")
    assert fake.token_calls == 1  # one admin sign-in served five provisionings
    fake.expire_admin_tokens()
    await provider.list_clients()
    assert fake.token_calls == 2


async def test_failures_are_described_without_leaking_secrets():
    fake = FakeKeycloak(URL, SECRET)
    wrong = KeycloakAgentIdentity(
        Settings(agent_idp="keycloak", keycloak_url=URL, keycloak_admin_client_secret="the-wrong-secret"),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app)),
    )
    with pytest.raises(IdentityUnavailable, match="refused the control-plane client") as refused:
        await wrong.list_clients()
    assert "the-wrong-secret" not in str(refused.value)

    provider, fake = build(fake)
    fake.denied_admin = True
    with pytest.raises(IdentityUnavailable, match="manage-clients and view-clients"):
        await provider.list_clients()
    fake.denied_admin, fake.fail_admin = False, True
    with pytest.raises(IdentityUnavailable, match="503"):
        await provider.list_clients()

    def refuse(request):
        raise httpx.ConnectError("no route", request=request)

    down = KeycloakAgentIdentity(
        Settings(agent_idp="keycloak", keycloak_url=URL, keycloak_admin_client_secret=SECRET),
        httpx.AsyncClient(transport=httpx.MockTransport(refuse)),
    )
    with pytest.raises(IdentityUnavailable, match="cannot reach"):
        await down.list_clients()
    assert (await down.status())["reachable"] is False


async def test_status_reports_whether_the_provider_is_reachable():
    provider, fake = build()
    assert await provider.status() == {"provider": "keycloak", "reachable": True, "issuer": f"{URL}/realms/aegis"}
    fake.down = True
    status = await provider.status()
    assert status["reachable"] is False and "detail" in status


# ---- development key store, factory, settings ----


async def test_the_demo_key_store_is_used_only_when_configured(tmp_path):
    provider, _fake = build(identity_state_dir=str(tmp_path))
    issued = await provider.provision("AGT-DDDD-0001", "Demo store")
    assert await provider.development_private_key(issued.client_id) == issued.private_key_pem
    with pytest.raises(IdentityNotFound):
        await provider.development_private_key("agent-agt-nobody-0000")
    with pytest.raises(ValueError):
        await provider.development_private_key("../../etc/passwd")
    bare, _ = build()
    await bare.provision("AGT-DDDD-0002", "No store")
    with pytest.raises(IdentityNotFound):
        await bare.development_private_key("agent-agt-dddd-0002")


def test_the_factory_chooses_the_provider_and_demands_complete_settings(tmp_path):
    idp = DevIdp("http://control/idp", crypto.SigningKey(crypto.generate_private_key_pem(), "k"))
    assert isinstance(build_agent_identity(Settings(), idp), DevAgentIdentity)
    with pytest.raises(ValueError, match="AEGIS_KEYCLOAK_URL, AEGIS_KEYCLOAK_ADMIN_CLIENT_SECRET"):
        build_agent_identity(Settings(agent_idp="keycloak"), idp, httpx.AsyncClient())
    with pytest.raises(ValueError, match="AEGIS_KEYCLOAK_ADMIN_CLIENT_SECRET"):
        build_agent_identity(Settings(agent_idp="keycloak", keycloak_url=URL), idp, httpx.AsyncClient())
    with pytest.raises(ValueError):
        Settings(agent_idp="entra")  # only the providers that exist can be named
    assert "super-secret" not in repr(Settings(keycloak_admin_client_secret="super-secret"))


def test_key_ids_are_stable_and_derived_from_the_public_key():
    pem = crypto.generate_private_key_pem()
    assert crypto.key_id(pem) == crypto.key_id(pem) == crypto.public_jwk(crypto.public_pem_from_private(pem))["kid"]
    assert crypto.key_id(pem) != crypto.key_id(crypto.generate_private_key_pem())
    assert module.INFO_TTL <= 30  # a disabled identity is noticed quickly even without an explicit invalidation


# ---- the built-in provider behind the same interface ----


async def test_the_built_in_provider_behaves_as_before_behind_the_async_interface():
    idp = DevIdp("http://control/idp", crypto.SigningKey(crypto.generate_private_key_pem(), "k"))
    provider = DevAgentIdentity(idp, "http://control")
    issued = await provider.provision("AGT-EEEE-0001", "Dev agent")
    assert issued.token_endpoint == "http://control/idp/token" and issued.assertion_audience is None
    assertion = client_assertion(issued.client_id, issued.private_key_pem, issued.token_endpoint)
    token = idp.token_for_assertion(assertion)
    assert await provider.verify_token(token) == issued.client_id
    await provider.set_enabled(issued.client_id, False)
    with pytest.raises(jwt.InvalidTokenError):
        await provider.verify_token(token)
    with pytest.raises(IdentityNotFound):
        await provider.set_enabled("agent-unknown", True)
    await provider.register_unmanaged("shadow-bot", "Shadow")
    assert {c.client_id: c.agent_id for c in await provider.list_clients()}["shadow-bot"] is None
    assert (await provider.status())["provider"] == "dev-idp"
