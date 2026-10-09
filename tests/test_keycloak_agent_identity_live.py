"""Agent identities against a REAL Keycloak (skipped unless the local Keycloak from keycloak_setup is running).

    python -m aegis_demo.keycloak_setup start
    python -m pytest tests/test_keycloak_agent_identity_live.py -q

Every identity these tests create is deleted again, whether the test passes or fails.
"""

import json
import uuid

import httpx
import jwt
import pytest

from aegis.common import crypto
from aegis.common.settings import Settings
from aegis.control.identity.agent_identity import (
    AGENT_ATTRIBUTE,
    IdentityNotFound,
    KeycloakAgentIdentity,
)
from aegis.control.identity.idp import ASSERTION_TYPE, client_assertion
from aegis.control.identity.oidc import IdentityUnavailable
from aegis_demo import keycloak_setup as kc


def settings_or_skip() -> Settings:
    path = kc.HOME / "credentials.json"
    if not path.exists() or not kc.ready():
        pytest.skip("local Keycloak is not running (python -m aegis_demo.keycloak_setup start)")
    return Settings(
        agent_idp="keycloak",
        keycloak_url=f"http://127.0.0.1:{kc.PORT}",
        keycloak_admin_client_secret=json.loads(path.read_text("utf-8"))["control_plane_secret"],
    )


@pytest.fixture
async def identity():
    provider = KeycloakAgentIdentity(settings_or_skip(), httpx.AsyncClient(timeout=20, trust_env=False))
    created: list[str] = []
    provider.created = created  # type: ignore[attr-defined]
    try:
        yield provider
    finally:
        for client_id in created:
            found = await provider.admin.find_client(client_id)
            if found:
                await provider.admin.request("DELETE", f"/clients/{found['id']}")
        await provider.admin.http.aclose()


def new_agent_id() -> str:
    return f"AGT-T{uuid.uuid4().hex[:3].upper()}-{uuid.uuid4().hex[:4].upper()}"


async def sign_in(provider: KeycloakAgentIdentity, issued, key: str | None = None) -> httpx.Response:
    async with httpx.AsyncClient(timeout=20, trust_env=False) as http:
        return await http.post(
            issued.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": issued.client_id,
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": client_assertion(
                    issued.client_id, key or issued.private_key_pem, issued.assertion_audience
                ),
            },
        )


async def test_an_agent_gets_its_own_identity_and_signs_in_with_its_private_key(identity):
    agent_id = new_agent_id()
    issued = await identity.provision(agent_id, "Live test agent")
    identity.created.append(issued.client_id)
    assert issued.client_id == f"agent-{agent_id.lower()}" and issued.provider == "keycloak"
    assert issued.assertion_audience == identity.issuer and issued.token_endpoint.startswith(identity.issuer)

    reply = await sign_in(identity, issued)
    assert reply.status_code == 200, reply.text
    token = reply.json()["access_token"]
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == "aegis-sts" and claims["azp"] == issued.client_id and claims["typ"] == "Bearer"
    assert claims["exp"] - claims["iat"] == identity.settings.agent_token_ttl
    assert "realm_access" not in claims  # the agent carries no Keycloak roles
    assert await identity.verify_token(token) == issued.client_id

    stored = await identity.admin.find_client(issued.client_id)
    assert stored["attributes"][AGENT_ATTRIBUTE] == agent_id
    assert stored["clientAuthenticatorType"] == "client-jwt"
    # Keycloak keeps an unused internal secret on every confidential client; it must be useless for signing in.
    internal = (await identity.admin.request("GET", f"/clients/{stored['id']}/client-secret")).json()["value"]
    async with httpx.AsyncClient(trust_env=False) as http:
        by_secret = await http.post(
            issued.token_endpoint,
            data={"grant_type": "client_credentials", "client_id": issued.client_id, "client_secret": internal},
        )
    assert by_secret.status_code in (400, 401), "a shared secret must never work for an agent"
    assert stored["publicClient"] is False and stored["standardFlowEnabled"] is False
    assert len(stored["protocolMappers"]) == 1
    assert "PRIVATE" not in json.dumps(stored)  # Keycloak holds only the public key


async def test_a_wrong_key_wrong_audience_or_other_agents_key_cannot_sign_in(identity):
    one, two = (
        await identity.provision(new_agent_id(), "Agent one"),
        await identity.provision(new_agent_id(), "Agent two"),
    )
    identity.created += [one.client_id, two.client_id]
    assert (await sign_in(identity, one, key=two.private_key_pem)).status_code in (400, 401)  # another agent's key
    assert (await sign_in(identity, one, key=crypto.generate_private_key_pem())).status_code in (400, 401)
    now = crypto.now()
    wrong_audience = jwt.encode(
        {"iss": one.client_id, "sub": one.client_id, "aud": "http://elsewhere.example", "iat": now, "exp": now + 60},
        one.private_key_pem,
        algorithm="ES256",
        headers={"kid": crypto.key_id(one.private_key_pem)},
    )
    async with httpx.AsyncClient(trust_env=False) as http:
        reply = await http.post(
            one.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": one.client_id,
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": wrong_audience,
            },
        )
    assert reply.status_code in (400, 401)


async def test_disabling_an_identity_stops_new_tokens_and_rejects_existing_ones(identity):
    issued = await identity.provision(new_agent_id(), "Disable test")
    identity.created.append(issued.client_id)
    token = (await sign_in(identity, issued)).json()["access_token"]
    assert await identity.verify_token(token) == issued.client_id

    await identity.set_enabled(issued.client_id, False)
    assert (await sign_in(identity, issued)).status_code in (400, 401)  # no new token
    with pytest.raises(jwt.InvalidTokenError):  # and the one already issued stops working at once
        await identity.verify_token(token)

    await identity.set_enabled(issued.client_id, True)
    assert (await sign_in(identity, issued)).status_code == 200
    assert await identity.verify_token(token) == issued.client_id


async def test_provisioning_again_rotates_the_key_without_duplicating_anything(identity):
    agent_id = new_agent_id()
    first = await identity.provision(agent_id, "Rotation test")
    identity.created.append(first.client_id)
    old_token = (await sign_in(identity, first)).json()["access_token"]
    second = await identity.provision(agent_id, "Rotation test")
    assert second.client_id == first.client_id and second.private_key_pem != first.private_key_pem
    assert (await sign_in(identity, first)).status_code in (400, 401)  # the old key no longer works
    assert (await sign_in(identity, second)).status_code == 200
    stored = await identity.admin.find_client(first.client_id)
    assert len(stored["protocolMappers"]) == 1  # not one more mapper per provisioning
    assert len([c for c in await identity.admin.all_clients() if c["clientId"] == first.client_id]) == 1
    assert await identity.verify_token(old_token) == first.client_id  # tokens already issued live out their 5 minutes


async def test_an_unrelated_client_with_the_same_name_is_never_taken_over(identity):
    agent_id = new_agent_id()
    client_id = f"agent-{agent_id.lower()}"
    await identity.admin.request(
        "POST", "/clients", json={"clientId": client_id, "enabled": True, "publicClient": True}
    )
    identity.created.append(client_id)
    with pytest.raises(IdentityUnavailable, match="unrelated"):
        await identity.provision(agent_id, "Collision")


async def test_discovery_separates_governed_identities_from_shadow_ones(identity):
    governed = await identity.provision(new_agent_id(), "Governed agent")
    shadow = f"lead-bot-{uuid.uuid4().hex[:6]}"
    await identity.register_unmanaged(shadow, "Unmanaged bot")
    identity.created += [governed.client_id, shadow]
    clients = {c.client_id: c for c in await identity.list_clients()}
    assert clients[governed.client_id].agent_id is not None and clients[governed.client_id].enabled
    assert clients[shadow].agent_id is None and clients[shadow].name == "Unmanaged bot"
    # Aegis's own client and Keycloak's built-ins are never presented as agents.
    assert not ({"aegis-control-plane", "aegis-console", "account", "admin-cli", "broker"} & set(clients))


async def test_the_control_plane_client_can_manage_clients_but_not_users_or_realm_settings(identity):
    token = await identity.admin._access_token()
    realm = f"http://127.0.0.1:{kc.PORT}/admin/realms/{kc.REALM}"
    headers = {"authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(trust_env=False) as http:
        assert (await http.get(f"{realm}/clients", headers=headers)).status_code == 200
        # No personal data and no security configuration can be read ...
        for path in (
            "/users",
            "/users/count",
            "/groups",
            "/identity-provider/instances",
            "/components",
            "/events",
            "/keys",
        ):
            assert (await http.get(f"{realm}{path}", headers=headers)).status_code == 403, f"GET {path}"
        # ... and nothing but clients can be created or changed.
        for path, body in (("/users", {"username": "x"}), ("/roles", {"name": "x"}), ("/groups", {"name": "x"})):
            assert (await http.post(f"{realm}{path}", headers=headers, json=body)).status_code == 403, f"POST {path}"
        assert (await http.put(realm, headers=headers, json={"displayName": "x"})).status_code == 403
        master = f"http://127.0.0.1:{kc.PORT}/admin/realms/master/clients"
        assert (await http.get(master, headers=headers)).status_code == 403  # a different realm is out of reach


async def test_protected_clients_and_missing_identities_are_handled(identity):
    for protected in ("aegis-control-plane", "aegis-console", "account"):
        with pytest.raises(IdentityUnavailable, match="protected"):
            await identity.set_enabled(protected, False)
    with pytest.raises(IdentityNotFound):
        await identity.set_enabled("agent-agt-nope-0000", True)
    with pytest.raises(ValueError):
        await identity.set_enabled("bad id/with slash", True)
    wrong = KeycloakAgentIdentity(
        identity.settings.model_copy(update={"keycloak_admin_client_secret": "definitely-wrong"}),
        httpx.AsyncClient(trust_env=False),
    )
    with pytest.raises(IdentityUnavailable, match="refused the control-plane client"):
        await wrong.list_clients()
    down = KeycloakAgentIdentity(
        identity.settings.model_copy(update={"keycloak_url": "http://127.0.0.1:9"}), httpx.AsyncClient(trust_env=False)
    )
    with pytest.raises(IdentityUnavailable, match="cannot reach"):
        await down.list_clients()
    assert (await down.status())["reachable"] is False and (await identity.status())["reachable"] is True


async def test_tokens_that_are_not_agent_identity_tokens_are_rejected(identity):
    issued = await identity.provision(new_agent_id(), "Token test")
    identity.created.append(issued.client_id)
    token = (await sign_in(identity, issued)).json()["access_token"]
    head, body, signature = token.split(".")
    for bad in (token[:-4] + "AAAA", f"{head}.{body}", "garbage", ""):
        with pytest.raises(jwt.InvalidTokenError):
            await identity.verify_token(bad)
