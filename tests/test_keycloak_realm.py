"""The generated Keycloak realm must match the demo personas and the settings Aegis uses to read its tokens."""

import json

from aegis.common.settings import Settings
from aegis.control.identity.oidc import OidcConfig
from aegis_demo.catalog import PERSONAS
from aegis_demo.keycloak_setup import CLIENT_ID, ISSUER, STAFF_ROLES, build_realm, role_identities, role_map

PASSWORD = "unit-test-password"


def test_every_staff_role_gets_its_own_account_and_no_account_holds_two_roles():
    realm = build_realm(PASSWORD)
    users = {u["username"]: u for u in realm["users"]}
    staff = {name: roles for name, _, roles, _ in PERSONAS if roles != ["customer"]}
    # One account per (person, role): a person with two roles gets two accounts.
    assert len(users) == sum(len(roles) for roles in staff.values()) == len(STAFF_ROLES)
    for user in users.values():
        assert len(user["realmRoles"]) == 1  # never two roles on one login
        assert user["emailVerified"] and user["enabled"] and user["lastName"]
    held = sorted(role for user in users.values() for role in user["realmRoles"])
    assert held == sorted(f"aegis-{role}" for role in STAFF_ROLES)  # every role has exactly one account
    for name, roles in staff.items():
        assert users[name]["realmRoles"] == [f"aegis-{roles[0]}"]  # the person's own username keeps their first role
        for extra in roles[1:]:
            account = users[f"{name}.{extra}"]
            assert account["realmRoles"] == [f"aegis-{extra}"] and extra.replace("-", " ") in account["lastName"]
    assert not {"jan.devries"} & set(users)  # customers are bank customers, not people who sign in to the console


def test_names_use_only_characters_keycloak_accepts():
    # Keycloak's user profile rejects these in first and last names (error-person-name-invalid-character); one bad
    # account would make the whole realm import fail.
    forbidden = set('<>&"$%!#?§;*~/\\|^=[]{}()')
    for identity in role_identities():
        assert not forbidden & set(identity["first"] + identity["last"]), identity
        assert identity["first"].strip() and identity["last"].strip()
    for user in build_realm(PASSWORD)["users"]:
        assert not forbidden & set(user["firstName"] + user["lastName"]), user["username"]


def test_role_identities_are_unique_and_traceable_to_a_person():
    identities = role_identities()
    assert len({i["username"] for i in identities}) == len(identities)
    assert {i["role"] for i in identities} == set(STAFF_ROLES)
    assert {i["person"] for i in identities} == {name for _, name, roles, _ in PERSONAS if roles != ["customer"]}
    assert "priya.raman.policy-author" in {i["username"] for i in identities}


def test_role_map_covers_every_persona_role_and_every_defined_realm_role():
    mapping = role_map()
    defined = {r["name"] for r in build_realm(PASSWORD)["roles"]["realm"]}
    assert set(mapping) == defined and set(mapping.values()) == set(STAFF_ROLES)
    persona_roles = {r for _, _, roles, _ in PERSONAS for r in roles if r != "customer"}
    assert persona_roles <= set(mapping.values())


def test_the_console_client_is_public_pkce_only():
    (client,) = build_realm(PASSWORD)["clients"]
    assert client["clientId"] == CLIENT_ID and client["publicClient"] is True
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert not client["implicitFlowEnabled"] and not client["directAccessGrantsEnabled"]
    assert not client["serviceAccountsEnabled"] and "secret" not in client
    assert all(uri.endswith("/ui/auth/callback") and "*" not in uri for uri in client["redirectUris"])
    audience = next(m for m in client["protocolMappers"] if m["protocolMapper"] == "oidc-audience-mapper")
    assert audience["config"]["included.client.audience"] == CLIENT_ID  # Keycloak says "account" unless told


def test_origins_drive_redirects_web_origins_and_logout():
    (client,) = build_realm(PASSWORD, ("http://127.0.0.1:9999",))["clients"]
    assert client["redirectUris"] == ["http://127.0.0.1:9999/ui/auth/callback"]
    assert client["webOrigins"] == ["http://127.0.0.1:9999"]
    assert client["attributes"]["post.logout.redirect.uris"] == "http://127.0.0.1:9999/ui/"


def test_aegis_settings_for_keycloak_accept_the_realm_it_describes():
    config = OidcConfig.from_settings(
        Settings(
            oidc_issuer=ISSUER,
            oidc_one_role_per_account=True,
            oidc_client_id=CLIENT_ID,
            oidc_roles_claim="realm_access.roles",
            oidc_role_map=json.dumps(role_map()),
        )
    )
    assert (
        config is not None
        and config.audience == CLIENT_ID
        and config.role_map["aegis-risk-approver"] == ["risk-approver"]
    )


def test_the_only_password_in_the_realm_is_the_one_passed_in():
    text = json.dumps(build_realm(PASSWORD))
    assert text.count(PASSWORD) == len(build_realm(PASSWORD)["users"])
    assert "dev-internal-token" not in text and "secret" not in json.dumps(build_realm(PASSWORD)["clients"])
