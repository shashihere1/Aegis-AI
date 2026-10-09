"""One Keycloak account per role, against a REAL Keycloak (skipped unless the local Keycloak is running).

    python -m aegis_demo.keycloak_setup start
    python -m pytest tests/test_keycloak_role_identities_live.py -q

The sign-ins here use the real login form, the authorization-code + PKCE exchange and Aegis's own token checks, driven
over HTTP (no browser). Temporary accounts are removed again.
"""

import base64
import hashlib
import html
import json
import re
import secrets
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest

from aegis.common.settings import Settings
from aegis.control.identity.oidc import OidcConfig, OidcVerifier
from aegis_demo import keycloak_setup as kc

REDIRECT = "http://127.0.0.1:8000/ui/auth/callback"


def demo_password_or_skip() -> str:
    path = kc.HOME / "credentials.json"
    if not path.exists() or not kc.ready():
        pytest.skip("local Keycloak is not running (python -m aegis_demo.keycloak_setup start)")
    return json.loads(path.read_text("utf-8"))["demo_password"]


@pytest.fixture
def password() -> str:
    return demo_password_or_skip()


@pytest.fixture
async def verifier() -> OidcVerifier:
    """Aegis's own sign-in check, configured exactly as the Keycloak env script configures it."""
    config = OidcConfig.from_settings(
        Settings(
            oidc_issuer=kc.ISSUER,
            oidc_client_id=kc.CLIENT_ID,
            oidc_roles_claim="realm_access.roles",
            oidc_role_map=json.dumps(kc.role_map()),
            oidc_one_role_per_account=True,
        )
    )
    http = httpx.AsyncClient(timeout=20, trust_env=False)
    yield OidcVerifier(config, http)
    await http.aclose()


async def sign_in(username: str, password: str) -> str:
    """Log in through Keycloak's real login form and return the access token (authorization code + PKCE)."""
    verifier_ = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier_.encode()).digest()).rstrip(b"=").decode()
    async with httpx.AsyncClient(timeout=20, trust_env=False, follow_redirects=False) as http:
        page = await http.get(
            f"{kc.ISSUER}/protocol/openid-connect/auth",
            params={
                "client_id": kc.CLIENT_ID,
                "redirect_uri": REDIRECT,
                "response_type": "code",
                "scope": "openid profile",
                "state": "s-1",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert page.status_code == 200, page.text[:200]
        action = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page.text) or re.search(
            r'action="([^"]+authenticate[^"]*)"', page.text
        )
        assert action, "the Keycloak login form was not found"
        # Keycloak marks its login cookies Secure. Browsers send those to http://127.0.0.1, Python's cookie jar does
        # not, so the cookies are passed by hand.
        cookies = "; ".join(header.split(";")[0] for header in page.headers.get_list("set-cookie"))
        reply = await http.post(
            html.unescape(action.group(1)),
            data={"username": username, "password": password},
            headers={"cookie": cookies},
        )
        if reply.status_code != 302:
            raise AssertionError(f"login for {username} did not redirect (HTTP {reply.status_code})")
        query = parse_qs(urlsplit(reply.headers["location"]).query)
        assert query["state"] == ["s-1"] and "code" in query, reply.headers["location"]
        token = await http.post(
            f"{kc.ISSUER}/protocol/openid-connect/token",
            data={
                "grant_type": "authorization_code",
                "code": query["code"][0],
                "redirect_uri": REDIRECT,
                "client_id": kc.CLIENT_ID,
                "code_verifier": verifier_,
            },
        )
        assert token.status_code == 200, token.text
        return token.json()["access_token"]


async def test_the_running_realm_has_exactly_one_account_per_role():
    demo_password_or_skip()
    http = kc.admin_session()
    wanted = {i["username"]: f"{kc.KEYCLOAK_ROLE_PREFIX}{i['role']}" for i in kc.role_identities()}
    held = {}
    for username in wanted:
        found = http.get("/users", params={"username": username, "exact": "true"}).json()
        assert len(found) == 1, f"{username} is missing from Keycloak"
        roles = http.get(f"/users/{found[0]['id']}/role-mappings/realm").json()
        held[username] = sorted(r["name"] for r in roles if r["name"].startswith(kc.KEYCLOAK_ROLE_PREFIX))
    assert held == {username: [role] for username, role in wanted.items()}  # one Aegis role each, the right one
    # Every role has an account; security-approver has two people (a rule change needs two independent sign-offs).
    assert set(wanted.values()) == {f"{kc.KEYCLOAK_ROLE_PREFIX}{role}" for role in kc.STAFF_ROLES}


async def test_every_role_account_really_signs_in_and_aegis_sees_exactly_its_role(password, verifier):
    seen = {}
    for identity in kc.role_identities():
        token = await sign_in(identity["username"], password)
        persona = await verifier.authenticate(token)  # Aegis's own checks, with one-role-per-account switched on
        assert persona.username == identity["username"]
        assert persona.roles == [identity["role"]], f"{identity['username']} must hold exactly {identity['role']}"
        seen[identity["username"]] = persona.roles[0]
    assert len(seen) == len(kc.role_identities()) and set(seen.values()) == set(kc.STAFF_ROLES)  # every role signs in


async def test_a_person_with_two_duties_uses_two_logins_with_different_roles(password, verifier):
    developer = await verifier.authenticate(await sign_in("priya.raman", password))
    author = await verifier.authenticate(await sign_in("priya.raman.policy-author", password))
    assert (developer.roles, author.roles) == (["agent-developer"], ["policy-author"])
    assert developer.name == "Priya Raman" and author.name.startswith("Priya Raman")
    assert developer.username != author.username


async def test_a_wrong_password_is_refused_by_keycloak(password):
    with pytest.raises(AssertionError, match="did not redirect"):
        await sign_in("sanne.bakker", password + "-wrong")


async def test_a_login_that_holds_two_roles_is_refused_by_aegis(password, verifier):
    http = kc.admin_session()
    username = f"tmp-two-roles-{uuid.uuid4().hex[:6]}"
    realm_roles = {r["name"]: r for r in http.get("/roles", params={"max": 500}).json()}
    created = http.post(
        "/users",
        json=kc.user_representation({"username": username, "first": "Temp", "last": "Account"}, password),
    )
    assert created.status_code == 201, created.text
    user_id = created.headers["location"].rsplit("/", 1)[1]
    try:
        both = [realm_roles["aegis-risk-approver"], realm_roles["aegis-soc-analyst"]]
        assert http.post(f"/users/{user_id}/role-mappings/realm", json=both).status_code == 204
        token = await sign_in(username, password)
        with pytest.raises(jwt.InvalidTokenError, match="sign in with a separate account for each role"):
            await verifier.authenticate(token)
        # With the rule off the same login is accepted, so the rule is what makes the difference.
        relaxed = OidcVerifier(
            OidcConfig.from_settings(
                Settings(
                    oidc_issuer=kc.ISSUER,
                    oidc_client_id=kc.CLIENT_ID,
                    oidc_roles_claim="realm_access.roles",
                    oidc_role_map=json.dumps(kc.role_map()),
                )
            ),
            verifier.http,
        )
        assert sorted((await relaxed.authenticate(token)).roles) == ["risk-approver", "soc-analyst"]
    finally:
        http.delete(f"/users/{user_id}")
    assert http.get("/users", params={"username": username, "exact": "true"}).json() == []


async def test_the_generated_realm_file_imports_cleanly_into_a_fresh_realm(password):
    """A first-time start imports `build_realm()` as a file; prove Keycloak accepts every user in it."""
    admin = kc.admin_session()
    name = f"aegis-import-test-{uuid.uuid4().hex[:6]}"
    representation = kc.build_realm(password) | {"realm": name}
    root = admin.base_url.copy_with(path="/admin/realms")
    try:
        created = admin.post(str(root), json=representation)
        assert created.status_code == 201, created.text[:300]
        users = admin.get(f"{root}/{name}/users", params={"max": 100}).json()
        assert sorted(u["username"] for u in users) == sorted(i["username"] for i in kc.role_identities())
        wanted = {i["username"]: f"{kc.KEYCLOAK_ROLE_PREFIX}{i['role']}" for i in kc.role_identities()}
        for user in users:
            roles = admin.get(f"{root}/{name}/users/{user['id']}/role-mappings/realm").json()
            ours = [r["name"] for r in roles if r["name"].startswith(kc.KEYCLOAK_ROLE_PREFIX)]
            assert ours == [wanted[user["username"]]], user["username"]  # one role, the right one
            assert user["enabled"] and user["emailVerified"] and not user.get("requiredActions")
            credentials = admin.get(f"{root}/{name}/users/{user['id']}/credentials").json()
            assert [c["type"] for c in credentials] == ["password"]  # a usable, permanent password
        clients = {c["clientId"] for c in admin.get(f"{root}/{name}/clients").json()}
        assert kc.CLIENT_ID in clients
    finally:
        admin.delete(f"{root}/{name}")
    assert name not in {r["realm"] for r in admin.get(str(root)).json()}  # nothing left behind


class Browser:
    """Keeps cookies the way a real browser does (it sends Keycloak's Secure cookies to http://127.0.0.1)."""

    def __init__(self):
        self.http = httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=20)
        self.cookies: dict[str, str] = {}

    async def send(self, method: str, url: str, **kwargs) -> httpx.Response:
        headers = {"cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())}
        reply = await self.http.request(method, url, headers=headers, **kwargs)
        for header in reply.headers.get_list("set-cookie"):
            name, _, rest = header.partition("=")
            value = rest.split(";", 1)[0]
            if not value or "max-age=0" in header.lower() or "1970" in header:
                self.cookies.pop(name, None)  # the server is deleting it
            else:
                self.cookies[name] = value
        return reply


HOME = "http://127.0.0.1:8000/ui/"
AUTH = f"{kc.ISSUER}/protocol/openid-connect/auth"
LOGOUT = f"{kc.ISSUER}/protocol/openid-connect/logout"


def authorize_query() -> tuple[str, dict]:
    verifier_ = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier_.encode()).digest()).rstrip(b"=").decode()
    return verifier_, {
        "client_id": kc.CLIENT_ID,
        "redirect_uri": REDIRECT,
        "response_type": "code",
        "scope": "openid profile email",
        "state": "s-1",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


async def sign_in_with(browser: Browser, username: str, password: str, login_page: httpx.Response | None = None):
    """Run the whole login in this browser; returns (token response, whether Keycloak showed a login form)."""
    verifier_, query = authorize_query()
    page = login_page or await browser.send("GET", AUTH, params=query)
    shows_form = page.status_code == 200 and "kc-form-login" in page.text
    if shows_form:
        action = html.unescape(re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page.text).group(1))
        page = await browser.send("POST", action, data={"username": username, "password": password})
    assert page.status_code == 302, f"expected a redirect back to the console, got HTTP {page.status_code}"
    code = parse_qs(urlsplit(page.headers["location"]).query)["code"][0]
    token = await browser.send(
        "POST",
        f"{kc.ISSUER}/protocol/openid-connect/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": kc.CLIENT_ID,
            "code_verifier": verifier_,
        },
    )
    assert token.status_code == 200, token.text
    return token.json(), shows_form


def account_of(tokens: dict) -> str:
    return jwt.decode(tokens["access_token"], options={"verify_signature": False})["preferred_username"]


async def test_without_ending_the_keycloak_session_the_next_sign_in_is_silent_and_cannot_change_account(password):
    """Why the console must end the provider session first: Keycloak otherwise signs you straight back in."""
    browser = Browser()
    first, _ = await sign_in_with(browser, "sanne.bakker", password)
    assert account_of(first) == "sanne.bakker"
    again, showed_form = await sign_in_with(browser, "mark.jansen", password)  # asks for Mark, but...
    assert showed_form is False and account_of(again) == "sanne.bakker"  # ...no form, and still Sanne
    # prompt=login only re-asks for the SAME user's password; it cannot switch accounts either.
    _, query = authorize_query()
    reauth = await browser.send("GET", AUTH, params=query | {"prompt": "login"})
    assert reauth.status_code == 200 and 'name="username"' not in reauth.text
    await browser.http.aclose()


async def test_ending_the_session_first_lets_a_person_sign_in_as_another_role(password, verifier):
    """The sequence the console runs for 'Switch account': log out at Keycloak, then sign in again."""
    browser = Browser()
    first, _ = await sign_in_with(browser, "sanne.bakker", password)
    assert (await verifier.authenticate(first["access_token"])).roles == ["risk-approver"]

    out = await browser.send(
        "GET",
        LOGOUT,
        params={"client_id": kc.CLIENT_ID, "post_logout_redirect_uri": HOME, "id_token_hint": first["id_token"]},
    )
    assert out.status_code == 302 and out.headers["location"] == HOME  # back to the console, session ended

    second, showed_form = await sign_in_with(browser, "mark.jansen", password)
    assert showed_form is True  # a real login form this time, so the person chooses the account
    assert account_of(second) == "mark.jansen"
    assert (await verifier.authenticate(second["access_token"])).roles == ["soc-analyst"]
    assert (await verifier.authenticate(first["access_token"])).roles == [
        "risk-approver"
    ]  # old token lives out its life
    await browser.http.aclose()


async def test_logging_out_when_there_is_no_session_returns_straight_to_the_console(password):
    """Persona switching or a first sign-in may call logout with nothing to end; that must not show an error."""
    browser = Browser()
    out = await browser.send("GET", LOGOUT, params={"client_id": kc.CLIENT_ID, "post_logout_redirect_uri": HOME})
    assert out.status_code == 302 and out.headers["location"] == HOME
    await browser.http.aclose()


async def test_the_logout_only_returns_to_registered_console_addresses(password):
    browser = Browser()
    for target in ("https://evil.example/phish", HOME + "elsewhere", HOME + "?next=1"):
        out = await browser.send("GET", LOGOUT, params={"client_id": kc.CLIENT_ID, "post_logout_redirect_uri": target})
        assert out.status_code == 400, target  # never an open redirect
    await browser.http.aclose()
