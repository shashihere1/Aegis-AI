"""Sign-in for people: the generic OIDC adapter against a fake provider, and the built-in provider end to end."""

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aegis.common.crypto import SigningKey
from aegis.common.settings import Settings
from aegis.control.identity import oidc as oidc_module
from aegis.control.identity.idp import DevIdp, Persona
from aegis.control.identity.oidc import IdentityUnavailable, OidcConfig, OidcVerifier
from aegis.control.identity.users import UserAuthenticator
from aegis_demo.testing import BASE, FAKE_LLM_URL, running_world

ISSUER = "https://idp.example.test/realms/aegis"
CLIENT = "aegis-console"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeProvider:
    """A stand-in for Keycloak / Entra ID: discovery document, JWKS and RS256 tokens."""

    def __init__(self):
        self.keys: dict[str, rsa.RSAPrivateKey] = {}
        self.add_key("k1")
        self.jwks_hits = 0
        self.issuer_in_discovery = ISSUER
        self.down = False

    def add_key(self, kid: str) -> None:
        self.keys[kid] = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwks(self) -> dict:
        keys = []
        for kid, key in self.keys.items():
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
            keys.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": keys}

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            return httpx.Response(500)
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": self.issuer_in_discovery,
                    "jwks_uri": f"{ISSUER}/keys",
                    "authorization_endpoint": f"{ISSUER}/auth",
                    "token_endpoint": f"{ISSUER}/tok",
                },
            )
        if request.url.path.endswith("/keys"):
            self.jwks_hits += 1
            return httpx.Response(200, json=self.jwks())
        return httpx.Response(404)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    def token(self, kid: str = "k1", **overrides) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": "u-1",
            "aud": CLIENT,
            "iat": now,
            "exp": now + 600,
            "preferred_username": "sanne.bakker",
            "name": "Sanne Bakker",
            "realm_access": {"roles": ["aegis-approver", "offline_access"]},
            **overrides,
        }
        claims = {k: v for k, v in claims.items() if v is not None}
        pem = self.keys[kid].private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": kid})


def settings(**kw) -> Settings:
    base = {
        "oidc_issuer": ISSUER,
        "oidc_client_id": CLIENT,
        "oidc_roles_claim": "realm_access.roles",
        "oidc_role_map": json.dumps({"aegis-approver": "risk-approver", "aegis-soc": ["soc-analyst"]}),
    }
    return Settings(**(base | kw))


def verifier(provider: FakeProvider, **kw) -> OidcVerifier:
    return OidcVerifier(OidcConfig.from_settings(settings(**kw)), provider.client())


@pytest.fixture(scope="module")
def provider() -> FakeProvider:
    return FakeProvider()


async def test_valid_token_becomes_a_persona_with_mapped_roles(provider):
    persona = await verifier(provider).authenticate(provider.token())
    assert (persona.username, persona.name) == ("sanne.bakker", "Sanne Bakker")
    assert persona.roles == ["risk-approver"]  # offline_access is not in the map, so it is not granted


async def test_entra_style_claims_pass_roles_through_and_accept_an_audience_list(provider):
    v = verifier(provider, oidc_roles_claim="roles", oidc_role_map="", oidc_audience=f"api://{CLIENT}")
    token = provider.token(
        aud=[f"api://{CLIENT}", "other"],
        roles=["risk-approver", "auditor"],
        realm_access=None,
        entitlements=["own_accounts.read"],
    )
    persona = await v.authenticate(token)
    assert persona.roles == ["risk-approver", "auditor"] and persona.entitlements == ["own_accounts.read"]


async def test_one_role_per_account_refuses_logins_that_hold_several_roles(provider):
    two = provider.token(realm_access={"roles": ["aegis-approver", "aegis-soc", "offline_access"]})
    mapping = json.dumps({"aegis-approver": "risk-approver", "aegis-soc": "soc-analyst"})
    strict = verifier(provider, oidc_role_map=mapping, oidc_one_role_per_account=True)
    with pytest.raises(jwt.InvalidTokenError, match="sign in with a separate account for each role") as refused:
        await strict.authenticate(two)
    assert "risk-approver" in str(refused.value) and "soc-analyst" in str(refused.value)
    # one role (extra provider roles that map to nothing do not count), or none at all, is fine
    assert (await strict.authenticate(provider.token())).roles == ["risk-approver"]
    nothing = await strict.authenticate(provider.token(realm_access={"roles": ["offline_access"]}))
    assert nothing.roles == []  # signed in, but entitled to nothing
    # the same token is accepted when the rule is off (the default), so existing setups keep working
    relaxed = verifier(provider, oidc_role_map=mapping)
    assert (await relaxed.authenticate(two)).roles == ["risk-approver", "soc-analyst"]
    # two provider roles that map to the same Aegis role are still one role
    same = json.dumps({"a": "auditor", "b": "auditor"})
    merged = verifier(provider, oidc_role_map=same, oidc_one_role_per_account=True)
    assert (await merged.authenticate(provider.token(realm_access={"roles": ["a", "b"]}))).roles == ["auditor"]


async def test_the_rule_also_guards_the_token_exchange_path(provider):
    idp = DevIdp("http://control.test/idp", SigningKey.load_or_generate("", "idp-1"))
    mapping = json.dumps({"aegis-approver": "risk-approver", "aegis-soc": "soc-analyst"})
    cfg = settings(oidc_role_map=mapping, oidc_one_role_per_account=True)
    users = UserAuthenticator(idp, cfg, OidcVerifier(OidcConfig.from_settings(cfg), provider.client()))
    with pytest.raises(jwt.InvalidTokenError):
        await users.authenticate(provider.token(realm_access={"roles": ["aegis-approver", "aegis-soc"]}))


async def test_username_falls_back_to_email_then_subject(provider):
    v = verifier(provider)
    assert (await v.authenticate(provider.token(preferred_username=None, email="a@b.test"))).username == "a@b.test"
    assert (await v.authenticate(provider.token(preferred_username=None))).username == "u-1"


def forged(header: dict, payload: dict, secret: bytes | None = None) -> str:
    head, body = b64(json.dumps(header).encode()), b64(json.dumps(payload).encode())
    signature = b64(hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()) if secret else ""
    return f"{head}.{body}.{signature}"


async def test_bad_tokens_are_rejected(provider):
    v = verifier(provider)
    now = int(time.time())
    good = provider.token()
    head, body, signature = good.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    escalated = {**claims, "realm_access": {"roles": ["aegis-soc"]}}
    public_pem = (
        provider.keys["k1"]
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    cases = {
        "expired": provider.token(exp=now - 3600, iat=now - 7200),
        "wrong audience": provider.token(aud="some-other-app"),
        "wrong issuer": provider.token(iss="https://evil.example.test"),
        "no expiry": provider.token(exp=None),
        "not yet valid": provider.token(nbf=now + 3600),
        "tampered claims": f"{head}.{b64(json.dumps(escalated).encode())}.{signature}",
        "signed by an unknown key": provider.token(kid="k1")[:-6] + "AAAAAA",
        "alg none": forged({"alg": "none", "kid": "k1"}, claims),
        "HS256 with the public key as secret": forged({"alg": "HS256", "kid": "k1"}, claims, public_pem),
        "no key id": forged({"alg": "RS256"}, claims),
        "garbage": "not-a-token",
    }
    for name, token in cases.items():
        with pytest.raises(jwt.InvalidTokenError):
            await v.authenticate(token)
        print("rejected:", name)


async def test_rotated_keys_are_picked_up_but_unknown_keys_cannot_hammer_the_provider(provider, monkeypatch):
    v = verifier(provider)
    await v.authenticate(provider.token())
    hits = provider.jwks_hits
    provider.add_key("k2")
    with pytest.raises(jwt.InvalidTokenError):  # inside the cooldown a new key is not fetched yet
        await v.authenticate(provider.token(kid="k2"))
    assert provider.jwks_hits == hits
    monkeypatch.setattr(oidc_module, "JWKS_REFRESH_COOLDOWN", 0)
    assert (await v.authenticate(provider.token(kid="k2"))).username == "sanne.bakker"
    assert provider.jwks_hits == hits + 1
    del provider.keys["k2"]


async def test_discovery_must_confirm_the_issuer(provider):
    provider.issuer_in_discovery = "https://other.example.test"
    try:
        with pytest.raises(IdentityUnavailable):
            await verifier(provider).authenticate(provider.token())
    finally:
        provider.issuer_in_discovery = ISSUER


async def test_an_unreachable_provider_is_unavailable_not_unauthorised(provider):
    provider.down = True
    try:
        with pytest.raises(IdentityUnavailable):
            await verifier(provider).authenticate(provider.token())
    finally:
        provider.down = False


def test_symmetric_algorithms_cannot_be_configured():
    with pytest.raises(ValueError):
        OidcConfig.from_settings(settings(oidc_algorithms="HS256"))
    assert OidcConfig.from_settings(Settings()) is None  # nothing configured, no SSO


async def test_authenticator_picks_the_verifier_by_issuer(provider):
    idp = DevIdp("http://control.test/idp", SigningKey.load_or_generate("", "idp-1"))
    idp.add_persona(Persona("mark.jansen", "Mark Jansen", ["soc-analyst"]))
    cfg = settings()
    users = UserAuthenticator(idp, cfg, verifier(provider))
    assert (await users.authenticate(idp.login("mark.jansen"))).roles == ["soc-analyst"]
    assert (await users.authenticate(provider.token())).roles == ["risk-approver"]
    with pytest.raises(jwt.InvalidTokenError):
        await users.authenticate(provider.token(iss="https://unknown.example.test"))
    cfg.enable_dev_login = False
    with pytest.raises(jwt.InvalidTokenError):  # a real SSO deployment refuses persona tokens outright
        await users.authenticate(idp.login("mark.jansen"))
    assert (await users.authenticate(provider.token())).username == "sanne.bakker"


# ---- the built-in provider and the API, end to end ----

PASSWORD = "correct-horse-battery"
REDIRECT = "http://127.0.0.1:8000/ui/auth/callback"


@pytest.fixture
async def sso():
    ready: asyncio.Future = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()

    async def owner():
        async with running_world(llm_upstream_url=FAKE_LLM_URL, builtin_oidc=True, builtin_oidc_password=PASSWORD) as w:
            ready.set_result(w)
            await stop.wait()

    task = asyncio.create_task(owner())
    await asyncio.wait({task, ready}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        task.result()
    yield ready.result()
    stop.set()
    await task


def pkce() -> tuple[str, str]:
    verifier_ = secrets.token_urlsafe(48)
    return verifier_, b64(hashlib.sha256(verifier_.encode()).digest())


def authorize_params(challenge: str, **kw) -> dict:
    return {
        "client_id": CLIENT,
        "redirect_uri": REDIRECT,
        "response_type": "code",
        "scope": "openid profile",
        "state": "st-1",
        "nonce": "nonce-1",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    } | kw


async def login(w, challenge: str, username="mark.jansen", password=PASSWORD, **kw) -> httpx.Response:
    return await w.http.post(
        f"{BASE}/oidc/authorize",
        data=authorize_params(challenge, **kw) | {"username": username, "password": password},
        follow_redirects=False,
    )


async def exchange(w, code: str, verifier_: str, **kw) -> httpx.Response:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": CLIENT,
        "code_verifier": verifier_,
    } | kw
    return await w.http.post(f"{BASE}/oidc/token", data=data)


def code_from(response: httpx.Response) -> str:
    assert response.status_code == 302, response.text
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["state"] == ["st-1"] and query["iss"] == [f"{BASE}/oidc"]
    return query["code"][0]


async def test_console_config_advertises_the_providers_endpoints(sso):
    config = (await sso.http.get(f"{BASE}/v1/auth/config")).json()
    assert config["dev_login"] is True and config["oidc_error"] is None
    assert config["oidc"]["authorization_endpoint"] == f"{BASE}/oidc/authorize"
    assert config["oidc"]["client_id"] == CLIENT and config["oidc"]["builtin"] is True
    discovery = (await sso.http.get(f"{BASE}/oidc/.well-known/openid-configuration")).json()
    assert discovery["code_challenge_methods_supported"] == ["S256"] and discovery["issuer"] == f"{BASE}/oidc"


async def test_authorization_code_flow_with_pkce_signs_a_person_in(sso):
    verifier_, challenge = pkce()
    form = await sso.http.get(f"{BASE}/oidc/authorize", params=authorize_params(challenge))
    assert (
        form.status_code == 200 and "Sign in to Aegis AI" in form.text and form.headers["cache-control"] == "no-store"
    )
    tokens = (await exchange(sso, code_from(await login(sso, challenge)), verifier_)).json()
    me = await sso.http.get(f"{BASE}/v1/auth/me", headers={"authorization": f"Bearer {tokens['access_token']}"})
    assert me.json()["username"] == "mark.jansen" and "soc-analyst" in me.json()["roles"]
    assert jwt.decode(tokens["id_token"], options={"verify_signature": False})["nonce"] == "nonce-1"


async def test_sso_roles_decide_what_a_person_may_do(sso):
    async def call(username: str, method: str, path: str, **kw):
        verifier_, challenge = pkce()
        token = (await exchange(sso, code_from(await login(sso, challenge, username)), verifier_)).json()
        return await sso.http.request(
            method, f"{BASE}{path}", headers={"authorization": f"Bearer {token['access_token']}"}, **kw
        )

    assert (await call("mark.jansen", "GET", "/v1/agents/stats")).status_code == 200
    assert (
        await call("mark.jansen", "POST", "/v1/agents/AGT-NONE/approve", json={})
    ).status_code == 403  # not an approver
    assert (await call("sanne.bakker", "POST", "/v1/agents/AGT-NONE/approve", json={})).status_code == 404  # allowed in


async def test_the_code_is_bound_to_pkce_and_works_once(sso):
    verifier_, challenge = pkce()
    code = code_from(await login(sso, challenge))
    wrong = await exchange(sso, code, "x" * 50)
    assert wrong.status_code == 400 and wrong.json()["error"] == "invalid_grant"
    assert (await exchange(sso, code, verifier_)).status_code == 400  # a failed attempt burns the code

    code = code_from(await login(sso, challenge))
    assert (await exchange(sso, code, verifier_)).status_code == 200
    assert (await exchange(sso, code, verifier_)).status_code == 400  # replay
    code = code_from(await login(sso, challenge))
    assert (await exchange(sso, code, verifier_, redirect_uri="http://127.0.0.1:8000/other")).status_code == 400
    assert (
        await exchange(sso, code_from(await login(sso, challenge)), verifier_, client_id="other")
    ).status_code == 400


async def test_unsafe_authorization_requests_are_refused(sso):
    _, challenge = pkce()
    evil = await sso.http.get(
        f"{BASE}/oidc/authorize", params=authorize_params(challenge, redirect_uri="https://evil.test/cb")
    )
    assert evil.status_code == 400 and "location" not in evil.headers  # never redirect to an unregistered URI
    plain = await sso.http.get(
        f"{BASE}/oidc/authorize",
        params=authorize_params(challenge, code_challenge_method="plain"),
        follow_redirects=False,
    )
    assert plain.status_code == 302 and "error=invalid_request" in plain.headers["location"]
    no_state = await sso.http.get(
        f"{BASE}/oidc/authorize", params=authorize_params(challenge, state=""), follow_redirects=False
    )
    assert "error=invalid_request" in no_state.headers["location"]
    tampered = await login(sso, challenge, redirect_uri="https://evil.test/cb")  # hidden fields are re-validated
    assert tampered.status_code == 400


async def test_wrong_passwords_and_customers_cannot_sign_in_and_guessing_is_throttled(sso):
    _, challenge = pkce()
    assert (await login(sso, challenge, password="nope")).status_code == 401
    assert (await login(sso, challenge, username="jan.devries")).status_code == 401  # customers are not staff
    assert (await login(sso, challenge, username="nobody")).status_code == 401
    for _ in range(5):
        await login(sso, challenge, username="eva.visser", password="guess")
    assert (await login(sso, challenge, username="eva.visser")).status_code == 429  # even with the right password


async def test_token_endpoint_allows_only_the_consoles_own_origins(sso):
    _, challenge = pkce()
    ok = await sso.http.post(
        f"{BASE}/oidc/token", headers={"origin": "http://127.0.0.1:5173"}, data={"grant_type": "x"}
    )
    assert ok.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"
    evil = await sso.http.post(f"{BASE}/oidc/token", headers={"origin": "https://evil.test"}, data={"grant_type": "x"})
    assert "access-control-allow-origin" not in evil.headers


async def test_turning_dev_login_off_leaves_only_sso(sso):
    dev_token = sso.token("mark.jansen")
    assert (
        await sso.http.get(f"{BASE}/v1/auth/me", headers={"authorization": f"Bearer {dev_token}"})
    ).status_code == 200
    sso.ctx.settings.enable_dev_login = False
    assert (await sso.http.post(f"{BASE}/idp/login", json={"username": "mark.jansen"})).status_code == 403
    assert (await sso.http.get(f"{BASE}/idp/personas")).status_code == 403
    assert (
        await sso.http.get(f"{BASE}/v1/auth/me", headers={"authorization": f"Bearer {dev_token}"})
    ).status_code == 401
    assert (await sso.http.get(f"{BASE}/v1/auth/config")).json()["dev_login"] is False
    verifier_, challenge = pkce()
    tokens = (await exchange(sso, code_from(await login(sso, challenge)), verifier_)).json()
    me = await sso.http.get(f"{BASE}/v1/auth/me", headers={"authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200


async def test_the_built_in_provider_accepts_the_consoles_logout_request(sso):
    home = "http://127.0.0.1:8000/ui/"
    ok = await sso.http.get(
        f"{BASE}/oidc/logout",
        params={"client_id": CLIENT, "post_logout_redirect_uri": home, "id_token_hint": "any.token.here"},
        follow_redirects=False,
    )
    assert ok.status_code == 302 and ok.headers["location"] == home
    elsewhere = await sso.http.get(
        f"{BASE}/oidc/logout",
        params={"client_id": CLIENT, "post_logout_redirect_uri": "https://evil.example/x"},
        follow_redirects=False,
    )
    assert elsewhere.status_code == 200 and "location" not in elsewhere.headers  # never an open redirect
