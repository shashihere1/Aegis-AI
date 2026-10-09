"""A small standards-compliant OpenID Connect provider built into the demo server, mounted at /oidc.

It exists so the console's real sign-in flow (authorization code + PKCE, discovery, JWKS) can be shown on a laptop
with nothing installed. Aegis consumes it exactly like Keycloak or Microsoft Entra ID, through `oidc.OidcVerifier`.
DEMO ONLY: accounts are the demo personas, all sharing one password, and signing keys are generated at start-up.
"""

import base64
import hashlib
import hmac
import html
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from aegis.common import crypto
from aegis.common.crypto import SigningKey
from aegis.common.settings import Settings
from aegis.control.identity.idp import Persona
from aegis.control.identity.oidc import OidcConfig

CODE_TTL = 60
TOKEN_TTL = 3600
MAX_FAILURES = 5
FAILURE_WINDOW = 60
NO_STORE = {"cache-control": "no-store", "pragma": "no-cache"}
PAGE_HEADERS = {**NO_STORE, "x-frame-options": "DENY", "content-security-policy": "frame-ancestors 'none'"}


@dataclass
class AuthCode:
    username: str
    redirect_uri: str
    challenge: str
    nonce: str
    scope: str
    expires: float


class BuiltinOidc:
    def __init__(self, settings: Settings, config: OidcConfig, personas: dict[str, Persona]):
        if not settings.builtin_oidc_password:
            raise RuntimeError("AEGIS_BUILTIN_OIDC_PASSWORD is required when AEGIS_BUILTIN_OIDC is on")
        self.password = settings.builtin_oidc_password
        self.config = config
        self.personas = personas
        self.key = SigningKey.load_or_generate("", "oidc-1")
        self.redirect_uris = {u.strip() for u in settings.oidc_redirect_uris.split(",") if u.strip()}
        self.codes: dict[str, AuthCode] = {}
        self.failures: dict[str, tuple[int, float]] = {}

    # ---- addresses ----
    @property
    def issuer(self) -> str:
        return self.config.issuer

    @property
    def origins(self) -> set[str]:
        return {f"{u.scheme}://{u.netloc}" for u in map(urlsplit, self.redirect_uris)}

    @property
    def logout_uris(self) -> set[str]:
        return {u.rsplit("auth/callback", 1)[0] for u in self.redirect_uris if u.endswith("auth/callback")}

    def discovery(self) -> dict:
        base = self.issuer
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "jwks_uri": f"{base}/jwks",
            "end_session_endpoint": f"{base}/logout",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [crypto.ALGORITHM],
            "scopes_supported": ["openid", "profile"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": ["sub", "name", "preferred_username", "roles", "entitlements"],
            "authorization_response_iss_parameter_supported": True,
        }

    # ---- accounts ----
    def account(self, username: str) -> Persona | None:
        persona = self.personas.get(username.strip())
        if persona is None or persona.status != "active" or persona.roles == ["customer"]:
            return None
        return persona

    def staff_names(self) -> list[str]:
        return sorted(p.username for p in self.personas.values() if p.status == "active" and p.roles != ["customer"])

    def throttled(self, username: str) -> bool:
        count, started = self.failures.get(username.lower(), (0, 0.0))
        return count >= MAX_FAILURES and time.monotonic() - started < FAILURE_WINDOW

    def note_failure(self, username: str) -> None:
        count, started = self.failures.get(username.lower(), (0, 0.0))
        now = time.monotonic()
        self.failures[username.lower()] = (1, now) if now - started >= FAILURE_WINDOW else (count + 1, started)

    def check_password(self, username: str, password: str) -> bool:
        ok = hmac.compare_digest(password.encode(), self.password.encode())  # always compare, same cost either way
        return ok and self.account(username) is not None

    # ---- tokens ----
    def issue(self, persona: Persona, nonce: str = "", id_token: bool = False) -> str:
        now = crypto.now()
        claims = {
            "iss": self.issuer,
            "sub": persona.username,
            "aud": self.config.client_id,
            "azp": self.config.client_id,
            "iat": now,
            "nbf": now,
            "exp": now + TOKEN_TTL,
            "jti": crypto.new_jti("oidc"),
            "preferred_username": persona.username,
            "name": persona.name,
            "roles": persona.roles,
            "entitlements": persona.entitlements,
        }
        if id_token:
            claims["nonce"] = nonce
            claims["auth_time"] = now
        return self.key.sign(claims)

    def new_code(self, username: str, params: dict) -> str:
        now = time.monotonic()
        self.codes = {c: v for c, v in self.codes.items() if v.expires > now}  # drop expired codes
        code = secrets.token_urlsafe(32)
        self.codes[code] = AuthCode(
            username,
            params["redirect_uri"],
            params["code_challenge"],
            params.get("nonce", ""),
            params.get("scope", ""),
            now + CODE_TTL,
        )
        return code


def check_authorize(p: BuiltinOidc, params: dict) -> tuple[str, str] | None:
    """Return ('page'|'redirect', message) when the request is invalid, else None."""
    if params.get("client_id") != p.config.client_id:
        return "page", "Unknown client_id."
    if params.get("redirect_uri") not in p.redirect_uris:
        return "page", "This redirect_uri is not registered for the client."
    if params.get("response_type") != "code":
        return "redirect", "unsupported_response_type"
    if params.get("code_challenge_method") != "S256" or not params.get("code_challenge"):
        return "redirect", "invalid_request"  # PKCE with S256 is mandatory
    if "openid" not in params.get("scope", "").split():
        return "redirect", "invalid_scope"
    if not params.get("state"):
        return "redirect", "invalid_request"
    return None


def back_to_client(p: BuiltinOidc, params: dict, **result: str) -> RedirectResponse:
    query = {**result, "state": params.get("state", ""), "iss": p.issuer}
    separator = "&" if "?" in params["redirect_uri"] else "?"
    return RedirectResponse(f"{params['redirect_uri']}{separator}{urlencode(query)}", status_code=302, headers=NO_STORE)


STYLE = """
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1118;
color:#e6edf3;font:15px/1.5 system-ui,Segoe UI,sans-serif}.card{width:min(420px,92vw);background:#111a24;
border:1px solid #223041;border-radius:16px;padding:28px}h1{margin:0 0 4px;font-size:20px}.sub{color:#8b9db0;
margin:0 0 20px;font-size:13px}label{display:block;font-size:12px;color:#8b9db0;margin:14px 0 6px}
input{width:100%;padding:11px 12px;border-radius:10px;border:1px solid #2b3b4e;background:#0b1118;color:inherit;
font:inherit}input:focus{outline:2px solid #22c55e;border-color:transparent}button{margin-top:20px;width:100%;
padding:12px;border:0;border-radius:10px;background:#16a34a;color:#fff;font:600 15px system-ui;cursor:pointer}
.err{background:#3b1519;border:1px solid #7f1d1d;color:#fecaca;padding:10px 12px;border-radius:10px;margin-bottom:8px;
font-size:13px}.warn{margin-top:18px;font-size:12px;color:#d6a64a}.hint{margin-top:10px;font-size:12px;color:#8b9db0}
"""

PASS_THROUGH = (
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
)


def page(body: str, status: int = 200) -> HTMLResponse:
    document = (
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width'>"
        f"<title>Aegis sign-in</title><style>{STYLE}</style><body><main class=card>{body}</main></body></html>"
    )
    return HTMLResponse(document, status_code=status, headers=PAGE_HEADERS)


def login_form(p: BuiltinOidc, params: dict, error: str = "", username: str = "", status: int = 200) -> HTMLResponse:
    hidden = "".join(
        f'<input type=hidden name={name} value="{html.escape(params.get(name, ""), quote=True)}">'
        for name in PASS_THROUGH
    )
    notice = f"<div class=err role=alert>{html.escape(error)}</div>" if error else ""
    accounts = html.escape(", ".join(p.staff_names()))
    return page(
        "<h1>Sign in to Aegis AI</h1><p class=sub>Agent governance console</p>"
        f'{notice}<form method=post action="{html.escape(p.issuer, quote=True)}/authorize">{hidden}'
        "<label for=u>Username</label>"
        "<input id=u name=username autocomplete=username autofocus required "
        f'value="{html.escape(username, quote=True)}">'
        "<label for=p>Password</label><input id=p name=password type=password autocomplete=current-password required>"
        "<button type=submit>Sign in</button></form>"
        f"<p class=hint>Demo accounts: {accounts}</p>"
        "<p class=warn>Built-in development provider. Real deployments use Keycloak, Microsoft Entra ID or any "
        "OpenID Connect provider.</p>",
        status,
    )


def router() -> APIRouter:
    r = APIRouter(prefix="/oidc", tags=["builtin-oidc"], include_in_schema=True)

    def provider(request: Request) -> BuiltinOidc:
        found = request.app.state.ctx.builtin_oidc
        if found is None:
            raise HTTPException(404, "the built-in OpenID Connect provider is not enabled")
        return found

    @r.get("/.well-known/openid-configuration")
    async def discovery(request: Request):
        return provider(request).discovery()

    @r.get("/jwks")
    async def jwks(request: Request):
        return {"keys": [provider(request).key.jwk()]}

    @r.get("/authorize")
    async def authorize_form(request: Request):
        p = provider(request)
        params = dict(request.query_params)
        problem = check_authorize(p, params)
        if problem and problem[0] == "page":
            return page(f"<h1>Cannot sign in</h1><p class=sub>{html.escape(problem[1])}</p>", 400)
        if problem:
            return back_to_client(p, params, error=problem[1])
        return login_form(p, params)

    @r.post("/authorize")
    async def authorize_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        client_id: str = Form(""),
        redirect_uri: str = Form(""),
        response_type: str = Form(""),
        scope: str = Form(""),
        state: str = Form(""),
        nonce: str = Form(""),
        code_challenge: str = Form(""),
        code_challenge_method: str = Form(""),
    ):
        p = provider(request)
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        problem = check_authorize(p, params)  # hidden fields are user-controlled, so validate again
        if problem and problem[0] == "page":
            return page(f"<h1>Cannot sign in</h1><p class=sub>{html.escape(problem[1])}</p>", 400)
        if problem:
            return back_to_client(p, params, error=problem[1])
        if p.throttled(username):
            return login_form(p, params, "Too many attempts. Wait a minute and try again.", username, 429)
        if not p.check_password(username, password):
            p.note_failure(username)
            return login_form(p, params, "Incorrect username or password.", username, 401)
        return back_to_client(p, params, code=p.new_code(username.strip(), params))

    def cors(p: BuiltinOidc, request: Request) -> dict[str, str]:
        origin = request.headers.get("origin", "")
        return {"access-control-allow-origin": origin, "vary": "Origin"} if origin in p.origins else {}

    @r.options("/token")
    async def token_preflight(request: Request):
        p = provider(request)
        allowed = cors(p, request)
        if allowed:
            allowed |= {
                "access-control-allow-methods": "POST",
                "access-control-allow-headers": "content-type",
                "access-control-max-age": "600",
            }
        return Response(status_code=204, headers=allowed)

    @r.post("/token")
    async def token(
        request: Request,
        grant_type: str = Form(""),
        code: str = Form(""),
        redirect_uri: str = Form(""),
        client_id: str = Form(""),
        code_verifier: str = Form(""),
    ):
        p = provider(request)
        headers = NO_STORE | cors(p, request)

        def fail(error: str, description: str) -> JSONResponse:
            return JSONResponse({"error": error, "error_description": description}, 400, headers)

        if grant_type != "authorization_code":
            return fail("unsupported_grant_type", "only authorization_code is supported")
        if client_id != p.config.client_id:
            return fail("invalid_client", "unknown client")
        grant = p.codes.pop(code, None)  # single use, whatever happens next
        if grant is None or grant.expires < time.monotonic():
            return fail("invalid_grant", "the authorization code is invalid or has expired")
        if grant.redirect_uri != redirect_uri:
            return fail("invalid_grant", "redirect_uri does not match the authorization request")
        digest = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        if not code_verifier or not hmac.compare_digest(digest, grant.challenge):
            return fail("invalid_grant", "PKCE verification failed")
        persona = p.account(grant.username)
        if persona is None:
            return fail("invalid_grant", "the account is no longer active")
        return JSONResponse(
            {
                "access_token": p.issue(persona),
                "id_token": p.issue(persona, nonce=grant.nonce, id_token=True),
                "token_type": "Bearer",
                "expires_in": TOKEN_TTL,
                "scope": grant.scope,
            },
            200,
            headers,
        )

    @r.get("/logout")
    async def logout(request: Request, post_logout_redirect_uri: str = "", state: str = ""):
        p = provider(request)
        if post_logout_redirect_uri in p.logout_uris:
            target = post_logout_redirect_uri + (f"?{urlencode({'state': state})}" if state else "")
            return RedirectResponse(target, status_code=302, headers=NO_STORE)
        return page("<h1>Signed out</h1><p class=sub>You can close this window.</p>")

    return r
