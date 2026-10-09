"""A small, faithful stand-in for Keycloak: the Admin REST API subset Aegis uses, signed-JWT client sign-in and the
realm's published keys. Behaviour was copied from probing a real Keycloak 26.2.5 (see the _live test file).

Switches for tests: `down` (every endpoint answers 503), `fail_admin` (only the Admin API does), `admin_calls`,
`token_calls`, `agent_signins`, `expire_admin_tokens()`.
"""

import json
import secrets
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

REALM = "aegis"
CONTROL_PLANE = "aegis-control-plane"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class FakeKeycloak:
    def __init__(self, public_url: str, control_plane_secret: str = "control-plane-secret"):
        self.public_url = public_url.rstrip("/")  # what a caller sees, e.g. http://127.0.0.1:8000/kc
        self.issuer = f"{self.public_url}/realms/{REALM}"
        self.control_plane_secret = control_plane_secret
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "realm-key-1"
        self.clients: dict[str, dict] = {}
        self.admin_tokens: dict[str, float] = {}
        self.down = False
        self.fail_admin = False
        self.admin_calls = 0
        self.token_calls = 0
        self.agent_signins = 0
        self.denied_admin = False  # emulate a control-plane client without permissions
        # Real Keycloak has these built-ins; the adapter must never present them as agents.
        for built_in in ("account", "admin-cli", "broker", "realm-management", "security-admin-console"):
            self._add(
                {
                    "clientId": built_in,
                    "enabled": True,
                    "publicClient": built_in != "broker",
                    "bearerOnly": built_in in {"broker", "realm-management"},
                }
            )
        self._add({"clientId": CONTROL_PLANE, "enabled": True, "serviceAccountsEnabled": True, "publicClient": False})
        self._add({"clientId": "aegis-console", "enabled": True, "publicClient": True, "standardFlowEnabled": True})
        self.app = Starlette(
            routes=[
                Route("/realms/{realm}/.well-known/openid-configuration", self.discovery),
                Route("/realms/{realm}/protocol/openid-connect/certs", self.certs),
                Route("/realms/{realm}/protocol/openid-connect/token", self.token, methods=["POST"]),
                Route("/admin/realms/{realm}/clients", self.clients_collection, methods=["GET", "POST"]),
                Route("/admin/realms/{realm}/clients/{uuid}", self.client_item, methods=["GET", "PUT", "DELETE"]),
            ]
        )

    # ---- helpers for tests ----
    def _add(self, representation: dict) -> dict:
        stored = {"id": str(uuid.uuid4()), "attributes": {}, "protocolMappers": [], **representation}
        self.clients[stored["id"]] = stored
        return stored

    def by_client_id(self, client_id: str) -> dict | None:
        return next((c for c in self.clients.values() if c["clientId"] == client_id), None)

    def managed(self) -> list[dict]:
        return [c for c in self.clients.values() if c["attributes"].get("aegis.managed") == "true"]

    def expire_admin_tokens(self) -> None:
        self.admin_tokens.clear()

    @property
    def public_pem(self) -> str:
        return (
            self.key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )

    def issue(self, client: dict, **overrides) -> str:
        """A realm-signed token as Keycloak would issue it to a service-account client."""
        now = int(time.time())
        lifespan = int(client["attributes"].get("access.token.lifespan", 300))
        claims = {
            "iss": self.issuer,
            "aud": next(
                (
                    m["config"]["included.custom.audience"]
                    for m in client["protocolMappers"]
                    if m.get("protocolMapper") == "oidc-audience-mapper"
                ),
                "account",
            ),
            "azp": client["clientId"],
            "client_id": client["clientId"],
            "sub": client["id"],
            "typ": "Bearer",
            "iat": now,
            "exp": now + lifespan,
            "jti": uuid.uuid4().hex,
        } | overrides
        pem = self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return jwt.encode(
            {k: v for k, v in claims.items() if v is not None}, pem, algorithm="RS256", headers={"kid": self.kid}
        )

    # ---- endpoints ----
    def _unavailable(self) -> Response | None:
        return JSONResponse({"error": "unavailable"}, 503) if self.down else None

    async def discovery(self, request: Request):
        if (r := self._unavailable()) is not None:
            return r
        return JSONResponse(
            {
                "issuer": self.issuer,
                "jwks_uri": f"{self.issuer}/protocol/openid-connect/certs",
                "token_endpoint": f"{self.issuer}/protocol/openid-connect/token",
                "authorization_endpoint": f"{self.issuer}/protocol/openid-connect/auth",
            }
        )

    async def certs(self, request: Request):
        if (r := self._unavailable()) is not None:
            return r
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return JSONResponse({"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]})

    async def token(self, request: Request):
        if (r := self._unavailable()) is not None:
            return r
        self.token_calls += 1
        form = await request.form()
        if form.get("grant_type") != "client_credentials":
            return JSONResponse({"error": "unsupported_grant_type"}, 400)
        if form.get("client_assertion"):
            return self._agent_token(form)
        client = self.by_client_id(form.get("client_id", ""))
        if client and client["clientId"] == CONTROL_PLANE and form.get("client_secret") == self.control_plane_secret:
            token = secrets.token_urlsafe(24)
            self.admin_tokens[token] = time.monotonic() + 60
            return JSONResponse({"access_token": token, "expires_in": 60, "token_type": "Bearer"})
        if client and client["clientId"] != CONTROL_PLANE and "client_secret" in form:
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Parameter client_assertion_type is missing"}, 400
            )
        return JSONResponse({"error": "unauthorized_client"}, 401)

    def _agent_token(self, form) -> Response:
        if form.get("client_assertion_type") != ASSERTION_TYPE:
            return JSONResponse({"error": "invalid_client"}, 400)
        assertion = form["client_assertion"]
        try:
            issuer_claim = jwt.decode(assertion, options={"verify_signature": False}).get("iss", "")
        except jwt.PyJWTError:
            return JSONResponse({"error": "invalid_client"}, 400)
        client = self.by_client_id(issuer_claim)
        if client is None or not client.get("enabled", True):
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Invalid client or Invalid client credentials"}, 401
            )
        if client.get("clientAuthenticatorType") != "client-jwt":
            return JSONResponse({"error": "invalid_client"}, 400)
        try:
            keys = json.loads(client["attributes"]["jwks.string"])["keys"]
            header = jwt.get_unverified_header(assertion)
            jwk = next(k for k in keys if k["kid"] == header.get("kid"))
            claims = jwt.decode(
                assertion,
                jwt.PyJWK.from_dict(jwk).key,
                algorithms=["ES256"],
                audience=[self.issuer, f"{self.issuer}/protocol/openid-connect/token"],
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
        except (KeyError, StopIteration, ValueError, jwt.PyJWTError) as exc:
            return JSONResponse(
                {
                    "error": "invalid_client",
                    "error_description": f"Client authentication with signed JWT failed: {type(exc).__name__}",
                },
                400,
            )
        if claims["sub"] != client["clientId"]:
            return JSONResponse({"error": "invalid_client"}, 400)
        self.agent_signins += 1
        return JSONResponse({"access_token": self.issue(client), "token_type": "Bearer", "expires_in": 300})

    def _admin_guard(self, request: Request) -> Response | None:
        if (r := self._unavailable()) is not None:
            return r
        self.admin_calls += 1
        if self.fail_admin:
            return JSONResponse({"error": "boom"}, 503)
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if self.admin_tokens.get(token, 0) < time.monotonic():
            return JSONResponse({"error": "HTTP 401 Unauthorized"}, 401)
        if self.denied_admin:
            return JSONResponse({"error": "HTTP 403 Forbidden"}, 403)
        return None

    async def clients_collection(self, request: Request):
        if (r := self._admin_guard(request)) is not None:
            return r
        if request.method == "POST":
            body = await request.json()
            if self.by_client_id(body["clientId"]):
                return JSONResponse({"errorMessage": "Client already exists"}, 409)
            created = self._add(body)
            return Response(status_code=201, headers={"location": f"{request.url}/{created['id']}"})
        found = list(self.clients.values())
        if "clientId" in request.query_params:
            found = [c for c in found if c["clientId"] == request.query_params["clientId"]]
        first = int(request.query_params.get("first", 0))
        limit = int(request.query_params.get("max", 100))
        return JSONResponse(found[first : first + limit])

    async def client_item(self, request: Request):
        if (r := self._admin_guard(request)) is not None:
            return r
        client = self.clients.get(request.path_params["uuid"])
        if client is None:
            return JSONResponse({"error": "Could not find client"}, 404)
        if request.method == "GET":
            return JSONResponse(client)
        if request.method == "DELETE":
            del self.clients[client["id"]]
            return Response(status_code=204)
        client.update(
            {k: v for k, v in (await request.json()).items() if v is not None}
        )  # partial updates keep the rest
        return Response(status_code=204)
