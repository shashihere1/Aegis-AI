"""Identity provider adapter (plan §8.3) and a built-in development IdP.

`IdentityProvider` is the seam for Keycloak and Microsoft Entra Agent ID. `DevIdp` lets the whole
system run on a laptop without external services: humans log in as demo personas, and agents
authenticate with `private_key_jwt` client assertions (RFC 7523) - no shared secrets.
DevIdp is for development and demos only; it has no passwords.
"""

from dataclasses import dataclass, field
from typing import Protocol

import jwt
from fastapi import APIRouter, Form, HTTPException, Request
from pydantic import BaseModel

from aegis.common import crypto
from aegis.common.crypto import SigningKey

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
STS_AUDIENCE = "aegis-sts"
CONSOLE_AUDIENCE = "aegis"


@dataclass
class Persona:
    username: str
    name: str
    roles: list[str]
    entitlements: list[str] = field(default_factory=list)
    status: str = "active"  # active | left
    manager: str | None = None


@dataclass
class Client:
    client_id: str
    name: str
    public_pem: str
    enabled: bool = True
    agent_id: str | None = None  # None -> created outside Aegis (shadow identity)


class IdentityProvider(Protocol):
    def provision_agent_identity(self, agent_id: str, name: str) -> tuple[str, str]: ...
    def set_enabled(self, client_id: str, enabled: bool) -> None: ...
    def verify_agent_token(self, token: str) -> str: ...
    def verify_user_token(self, token: str) -> Persona: ...
    def list_clients(self) -> list[Client]: ...


class DevIdp:
    def __init__(self, issuer: str, key: SigningKey):
        self.issuer = issuer
        self.key = key
        self.personas: dict[str, Persona] = {}
        self.clients: dict[str, Client] = {}

    # ---- humans ----
    def add_persona(self, persona: Persona) -> None:
        self.personas[persona.username] = persona

    def login(self, username: str) -> str:
        persona = self.personas.get(username)
        if persona is None or persona.status != "active":
            raise PermissionError("unknown or inactive user")
        now = crypto.now()
        return self.key.sign({
            "iss": self.issuer, "sub": f"user:{persona.username}", "aud": CONSOLE_AUDIENCE,
            "name": persona.name, "roles": persona.roles, "entitlements": persona.entitlements,
            "typ": "user", "iat": now, "exp": now + 8 * 3600, "jti": crypto.new_jti("usr"),
        })

    def verify_user_token(self, token: str) -> Persona:
        claims = crypto.verify(token, self.key.public_pem, audience=CONSOLE_AUDIENCE, issuer=self.issuer)
        if claims.get("typ") != "user":
            raise jwt.InvalidTokenError("not a user token")
        persona = self.personas.get(claims["sub"].removeprefix("user:"))
        if persona is None or persona.status != "active":
            raise jwt.InvalidTokenError("user is not active")
        return persona

    def mark_leaver(self, username: str) -> Persona:
        persona = self.personas[username]
        persona.status = "left"
        return persona

    # ---- agents ----
    def provision_agent_identity(self, agent_id: str, name: str) -> tuple[str, str]:
        """Create a confidential client for the agent. Returns (client_id, private key PEM) once."""
        private_pem = crypto.generate_private_key_pem()
        client_id = f"agent-{agent_id.lower()}"
        self.clients[client_id] = Client(client_id, name, crypto.public_pem_from_private(private_pem),
                                         agent_id=agent_id)
        return client_id, private_pem

    def register_unmanaged_client(self, client_id: str, name: str) -> str:
        """An identity created directly in the IdP, bypassing Aegis (used to demo shadow discovery)."""
        private_pem = crypto.generate_private_key_pem()
        self.clients[client_id] = Client(client_id, name, crypto.public_pem_from_private(private_pem))
        return private_pem

    def set_enabled(self, client_id: str, enabled: bool) -> None:
        if client_id in self.clients:
            self.clients[client_id].enabled = enabled

    def list_clients(self) -> list[Client]:
        return list(self.clients.values())

    def token_for_assertion(self, assertion: str) -> str:
        client_id = jwt.decode(assertion, options={"verify_signature": False}).get("iss", "")
        client = self.clients.get(client_id)
        if client is None or not client.enabled:
            raise PermissionError("unknown or disabled client")
        claims = jwt.decode(assertion, client.public_pem, algorithms=[crypto.ALGORITHM],
                            audience=f"{self.issuer}/token", options={"require": ["exp", "iat"]})
        if claims.get("sub") != client_id:
            raise PermissionError("assertion subject mismatch")
        now = crypto.now()
        return self.key.sign({
            "iss": self.issuer, "sub": client_id, "azp": client_id, "aud": STS_AUDIENCE, "typ": "agent",
            "iat": now, "exp": now + 300, "jti": crypto.new_jti("idt"),
        })

    def verify_agent_token(self, token: str) -> str:
        claims = crypto.verify(token, self.key.public_pem, audience=STS_AUDIENCE, issuer=self.issuer)
        client = self.clients.get(claims.get("sub", ""))
        if claims.get("typ") != "agent" or client is None or not client.enabled:
            raise jwt.InvalidTokenError("agent identity is not valid or is disabled")
        return client.client_id


def client_assertion(client_id: str, private_pem: str, token_endpoint: str) -> str:
    """Build a private_key_jwt client assertion (used by the SDK)."""
    now = crypto.now()
    return jwt.encode(
        {"iss": client_id, "sub": client_id, "aud": token_endpoint, "iat": now, "exp": now + 60,
         "jti": crypto.new_jti("ca")},
        private_pem, algorithm=crypto.ALGORITHM,
    )


class LoginRequest(BaseModel):
    username: str


def router() -> APIRouter:
    r = APIRouter(prefix="/idp", tags=["dev-idp"])

    @r.post("/token")
    async def token(request: Request, grant_type: str = Form(...), client_assertion_type: str = Form(...),
                    client_assertion: str = Form(...)):
        if grant_type != "client_credentials" or client_assertion_type != ASSERTION_TYPE:
            raise HTTPException(400, {"error": "unsupported_grant_type"})
        try:
            access_token = request.app.state.ctx.idp.token_for_assertion(client_assertion)
        except (PermissionError, jwt.InvalidTokenError) as exc:
            raise HTTPException(401, {"error": "invalid_client", "error_description": str(exc)}) from exc
        return {"access_token": access_token, "token_type": "Bearer", "expires_in": 300}

    @r.post("/login")
    async def login(request: Request, body: LoginRequest):
        """Development login for demo personas (no password - never enable outside local/demo)."""
        try:
            return {"access_token": request.app.state.ctx.idp.login(body.username), "token_type": "Bearer"}
        except PermissionError as exc:
            raise HTTPException(401, str(exc)) from exc

    @r.get("/personas")
    async def personas(request: Request):
        """Demo personas for the console's role switcher (dev IdP only)."""
        return [{"username": p.username, "name": p.name, "roles": p.roles, "status": p.status}
                for p in request.app.state.ctx.idp.personas.values()]

    @r.get("/jwks")
    async def jwks(request: Request):
        return {"keys": [request.app.state.ctx.idp.key.jwk()]}

    return r
