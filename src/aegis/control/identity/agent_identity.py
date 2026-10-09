"""Agent identities (plan §8.3): where each agent's own identity is created, switched off and checked.

People sign in with OpenID Connect (`oidc.py`). Agents are different: every approved agent gets one identity of its
own and proves it with a private key it alone holds (`private_key_jwt`, RFC 7523), so no shared secret exists. Two
providers sit behind the same small interface:

* `DevAgentIdentity` - the built-in demo identity provider (laptop demos and tests).
* `KeycloakAgentIdentity` - each agent becomes a Keycloak client. Aegis registers only the agent's *public* key and
  manages the client through Keycloak's Admin REST API with a service account that holds nothing beyond
  `manage-clients` / `view-clients`. Keycloak, not Aegis, issues the five-minute identity token; Aegis checks it
  against the realm's published keys and confirms the client still exists and is enabled.

The private key leaves Aegis exactly once, in the approval response, for the agent's own secret store.
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx
import jwt

from aegis.common import crypto
from aegis.common.settings import Settings
from aegis.control.identity.idp import STS_AUDIENCE, Client, DevIdp
from aegis.control.identity.oidc import IdentityUnavailable, OidcConfig, OidcVerifier

log = logging.getLogger("aegis.identity")

MANAGED = "aegis.managed"
AGENT_ATTRIBUTE = "aegis.agent_id"
CLIENT_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,159}")
INFO_TTL = 10.0  # seconds a client's enabled state is trusted between checks
PAGE = 100
KEYCLOAK_BUILT_IN = frozenset(
    {"account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"}
)


class IdentityNotFound(IdentityUnavailable):
    """The identity does not exist in the provider (for example the realm was recreated)."""


@dataclass(frozen=True)
class IssuedIdentity:
    client_id: str
    private_key_pem: str
    token_endpoint: str
    assertion_audience: str | None  # None: the assertion's audience is the token endpoint itself
    provider: str

    def credentials(self) -> dict:
        """What the agent runtime needs; returned once, never stored by Aegis."""
        return {
            "client_id": self.client_id,
            "private_key_pem": self.private_key_pem,
            "token_endpoint": self.token_endpoint,
            "assertion_audience": self.assertion_audience,
        }


class AgentIdentityProvider(Protocol):
    name: str
    token_endpoint: str  # where agents sign in
    assertion_audience: str | None  # audience of their signed login note; None means the endpoint itself

    async def provision(self, agent_id: str, name: str) -> IssuedIdentity: ...
    async def set_enabled(self, client_id: str, enabled: bool) -> None: ...
    async def verify_token(self, token: str) -> str: ...
    async def list_clients(self) -> list[Client]: ...
    async def register_unmanaged(self, client_id: str, name: str) -> str: ...
    async def development_private_key(self, client_id: str) -> str: ...
    async def status(self) -> dict: ...


class DevAgentIdentity:
    """The built-in demo IdP behind the async interface (behaviour unchanged)."""

    name = "dev-idp"
    assertion_audience = None

    def __init__(self, idp: DevIdp, control_url: str):
        self.idp = idp
        self.token_endpoint = f"{control_url.rstrip('/')}/idp/token"

    async def provision(self, agent_id: str, name: str) -> IssuedIdentity:
        client_id, private_pem = self.idp.provision_agent_identity(agent_id, name)
        return IssuedIdentity(client_id, private_pem, self.token_endpoint, None, self.name)

    async def set_enabled(self, client_id: str, enabled: bool) -> None:
        if client_id not in self.idp.clients:
            raise IdentityNotFound(f"identity {client_id} does not exist")
        self.idp.set_enabled(client_id, enabled)

    async def verify_token(self, token: str) -> str:
        return self.idp.verify_agent_token(token)

    async def list_clients(self) -> list[Client]:
        return self.idp.list_clients()

    async def register_unmanaged(self, client_id: str, name: str) -> str:
        return self.idp.register_unmanaged_client(client_id, name)

    async def development_private_key(self, client_id: str) -> str:
        try:
            return self.idp.development_private_key(client_id)
        except (FileNotFoundError, RuntimeError) as exc:
            raise IdentityNotFound(f"no development key is stored for {client_id}") from exc

    async def status(self) -> dict:
        return {"provider": self.name, "reachable": True, "issuer": self.idp.issuer}


class KeycloakAdmin:
    """The part of Keycloak's Admin REST API Aegis uses, authenticated as a least-privilege service account."""

    def __init__(self, http: httpx.AsyncClient, base: str, realm: str, client_id: str, client_secret: str):
        self.http = http
        self.base = base.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self._secret = client_secret
        self._token: tuple[str, float] | None = None
        self._lock = asyncio.Lock()

    @property
    def token_url(self) -> str:
        return f"{self.base}/realms/{self.realm}/protocol/openid-connect/token"

    async def _access_token(self, refresh: bool = False) -> str:
        async with self._lock:
            if not refresh and self._token and self._token[1] - 20 > time.monotonic():
                return self._token[0]
            try:
                reply = await self.http.post(
                    self.token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self._secret,
                    },
                )
            except httpx.HTTPError as exc:
                raise IdentityUnavailable(f"cannot reach Keycloak at {self.base}: {type(exc).__name__}") from exc
            if reply.status_code != 200:
                raise IdentityUnavailable(
                    f"Keycloak refused the control-plane client {self.client_id!r} (HTTP {reply.status_code}); "
                    "check AEGIS_KEYCLOAK_ADMIN_CLIENT_ID / _SECRET"
                )
            body = reply.json()
            self._token = (body["access_token"], time.monotonic() + int(body.get("expires_in", 60)))
            return self._token[0]

    async def request(self, method: str, path: str, ok: tuple[int, ...] = (200, 201, 204), **kwargs) -> httpx.Response:
        url = f"{self.base}/admin/realms/{self.realm}{path}"
        for attempt in (0, 1):
            headers = {"authorization": f"Bearer {await self._access_token(refresh=attempt == 1)}"}
            try:
                reply = await self.http.request(method, url, headers=headers, **kwargs)
            except httpx.HTTPError as exc:
                raise IdentityUnavailable(f"cannot reach Keycloak at {self.base}: {type(exc).__name__}") from exc
            if reply.status_code == 401 and attempt == 0:
                continue  # the cached token expired or was revoked: fetch a new one once
            break
        if reply.status_code not in ok:
            hint = (
                " (the control-plane client needs manage-clients and view-clients)" if reply.status_code == 403 else ""
            )
            raise IdentityUnavailable(
                f"Keycloak {method} {path} returned {reply.status_code}{hint}: {reply.text[:200]}"
            )
        return reply

    async def find_client(self, client_id: str) -> dict | None:
        reply = await self.request("GET", "/clients", params={"clientId": client_id})
        return next((c for c in reply.json() if c.get("clientId") == client_id), None)

    async def all_clients(self) -> list[dict]:
        found: list[dict] = []
        while True:
            page = (await self.request("GET", "/clients", params={"first": len(found), "max": PAGE})).json()
            found.extend(page)
            if len(page) < PAGE:
                return found


class KeycloakAgentIdentity:
    name = "keycloak"

    def __init__(self, settings: Settings, http: httpx.AsyncClient):
        self.settings = settings
        self.base = settings.keycloak_url.rstrip("/")
        self.realm = settings.keycloak_realm
        self.issuer = f"{self.base}/realms/{self.realm}"
        self.token_endpoint = f"{self.issuer}/protocol/openid-connect/token"
        self.assertion_audience = self.issuer
        self.admin = KeycloakAdmin(
            http, self.base, self.realm, settings.keycloak_admin_client_id, settings.keycloak_admin_client_secret
        )
        self.verifier = OidcVerifier(
            OidcConfig(issuer=self.issuer, client_id=STS_AUDIENCE, audience=STS_AUDIENCE), http
        )
        self.protected = KEYCLOAK_BUILT_IN | {settings.keycloak_admin_client_id, "aegis-console"}
        self.state_dir = Path(settings.identity_state_dir) / "keycloak" if settings.identity_state_dir else None
        self._info: dict[str, tuple[float, dict]] = {}

    # ---- helpers ----
    @staticmethod
    def _check_client_id(client_id: str) -> None:
        if not CLIENT_ID_PATTERN.fullmatch(client_id):
            raise ValueError("Invalid agent identity name")

    def _representation(self, client_id: str, name: str, public_pem: str, agent_id: str | None) -> dict:
        attributes = {
            "use.jwks.string": "true",
            "jwks.string": json.dumps({"keys": [crypto.public_jwk(public_pem)]}),
            "token.endpoint.auth.signing.alg": crypto.ALGORITHM,
            "access.token.lifespan": str(self.settings.agent_token_ttl),
        }
        if agent_id:
            attributes |= {MANAGED: "true", AGENT_ATTRIBUTE: agent_id}
        return {
            "clientId": client_id,
            "name": name,
            "description": "AI agent identity managed by Aegis AI" if agent_id else "Identity created outside Aegis",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "clientAuthenticatorType": "client-jwt",  # signed-JWT sign-in: no client secret exists
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False,
            "defaultClientScopes": [],
            "optionalClientScopes": [],
            "attributes": attributes,
            "protocolMappers": [
                {
                    # The Aegis STS accepts only tokens addressed to it.
                    "name": "aegis-sts-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": False,
                    "config": {
                        "included.custom.audience": STS_AUDIENCE,
                        "id.token.claim": "false",
                        "access.token.claim": "true",
                    },
                }
            ],
        }

    async def _upsert(self, client_id: str, name: str, agent_id: str | None) -> str:
        self._check_client_id(client_id)
        private_pem = crypto.generate_private_key_pem()
        representation = self._representation(client_id, name, crypto.public_pem_from_private(private_pem), agent_id)
        existing = await self.admin.find_client(client_id)
        if existing is not None:
            if agent_id is not None and existing.get("attributes", {}).get(AGENT_ATTRIBUTE) != agent_id:
                raise IdentityUnavailable(f"Keycloak already has an unrelated client named {client_id!r}")
            # Rotating a key must never switch a suspended identity back on; only set_enabled does that.
            representation["enabled"] = bool(existing.get("enabled", True))
            await self.admin.request("PUT", f"/clients/{existing['id']}", json=representation)  # also rotates the key
        else:
            reply = await self.admin.request("POST", "/clients", ok=(201, 409), json=representation)
            if reply.status_code == 409:  # created concurrently: update it instead
                existing = await self.admin.find_client(client_id)
                if existing is None:
                    raise IdentityUnavailable(f"Keycloak reported a conflict for {client_id!r} but does not list it")
                representation["enabled"] = bool(existing.get("enabled", True))
                await self.admin.request("PUT", f"/clients/{existing['id']}", json=representation)
        self._info.pop(client_id, None)
        if self.state_dir:  # demo runtime only: a real agent keeps its key in its own secret store
            self.state_dir.mkdir(parents=True, exist_ok=True)
            (self.state_dir / f"{client_id}.pem").write_text(private_pem, encoding="utf-8")
        return private_pem

    async def _client_info(self, client_id: str) -> dict | None:
        cached = self._info.get(client_id)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        found = await self.admin.find_client(client_id)
        if found is not None:
            self._info[client_id] = (time.monotonic() + INFO_TTL, found)
        return found

    # ---- interface ----
    async def provision(self, agent_id: str, name: str) -> IssuedIdentity:
        client_id = f"agent-{agent_id.lower()}"
        private_pem = await self._upsert(client_id, name, agent_id)
        return IssuedIdentity(client_id, private_pem, self.token_endpoint, self.issuer, self.name)

    async def register_unmanaged(self, client_id: str, name: str) -> str:
        return await self._upsert(client_id, name, None)

    async def set_enabled(self, client_id: str, enabled: bool) -> None:
        self._check_client_id(client_id)
        if client_id in self.protected:
            raise IdentityUnavailable(f"{client_id!r} is a protected Keycloak client")
        found = await self.admin.find_client(client_id)
        if found is None:
            raise IdentityNotFound(f"identity {client_id} does not exist in Keycloak")
        await self.admin.request("PUT", f"/clients/{found['id']}", json={"enabled": enabled})
        self._info.pop(client_id, None)

    async def verify_token(self, token: str) -> str:
        claims = await self.verifier.verify(token)
        client_id = claims.get("azp") or claims.get("client_id")
        if not isinstance(client_id, str) or claims.get("typ") != "Bearer":
            raise jwt.InvalidTokenError("this is not an agent identity token")
        if claims.get("client_id", client_id) != client_id:
            raise jwt.InvalidTokenError("the token names two different clients")
        info = await self._client_info(client_id)
        if info is None or not info.get("enabled") or not info.get("serviceAccountsEnabled"):
            raise jwt.InvalidTokenError("agent identity is not valid or is disabled")
        return client_id

    async def list_clients(self) -> list[Client]:
        clients = []
        for item in await self.admin.all_clients():
            client_id = item.get("clientId", "")
            machine = item.get("serviceAccountsEnabled") and not item.get("bearerOnly")
            if not machine or client_id in self.protected:
                continue
            attributes = item.get("attributes") or {}
            clients.append(
                Client(
                    client_id=client_id,
                    name=item.get("name") or client_id,
                    public_pem="",  # the provider holds only the public key; Aegis never needs it back
                    enabled=bool(item.get("enabled")),
                    agent_id=attributes.get(AGENT_ATTRIBUTE) if attributes.get(MANAGED) == "true" else None,
                )
            )
        return clients

    async def development_private_key(self, client_id: str) -> str:
        self._check_client_id(client_id)
        path = self.state_dir / f"{client_id}.pem" if self.state_dir else None
        if path is None or not path.exists():
            raise IdentityNotFound(f"no development key is stored for {client_id}")
        return path.read_text(encoding="utf-8")

    async def status(self) -> dict:
        try:
            await self.verifier.discovery()
            await self.admin.request("GET", "/clients", params={"first": 0, "max": 1})
        except IdentityUnavailable as exc:
            return {"provider": self.name, "reachable": False, "issuer": self.issuer, "detail": str(exc)}
        return {"provider": self.name, "reachable": True, "issuer": self.issuer}


def build_agent_identity(
    settings: Settings, idp: DevIdp, http: httpx.AsyncClient | None = None
) -> AgentIdentityProvider:
    if settings.agent_idp == "dev":
        return DevAgentIdentity(idp, settings.control_url)
    missing = [
        name
        for name, value in (
            ("AEGIS_KEYCLOAK_URL", settings.keycloak_url),
            ("AEGIS_KEYCLOAK_ADMIN_CLIENT_SECRET", settings.keycloak_admin_client_secret),
        )
        if not value.strip()
    ]
    if missing:
        raise ValueError(f"AEGIS_AGENT_IDP=keycloak also needs: {', '.join(missing)}")
    if http is None:
        raise ValueError("an HTTP client is required for the Keycloak identity provider")
    return KeycloakAgentIdentity(settings, http)
