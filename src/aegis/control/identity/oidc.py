"""Generic OpenID Connect sign-in for people (plan §8.3): works with Keycloak, Microsoft Entra ID, Okta, Auth0...

Aegis never sees a password. The console signs users in at the provider (authorization code + PKCE) and sends the
resulting access token as a bearer token. This module validates it from the provider's published keys: signature,
issuer, audience and expiry, then maps the provider's roles or groups to Aegis roles.
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt

from aegis.common.settings import Settings
from aegis.control.identity.idp import Persona

BUILTIN_CLIENT_ID = "aegis-console"
DISCOVERY_TTL = 3600
JWKS_TTL = 3600
JWKS_REFRESH_COOLDOWN = 30  # an unknown key id can force at most one JWKS download per this many seconds
SAFE_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}


class IdentityUnavailable(Exception):
    """The provider could not be reached or returned something unusable (a 503, not a 401)."""


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    client_id: str
    audience: str
    jwks_url: str = ""
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    username_claim: str = "preferred_username"
    name_claim: str = "name"
    roles_claim: str = "roles"
    entitlements_claim: str = "entitlements"
    role_map: dict[str, list[str]] = field(default_factory=dict)
    scopes: str = "openid profile email"
    clock_skew: int = 60
    builtin: bool = False

    @classmethod
    def from_settings(cls, s: Settings) -> OidcConfig | None:
        issuer = s.oidc_issuer.strip() or (f"{s.control_url}/oidc" if s.builtin_oidc else "")
        if not issuer:
            return None
        client_id = s.oidc_client_id.strip() or (BUILTIN_CLIENT_ID if s.builtin_oidc else "")
        if not client_id:
            raise ValueError("AEGIS_OIDC_CLIENT_ID is required when AEGIS_OIDC_ISSUER is set")
        algorithms = tuple(a.strip() for a in s.oidc_algorithms.split(",") if a.strip())
        unsafe = set(algorithms) - SAFE_ALGORITHMS
        if not algorithms or unsafe:
            raise ValueError(f"AEGIS_OIDC_ALGORITHMS must be asymmetric algorithms, got {sorted(unsafe) or 'none'}")
        raw_map = json.loads(s.oidc_role_map) if s.oidc_role_map.strip() else {}
        role_map = {k: [v] if isinstance(v, str) else list(v) for k, v in raw_map.items()}
        return cls(
            issuer=issuer,
            client_id=client_id,
            audience=s.oidc_audience.strip() or client_id,
            jwks_url=s.oidc_jwks_url.strip(),
            algorithms=algorithms,
            username_claim=s.oidc_username_claim,
            name_claim=s.oidc_name_claim,
            roles_claim=s.oidc_roles_claim,
            entitlements_claim=s.oidc_entitlements_claim,
            role_map=role_map,
            scopes=s.oidc_scopes,
            clock_skew=s.oidc_clock_skew,
            builtin=s.builtin_oidc and not s.oidc_issuer.strip(),
        )


def claim_path(claims: dict, path: str) -> Any:
    """Read a (possibly dotted) claim such as realm_access.roles."""
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [str(v) for v in value] if isinstance(value, list | tuple | set) else [str(value)]


class OidcVerifier:
    def __init__(self, config: OidcConfig, http: httpx.AsyncClient):
        self.config = config
        self.http = http
        self._discovery: tuple[float, dict] | None = None
        self._keys: dict[str, jwt.PyJWK] = {}
        self._keys_loaded_at = 0.0
        self._last_refresh = 0.0
        self._lock = asyncio.Lock()

    async def _get_json(self, url: str) -> dict:
        try:
            response = await self.http.get(url, headers={"accept": "application/json"})
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise IdentityUnavailable(f"could not read {url}: {exc}") from exc

    async def discovery(self) -> dict:
        now = time.monotonic()
        if self._discovery and now - self._discovery[0] < DISCOVERY_TTL:
            return self._discovery[1]
        document = await self._get_json(f"{self.config.issuer.rstrip('/')}/.well-known/openid-configuration")
        if document.get("issuer") != self.config.issuer:  # RFC 8414 §3.3: guards against a mixed-up issuer
            raise IdentityUnavailable(
                f"discovery document issuer {document.get('issuer')!r} does not match {self.config.issuer!r}"
            )
        self._discovery = (now, document)
        return document

    async def _refresh_keys(self) -> None:
        url = self.config.jwks_url or (await self.discovery()).get("jwks_uri")
        if not url:
            raise IdentityUnavailable("the provider publishes no jwks_uri")
        keys = {}
        for jwk in (await self._get_json(url)).get("keys", []):
            if jwk.get("use", "sig") != "sig" or "kid" not in jwk:
                continue
            try:
                keys[jwk["kid"]] = jwt.PyJWK.from_dict(jwk)
            except jwt.PyJWTError:
                continue  # an unsupported key type in the set must not break the others
        if not keys:
            raise IdentityUnavailable("the provider's key set has no usable signing keys")
        self._keys = keys
        self._keys_loaded_at = self._last_refresh = time.monotonic()

    async def _key_for(self, kid: str) -> jwt.PyJWK:
        async with self._lock:
            now = time.monotonic()
            stale = now - self._keys_loaded_at > JWKS_TTL
            if kid in self._keys and not stale:
                return self._keys[kid]
            if not self._keys or stale or now - self._last_refresh >= JWKS_REFRESH_COOLDOWN:
                await self._refresh_keys()
            if kid not in self._keys:
                raise jwt.InvalidTokenError("the token was signed with an unknown key")
            return self._keys[kid]

    async def verify(self, token: str) -> dict:
        cfg = self.config
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg", "")
            if algorithm not in cfg.algorithms:
                raise jwt.InvalidTokenError(f"signing algorithm {algorithm!r} is not accepted")
            kid = header.get("kid")
            if not kid:
                raise jwt.InvalidTokenError("the token has no key id")
            key = await self._key_for(kid)
            return jwt.decode(
                token,
                key.key,
                algorithms=[algorithm],
                audience=cfg.audience,
                issuer=cfg.issuer,
                leeway=cfg.clock_skew,
                options={"require": ["exp", "iss", "sub"]},
            )
        except jwt.InvalidTokenError:
            raise
        except jwt.PyJWTError as exc:  # e.g. a key that does not suit the algorithm
            raise jwt.InvalidTokenError(str(exc)) from exc

    def roles_from(self, claims: dict) -> list[str]:
        provided = as_list(claim_path(claims, self.config.roles_claim))
        if not self.config.role_map:
            return provided
        mapped: list[str] = []
        for value in provided:
            for role in self.config.role_map.get(value, []):
                if role not in mapped:
                    mapped.append(role)
        return mapped

    def persona_from(self, claims: dict) -> Persona:
        cfg = self.config
        username = claim_path(claims, cfg.username_claim) or claims.get("email") or claims["sub"]
        return Persona(
            username=str(username),
            name=str(claim_path(claims, cfg.name_claim) or username),
            roles=self.roles_from(claims),
            entitlements=as_list(claim_path(claims, cfg.entitlements_claim)),
        )

    async def authenticate(self, token: str) -> Persona:
        return self.persona_from(await self.verify(token))
