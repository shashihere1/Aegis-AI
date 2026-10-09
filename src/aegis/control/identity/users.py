"""Who is this person? Routes a bearer token to the right verifier (plan §8.3, §8.14).

Two sources can be active together: the development persona switcher and a real OpenID Connect provider. The
token's issuer decides which verifier checks it, and that verifier then checks everything else; an issuer that
is not configured is rejected.
"""

from dataclasses import replace

import jwt

from aegis.common.investigation import ENTITLEMENT, ROLES
from aegis.common.settings import Settings
from aegis.control.identity.idp import DevIdp, Persona
from aegis.control.identity.oidc import OidcVerifier


class UserAuthenticator:
    def __init__(self, idp: DevIdp, settings: Settings, oidc: OidcVerifier | None = None):
        self.idp = idp
        self.settings = settings
        self.oidc = oidc

    @staticmethod
    def _issuer(token: str) -> str:
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise jwt.InvalidTokenError("not a valid token") from exc
        issuer = claims.get("iss")
        if not isinstance(issuer, str):
            raise jwt.InvalidTokenError("the token has no issuer")
        return issuer

    async def authenticate(self, token: str) -> Persona:
        issuer = self._issuer(token)  # only used to pick a verifier; the verifier checks the signature
        if issuer == self.idp.issuer:
            if not self.settings.enable_dev_login:
                raise jwt.InvalidTokenError("development login is disabled")
            persona = self.idp.verify_user_token(token)
        elif self.oidc is not None and issuer == self.oidc.config.issuer:
            persona = await self.oidc.authenticate(token)
        else:
            raise jwt.InvalidTokenError("the token was issued by an unknown issuer")
        # This capability is role-derived, never a caller-supplied grant. Apply after verification for both IdPs.
        entitlements = [e for e in persona.entitlements if e != ENTITLEMENT]
        if set(persona.roles).intersection(ROLES) and persona.status == "active":
            entitlements.append(ENTITLEMENT)
        return replace(persona, entitlements=entitlements)
