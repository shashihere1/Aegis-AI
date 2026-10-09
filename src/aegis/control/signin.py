"""What the console needs to sign a person in, and who the bearer token says they are (plan §8.14)."""

from fastapi import APIRouter, Depends, Request

from aegis.control.auth import current_user
from aegis.control.identity.idp import Persona
from aegis.control.identity.oidc import IdentityUnavailable


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/auth", tags=["sign-in"])

    @r.get("/config")
    async def config(request: Request):
        """Public: which sign-in methods are on, and the provider's endpoints for the console's PKCE flow."""
        c = request.app.state.ctx
        sso: dict | None = None
        problem: str | None = None
        if c.oidc is not None:
            try:
                document = await c.oidc.discovery()
            except IdentityUnavailable as exc:
                problem = str(exc)
            else:
                cfg = c.oidc.config
                sso = {
                    "issuer": cfg.issuer,
                    "client_id": cfg.client_id,
                    "authorization_endpoint": document["authorization_endpoint"],
                    "token_endpoint": document["token_endpoint"],
                    "end_session_endpoint": document.get("end_session_endpoint"),
                    "scopes": cfg.scopes,
                    "builtin": cfg.builtin,
                }
        return {"dev_login": c.settings.enable_dev_login, "oidc": sso, "oidc_error": problem}

    @r.get("/me")
    async def me(user: Persona = Depends(current_user)):
        return {"username": user.username, "name": user.name, "roles": user.roles, "entitlements": user.entitlements}

    return r
