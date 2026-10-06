"""Operator authentication (OIDC bearer tokens) and role checks (plan §8.14)."""

import hmac

import jwt
from fastapi import Depends, HTTPException, Request

from aegis.control.identity.idp import Persona


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    return header[7:]


async def current_user(request: Request) -> Persona:
    try:
        return request.app.state.ctx.idp.verify_user_token(_bearer(request))
    except jwt.InvalidTokenError as exc:
        raise HTTPException(401, f"invalid token: {exc}") from exc


def require_roles(*roles: str):
    async def check(user: Persona = Depends(current_user)) -> Persona:
        if not set(roles) & set(user.roles):
            raise HTTPException(403, f"requires one of the roles: {', '.join(roles)}")
        return user

    return check


async def require_internal(request: Request) -> None:
    """Gateway -> control-plane calls. Replace with workload identity (managed identity / mTLS) in Azure."""
    supplied = request.headers.get("x-aegis-internal", "")
    if not hmac.compare_digest(supplied, request.app.state.ctx.settings.internal_token):
        raise HTTPException(401, "internal endpoint")


OPERATORS = ("admin", "agent-developer", "agent-owner", "risk-approver", "security-approver",
             "soc-analyst", "auditor", "policy-author", "policy-approver")
