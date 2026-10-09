"""Operator authentication (OIDC bearer tokens) and role checks (plan §8.14)."""

import jwt
from fastapi import Depends, HTTPException, Request

from aegis.common.service_identity import verify_service_token
from aegis.control.identity.idp import Persona
from aegis.control.identity.oidc import IdentityUnavailable


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    return header[7:]


async def current_user(request: Request) -> Persona:
    try:
        return await request.app.state.ctx.users.authenticate(_bearer(request))
    except jwt.InvalidTokenError as exc:
        raise HTTPException(401, f"invalid token: {exc}") from exc
    except IdentityUnavailable as exc:
        raise HTTPException(503, "the identity provider is unavailable") from exc


def require_roles(*roles: str):
    async def check(user: Persona = Depends(current_user)) -> Persona:
        if not set(roles) & set(user.roles):
            raise HTTPException(403, f"requires one of the roles: {', '.join(roles)}")
        return user

    return check


async def require_internal(request: Request) -> None:
    """Authenticate a Gateway → control-plane call by verifying its signed service assertion.

    The Gateway signs with its private key; we verify with its public key only (no shared secret).
    A captured assertion expires in 60 s; TLS/mTLS stops capture in transit. Fails closed if the
    Gateway's public key is not configured. In Azure, pin this to the workload identity at the ingress.
    """
    public_pem = request.app.state.ctx.gateway_service_public_pem
    if not public_pem:
        raise HTTPException(503, "internal service identity not configured")
    try:
        verify_service_token(request.headers.get("x-aegis-internal", ""), public_pem)
    except jwt.InvalidTokenError as exc:
        raise HTTPException(401, "internal endpoint") from exc


OPERATORS = ("admin", "agent-developer", "agent-owner", "risk-approver", "security-approver",
             "soc-analyst", "auditor", "policy-author", "policy-approver")
