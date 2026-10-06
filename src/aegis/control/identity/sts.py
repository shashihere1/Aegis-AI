"""Aegis Security Token Service (plan §8.3, flows F2 and F4).

Mints *Mandates*: short-lived JWTs bound to one task's purpose, obtained by OAuth 2.0 Token Exchange
(RFC 8693) with the intent carried as a Rich Authorization Request (RFC 9396).

- Root mandate:   actor_token = agent identity (from the IdP), subject_token = the user's token
                  (omitted for autonomous agents).
- Delegation:     actor_token = the child agent's identity, subject_token = the parent's Mandate.
                  The child can only receive a *narrower* purpose, data ceiling, entitlements and
                  lifetime (attenuation); the chain of actors is kept in nested `act` claims.
Effective permission = agent capabilities ∩ user entitlements ∩ mandate purpose.
"""

import json
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common import crypto
from aegis.common.ids import new_id
from aegis.common.models import AgentStatus, data_class_rank
from aegis.control import ledger
from aegis.control.auth import require_roles
from aegis.control.context import ControlContext, ctx, session
from aegis.control.tables import Agent, Approval, DecisionRecord, Mandate, Tool

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
TIER_TTL = {"low": 900, "medium": 600, "high": 300, "critical": 120}
LLM_SCOPE = "llm.chat"


class StsError(Exception):
    def __init__(self, error: str, description: str, rule: str | None = None):
        super().__init__(description)
        self.error, self.description, self.rule = error, description, rule


def classify_intent(intent: str, taxonomy: dict[str, list[str]]) -> list[str]:
    text = f" {intent.lower()} "
    return sorted(c for c, words in taxonomy.items() if any(w in text for w in words))


def audience_for(gateway_url: str, scopes: list[str]) -> list[str]:
    aud = set()
    for scope in scopes:
        if scope.startswith("a2a:"):
            aud.add(f"{gateway_url}/a2a/{scope[4:]}")
        elif scope == LLM_SCOPE:
            aud.add(f"{gateway_url}/llm")
        else:
            aud.add(f"{gateway_url}/mcp/{scope.split('.', 1)[0]}")
    return sorted(aud)


async def eligible_tools(
    s: AsyncSession, agent: Agent, categories: list[str], entitlements: list[str], requested: list[str] | None
) -> list[str]:
    if not agent.capabilities:
        return []
    tools = (await s.execute(select(Tool).where(Tool.id.in_(agent.capabilities), Tool.status == "approved"))).scalars()
    granted = []
    for tool in tools:
        c = tool.classification or {}
        if not set(c.get("intent_tags", [])) & set(categories):
            continue
        required = c.get("required_entitlement")
        if required and required not in entitlements:  # the intersection rule
            continue
        if requested and tool.id not in requested:
            continue
        granted.append(tool.id)
    return sorted(granted)


async def delegation_targets(s: AsyncSession, agent: Agent, categories: list[str]) -> list[str]:
    if not agent.can_delegate_to:
        return []
    targets = (
        await s.execute(select(Agent).where(Agent.id.in_(agent.can_delegate_to), Agent.status == AgentStatus.ACTIVE))
    ).scalars()
    return sorted(
        f"a2a:{t.id}" for t in targets
        if agent.id in t.can_receive_from and set(t.intent_categories) & set(categories)
    )


async def exchange(c: ControlContext, s: AsyncSession, form: dict) -> dict:
    if form.get("grant_type") != TOKEN_EXCHANGE:
        raise StsError("unsupported_grant_type", "only RFC 8693 token exchange is supported")
    if not form.get("actor_token"):
        raise StsError("invalid_request", "actor_token (the agent's identity) is required")
    try:
        client_id = c.idp.verify_agent_token(form["actor_token"])
    except jwt.InvalidTokenError as exc:
        raise StsError("invalid_client", f"agent identity rejected: {exc}") from exc
    agent = (await s.execute(select(Agent).where(Agent.idp_client_id == client_id))).scalar_one_or_none()
    if agent is None or agent.status != AgentStatus.ACTIVE:
        raise StsError("invalid_grant", "agent is not registered or not active", "AGT-001")

    details = {}
    for item in json.loads(form.get("authorization_details") or "[]"):
        if item.get("type") == "aegis_mandate":
            details = item
    intent = (details.get("intent") or "").strip()
    asked_categories = details.get("intent_categories") or (classify_intent(intent, c.taxonomy) if intent else [])
    requested_tools = details.get("tools")
    now = datetime.now(UTC)

    subject_token = form.get("subject_token")
    parent: Mandate | None = None
    parent_claims: dict | None = None
    persona = None
    if subject_token:
        if crypto.unverified_header(subject_token).get("kid") == c.sts_key.kid:
            try:
                parent_claims = crypto.verify(subject_token, c.sts_key.public_pem, issuer=c.sts_issuer)
            except jwt.InvalidTokenError as exc:
                raise StsError("invalid_grant", f"parent mandate rejected: {exc}") from exc
            parent = await s.get(Mandate, parent_claims["aegis"]["mandate_id"])
        else:
            try:
                persona = c.idp.verify_user_token(subject_token)
            except jwt.InvalidTokenError as exc:
                raise StsError("invalid_grant", f"user token rejected: {exc}") from exc

    if parent is not None:
        if parent.status != "active" or parent.expires_at.replace(tzinfo=UTC) <= now:
            raise StsError("invalid_grant", "parent mandate is no longer active", "REV-001")
        revoked = await c.hotstore.revoked(
            [("mdt", parent.id), ("root", parent.root_id), ("jti", parent.jti)]
            + [("agent", a) for a in parent.chain]
        )
        if revoked:
            raise StsError("invalid_grant", revoked, "REV-001")
        if f"a2a:{agent.id}" not in parent.scopes:
            raise StsError("invalid_grant", "the parent mandate does not delegate to this agent", "DLG-001")
        parent_agent = await s.get(Agent, parent.agent_id)
        if agent.id not in parent_agent.can_delegate_to or parent_agent.id not in agent.can_receive_from:
            raise StsError("invalid_grant", "this delegation pair is not allowed by the registry", "DLG-001")
        if agent.id in parent.chain:
            raise StsError("invalid_grant", "delegation cycle detected", "DLG-003")
        limit = min(c.settings.max_delegation_depth, parent_agent.max_depth)
        if parent.depth + 1 > limit:
            raise StsError("invalid_grant", f"delegation depth would exceed {limit}", "DLG-002")
        wanted = asked_categories or parent.intent_categories
        widened = set(wanted) - set(parent.intent_categories)
        if widened:
            raise StsError("invalid_scope", f"delegation cannot widen the purpose: {sorted(widened)}", "DLG-004")
        categories = [x for x in wanted if x in agent.intent_categories]
        subject, entitlements = parent.subject, list(parent.entitlements)
        max_data = min(parent.max_data_class, agent.max_data_class, key=data_class_rank)
        depth, chain = parent.depth + 1, [*parent.chain, agent.id]
        act = {"sub": f"agent:{agent.id}", "act": parent_claims["act"]}
        intent = intent or parent.intent
        latest_exp = parent.expires_at.replace(tzinfo=UTC)
        root_id = parent.root_id
        depth_limit = limit
    else:
        if not intent:
            raise StsError("invalid_request", "authorization_details must carry the task intent")
        categories = list(asked_categories)
        outside = set(categories) - set(agent.intent_categories)
        if outside:
            raise StsError("invalid_scope", f"intent is outside the agent's registered purpose: {sorted(outside)}",
                           "PUR-001")
        subject = f"user:{persona.username}" if persona else f"agent:{agent.id}"
        entitlements = list(persona.entitlements) if persona else []
        max_data = agent.max_data_class
        depth, chain = 0, [agent.id]
        act = {"sub": f"agent:{agent.id}"}
        latest_exp = None
        root_id = None
        depth_limit = min(c.settings.max_delegation_depth, agent.max_depth)

    if not categories:
        raise StsError("invalid_scope", "the intent could not be mapped to this agent's purpose; "
                                        "pass intent_categories explicitly", "PUR-001")

    tools = await eligible_tools(s, agent, categories, entitlements, requested_tools)
    targets = await delegation_targets(s, agent, categories) if depth + 1 <= depth_limit else []
    if not tools and not targets:
        raise StsError("invalid_scope", "no approved tool or delegate of this agent serves this intent", "SCP-001")
    scopes = [*tools, *targets, LLM_SCOPE]

    ttl = min(TIER_TTL.get(agent.risk_tier, 300), int(form.get("requested_ttl") or c.settings.mandate_default_ttl))
    expires = now + timedelta(seconds=ttl)
    if latest_exp and expires > latest_exp:
        expires = latest_exp

    mandate_id = new_id("mdt")
    jti = crypto.new_jti()
    mandate = Mandate(
        id=mandate_id, parent_id=parent.id if parent else None, root_id=root_id or mandate_id, agent_id=agent.id,
        subject=subject, chain=chain, intent=intent, intent_categories=categories, scopes=scopes,
        audience=audience_for(c.settings.gateway_url, scopes), entitlements=entitlements, max_data_class=max_data,
        depth=depth, jti=jti, issued_at=now, expires_at=expires,
    )
    s.add(mandate)
    agent.last_active_at = now
    claims = {
        "iss": c.sts_issuer, "sub": subject, "aud": mandate.audience, "azp": agent.id, "act": act,
        "iat": int(now.timestamp()), "nbf": int(now.timestamp()), "exp": int(expires.timestamp()), "jti": jti,
        "scope": " ".join(scopes),
        "authorization_details": [{
            "type": "aegis_mandate", "intent": intent, "intent_categories": categories,
            "resources": details.get("resources", {}), "max_data_class": max_data,
        }],
        "aegis": {
            "mandate_id": mandate_id, "root_id": mandate.root_id, "parent_id": mandate.parent_id,
            "depth": depth, "chain": chain, "ent": entitlements, "env": agent.environment,
            "risk_tier": agent.risk_tier,
        },
    }
    await ledger.append(s, "mandate.issued", f"agent:{agent.id}", mandate_id,
                        {"subject": subject, "chain": chain, "intent": intent, "scopes": scopes,
                         "parent": mandate.parent_id, "expires_at": expires.isoformat()})
    await s.commit()
    return {
        "access_token": c.sts_key.sign(claims),
        "issued_token_type": JWT_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": int((expires - now).total_seconds()),
        "scope": " ".join(scopes),
        "mandate_id": mandate_id,
    }


# ---- revocation --------------------------------------------------------------

async def descendants(s: AsyncSession, mandate_ids: list[str]) -> list[Mandate]:
    tree = select(Mandate.id).where(Mandate.id.in_(mandate_ids)).cte("tree", recursive=True)
    tree = tree.union_all(select(Mandate.id).join(tree, Mandate.parent_id == tree.c.id))
    return list((await s.execute(select(Mandate).where(Mandate.id.in_(select(tree.c.id))))).scalars())


async def revoke_tree(c: ControlContext, s: AsyncSession, mandate_ids: list[str], reason: str, actor: str,
                      status: str = "revoked") -> list[str]:
    revoked = []
    for m in await descendants(s, mandate_ids):
        if m.status == "active":
            m.status, m.revoked_reason = status, reason
            revoked.append(m.id)
        await c.hotstore.revoke("mdt", m.id, reason)
        await c.hotstore.revoke("jti", m.jti, reason)
    if revoked:
        await ledger.append(s, f"mandate.{status}", actor, ",".join(revoked[:20]),
                            {"count": len(revoked), "reason": reason})
    return revoked


async def blast_radius(s: AsyncSession, agent_id: str) -> dict:
    active = (await s.execute(select(Mandate).where(Mandate.status == "active"))).scalars().all()
    direct = [m.id for m in active if agent_id in m.chain]
    tree = [m for m in await descendants(s, direct) if m.status == "active"] if direct else []
    tree_ids = [m.id for m in tree]
    approvals = (
        await s.execute(select(Approval).where(Approval.mandate_id.in_(tree_ids), Approval.status == "pending"))
    ).scalars().all() if tree_ids else []
    return {
        "agent_id": agent_id,
        "mandates": tree_ids,
        "agents_affected": sorted({a for m in tree for a in m.chain}),
        "pending_approvals": [a.id for a in approvals],
    }


async def suspend_agent(c: ControlContext, s: AsyncSession, agent_id: str, reason: str, actor: str) -> dict:
    """Kill switch (plan F6): suspend, cascade-revoke, disable the IdP identity, cancel approvals."""
    agent = await s.get(Agent, agent_id)
    radius = await blast_radius(s, agent_id)
    await c.hotstore.revoke("agent", agent_id, reason)
    if agent is not None:
        agent.status = AgentStatus.SUSPENDED
        if agent.idp_client_id:
            c.idp.set_enabled(agent.idp_client_id, False)
    await revoke_tree(c, s, radius["mandates"], reason, actor)
    for approval_id in radius["pending_approvals"]:
        approval = await s.get(Approval, approval_id)
        approval.status = "cancelled"
    await ledger.append(s, "agent.suspended", actor, agent_id, {"reason": reason, "blast_radius": radius})
    return radius


async def rehydrate_revocations(c: ControlContext) -> None:
    """Re-load durable revocations into the hot store at start-up."""
    async with c.db.sessionmaker() as s:
        now = datetime.now(UTC)
        for m in (await s.execute(select(Mandate).where(Mandate.status != "active"))).scalars():
            if m.expires_at.replace(tzinfo=UTC) > now:
                await c.hotstore.revoke("mdt", m.id, m.revoked_reason or m.status)
                await c.hotstore.revoke("jti", m.jti, m.revoked_reason or m.status)
        for a in (await s.execute(select(Agent).where(Agent.status == AgentStatus.SUSPENDED))).scalars():
            await c.hotstore.revoke("agent", a.id, "suspended")


# ---- HTTP ----------------------------------------------------------------------

def router() -> APIRouter:
    r = APIRouter(tags=["sts"])

    @r.post("/sts/token")
    async def token(
        request: Request,
        grant_type: str = Form(...),
        actor_token: str | None = Form(None),
        actor_token_type: str | None = Form(None),
        subject_token: str | None = Form(None),
        subject_token_type: str | None = Form(None),
        authorization_details: str | None = Form(None),
        requested_ttl: int | None = Form(None),
        s: AsyncSession = Depends(session),
    ):
        c = request.app.state.ctx
        form = {"grant_type": grant_type, "actor_token": actor_token, "subject_token": subject_token,
                "authorization_details": authorization_details, "requested_ttl": requested_ttl}
        try:
            return await exchange(c, s, form)
        except StsError as exc:
            await s.rollback()
            s.add(DecisionRecord(
                id=new_id("dec"), action="sts.token_exchange", decision="deny",
                reasons=[{"rule": exc.rule or exc.error, "message": exc.description}],
                input_snapshot={"authorization_details": authorization_details},
            ))
            await ledger.append(s, "mandate.denied", "sts", exc.rule or exc.error, {"reason": exc.description})
            await s.commit()
            return JSONResponse({"error": exc.error, "error_description": exc.description, "rule": exc.rule},
                                status_code=400)

    @r.get("/.well-known/jwks.json")
    async def jwks(c: ControlContext = Depends(ctx)):
        return {"keys": [c.sts_key.jwk()]}

    @r.get("/.well-known/oauth-authorization-server")
    async def metadata(c: ControlContext = Depends(ctx)):
        return {
            "issuer": c.sts_issuer,
            "token_endpoint": f"{c.settings.control_url}/sts/token",
            "jwks_uri": f"{c.settings.control_url}/.well-known/jwks.json",
            "grant_types_supported": [TOKEN_EXCHANGE],
            "authorization_details_types_supported": ["aegis_mandate"],
        }

    @r.post("/v1/mandates/complete")
    async def complete(request: Request, s: AsyncSession = Depends(session)):
        """The holder closes its own task: the mandate tree is revoked as 'completed'."""
        c = request.app.state.ctx
        token = request.headers.get("authorization", "")[7:]
        try:
            claims = crypto.verify(token, c.sts_key.public_pem, issuer=c.sts_issuer)
        except jwt.InvalidTokenError as exc:
            raise HTTPException(401, str(exc)) from exc
        done = await revoke_tree(c, s, [claims["aegis"]["mandate_id"]], "task completed", claims["azp"],
                                 status="completed")
        await s.commit()
        return {"completed": done}

    @r.get("/v1/mandates", dependencies=[Depends(require_roles("soc-analyst", "risk-approver", "auditor",
                                                                   "admin"))])
    async def list_mandates(status: str = "active", s: AsyncSession = Depends(session)):
        rows = (await s.execute(select(Mandate).where(Mandate.status == status).order_by(Mandate.issued_at.desc())
                                .limit(200))).scalars().all()
        names = dict((await s.execute(select(Agent.id, Agent.name).where(
            Agent.id.in_({a for m in rows for a in m.chain})))).all())
        return [
            {"id": m.id, "root_id": m.root_id, "parent_id": m.parent_id, "agent_id": m.agent_id,
             "agent_name": names.get(m.agent_id), "subject": m.subject, "chain": m.chain,
             "chain_names": [names.get(a, a) for a in m.chain], "intent": m.intent,
             "intent_categories": m.intent_categories, "scopes": m.scopes, "depth": m.depth,
             "issued_at": m.issued_at, "expires_at": m.expires_at, "status": m.status,
             "revoked_reason": m.revoked_reason}
            for m in rows
        ]

    @r.post("/v1/mandates/{mandate_id}/revoke")
    async def revoke(mandate_id: str, request: Request, s: AsyncSession = Depends(session),
                     user=Depends(require_roles("soc-analyst", "risk-approver"))):
        c = request.app.state.ctx
        done = await revoke_tree(c, s, [mandate_id], f"revoked by {user.username}", f"user:{user.username}")
        await s.commit()
        return {"revoked": done}

    return r
