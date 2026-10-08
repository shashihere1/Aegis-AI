"""Aegis Gateway - the Policy Enforcement Point for MCP, A2A and LLM traffic (plan §8.5, flow F3).

Every call carries a Mandate. The Gateway authenticates it, checks revocation, asks the PDP,
applies obligations (redact, rate-limit, hold for approval), scans untrusted output, tracks the
task's information flow (taint) and records the decision as evidence. Agent tokens are never
forwarded upstream: upstream credentials are brokered by the Gateway.
"""

import asyncio
import hashlib
import json
import os
import time

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from opentelemetry import trace

from aegis.common.hashing import action_hash, tool_definition_hash
from aegis.common.settings import Settings
from aegis.gateway.control_client import ControlPlaneClient
from aegis.guard import pii
from aegis.guard.detectors import scan_text
from aegis.hotstore import HotStore
from aegis.policy.engine import PolicyEngine
from aegis.telemetry import tracing_headers

MCP_HEADERS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}
DENIED, APPROVAL_PENDING, RATE_LIMITED = -32001, -32002, -32003

tracer = trace.get_tracer("aegis.gateway")


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def rpc_error(rpc_id, code: int, message: str, data: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message, "data": data or {}}}


def brokered_headers(server_id: str) -> dict:
    """Upstream credential from the secrets broker (Key Vault in Azure; env var locally)."""
    secret = os.environ.get(f"AEGIS_UPSTREAM_TOKEN_{server_id.upper().replace('-', '_')}")
    return {"authorization": f"Bearer {secret}"} if secret else {}


def parse_mcp_response(response: httpx.Response) -> dict:
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        data = [line[5:].strip() for line in response.text.splitlines() if line.startswith("data:")]
        return json.loads(data[-1])
    return response.json()


def result_text(result: dict) -> str:
    parts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
    if result.get("structuredContent"):
        parts.append(json.dumps(result["structuredContent"]))
    return "\n".join(parts)


def trace_id() -> str | None:
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None


def create_gateway(
    settings: Settings, http: httpx.AsyncClient, hotstore: HotStore, engine: PolicyEngine, telemetry=None
) -> FastAPI:
    tracer = telemetry.tracer("aegis.gateway") if telemetry else trace.get_tracer("aegis.gateway")
    app = FastAPI(title="Aegis Gateway (PEP)", version="0.1.0")
    cp = ControlPlaneClient(http, settings.control_url, settings.internal_token, settings.cache_seconds)
    gw = settings.gateway_url.rstrip("/")
    upstream_cache: dict[str, tuple[float, dict[str, str]]] = {}

    async def authenticate(request: Request, resource: str) -> dict:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            fingerprint = client_fingerprint(request)
            if await hotstore.is_blocked(fingerprint):
                raise AuthError(403, "caller is quarantined")
            await cp.event(
                {
                    "type": "discovery.unknown_client",
                    "fingerprint": fingerprint,
                    "resource": resource,
                    "user_agent": request.headers.get("user-agent", ""),
                }
            )
            raise AuthError(401, "a Mandate is required (see the protected resource metadata)")
        token = header[7:]
        try:
            claims = jwt.decode(
                token,
                await cp.sts_public_key(),
                algorithms=["ES256"],
                audience=resource,
                issuer=f"{settings.control_url}/sts",
                options={"require": ["exp", "aud", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            await cp.event({"type": "token.revoked_use", "reason": "expired", "resource": resource})
            raise AuthError(401, "mandate expired") from None
        except jwt.InvalidAudienceError:
            raise AuthError(401, "mandate audience does not include this resource") from None
        except jwt.InvalidTokenError as exc:
            raise AuthError(401, f"invalid mandate: {exc}") from exc
        meta = claims["aegis"]
        revoked = await hotstore.revoked(
            [("jti", claims["jti"]), ("mdt", meta["mandate_id"]), ("root", meta["root_id"])]
            + [("agent", a) for a in meta["chain"]]
        )
        if revoked:
            await cp.event(
                {
                    "type": "token.revoked_use",
                    "reason": revoked,
                    "agent_id": claims["azp"],
                    "mandate_id": meta["mandate_id"],
                    "resource": resource,
                }
            )
            raise AuthError(401, f"mandate revoked ({revoked})")
        return claims

    def client_fingerprint(request: Request) -> str:
        api_key = request.headers.get("x-api-key")
        if api_key:
            return "api-key:" + hashlib.sha256(api_key.encode()).hexdigest()[:16]
        return f"anon:{request.headers.get('user-agent', 'unknown')}"

    def auth_failure(exc: AuthError, rpc_id=None, resource_path: str = "") -> JSONResponse:
        headers = {}
        if exc.status == 401 and resource_path:
            headers["www-authenticate"] = (
                f'Bearer resource_metadata="{gw}/.well-known/oauth-protected-resource{resource_path}"'
            )
        return JSONResponse(rpc_error(rpc_id, -32000, str(exc)), status_code=exc.status, headers=headers)

    async def record(
        claims: dict,
        action: str,
        verdict: dict,
        decision: str | None = None,
        snapshot: dict | None = None,
        data_class: str | None = None,
        started: float = 0.0,
    ) -> None:
        meta = claims["aegis"]
        await cp.decision(
            {
                "mandate_id": meta["mandate_id"],
                "root_id": meta["root_id"],
                "agent_id": claims["azp"],
                "subject": claims["sub"],
                "action": action,
                "decision": decision or verdict["decision"],
                "reasons": verdict.get("reasons", []),
                "obligations": verdict.get("obligations", []),
                "policy_version": verdict.get("policy_version", engine.version),
                "input_snapshot": snapshot or {},
                "data_class": data_class,
                "trace_id": trace_id(),
                "latency_ms": round((time.perf_counter() - started) * 1000, 2) if started else 0.0,
            }
        )

    async def upstream_call(server_url: str, server_id: str, body: dict) -> dict:
        response = await http.post(
            server_url, headers=tracing_headers({**MCP_HEADERS, **brokered_headers(server_id)}), json=body
        )
        response.raise_for_status()
        return parse_mcp_response(response)

    async def upstream_hashes(server_url: str, server_id: str) -> dict[str, str]:
        hit = upstream_cache.get(server_id)
        if hit and time.monotonic() - hit[0] < settings.cache_seconds:
            return hit[1]
        listing = await upstream_call(
            server_url, server_id, {"jsonrpc": "2.0", "id": "aegis-pin", "method": "tools/list", "params": {}}
        )
        hashes = {t["name"]: tool_definition_hash(t) for t in listing.get("result", {}).get("tools", [])}
        upstream_cache[server_id] = (time.monotonic(), hashes)
        return hashes

    # ---- MCP ---------------------------------------------------------------

    @app.get("/.well-known/oauth-protected-resource/mcp/{server_id}")
    async def protected_resource_metadata(server_id: str):
        """RFC 9728 metadata so standard MCP clients can discover the Aegis STS."""
        return {
            "resource": f"{gw}/mcp/{server_id}",
            "authorization_servers": [f"{settings.control_url}/sts"],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mandate"],
        }

    @app.post("/mcp/{server_id}")
    async def mcp(server_id: str, request: Request):
        body = await request.json()
        rpc_id, method = body.get("id"), body.get("method", "")
        resource = f"{gw}/mcp/{server_id}"
        try:
            claims = await authenticate(request, resource)
        except AuthError as exc:
            return auth_failure(exc, rpc_id, f"/mcp/{server_id}")
        server_url = await cp.server_url(server_id)
        if server_url is None:
            return JSONResponse(rpc_error(rpc_id, DENIED, "unknown MCP server"), status_code=404)
        scopes = claims["scope"].split()

        with tracer.start_as_current_span(f"mcp {method}") as span:
            span.set_attributes(
                {
                    "mcp.method.name": method,
                    "gen_ai.agent.id": claims["azp"],
                    "aegis.mandate.id": claims["aegis"]["mandate_id"],
                    "aegis.user.id": claims["sub"],
                }
            )
            if method == "tools/list":
                upstream = await upstream_call(server_url, server_id, body)
                registry = await cp.tools(server_id)
                visible = []
                for tool in upstream.get("result", {}).get("tools", []):
                    rec = registry.get(tool["name"])
                    if rec is None:
                        continue
                    if rec["approved_hash"] and tool_definition_hash(tool) != rec["approved_hash"]:
                        await cp.event({"type": "tool.drift", "tool": rec["id"], "upstream": tool})
                        continue
                    # Agents cannot misuse tools they cannot see.
                    if rec["status"] == "approved" and rec["id"] in scopes:
                        visible.append(tool)
                if "result" in upstream:
                    upstream["result"]["tools"] = visible
                return upstream
            if method == "tools/call":
                return await tools_call(server_id, server_url, body, claims, request)
            # initialize / server/discover / other methods: authenticated pass-through.
            return await upstream_call(server_url, server_id, body)

    async def tools_call(server_id: str, server_url: str, body: dict, claims: dict, request: Request):
        started = time.perf_counter()
        rpc_id = body.get("id")
        params = body.get("params", {})
        name, arguments = params.get("name", ""), params.get("arguments") or {}
        tool_id = f"{server_id}.{name}"
        meta = claims["aegis"]
        span = trace.get_current_span()
        span.update_name(f"execute_tool {tool_id}")
        span.set_attributes({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool_id})

        rec = (await cp.tools(server_id)).get(name) or {
            "status": "unknown",
            "approved_hash": None,
            "classification": {},
        }
        current = (await upstream_hashes(server_url, server_id)).get(name)
        pinned = rec["status"] == "approved" and current is not None and current == rec["approved_hash"]
        if rec["status"] == "approved" and current is not None and not pinned:
            await cp.event({"type": "tool.drift", "tool": rec.get("id", tool_id)})
        agent = await cp.agent(claims["azp"]) or {"status": "unknown"}
        taint = await hotstore.get_taint(meta["root_id"])

        approval_ctx = None
        approval_id = request.headers.get("x-aegis-approval")
        if approval_id:
            approval = await cp.approval(approval_id)
            if approval is None or approval["action_hash"] != action_hash(tool_id, arguments, meta["mandate_id"]):
                approval_ctx = {"status": "mismatch", "id": approval_id}
            else:
                approval_ctx = {"status": approval["status"], "id": approval_id}

        classification = rec.get("classification") or {}
        policy_input = {
            "subject": {
                "type": "agent",
                "id": claims["azp"],
                "properties": {
                    "status": agent.get("status"),
                    "risk_tier": agent.get("risk_tier"),
                    "env": agent.get("env"),
                    "autonomy": agent.get("autonomy"),
                },
            },
            "action": {"name": "tools/call", "properties": {"tool": tool_id, "args": arguments}},
            "resource": {
                "type": "mcp_tool",
                "id": tool_id,
                "properties": {**classification, "status": rec["status"], "pinned": pinned},
            },
            "context": {
                "user": {"id": claims["sub"]},
                "mandate": {
                    "id": meta["mandate_id"],
                    "scopes": claims["scope"].split(),
                    "intent_categories": claims["authorization_details"][0]["intent_categories"],
                    "max_data_class": claims["authorization_details"][0]["max_data_class"],
                    "entitlements": meta["ent"],
                    "chain": meta["chain"],
                    "depth": meta["depth"],
                },
                "session": {
                    "tainted": taint.tainted,
                    "max_data_class_read": taint.max_data_class_read,
                    "external_egress": taint.external_egress,
                },
                "approval": approval_ctx,
            },
        }
        verdict = await engine.evaluate(policy_input)
        span.set_attributes(
            {
                "aegis.decision": verdict["decision"],
                "aegis.policy.version": verdict["policy_version"],
                "aegis.policy.rules": ",".join(r["rule"] for r in verdict["reasons"]),
            }
        )

        if verdict["decision"] == "require_approval":
            pending = await cp.create_approval(
                {
                    "mandate_id": meta["mandate_id"],
                    "agent_id": claims["azp"],
                    "tool": tool_id,
                    "arguments": arguments,
                    "reasons": verdict["reasons"],
                }
            )
            deadline = time.monotonic() + settings.approval_hold_seconds
            while time.monotonic() < deadline:  # optional hold (plan F5); the SDK can also wait and retry
                await asyncio.sleep(0.5)
                status = (await cp.approval(pending["id"]) or {}).get("status")
                if status != "pending":
                    break
            await record(
                claims, tool_id, verdict, snapshot={**policy_input, "approval_id": pending["id"]}, started=started
            )
            return rpc_error(
                rpc_id,
                APPROVAL_PENDING,
                "Human approval required by Aegis",
                {"approval_id": pending["id"], "status": "pending", "reasons": verdict["reasons"]},
            )

        if verdict["decision"] == "deny":
            await record(claims, tool_id, verdict, snapshot=policy_input, started=started)
            rules = ", ".join(f"{r['rule']} {r['message']}" for r in verdict["reasons"])
            return rpc_error(rpc_id, DENIED, f"Denied by Aegis: {rules}", {"reasons": verdict["reasons"]})

        for obligation in verdict["obligations"]:
            if obligation["type"] == "rate_limit" and not await hotstore.rate_hit(
                obligation["key"], obligation["limit"]
            ):
                await record(claims, tool_id, verdict, decision="rate_limited", snapshot=policy_input, started=started)
                return rpc_error(
                    rpc_id,
                    RATE_LIMITED,
                    "Rate limit reached for this agent and tool",
                    {"limit_per_min": obligation["limit"]},
                )

        upstream = await upstream_call(server_url, server_id, body)
        if approval_ctx and approval_ctx["status"] == "approved":
            await cp.consume_approval(approval_ctx["id"])

        result = upstream.get("result", {})
        guard = scan_text(result_text(result))
        if guard.injection:
            await hotstore.update_taint(meta["root_id"], tainted_by=f"injection:{tool_id}")
            await cp.event(
                {
                    "type": "guard.injection",
                    "tool": tool_id,
                    "agent_id": claims["azp"],
                    "mandate_id": meta["mandate_id"],
                    "score": guard.score,
                    "findings": guard.findings,
                }
            )
        if classification.get("untrusted_content"):
            await hotstore.update_taint(meta["root_id"], tainted_by=f"untrusted:{tool_id}")
        await hotstore.update_taint(
            meta["root_id"],
            data_class=classification.get("returns_data_class"),
            external_egress=classification.get("egress") == "external",
        )

        redactions = 0
        for obligation in verdict["obligations"]:
            if obligation["type"] == "redact":
                redacted, redactions = pii.redact(result, obligation["entities"])
                upstream["result"] = result = redacted
        await record(
            claims,
            tool_id,
            verdict,
            snapshot={**policy_input, "redactions": redactions, "guard_score": guard.score},
            data_class=classification.get("returns_data_class"),
            started=started,
        )
        return upstream

    # ---- A2A ---------------------------------------------------------------

    @app.post("/a2a/{agent_id}")
    async def a2a(agent_id: str, request: Request):
        """Agent-to-agent delegation (plan F4). The child exchanges the forwarded parent Mandate at the STS."""
        body = await request.json()
        rpc_id = body.get("id")
        try:
            claims = await authenticate(request, f"{gw}/a2a/{agent_id}")
        except AuthError as exc:
            return auth_failure(exc, rpc_id)
        started = time.perf_counter()
        meta = claims["aegis"]
        target = await cp.agent(agent_id)
        caller = await cp.agent(claims["azp"])
        reasons = []
        if f"a2a:{agent_id}" not in claims["scope"].split():
            reasons.append({"rule": "DLG-001", "message": "the mandate does not delegate to this agent"})
        if not target or target["status"] != "active" or not target.get("endpoint_url"):
            reasons.append({"rule": "AGT-001", "message": "target agent is not active"})
        elif caller and (agent_id not in caller["can_delegate_to"] or caller["id"] not in target["can_receive_from"]):
            reasons.append({"rule": "DLG-001", "message": "delegation pair not allowed by the registry"})
        if agent_id in meta["chain"]:
            reasons.append({"rule": "DLG-003", "message": "delegation cycle detected"})
        verdict = {
            "decision": "deny" if reasons else "allow",
            "reasons": reasons,
            "obligations": [],
            "policy_version": engine.version,
        }
        with tracer.start_as_current_span(f"invoke_agent {agent_id}") as span:
            span.set_attributes(
                {
                    "gen_ai.operation.name": "invoke_agent",
                    "gen_ai.agent.id": agent_id,
                    "aegis.decision": verdict["decision"],
                }
            )
            await record(claims, f"a2a:{agent_id}", verdict, snapshot={"caller": claims["azp"]}, started=started)
            if reasons:
                return rpc_error(
                    rpc_id, DENIED, "Denied by Aegis: " + ", ".join(r["rule"] for r in reasons), {"reasons": reasons}
                )
            response = await http.post(
                target["endpoint_url"],
                json=body,
                timeout=60.0,
                headers=tracing_headers({"x-aegis-parent-mandate": request.headers["authorization"][7:]}),
            )
            return JSONResponse(response.json(), status_code=response.status_code)

    # ---- LLM ---------------------------------------------------------------

    @app.post("/llm/v1/chat/completions")
    async def chat(request: Request):
        """OpenAI-compatible proxy to the OneStop-approved Azure OpenAI deployment; records tokens and cost."""
        body = await request.json()
        try:
            claims = await authenticate(request, f"{gw}/llm")
        except AuthError as exc:
            return auth_failure(exc)
        if "llm.chat" not in claims["scope"].split():
            return JSONResponse({"error": "mandate does not allow LLM calls"}, status_code=403)
        prompt = "\n".join(str(m.get("content", "")) for m in body.get("messages", []))
        guard = scan_text(prompt)
        if guard.injection:
            await cp.event(
                {
                    "type": "guard.injection",
                    "tool": "llm.prompt",
                    "agent_id": claims["azp"],
                    "score": guard.score,
                    "findings": guard.findings,
                }
            )
        if settings.llm_upstream_url:
            url, headers = f"{settings.llm_upstream_url.rstrip('/')}/chat/completions", {}
        elif settings.azure_openai_endpoint:
            url = (
                f"{settings.azure_openai_endpoint.rstrip('/')}/openai/deployments/"
                f"{settings.azure_openai_deployment}/chat/completions"
                f"?api-version={settings.azure_openai_api_version}"
            )
            headers = {"api-key": settings.azure_openai_api_key}
        else:
            return JSONResponse({"error": "no approved LLM deployment configured"}, status_code=503)
        started = time.perf_counter()
        with tracer.start_as_current_span("chat") as span:
            response = await http.post(url, json=body, headers=tracing_headers(headers), timeout=60.0)
            latency = (time.perf_counter() - started) * 1000
            data = response.json()
            usage = data.get("usage") or {}
            tokens_in, tokens_out = usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
            model = data.get("model") or body.get("model") or settings.azure_openai_deployment
            span.set_attributes(
                {
                    "gen_ai.operation.name": "chat",
                    "gen_ai.request.model": model,
                    "gen_ai.usage.input_tokens": tokens_in,
                    "gen_ai.usage.output_tokens": tokens_out,
                    "gen_ai.agent.id": claims["azp"],
                }
            )
            cost = tokens_in / 1000 * settings.llm_price_in_per_1k + tokens_out / 1000 * settings.llm_price_out_per_1k
            await cp.usage(
                {
                    "agent_id": claims["azp"],
                    "mandate_id": claims["aegis"]["mandate_id"],
                    "model": model,
                    "input_tokens": tokens_in,
                    "output_tokens": tokens_out,
                    "cost_eur": round(cost, 6),
                    "latency_ms": round(latency, 1),
                }
            )
        return JSONResponse(data, status_code=response.status_code)

    @app.get("/health")
    async def health():
        return {"status": "ok", "policy_version": engine.version}

    return app
