"""Aegis SDK for agent developers (plan §8.16).

    agent = AegisAgent(http, control_url, gateway_url, client_id, private_key_pem)
    task = await agent.start_task("Verify identity document for address change", user_token=jan)
    result = await task.call_tool("kyc", "verify_document", {"customer_id": "C-1001"})
    await task.complete()

Agents that cannot use the SDK can still be governed with configuration only: point their MCP,
A2A and OpenAI-compatible base URLs at the Gateway and send the Mandate as a bearer token.
"""

import asyncio
import json
import uuid

import httpx
import jwt
from opentelemetry import propagate, trace

from aegis.common import crypto
from aegis.control.identity.idp import ASSERTION_TYPE, client_assertion
from aegis.control.identity.sts import JWT_TOKEN_TYPE, TOKEN_EXCHANGE

MCP_HEADERS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


def current_trace_headers() -> dict:
    headers = {}
    propagate.inject(headers)
    return {key: value for key, value in headers.items() if key in {"traceparent", "tracestate"}}


class AegisDenied(Exception):
    def __init__(self, message: str, reasons: list[dict] | None = None):
        super().__init__(message)
        self.reasons = reasons or []

    @property
    def rules(self) -> list[str]:
        return [r.get("rule") for r in self.reasons]


class ApprovalRequired(Exception):
    def __init__(self, approval_id: str, reasons: list[dict]):
        super().__init__(f"human approval required ({approval_id})")
        self.approval_id, self.reasons = approval_id, reasons


class RateLimited(AegisDenied):
    pass


class AegisAgent:
    def __init__(
        self,
        http: httpx.AsyncClient,
        control_url: str,
        gateway_url: str,
        client_id: str,
        private_key_pem: str,
        telemetry=None,
    ):
        self.http = http
        self.control_url = control_url.rstrip("/")
        self.gateway_url = gateway_url.rstrip("/")
        self.client_id = client_id
        self._key = private_key_pem
        self._identity: tuple[str, int] | None = None
        self.tracer = telemetry.tracer("aegis.sdk") if telemetry else trace.get_tracer("aegis.sdk")

    async def identity_token(self) -> str:
        """Short-lived identity from the IdP via a private_key_jwt client assertion (no shared secret)."""
        if self._identity and self._identity[1] - 30 > crypto.now():
            return self._identity[0]
        endpoint = f"{self.control_url}/idp/token"
        response = await self.http.post(
            endpoint,
            headers=current_trace_headers(),
            data={
                "grant_type": "client_credentials",
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": client_assertion(self.client_id, self._key, endpoint),
            },
        )
        if response.status_code != 200:
            raise AegisDenied(f"identity provider refused this agent: {response.text}")
        token = response.json()["access_token"]
        self._identity = (token, jwt.decode(token, options={"verify_signature": False})["exp"])
        return token

    async def _exchange(
        self, subject_token: str | None, intent: str | None, categories: list[str] | None, tools: list[str] | None
    ) -> Task:
        with self.tracer.start_as_current_span("agent task / mandate exchange", record_exception=False):
            return await self._exchange_inner(subject_token, intent, categories, tools)

    async def _exchange_inner(self, subject_token, intent, categories, tools):
        details: dict = {"type": "aegis_mandate"}
        if intent:
            details["intent"] = intent
        if categories:
            details["intent_categories"] = categories
        if tools:
            details["tools"] = tools
        form = {
            "grant_type": TOKEN_EXCHANGE,
            "actor_token": await self.identity_token(),
            "actor_token_type": JWT_TOKEN_TYPE,
            "authorization_details": json.dumps([details]),
        }
        if subject_token:
            form |= {"subject_token": subject_token, "subject_token_type": JWT_TOKEN_TYPE}
        response = await self.http.post(f"{self.control_url}/sts/token", data=form, headers=current_trace_headers())
        payload = response.json()
        if response.status_code != 200:
            raise AegisDenied(
                payload.get("error_description", response.text),
                [{"rule": payload.get("rule") or payload.get("error"), "message": payload.get("error_description")}],
            )
        return Task(self, payload["access_token"])

    async def start_task(
        self,
        intent: str,
        user_token: str | None = None,
        intent_categories: list[str] | None = None,
        tools: list[str] | None = None,
    ) -> Task:
        return await self._exchange(user_token, intent, intent_categories, tools)

    async def accept_delegation(
        self, parent_mandate: str, intent: str | None = None, intent_categories: list[str] | None = None
    ) -> Task:
        return await self._exchange(parent_mandate, intent, intent_categories, None)


class Task:
    """One governed task: a Mandate plus helpers to use it through the Gateway."""

    def __init__(self, agent: AegisAgent, token: str):
        self.agent = agent
        self.token = token
        self.claims = jwt.decode(token, options={"verify_signature": False})
        self.trace_headers = current_trace_headers()

    @property
    def mandate_id(self) -> str:
        return self.claims["aegis"]["mandate_id"]

    @property
    def root_id(self) -> str:
        return self.claims["aegis"]["root_id"]

    @property
    def scopes(self) -> list[str]:
        return self.claims["scope"].split()

    def _auth(self, extra: dict | None = None) -> dict:
        return {"authorization": f"Bearer {self.token}", **self.trace_headers, **(extra or {})}

    async def _mcp(self, server: str, method: str, params: dict, headers: dict | None = None) -> dict:
        body = {"jsonrpc": "2.0", "id": uuid.uuid4().hex[:8], "method": method, "params": params}
        response = await self.agent.http.post(
            f"{self.agent.gateway_url}/mcp/{server}", json=body, headers={**MCP_HEADERS, **self._auth(headers)}
        )
        payload = response.json()
        if response.status_code in (401, 403):
            raise AegisDenied(payload.get("error", {}).get("message", response.text))
        error = payload.get("error")
        if error:
            data = error.get("data") or {}
            if error["code"] == -32002:
                raise ApprovalRequired(data["approval_id"], data.get("reasons", []))
            if error["code"] == -32003:
                raise RateLimited(error["message"])
            raise AegisDenied(error["message"], data.get("reasons"))
        return payload["result"]

    async def list_tools(self, server: str) -> list[dict]:
        return (await self._mcp(server, "tools/list", {}))["tools"]

    async def call_tool(self, server: str, tool: str, arguments: dict, approval_id: str | None = None) -> dict:
        headers = {"x-aegis-approval": approval_id} if approval_id else None
        return await self._mcp(server, "tools/call", {"name": tool, "arguments": arguments}, headers)

    async def wait_for_approval(self, approval_id: str, timeout: float = 120.0, interval: float = 0.5) -> str:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            response = await self.agent.http.get(
                f"{self.agent.control_url}/v1/approvals/{approval_id}/status", headers=self._auth()
            )
            status = response.json().get("status")
            if status != "pending" or asyncio.get_running_loop().time() > deadline:
                return status
            await asyncio.sleep(interval)

    async def delegate(self, agent_id: str, text: str, data: dict | None = None) -> dict:
        """Send an A2A message to another agent through the Gateway."""
        body = {
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex[:8],
            "method": "SendMessage",
            "params": {
                "message": {
                    "role": "user",
                    "messageId": uuid.uuid4().hex,
                    "parts": [{"text": text}],
                    "metadata": data or {},
                }
            },
        }
        response = await self.agent.http.post(
            f"{self.agent.gateway_url}/a2a/{agent_id}", json=body, headers=self._auth(), timeout=60.0
        )
        payload = response.json()
        if response.status_code in (401, 403) or payload.get("error"):
            error = payload.get("error", {})
            raise AegisDenied(error.get("message", response.text), (error.get("data") or {}).get("reasons"))
        return payload["result"]

    async def chat(self, messages: list[dict], **kwargs) -> dict:
        response = await self.agent.http.post(
            f"{self.agent.gateway_url}/llm/v1/chat/completions",
            json={"messages": messages, **kwargs},
            headers=self._auth(),
        )
        if response.status_code != 200:
            raise AegisDenied(response.text)
        return response.json()

    async def complete(self) -> None:
        await self.agent.http.post(f"{self.agent.control_url}/v1/mandates/complete", headers=self._auth())
