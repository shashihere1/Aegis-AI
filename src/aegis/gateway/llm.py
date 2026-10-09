"""Bounded, non-streaming chat and gateway-only access to one configured Azure deployment."""

import json
import re

import httpx

from aegis.common.settings import Settings
from aegis.telemetry import tracing_headers


class LlmError(Exception):
    """Only these deliberately non-sensitive messages may be returned to callers."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code = status, code

    def payload(self) -> dict:
        return {"error": {"code": self.code, "message": str(self)}}


def azure_chat_url(settings: Settings) -> httpx.URL:
    """Reject full API URLs, credentials, non-Azure hosts and alternate ports before sending a key."""
    try:
        endpoint = httpx.URL(settings.azure_openai_endpoint)
    except httpx.InvalidURL:
        raise LlmError(503, "azure_configuration", "The Azure resource base endpoint is invalid.") from None
    if (
        endpoint.scheme != "https"
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]*\.(?:openai|services\.ai)\.azure\.com", endpoint.host)
        or endpoint.port not in (None, 443)
        or endpoint.userinfo
        or endpoint.path not in ("", "/")
        or endpoint.query
        or endpoint.fragment
    ):
        raise LlmError(
            503,
            "azure_configuration",
            "Use an HTTPS Azure resource base endpoint, without a deployment path, query or credentials.",
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", settings.azure_openai_deployment):
        raise LlmError(503, "azure_configuration", "Configure a valid Azure deployment name.")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:-preview)?", settings.azure_openai_api_version):
        raise LlmError(503, "azure_configuration", "Configure a dated Azure API version.")
    return endpoint.copy_with(
        path=f"/openai/deployments/{settings.azure_openai_deployment}/chat/completions",
        query=f"api-version={settings.azure_openai_api_version}".encode("ascii"),
    )


def bounded_chat(body: object, settings: Settings) -> dict:
    """No streaming, remote media, extra generations, arbitrary destinations or unbounded outputs."""
    if not isinstance(body, dict):
        raise LlmError(400, "invalid_chat_request", "The chat body must be a JSON object.")
    allowed = {
        "messages",
        "model",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "stop",
        "seed",
        "response_format",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "stream",
        "n",
    }
    if set(body) - allowed:
        raise LlmError(400, "invalid_chat_request", "The request contains unsupported chat parameters.")
    messages = body.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 64:
        raise LlmError(400, "invalid_chat_request", "Supply between 1 and 64 chat messages.")
    for message in messages:
        if (
            not isinstance(message, dict)
            or not isinstance(message.get("role"), str)
            or message.get("role") not in {"system", "developer", "user", "assistant", "tool"}
            or (message.get("content") is not None and not isinstance(message["content"], str))
        ):
            raise LlmError(400, "invalid_chat_request", "Only text chat messages are supported by this gateway.")
    # Count definitions and arguments too, not just the natural-language prompt.
    if len(json.dumps(body, ensure_ascii=False)) > settings.llm_max_request_chars:
        raise LlmError(413, "chat_request_too_large", "The chat request exceeds the gateway size limit.")
    if body.get("stream", False) is not False or type(body.get("n", 1)) is not int or body.get("n", 1) != 1:
        raise LlmError(400, "invalid_chat_request", "Only one non-streaming completion is supported.")
    if "max_tokens" in body and "max_completion_tokens" in body:
        raise LlmError(400, "invalid_chat_request", "Specify only one output-token limit.")
    token_field = "max_completion_tokens" if "max_completion_tokens" in body else "max_tokens"
    limit = body.get(token_field, settings.llm_max_output_tokens)
    if type(limit) is not int or not 1 <= limit <= settings.llm_max_output_tokens:
        raise LlmError(400, "invalid_chat_request", "The output-token limit exceeds the gateway allowance.")
    tools = body.get("tools", [])
    if not isinstance(tools, list) or any(not isinstance(t, dict) or t.get("type") != "function" for t in tools):
        raise LlmError(400, "invalid_chat_request", "Only application-executed function tools are supported.")
    return {**body, token_field: limit, "stream": False, "n": 1}


def completion_usage(data: object) -> tuple[int, int]:
    """Never turn a malformed response or absent usage into a successful zero-token call."""
    if not isinstance(data, dict) or not isinstance(data.get("choices"), list) or not data["choices"]:
        raise LlmError(502, "invalid_llm_response", "The model returned an invalid chat-completion response.")
    for choice in data["choices"]:
        if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
            raise LlmError(502, "invalid_llm_response", "The model returned an invalid chat message.")
    if data.get("model") is not None and not isinstance(data["model"], str):
        raise LlmError(502, "invalid_llm_response", "The model returned an invalid model identifier.")
    usage = data.get("usage")
    if not isinstance(usage, dict):
        raise LlmError(
            502, "missing_llm_usage", "The model response did not include token usage; do not retry automatically."
        )
    values = (usage.get("prompt_tokens"), usage.get("completion_tokens"))
    if any(type(v) is not int or v < 0 for v in values):
        raise LlmError(502, "invalid_llm_usage", "The model returned invalid token usage; do not retry automatically.")
    return values


def safe_request_id(response: httpx.Response) -> str:
    for name in ("apim-request-id", "x-request-id", "x-ms-request-id"):
        value = response.headers.get(name, "")
        if re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
            return value
    return ""


class AzureChatUpstream:
    """Separate client: only the gateway can call it; destination comes from settings, never request JSON."""

    def __init__(self, settings: Settings):
        self.settings = settings
        # Environment proxy/certificate settings work normally. TLS stays verified; redirects and retries are off.
        self.http = httpx.AsyncClient(timeout=settings.llm_timeout_seconds, follow_redirects=False)

    def configuration(self) -> tuple[httpx.URL, str]:
        url = azure_chat_url(self.settings)
        key = self.settings.azure_openai_api_key.strip()
        if not key:
            raise LlmError(503, "azure_key_missing", "Set AEGIS_AZURE_OPENAI_API_KEY locally on the server.")
        return url, key

    async def complete(self, body: dict) -> httpx.Response:
        url, key = self.configuration()
        model = body.get("model")
        if model not in (None, self.settings.azure_openai_deployment):
            raise LlmError(403, "deployment_not_allowed", "Only the configured Azure deployment is permitted.")
        try:
            response = await self.http.post(
                url,
                json={**body, "model": self.settings.azure_openai_deployment},
                headers=tracing_headers({"api-key": key}),
                follow_redirects=False,
            )
        except httpx.TimeoutException:
            raise LlmError(
                504, "azure_timeout", "Azure timed out; the request may have reached Azure. Do not retry automatically."
            ) from None
        except httpx.RequestError:
            raise LlmError(
                502, "azure_network", "Cannot reach Azure. Check the approved proxy, DNS, VPN and firewall."
            ) from None
        if response.status_code != 200:
            code, message = {
                400: (
                    "azure_bad_request",
                    "Azure rejected the request. Check API-version/model compatibility and content filters.",
                ),
                401: ("azure_authentication", "Azure rejected the API key. Check the key on the server."),
                403: (
                    "azure_access",
                    "Azure denied access. Check resource permissions, key authentication and networking.",
                ),
                404: (
                    "azure_not_found",
                    "Azure could not find this deployment or API route. Check the resource, name and version.",
                ),
                429: (
                    "azure_rate_limit",
                    "Azure rate-limited the request. Check deployment quota and wait before trying again.",
                ),
            }.get(
                response.status_code,
                ("azure_upstream_error", "Azure returned an unsuccessful response; do not retry automatically."),
            )
            # Never echo raw cloud errors (which may include prompts, identifiers or secrets).
            raise LlmError(429 if response.status_code == 429 else 502, code, message)
        return response

    async def aclose(self) -> None:
        await self.http.aclose()
