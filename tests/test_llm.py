"""Offline regression coverage. No Azure calls or credentials are required."""

import json

import httpx
import pytest

from aegis.common.settings import Settings
from aegis.gateway.llm import AzureChatUpstream, LlmError, azure_chat_url, bounded_chat, completion_usage
from aegis_demo.llm_smoke import local_base_url
from aegis_demo.testing import BASE

ENDPOINT = "https://test-resource.openai.azure.com"
CHAT = {"messages": [{"role": "user", "content": "A synthetic question."}], "max_tokens": 128}
COMPLETION = {
    "id": "offline-test-completion",
    "model": "gpt-4.1-mini",
    "choices": [{"message": {"role": "assistant", "content": "An offline regression response."}}],
    "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
}


def settings(**overrides):
    return Settings(
        **{
            "azure_openai_endpoint": ENDPOINT,
            "azure_openai_deployment": "aegis-chat",
            "azure_openai_api_version": "2025-01-01-preview",
            "azure_openai_api_key": "offline-placeholder-key",
            "llm_processing_scope": "eu",
            "llm_allowed_processing_scope": "eu",
            **overrides,
        }
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://test-resource.openai.azure.com",
        "https://attacker.example",
        "https://test-resource.openai.azure.com.attacker.example",
        "https://test-resource.openai.azure.com/openai/v1/",
        "https://test-resource.openai.azure.com?api-key=not-a-key",
        "https://user:password@test-resource.openai.azure.com",
        "https://test-resource.openai.azure.com:8443",
    ],
)
def test_azure_destination_is_restricted(endpoint):
    with pytest.raises(LlmError):
        azure_chat_url(settings(azure_openai_endpoint=endpoint))


def test_azure_url_matches_supplied_route():
    assert str(azure_chat_url(settings())) == (
        f"{ENDPOINT}/openai/deployments/aegis-chat/chat/completions?api-version=2025-01-01-preview"
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"stream": True},
        {"n": 2},
        {"max_tokens": 10000},
        {"max_tokens": True},
        {"max_tokens": 1, "max_completion_tokens": 1},
        {"base_url": "https://attacker.example"},
        {"tools": [{"type": "web_search"}]},
        {"messages": [{"role": [], "content": "invalid"}]},
        {
            "messages": [
                {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://example.com"}}]}
            ]
        },
    ],
)
def test_unbounded_and_remote_media_requests_are_refused(extra):
    with pytest.raises(LlmError):
        bounded_chat({**CHAT, **extra}, settings())


def test_missing_usage_is_not_fabricated():
    with pytest.raises(LlmError):
        completion_usage({"choices": COMPLETION["choices"]})
    assert completion_usage(COMPLETION) == (12, 6)


async def test_gateway_client_brokers_key_to_the_configured_deployment_only():
    calls = []

    def upstream(request):
        calls.append(request)
        assert request.url == azure_chat_url(settings())
        assert request.headers["api-key"] == "offline-placeholder-key"
        assert "authorization" not in request.headers
        assert json.loads(request.content)["model"] == "aegis-chat"
        return httpx.Response(200, json=COMPLETION)

    azure = AzureChatUpstream(settings())
    await azure.http.aclose()
    azure.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    try:
        await azure.complete(bounded_chat(CHAT, settings()))
        with pytest.raises(LlmError) as caught:
            await azure.complete({**CHAT, "model": "another-deployment"})
        assert caught.value.code == "deployment_not_allowed"
        assert len(calls) == 1
    finally:
        await azure.aclose()


@pytest.mark.parametrize("status", [302, 401, 403, 404, 429, 500])
async def test_azure_errors_are_sanitized_and_never_retried(status):
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(
            status,
            headers={"location": "https://attacker.example"},
            json={"error": {"message": "sensitive-cloud-error-text"}},
        )

    azure = AzureChatUpstream(settings())
    await azure.http.aclose()
    azure.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream), follow_redirects=True)
    try:
        with pytest.raises(LlmError) as caught:
            await azure.complete(bounded_chat(CHAT, settings()))
        assert "sensitive-cloud-error-text" not in str(caught.value)
        assert len(calls) == 1
    finally:
        await azure.aclose()


def test_cli_is_loopback_only():
    import argparse

    assert local_base_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    with pytest.raises(argparse.ArgumentTypeError):
        local_base_url("https://remote.example")


async def test_smoke_api_requires_auth_and_refuses_the_fake_model(world):
    anonymous = await world.http.post(f"{BASE}/demo/api/llm/smoke", json={"confirm_external_call": True})
    assert anonymous.status_code == 401
    operator = await world.api("priya.raman", "POST", "/demo/api/llm/smoke", json={"confirm_external_call": True})
    assert operator.status_code == 403
    status = (await world.api("jan.devries", "GET", "/demo/api/llm/status")).json()
    assert not status["ready"] and not status["azure_called"]
    refused = await world.api("jan.devries", "POST", "/demo/api/llm/smoke", json={"confirm_external_call": True})
    assert refused.status_code == 503


@pytest.mark.parametrize("upstream_status", [200, 401])
async def test_smoke_call_records_usage_only_on_success_and_always_completes(upstream_status):
    from aegis_demo.testing import FAKE_LLM_URL, running_world

    config = settings().model_dump()
    # Including an offline upstream proves that configured Azure takes precedence, with no fake fallback.
    config.update(
        control_url=BASE,
        gateway_url=f"{BASE}/gw",
        database_url="sqlite+aiosqlite:///:memory:",
        llm_upstream_url=FAKE_LLM_URL,
    )
    async with running_world(**config) as world:
        azure = world.gateway.state.azure_upstream
        await azure.http.aclose()
        calls = []

        def upstream(request):
            calls.append(request)
            assert request.url == azure_chat_url(world.settings)
            assert "authorization" not in request.headers
            return httpx.Response(
                upstream_status,
                json=COMPLETION if upstream_status == 200 else {"error": {"message": "sensitive-cloud-error-text"}},
                headers={"apim-request-id": "offline-request-id"},
            )

        azure.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
        response = await world.api("jan.devries", "POST", "/demo/api/llm/smoke", json={"confirm_external_call": True})
        assert len(calls) == 1
        assert response.status_code == (200 if upstream_status == 200 else 502)
        usage = (await world.api("mark.jansen", "GET", "/v1/usage")).json()
        completed = (await world.api("mark.jansen", "GET", "/v1/mandates?status=completed")).json()
        assert len(completed) == 1
        if upstream_status == 200:
            result = response.json()
            assert result["provider"] == "azure-openai" and result["mandate_completed"]
            assert not result["bank_tools_called"]
            assert result["metadata"]["x-aegis-azure-request-id"] == "offline-request-id"
            assert result["mandate_id"] == completed[0]["id"]
            assert usage[0]["input_tokens"] == 12 and usage[0]["output_tokens"] == 6
        else:
            assert usage == []
            assert "sensitive-cloud-error-text" not in response.text
