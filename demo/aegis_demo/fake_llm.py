"""Deterministic OpenAI-compatible endpoint for tests and offline demos.

The live demo uses the OneStop-approved Azure OpenAI deployment (AEGIS_AZURE_OPENAI_* settings).
"""

from fastapi import FastAPI, Request


def fake_llm_app() -> FastAPI:
    app = FastAPI(title="Fake LLM (tests only)")

    @app.post("/v1/chat/completions")
    async def completions(request: Request):
        body = await request.json()
        prompt = " ".join(str(m.get("content", "")) for m in body.get("messages", []))
        prompt_tokens = max(1, len(prompt.split()))
        return {
            "id": "chatcmpl-demo", "object": "chat.completion", "model": body.get("model", "gpt-4o-mini-demo"),
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "Summary: the request was handled."}}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 7, "total_tokens": prompt_tokens + 7},
        }

    return app
