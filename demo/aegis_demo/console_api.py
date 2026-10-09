"""Live assistant and investigation APIs. No scripted scenarios or fake model routes."""

import asyncio
from collections.abc import Callable
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from aegis.control.auth import OPERATORS, require_roles
from aegis.control.identity.idp import Persona
from aegis.control.model_controls import policy, policy_error
from aegis.gateway.llm import LlmError, azure_chat_url
from aegis.sdk import AegisDenied, LlmCallError
from aegis_demo.agent_api import router as agent_router
from aegis_demo.copilot import router as copilot_router
from aegis_demo.data import DOCUMENTS
from aegis_demo.walkthrough import router as walkthrough_router

JAN = "jan.devries"


class LlmSmokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm_external_call: Literal[True]


def console_app(get_world: Callable, *, include_sandbox: bool = True) -> FastAPI:
    app = FastAPI(title="Aegis live console")
    app.include_router(agent_router(get_world))
    app.include_router(copilot_router(get_world))
    app.include_router(walkthrough_router(get_world))
    llm_lock = asyncio.Lock()

    def llm_configuration() -> dict:
        w = get_world()
        result = {
            "provider": "azure-openai" if w.settings.azure_openai_endpoint else "not-azure",
            "ready": False,
            "endpoint": None,
            "deployment": None,
            "api_version": None,
            "key_configured": bool(w.settings.azure_openai_api_key.strip()),
            "azure_called": False,
        }
        azure = w.gateway.state.azure_upstream
        if azure is None:
            result["error"] = {
                "code": "azure_not_configured",
                "message": "Configure Azure on the server; fake models cannot satisfy this check.",
            }
        else:
            try:
                url = azure_chat_url(w.settings)
                result["endpoint"] = f"https://{url.host}"
                result["deployment"] = w.settings.azure_openai_deployment
                result["api_version"] = w.settings.azure_openai_api_version
                azure.configuration()
                result["model_policy"] = policy(w.settings)
                error = policy_error(w.settings, w.settings.azure_openai_deployment, "confidential")
                result["ready"] = error is None
                if error:
                    result["error"] = {"code": "LLM-MODEL-POLICY", "message": error}
            except LlmError as exc:
                result["error"] = exc.payload()["error"]
        return result

    @app.get("/llm/status")
    async def llm_status(user: Persona = Depends(require_roles("customer", *OPERATORS))):
        """Configuration only: no model call, credential output or connectivity claim."""
        return llm_configuration()

    @app.post("/llm/smoke")
    async def llm_smoke(body: LlmSmokeRequest, request: Request, user: Persona = Depends(require_roles("customer"))):
        """One paid, synthetic call using the initiating user's token and Ava's real Mandate exchange."""
        if user.username != JAN:
            raise HTTPException(403, "This local smoke call is restricted to the synthetic Jan persona.")
        config = llm_configuration()
        if not config["ready"]:
            raise HTTPException(503, config["error"])
        if llm_lock.locked():
            raise HTTPException(409, "A smoke call is already running. It is not safe to submit another.")
        async with llm_lock:
            w = get_world()
            try:
                task = await w.sdks["ava"].start_task(
                    "Explain a synthetic customer account inquiry without using bank tools",
                    request.headers["authorization"][7:],
                    intent_categories=["customer.inquiry.read"],
                    tools=["core-banking.get_balance"],
                )
            except AegisDenied:
                raise HTTPException(
                    403, "Aegis refused Ava's task. Check its approved identity, status and permitted capabilities."
                ) from None
            try:
                reply = await task.chat(
                    [
                        {
                            "role": "user",
                            "content": (
                                "This is a synthetic connectivity check, not a banking action. "
                                "Explain zero trust in one short sentence. "
                                "Do not claim to have changed any account or executed a payment."
                            ),
                        }
                    ],
                    max_tokens=min(128, w.settings.llm_max_output_tokens),
                )
                metadata = task.last_chat_metadata
                if metadata.get("x-aegis-llm-provider") != "azure-openai":
                    raise HTTPException(502, "The response was not identified as an Azure response by Aegis.")
                message = reply["choices"][0].get("message", {})
                if not isinstance(message.get("content"), str) or not message["content"].strip():
                    raise HTTPException(
                        502, "Azure returned no text, possibly because of a content filter. Do not retry automatically."
                    )
                result = {
                    "provider": "azure-openai",
                    "endpoint": config["endpoint"],
                    "deployment": config["deployment"],
                    "api_version": config["api_version"],
                    "agent_id": w.agent_ids["ava"],
                    "user": user.username,
                    "mandate_id": task.mandate_id,
                    "root_id": task.root_id,
                    "completion_id": reply.get("id"),
                    "model": reply.get("model"),
                    "reply": message["content"],
                    "usage": reply["usage"],
                    "metadata": metadata,
                    "synthetic_input": True,
                    "bank_tools_called": False,
                    "mandate_completed": True,
                    "cost_note": (
                        "Configured estimate only; not an Azure invoice. Check pricing before interpreting cost."
                    ),
                }
            except LlmCallError as exc:
                raise HTTPException(exc.status_code, {"code": exc.code, "message": str(exc)}) from None
            finally:
                try:
                    await task.complete()
                except AegisDenied, httpx.HTTPError:
                    raise HTTPException(
                        503,
                        "Task cleanup failed. Check or revoke its Mandate before retrying; "
                        "Azure may already have processed the call.",
                    ) from None
            return result

    if include_sandbox:

        @app.get("/bank/account")
        async def bank_account(user: Persona = Depends(require_roles("customer"))):
            try:
                return await get_world().bank.snapshot(f"user:{user.username}")
            except ValueError as exc:
                raise HTTPException(403, str(exc)) from None

        @app.get("/samples")
        async def samples(user: Persona = Depends(require_roles(*OPERATORS))):
            """Explicit synthetic adversarial samples for the detector playground, not scripted executions."""
            return {"poisoned_document": DOCUMENTS["D-99"]["text"], "passport": DOCUMENTS["D-77"]["text"]}

    return app
