"""Offline Python-model-control coverage; no live inference or provider credentials."""

from sqlalchemy import func, select

from aegis.common.settings import Settings
from aegis.control.model_controls import policy_error
from aegis.control.tables import LlmReservation, Usage
from aegis_demo.world import BASE


def test_model_controls_fail_closed():
    settings = Settings(azure_openai_deployment="demo", llm_processing_scope="unknown")
    assert policy_error(settings, "demo", "confidential")
    settings.llm_processing_scope = "global"
    assert policy_error(settings, "demo", "confidential")  # Default EU permission cannot authorize Global Standard.
    settings.llm_allowed_processing_scope = "global"
    assert policy_error(settings, "demo", "confidential") is None
    assert policy_error(settings, "other", "confidential")
    assert policy_error(settings, "demo", "restricted")


async def test_gateway_binds_fixture_resources_to_signed_user(world):
    task = await world.sdks["ava"].start_task(
        "Read my account balance", world.token("jan.devries"), intent_categories=["customer.inquiry.read"]
    )
    import pytest

    from aegis.sdk import AegisDenied

    try:
        with pytest.raises(AegisDenied, match="ownership"):
            await task.call_tool("core-banking", "get_balance", {"customer_id": "C-1002"})
        result = await task.call_tool("core-banking", "get_balance", {"customer_id": "C-1001"})
        assert not result.get("isError")
    finally:
        await task.complete()


async def test_budget_hold_denies_overspend_and_settlement_is_idempotent(world):
    settings = world.ctx.settings
    settings.azure_openai_deployment = "offline"
    settings.llm_processing_scope = settings.llm_allowed_processing_scope = "eu"
    settings.llm_daily_budget_eur = 0.04
    headers = world.internal_headers()
    body = {
        "agent_id": world.agent_ids["ava"],
        "mandate_id": "offline-mandate",
        "deployment": "offline",
        "data_class": "confidential",
        "input_bound_tokens": 10000,
        "output_bound_tokens": 1,
    }

    async def reserve():
        return (await world.http.post(f"{BASE}/internal/llm/reserve", json=body, headers=headers)).json()

    first = await reserve()
    assert first["allowed"]
    second = await reserve()
    assert not second["allowed"] and second["rule"] == "LLM-BUDGET"
    settlement = {"model": "offline", "input_tokens": 12, "output_tokens": 6, "latency_ms": 1.0}
    for _ in range(2):
        response = await world.http.post(
            f"{BASE}/internal/llm/{first['reservation_id']}/settle", json=settlement, headers=headers
        )
        assert response.json()["settled"]
    async with world.ctx.db.sessionmaker() as s:
        assert await s.scalar(select(func.count()).select_from(Usage)) == 1
        row = await s.get(LlmReservation, first["reservation_id"])
        assert row.status == "settled" and row.charged_eur < row.reserved_eur
    assert (await reserve())["allowed"]


async def test_budget_warning_is_once_and_budget_api_does_not_grant_customer_access(world):
    from aegis.control.tables import Alert, BudgetNotice

    settings = world.ctx.settings
    settings.azure_openai_deployment = "offline"
    settings.llm_processing_scope = settings.llm_allowed_processing_scope = "eu"
    settings.llm_daily_budget_eur = 0.04
    headers = world.internal_headers()
    body = {
        "agent_id": world.agent_ids["ava"],
        "mandate_id": "offline",
        "deployment": "offline",
        "data_class": "confidential",
        "input_bound_tokens": 13000,
        "output_bound_tokens": 1,
    }
    first = (await world.http.post(f"{BASE}/internal/llm/reserve", json=body, headers=headers)).json()
    assert first["allowed"]
    smaller = {**body, "input_bound_tokens": 100}
    assert (await world.http.post(f"{BASE}/internal/llm/reserve", json=smaller, headers=headers)).json()["allowed"]
    async with world.ctx.db.sessionmaker() as s:
        assert await s.scalar(select(func.count()).select_from(Alert).where(Alert.rule_id == "DET-16")) == 1
        assert await s.scalar(select(func.count()).select_from(BudgetNotice)) == 1
    assert (await world.api("jan.devries", "GET", "/v1/model-budgets")).status_code == 403
    response = await world.api("mark.jansen", "GET", "/v1/model-budgets")
    assert response.status_code == 200
    budget = next(item for item in response.json()["items"] if item["agent_id"] == world.agent_ids["ava"])
    assert budget["state"] == "warning" and budget["outstanding_holds"] == 2
