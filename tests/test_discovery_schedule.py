"""Automatic identity-provider scan: the shared scan function, the background schedule and its status."""

import asyncio
from contextlib import asynccontextmanager

import pytest
from pydantic import ValidationError

from aegis.common.settings import Settings
from aegis.control import discovery
from aegis.control.identity.oidc import IdentityUnavailable
from aegis_demo.testing import FAKE_LLM_URL, running_world


@asynccontextmanager
async def scheduled_world(interval: int):
    # The MCP SDK's task groups must be entered and exited in the same task (see conftest.world).
    ready: asyncio.Future = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()

    async def owner():
        async with running_world(llm_upstream_url=FAKE_LLM_URL, discovery_scan_interval=interval) as w:
            ready.set_result(w)
            await stop.wait()

    task = asyncio.create_task(owner())
    await asyncio.wait({task, ready}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        task.result()
    try:
        yield ready.result()
    finally:
        stop.set()
        await task


async def eventually(check, timeout: float = 5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        value = await check()
        if value:
            return value
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.05)


async def findings_for(world, fingerprint: str) -> list[dict]:
    return [f for f in (await world.api("mark.jansen", "GET", "/v1/discovery/findings")).json()
            if f["fingerprint"] == fingerprint]


async def alerts_for(world, fingerprint: str) -> list[dict]:
    return [a for a in (await world.api("mark.jansen", "GET", "/v1/alerts")).json()
            if a["rule_id"] == "DET-07" and fingerprint in a["title"]]


async def test_manual_scan_finds_ungoverned_identity_and_reports_status(world):
    world.ctx.idp.register_unmanaged_client("rogue-bot", "Rogue bot")
    result = (await world.api("mark.jansen", "POST", "/v1/discovery/scan")).json()
    assert result["found"] == ["idp-client:rogue-bot"] and result["new"] == 1  # governed demo agents are not flagged
    assert result["checked"] > 1

    status = (await world.api("eva.visser", "GET", "/v1/discovery/status")).json()
    run = status["idp_scan"]["last_run"]
    assert run["trigger"] == "manual" and run["actor"] == "user:mark.jansen" and run["ok"] and run["new"] == 1
    assert status["idp_scan"]["automatic"] is False and status["idp_scan"]["next_run_at"] is None
    assert status["sources"] == {"gateway": "active", "idp": "manual", "otel": "planned", "repo": "planned",
                                 "cloud": "planned"}


async def test_scan_still_requires_a_soc_or_admin_role(world):
    assert (await world.api("priya.raman", "POST", "/v1/discovery/scan")).status_code == 403


async def test_scheduled_rescan_refreshes_without_inflating_hits_or_alerts(world):
    world.ctx.idp.register_unmanaged_client("rogue-bot", "Rogue bot")
    await world.api("mark.jansen", "POST", "/v1/discovery/scan")
    [before] = await findings_for(world, "idp-client:rogue-bot")

    for _ in range(3):
        await discovery.run_idp_scan(world.ctx, discovery.SCHEDULER, "scheduled")

    [after] = await findings_for(world, "idp-client:rogue-bot")
    assert after["hits"] == before["hits"] == 1
    assert len(after["evidence"]) == len(before["evidence"])
    assert after["last_seen"] >= before["last_seen"]
    assert len(await alerts_for(world, "idp-client:rogue-bot")) == 1


async def test_scheduled_scan_counts_a_brand_new_identity_once(world):
    world.ctx.idp.register_unmanaged_client("night-crawler", "Night crawler")
    report = await discovery.run_idp_scan(world.ctx, discovery.SCHEDULER, "scheduled")
    assert report["new"] == 1
    [finding] = await findings_for(world, "idp-client:night-crawler")
    assert finding["hits"] == 1 and finding["sources"] == ["idp"]
    assert world.ctx.discovery_status["last_run"]["actor"] == discovery.SCHEDULER


async def test_overlapping_manual_and_scheduled_scans_create_one_finding(world):
    world.ctx.idp.register_unmanaged_client("rogue-bot", "Rogue bot")
    await asyncio.gather(
        discovery.run_idp_scan(world.ctx, "user:mark.jansen", "manual"),
        discovery.run_idp_scan(world.ctx, discovery.SCHEDULER, "scheduled"),
    )
    assert len(await findings_for(world, "idp-client:rogue-bot")) == 1
    assert len(await alerts_for(world, "idp-client:rogue-bot")) == 1


class FlakyIdentity:
    """Wraps the real provider; list_clients fails until `failures` runs out."""

    def __init__(self, inner, failures: int):
        self.inner, self.failures = inner, failures

    async def list_clients(self):
        if self.failures:
            self.failures -= 1
            raise IdentityUnavailable("http://keycloak.internal:8080 refused the connection")
        return await self.inner.list_clients()

    def __getattr__(self, name):
        return getattr(self.inner, name)


async def test_loop_survives_an_unavailable_provider_and_recovers(world):
    world.ctx.agent_identity = FlakyIdentity(world.ctx.agent_identity, failures=1)
    world.ctx.settings = world.ctx.settings.model_copy(update={"discovery_scan_interval": 1})
    loop = asyncio.create_task(discovery.scan_periodically(world.ctx))
    try:
        failed = await eventually(async_status(world, lambda r: r and not r["ok"]))
        assert failed["error"] == "IdentityUnavailable"
        assert "keycloak.internal" not in str(world.ctx.discovery_status)  # no provider detail kept
        recovered = await eventually(async_status(world, lambda r: r and r["ok"]))
        assert recovered["trigger"] == "scheduled" and world.ctx.discovery_status["next_run_at"]
    finally:
        loop.cancel()
        with pytest.raises(asyncio.CancelledError):
            await loop


def async_status(world, predicate):
    async def check():
        run = world.ctx.discovery_status.get("last_run")
        return run if predicate(run) else None
    return check


async def test_manual_scan_failure_is_recorded_and_fails_closed(world):
    world.ctx.agent_identity = FlakyIdentity(world.ctx.agent_identity, failures=1)
    response = await world.api("mark.jansen", "POST", "/v1/discovery/scan")
    assert response.status_code == 503
    run = (await world.api("mark.jansen", "GET", "/v1/discovery/status")).json()["idp_scan"]["last_run"]
    assert run == {"at": run["at"], "trigger": "manual", "actor": "user:mark.jansen", "ok": False,
                   "error": "IdentityUnavailable"}


async def test_control_plane_starts_the_schedule_when_configured():
    async with scheduled_world(interval=60) as world:
        async def scheduled_run():
            status = (await world.api("mark.jansen", "GET", "/v1/discovery/status")).json()
            run = status["idp_scan"]["last_run"]
            return status if run and run["trigger"] == "scheduled" and run["ok"] else None

        status = await eventually(scheduled_run)
        assert status["idp_scan"]["automatic"] is True and status["idp_scan"]["interval_seconds"] == 60
        assert status["idp_scan"]["next_run_at"] and status["sources"]["idp"] == "scheduled"


async def test_no_schedule_runs_when_interval_is_zero(world):
    await asyncio.sleep(0.2)
    assert "last_run" not in world.ctx.discovery_status


def test_interval_setting_is_validated_and_read_from_the_environment(monkeypatch):
    with pytest.raises(ValidationError):
        Settings(discovery_scan_interval=-1)
    monkeypatch.setenv("AEGIS_DISCOVERY_SCAN_INTERVAL", "120")
    assert Settings.from_env().discovery_scan_interval == 120
