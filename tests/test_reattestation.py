"""Ownership re-attestation: hand-over when an owner leaves, the campaign rules, enforcement and the schedule."""

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import select

from aegis.common.models import AgentStatus
from aegis.common.settings import Settings
from aegis.control import ownership
from aegis.control.app import create_app
from aegis.control.identity.idp import Persona
from aegis.control.tables import Agent, Alert, LedgerEntry

NEW_OWNER = "new.owner"


def add(world, username, roles, person_id=None):
    world.ctx.idp.add_persona(Persona(username, username.title(), roles, person_id=person_id))


def agent_row(agent_id, name, **fields):
    values = dict(id=agent_id, name=name, purpose="Synthetic agent for re-attestation tests.",
                  owner="niels.vandijk", sponsor="retail.ops.head", registered_by="seed", environment="PRD",
                  cloud="azure", autonomy="L1", max_data_class="internal", status=AgentStatus.ACTIVE)
    return Agent(**(values | fields))


async def put(world, *agents):
    async with world.ctx.db.sessionmaker() as s:
        s.add_all(agents)
        await s.commit()


async def get(world, agent_id):
    async with world.ctx.db.sessionmaker() as s:
        return await s.get(Agent, agent_id)


async def edit(world, agent_id, **fields):
    async with world.ctx.db.sessionmaker() as s:
        agent = await s.get(Agent, agent_id)
        for key, value in fields.items():
            setattr(agent, key, value)
        await s.commit()


async def events(world, event_type):
    async with world.ctx.db.sessionmaker() as s:
        query = select(LedgerEntry).where(LedgerEntry.event_type == event_type).order_by(LedgerEntry.seq)
        return (await s.scalars(query)).all()


async def alerts(world, rule_id):
    async with world.ctx.db.sessionmaker() as s:
        return (await s.scalars(select(Alert).where(Alert.rule_id == rule_id).order_by(Alert.ts))).all()


def owner_url(agent_id):
    return f"/v1/agents/{agent_id}/owner"


def reassign(world, who, agent_id, new_owner=NEW_OWNER, reason="Previous owner left the bank"):
    return world.api(who, "POST", owner_url(agent_id), json={"new_owner": new_owner, "reason": reason})


def days_from_now(value):
    return (datetime.fromisoformat(value).replace(tzinfo=UTC) - datetime.now(UTC)).total_seconds() / 86400


# ---- hand-over ----


async def test_an_orphaned_agent_can_be_handed_to_a_new_owner_who_must_then_attest(world):
    add(world, NEW_OWNER, ["agent-owner"])
    ava = world.agent_ids["ava"]
    await world.api("admin", "POST", "/v1/idp-events/leaver", json={"username": "niels.vandijk"})
    assert (await get(world, ava)).orphaned is True

    handed = await reassign(world, "admin", ava, f"  {NEW_OWNER}  ")
    assert handed.status_code == 200, handed.text
    body = handed.json()
    assert body["owner"] == NEW_OWNER and body["orphaned"] is False and body["status"] == "active"
    assert 13 < days_from_now(body["attestation_due"]) <= 14  # the new owner has the grace period to confirm
    (event,) = [e for e in await events(world, "agent.owner_reassigned") if e.subject == ava]
    assert event.actor == "user:admin"
    assert event.payload == {"from": "niels.vandijk", "to": NEW_OWNER, "reason": "Previous owner left the bank",
                             "was_orphaned": True}

    attested = await world.api(NEW_OWNER, "POST", f"/v1/agents/{ava}/attest")
    assert attested.status_code == 200 and attested.json()["attestation_due"] is None
    assert any(e.actor == f"user:{NEW_OWNER}" for e in await events(world, "attestation.confirmed"))


async def test_the_orphaned_alert_records_the_hand_over(world):
    add(world, NEW_OWNER, ["agent-owner"])
    ava = world.agent_ids["ava"]
    await world.api("admin", "POST", "/v1/idp-events/leaver", json={"username": "niels.vandijk"})
    await reassign(world, "admin", ava)
    (alert,) = [a for a in await alerts(world, "DET-12") if a.agent_id == ava]
    assert alert.actions_taken == [{"action": "owner_reassigned", "from": "niels.vandijk", "to": NEW_OWNER}]


async def test_who_may_hand_an_agent_over(world):
    add(world, NEW_OWNER, ["agent-owner"])
    add(world, "other.owner", ["agent-owner"])
    ava, kyc = world.agent_ids["ava"], world.agent_ids["kyc-agent"]

    other = await reassign(world, "other.owner", ava)  # an owner of nothing here
    assert other.status_code == 403 and "OWN-001" in other.text
    assert (await reassign(world, "priya.raman", ava)).status_code == 403  # a developer holds no hand-over role
    assert (await reassign(world, "eva.visser", ava)).status_code == 403  # an auditor reads only
    assert (await get(world, ava)).owner == "niels.vandijk"

    assert (await reassign(world, "niels.vandijk", ava)).status_code == 200  # the owner may hand their agent on
    assert (await reassign(world, "sanne.bakker", kyc)).status_code == 200  # risk may do it for a leaver
    assert (await get(world, ava)).owner == (await get(world, kyc)).owner == NEW_OWNER


async def test_a_hand_over_is_refused_when_it_would_be_wrong(world):
    add(world, NEW_OWNER, ["agent-owner"])
    add(world, "niels.alt", ["agent-owner"], person_id="niels.vandijk")
    add(world, "gone.person", ["agent-owner"])
    world.ctx.idp.mark_leaver("gone.person")
    ava = world.agent_ids["ava"]

    same = await reassign(world, "admin", ava, "niels.vandijk")
    assert same.status_code == 409 and "already owns" in same.text
    alt = await reassign(world, "admin", ava, "niels.alt")  # another account of the same person
    assert alt.status_code == 409 and "already owns" in alt.text
    gone = await reassign(world, "admin", ava, "gone.person")
    assert gone.status_code == 409 and "has left" in gone.text
    mine = await reassign(world, "admin", ava, "admin")  # nobody may make themselves the owner
    assert mine.status_code == 403 and "SOD-004" in mine.text
    assert (await reassign(world, "admin", ava, reason="no")).status_code == 422
    assert (await reassign(world, "admin", ava, "   ")).status_code == 422
    assert (await reassign(world, "admin", "AGT-NOPE-0000")).status_code == 404
    assert (await get(world, ava)).owner == "niels.vandijk"
    assert not await events(world, "agent.owner_reassigned")


async def test_a_retired_agent_cannot_change_owner_and_a_suspended_one_gets_no_due_date(world):
    add(world, NEW_OWNER, ["agent-owner"])
    ava, kyc = world.agent_ids["ava"], world.agent_ids["kyc-agent"]
    await world.api("mark.jansen", "POST", f"/v1/agents/{ava}/suspend", json={})
    assert (await reassign(world, "admin", ava)).json()["attestation_due"] is None
    assert (await get(world, ava)).status == AgentStatus.SUSPENDED
    await world.api("admin", "POST", f"/v1/agents/{kyc}/retire", json={})
    retired = await reassign(world, "admin", kyc)
    assert retired.status_code == 409 and "retired" in retired.text


async def test_a_suspended_agent_is_orphaned_too_when_its_owner_leaves(world):
    ava = world.agent_ids["ava"]
    await world.api("mark.jansen", "POST", f"/v1/agents/{ava}/suspend", json={})
    await world.api("admin", "POST", "/v1/idp-events/leaver", json={"username": "niels.vandijk"})
    suspended = await get(world, ava)
    assert suspended.orphaned is True and suspended.attestation_due is None  # nothing is overdue while it is off
    active = await get(world, world.agent_ids["kyc-agent"])
    assert active.orphaned is True and active.attestation_due is not None


# ---- campaigns and enforcement ----


async def test_a_campaign_never_gives_an_agent_that_is_already_due_more_time(world):
    ava = world.agent_ids["ava"]
    first = await world.api("sanne.bakker", "POST", "/v1/attestations/campaign", json={"due_in_days": 14})
    assert first.status_code == 200
    original = (await get(world, ava)).attestation_due
    assert (await world.api("sanne.bakker", "POST", "/v1/attestations/campaign", json={"due_in_days": 30})
            ).status_code == 200
    assert (await get(world, ava)).attestation_due == original  # 30 days must not replace 14
    assert (await world.api("sanne.bakker", "POST", "/v1/attestations/campaign", json={"due_in_days": 1})
            ).status_code == 200
    assert (await get(world, ava)).attestation_due < original  # a shorter deadline does apply
    for bad in (0, -5, 4000):
        refused = await world.api("sanne.bakker", "POST", "/v1/attestations/campaign", json={"due_in_days": bad})
        assert refused.status_code == 422


async def test_enforcement_suspends_only_agents_that_are_overdue(world):
    ava, kyc = world.agent_ids["ava"], world.agent_ids["kyc-agent"]
    past, future = datetime.now(UTC) - timedelta(days=1), datetime.now(UTC) + timedelta(days=5)
    await edit(world, ava, attestation_due=past)
    await edit(world, kyc, attestation_due=future)
    assert (await world.api("niels.vandijk", "POST", "/v1/attestations/enforce")).status_code == 403
    done = await world.api("sanne.bakker", "POST", "/v1/attestations/enforce")
    assert done.status_code == 200 and done.json() == {"suspended": [ava]}
    assert (await get(world, ava)).status == AgentStatus.SUSPENDED
    assert (await get(world, kyc)).status == AgentStatus.ACTIVE


async def test_status_reports_the_schedule_and_where_agents_stand(world):
    assert (await world.api("jan.devries", "GET", "/v1/attestations/status")).status_code == 403
    before = (await world.api("eva.visser", "GET", "/v1/attestations/status")).json()
    assert before["interval_days"] == 90 and before["grace_days"] == 14 and before["auto_enforce"] is False
    assert before["due"] == before["overdue"] == before["orphaned"] == 0 and before["next_due"] is None
    assert before["scheduler_running"] is False  # an in-memory database never runs the background job
    await edit(world, world.agent_ids["ava"], attestation_due=datetime.now(UTC) - timedelta(days=1))
    await edit(world, world.agent_ids["kyc-agent"], attestation_due=datetime.now(UTC) + timedelta(days=3),
               orphaned=True)
    after = (await world.api("eva.visser", "GET", "/v1/attestations/status")).json()
    assert (after["due"], after["overdue"], after["orphaned"]) == (2, 1, 1)
    assert after["active_agents"] == before["active_agents"] and after["next_due"] is not None


# ---- the schedule ----


async def test_the_schedule_opens_campaigns_only_for_agents_not_confirmed_within_the_interval(world):
    now = datetime.now(UTC)
    old = now - timedelta(days=100)
    await put(
        world,
        agent_row("AGT-OLD-0001", "Old-Unattested", created_at=old),
        agent_row("AGT-OLD-0002", "Old-Attested", created_at=old),
        agent_row("AGT-NEW-0003", "New-One", created_at=now),
        agent_row("AGT-OLD-0004", "Old-Suspended", created_at=old, status=AgentStatus.SUSPENDED),
        agent_row("AGT-OLD-0005", "Old-Already-Due", created_at=old, attestation_due=now + timedelta(days=3)),
    )
    # a recent confirmation, recorded in the ledger, counts as much as being new
    assert (await world.api("niels.vandijk", "POST", "/v1/agents/AGT-OLD-0002/attest")).status_code == 200

    result = await ownership.scheduled_cycle(world.ctx, now)
    assert result == {"opened": ["AGT-OLD-0001"], "flagged": [], "suspended": []}
    opened = await get(world, "AGT-OLD-0001")
    assert 13 < (opened.attestation_due.replace(tzinfo=UTC) - now).total_seconds() / 86400 <= 14
    assert (await get(world, "AGT-OLD-0005")).attestation_due.replace(tzinfo=UTC) < now + timedelta(days=4)
    (entry,) = await events(world, "attestation.scheduled")
    assert entry.actor == ownership.SCHEDULER and entry.payload["agents"] == ["AGT-OLD-0001"]

    again = await ownership.scheduled_cycle(world.ctx, now)  # nothing new is due, and nothing is written twice
    assert again["opened"] == [] and len(await events(world, "attestation.scheduled")) == 1

    later = await ownership.scheduled_cycle(world.ctx, now + timedelta(days=91))  # a quarter on, everyone is due
    assert {"AGT-OLD-0002", "AGT-NEW-0003", world.agent_ids["ava"]} <= set(later["opened"])
    assert not {"AGT-OLD-0004", "AGT-OLD-0005", "AGT-OLD-0001"} & set(later["opened"])


async def test_an_interval_of_zero_turns_the_schedule_off(world):
    world.ctx.settings.attestation_interval_days = 0
    await put(world, agent_row("AGT-OLD-0001", "Old-Unattested", created_at=datetime.now(UTC) - timedelta(days=500)))
    assert (await ownership.scheduled_cycle(world.ctx))["opened"] == []


async def test_overdue_agents_raise_one_alert_per_due_date_and_are_suspended_only_when_configured(world):
    now = datetime.now(UTC)
    await put(world, agent_row("AGT-DUE-0001", "Overdue-One", attestation_due=now - timedelta(days=1)))

    first = await ownership.scheduled_cycle(world.ctx, now)
    assert first == {"opened": [], "flagged": ["AGT-DUE-0001"], "suspended": []}
    (alert,) = await alerts(world, ownership.OVERDUE_RULE)
    assert alert.agent_id == "AGT-DUE-0001" and alert.severity == "medium"
    assert "Overdue-One" in alert.title and "niels.vandijk" in alert.title
    assert (await get(world, "AGT-DUE-0001")).status == AgentStatus.ACTIVE  # a person decides, nothing is stopped

    assert (await ownership.scheduled_cycle(world.ctx, now))["flagged"] == []  # no repeat for the same due date
    assert len(await alerts(world, ownership.OVERDUE_RULE)) == 1
    await edit(world, "AGT-DUE-0001", attestation_due=now - timedelta(hours=2))  # a new due date alerts again
    assert (await ownership.scheduled_cycle(world.ctx, now))["flagged"] == ["AGT-DUE-0001"]
    assert len(await alerts(world, ownership.OVERDUE_RULE)) == 2

    world.ctx.settings.attestation_auto_enforce = True
    stopped = await ownership.scheduled_cycle(world.ctx, now)
    assert stopped["suspended"] == ["AGT-DUE-0001"]
    assert (await get(world, "AGT-DUE-0001")).status == AgentStatus.SUSPENDED
    (event,) = [e for e in await events(world, "agent.suspended") if e.subject == "AGT-DUE-0001"]
    assert event.actor == ownership.SCHEDULER and event.payload["reason"] == "attestation overdue"
    assert (await ownership.scheduled_cycle(world.ctx, now))["suspended"] == []  # a suspended agent is not re-enforced


async def test_a_manual_run_is_limited_to_risk_and_admin_and_credits_the_person(world):
    now = datetime.now(UTC)
    await put(
        world,
        agent_row("AGT-DUE-0001", "Overdue-One", attestation_due=now - timedelta(days=1)),
        agent_row("AGT-OLD-0002", "Old-Unattested", created_at=now - timedelta(days=100)),
    )
    assert (await world.api("niels.vandijk", "POST", "/v1/attestations/run")).status_code == 403
    assert (await world.api("mark.jansen", "POST", "/v1/attestations/run")).status_code == 403
    ran = await world.api("sanne.bakker", "POST", "/v1/attestations/run")
    assert ran.status_code == 200
    assert ran.json() == {"opened": ["AGT-OLD-0002"], "flagged": ["AGT-DUE-0001"], "suspended": []}
    (entry,) = await events(world, "attestation.scheduled")
    assert entry.actor == "user:sanne.bakker"
    assert (await get(world, "AGT-DUE-0001")).status == AgentStatus.ACTIVE  # auto-enforce is off


async def test_the_scheduler_loop_does_its_work_and_survives_a_failed_pass(world, monkeypatch):
    world.ctx.settings.attestation_check_seconds = 1
    await put(world, agent_row("AGT-OLD-0001", "Old-Unattested", created_at=datetime.now(UTC) - timedelta(days=100)))
    real, calls = ownership.scheduled_cycle, []

    async def flaky(c, now=None, actor=ownership.SCHEDULER):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("the database blinked")
        return await real(c, now, actor)

    monkeypatch.setattr(ownership, "scheduled_cycle", flaky)
    task = asyncio.create_task(ownership.run_scheduler(world.ctx, first_delay=0.01))
    try:
        for _ in range(80):
            await asyncio.sleep(0.1)
            if (await get(world, "AGT-OLD-0001")).attestation_due is not None:
                break
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert len(calls) >= 2 and (await get(world, "AGT-OLD-0001")).attestation_due is not None
    assert task.cancelled() or task.done()


async def test_the_scheduler_runs_with_a_persistent_database_and_stops_with_the_app(tmp_path):
    url = f"sqlite+aiosqlite:///{(tmp_path / 'aegis.db').as_posix()}"
    app = create_app(Settings(database_url=url), httpx.AsyncClient())
    async with app.router.lifespan_context(app):
        task = app.state.ctx.attestation_task
        assert task is not None and not task.done()
        async with app.state.ctx.db.sessionmaker() as s:
            assert (await ownership.status(app.state.ctx, s))["scheduler_running"] is True
    assert task.done()

    off = create_app(Settings(database_url=url, attestation_interval_days=0), httpx.AsyncClient())
    async with off.router.lifespan_context(off):
        assert off.state.ctx.attestation_task is None  # no interval and no auto-enforce: nothing to run

    enforcing = create_app(Settings(database_url=url, attestation_interval_days=0, attestation_auto_enforce=True),
                           httpx.AsyncClient())
    async with enforcing.router.lifespan_context(enforcing):
        assert enforcing.state.ctx.attestation_task is not None


def test_the_schedule_settings_are_validated_and_read_from_the_environment(monkeypatch):
    defaults = Settings()
    assert (defaults.attestation_interval_days, defaults.attestation_grace_days) == (90, 14)
    assert defaults.attestation_auto_enforce is False and defaults.attestation_check_seconds == 3600
    for bad in ({"attestation_interval_days": -1}, {"attestation_grace_days": 0}, {"attestation_check_seconds": 0}):
        with pytest.raises(ValidationError):
            Settings(**bad)
    monkeypatch.setenv("AEGIS_ATTESTATION_INTERVAL_DAYS", "30")
    monkeypatch.setenv("AEGIS_ATTESTATION_AUTO_ENFORCE", "true")
    loaded = Settings.from_env()
    assert loaded.attestation_interval_days == 30 and loaded.attestation_auto_enforce is True
