"""Agent ownership: who may act on an agent, hand-over when an owner leaves, and the re-attestation schedule (§8.2).

An owner must periodically confirm that an agent is still needed, correctly scoped and theirs. A confirmation is the
ledger entry `attestation.confirmed`, so "when was this last attested" is provable from the tamper-evident ledger and
needs no extra state. An agent becomes due when its last confirmation (or its activation) is older than the configured
interval; it is overdue once its due date has passed.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.models import AgentStatus
from aegis.control import ledger
from aegis.control.context import ControlContext
from aegis.control.identity import sts
from aegis.control.identity.idp import Persona
from aegis.control.soc import raise_alert
from aegis.control.tables import Agent, Alert, LedgerEntry

log = logging.getLogger("aegis.control.ownership")

SCHEDULER = "system:scheduler"
OVERDUE_RULE = "DET-14"
ORPHANED_RULE = "DET-12"
# An agent's last "ownership was confirmed" moments: the owner's attestation, or the agent (re)entering service.
CONFIRMING_EVENTS = ("attestation.confirmed", "agent.active")
FIRST_RUN_DELAY_SECONDS = 60.0


def aware(value: datetime) -> datetime:
    """SQLite returns naive timestamps; every timestamp in this module is UTC."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class Reassign(BaseModel):
    new_owner: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=5, max_length=500)


async def require_management_rights(
    c: ControlContext,
    s: AsyncSession,
    user: Persona,
    agent: Agent,
    action: str,
    *,
    any_agent_roles: tuple[str, ...] = (),
    registrant_may: bool = False,
) -> None:
    """Only the agent's owner (the person, under any of their accounts) may act on it, unless the caller holds a
    role that governs every agent. Holding the `agent-owner` role alone grants nothing over other people's agents."""
    if set(any_agent_roles) & set(user.roles):
        return
    if await c.people.same_person(s, user, agent.owner):
        return
    if registrant_may and await c.people.same_person(s, user, agent.registered_by):
        return
    raise HTTPException(403, f"OWN-001: only the owner of this agent can {action}")


# ---- hand-over ----


async def reassign_owner(
    c: ControlContext, s: AsyncSession, user: Persona, agent: Agent, new_owner: str, reason: str
) -> Agent:
    """Hand an agent to a new owner, typically because the old one left. The caller commits."""
    new_owner = new_owner.strip()
    if not new_owner:
        raise HTTPException(422, "the new owner is required")
    # The current owner may hand their own agent over; risk and platform administration can do it for a leaver.
    await require_management_rights(c, s, user, agent, "reassign it", any_agent_roles=("admin", "risk-approver"))
    if agent.status == AgentStatus.RETIRED:
        raise HTTPException(409, "a retired agent has no owner to change")
    if await c.people.same_people(s, agent.owner, new_owner):
        raise HTTPException(409, "this person already owns the agent")
    if c.people.has_left(new_owner):
        raise HTTPException(409, f"{new_owner} has left the bank and cannot own an agent")
    if await c.people.same_person(s, user, new_owner) and not await c.people.same_person(s, user, agent.owner):
        raise HTTPException(
            403, "SOD-004: you cannot make yourself the owner of an agent; another administrator must do it"
        )
    previous, was_orphaned, now = agent.owner, agent.orphaned, datetime.now(UTC)
    agent.owner, agent.orphaned = new_owner, False
    # The new owner starts accountable: they must confirm what they inherited within the grace period.
    agent.attestation_due = (
        now + timedelta(days=c.settings.attestation_grace_days) if agent.status == AgentStatus.ACTIVE else None
    )
    await ledger.append(
        s,
        "agent.owner_reassigned",
        f"user:{user.username}",
        agent.id,
        {"from": previous, "to": new_owner, "reason": reason, "was_orphaned": was_orphaned},
    )
    stale = (await s.execute(select(Alert).where(Alert.rule_id == ORPHANED_RULE, Alert.agent_id == agent.id))).scalars()
    for alert in stale:
        alert.actions_taken = [*alert.actions_taken, {"action": "owner_reassigned", "from": previous, "to": new_owner}]
    return agent


# ---- schedule ----


async def last_confirmed(s: AsyncSession) -> dict[str, datetime]:
    """Agent id -> when its ownership was last confirmed, from the ledger."""
    rows = (
        await s.execute(
            select(LedgerEntry.subject, func.max(LedgerEntry.ts))
            .where(LedgerEntry.event_type.in_(CONFIRMING_EVENTS))
            .group_by(LedgerEntry.subject)
        )
    ).all()
    return {subject: aware(datetime.fromisoformat(ts)) for subject, ts in rows}


async def open_due_campaigns(c: ControlContext, s: AsyncSession, now: datetime, actor: str = SCHEDULER) -> list[Agent]:
    """Mark every active agent whose last confirmation is older than the interval as due, with the grace period."""
    days = c.settings.attestation_interval_days
    if days <= 0:
        return []
    cutoff, due = now - timedelta(days=days), now + timedelta(days=c.settings.attestation_grace_days)
    confirmed = await last_confirmed(s)
    candidates = (
        await s.execute(select(Agent).where(Agent.status == AgentStatus.ACTIVE, Agent.attestation_due.is_(None)))
    ).scalars()
    opened = []
    for agent in candidates:
        since = max(confirmed.get(agent.id, aware(agent.created_at)), aware(agent.created_at))
        if since <= cutoff:
            agent.attestation_due = due
            opened.append(agent)
    if opened:
        await ledger.append(
            s,
            "attestation.scheduled",
            actor,
            "scheduled",
            {"agents": sorted(a.id for a in opened), "due": due.isoformat(), "interval_days": days},
        )
    return opened


async def overdue_agents(s: AsyncSession, now: datetime) -> list[Agent]:
    rows = (
        await s.execute(select(Agent).where(Agent.status == AgentStatus.ACTIVE, Agent.attestation_due.is_not(None)))
    ).scalars()
    return [a for a in rows if aware(a.attestation_due) <= now]


async def enforce_overdue(c: ControlContext, s: AsyncSession, actor: str, now: datetime | None = None) -> list[Agent]:
    """Suspend every overdue agent: an owner who does not confirm cannot leave an agent running unattended."""
    overdue = await overdue_agents(s, now or datetime.now(UTC))
    for agent in overdue:
        await sts.suspend_agent(c, s, agent.id, "attestation overdue", actor)
    return overdue


async def flag_overdue(c: ControlContext, s: AsyncSession, now: datetime) -> list[Agent]:
    """Raise one alert per overdue agent and due date, so a person is told even when nothing is suspended."""
    overdue = await overdue_agents(s, now)
    if not overdue:
        return []
    known = {
        (a.agent_id, (a.evidence or {}).get("due"))
        for a in (await s.execute(select(Alert).where(Alert.rule_id == OVERDUE_RULE))).scalars()
    }
    flagged = []
    for agent in overdue:
        due = aware(agent.attestation_due).astimezone(UTC).isoformat()
        if (agent.id, due) in known:
            continue
        await raise_alert(
            c,
            s,
            OVERDUE_RULE,
            "medium",
            f"Attestation overdue: {agent.name} (owner {agent.owner})",
            agent.id,
            {"owner": agent.owner, "due": due, "orphaned": agent.orphaned},
        )
        flagged.append(agent)
    return flagged


async def scheduled_cycle(c: ControlContext, now: datetime | None = None, actor: str = SCHEDULER) -> dict:
    """One scheduler pass: open campaigns that are due, alert on overdue agents, and (if configured) suspend them."""
    now = now or datetime.now(UTC)
    async with c.db.sessionmaker() as s:
        opened = await open_due_campaigns(c, s, now, actor)
        flagged = await flag_overdue(c, s, now)
        suspended = await enforce_overdue(c, s, actor, now) if c.settings.attestation_auto_enforce else []
        await s.commit()
    return {
        "opened": sorted(a.id for a in opened),
        "flagged": sorted(a.id for a in flagged),
        "suspended": sorted(a.id for a in suspended),
    }


async def run_scheduler(c: ControlContext, first_delay: float = FIRST_RUN_DELAY_SECONDS) -> None:
    """Run `scheduled_cycle` for the life of the control plane. A failed pass is logged and tried again later."""
    delay = first_delay
    while True:
        await asyncio.sleep(delay)
        delay = c.settings.attestation_check_seconds
        try:
            result = await scheduled_cycle(c)
        except Exception:
            log.exception("attestation schedule pass failed; trying again in %s seconds", delay)
            continue
        if any(result.values()):
            log.info("attestation schedule: %s", result)


async def status(c: ControlContext, s: AsyncSession, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    agents = (await s.execute(select(Agent).where(Agent.status == AgentStatus.ACTIVE))).scalars().all()
    due = [aware(a.attestation_due) for a in agents if a.attestation_due is not None]
    task = c.attestation_task
    return {
        "interval_days": c.settings.attestation_interval_days,
        "grace_days": c.settings.attestation_grace_days,
        "auto_enforce": c.settings.attestation_auto_enforce,
        "scheduler_running": task is not None and not task.done(),
        "active_agents": len(agents),
        "due": len(due),
        "overdue": sum(1 for d in due if d <= now),
        "orphaned": sum(1 for a in agents if a.orphaned),
        "next_due": min(due).isoformat() if due else None,
    }
