"""Tamper-evident evidence ledger: every entry hashes the previous one (plan §8.12)."""

import asyncio
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.hashing import sha256_hex
from aegis.control.tables import LedgerEntry

GENESIS = "0" * 64

# Single writer per process. In PostgreSQL deployments use pg_advisory_xact_lock instead.
_append_lock = asyncio.Lock()


def entry_hash(prev_hash: str, ts: str, event_type: str, actor: str, subject: str, payload: dict) -> str:
    return sha256_hex(
        {"prev": prev_hash, "ts": ts, "type": event_type, "actor": actor, "subject": subject, "payload": payload}
    )


async def append(session: AsyncSession, event_type: str, actor: str, subject: str, payload: dict) -> LedgerEntry:
    """Add an entry to the session; the caller commits it together with the change it records."""
    async with _append_lock:
        last = (
            await session.execute(select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(1))
        ).scalar_one_or_none()
        prev = last.entry_hash if last else GENESIS
        ts = datetime.now(UTC).isoformat()
        entry = LedgerEntry(
            ts=ts,
            event_type=event_type,
            actor=actor,
            subject=subject,
            payload=payload,
            prev_hash=prev,
            entry_hash=entry_hash(prev, ts, event_type, actor, subject, payload),
        )
        session.add(entry)
        await session.flush()
        return entry


def verify_entries(entries: list[LedgerEntry]) -> dict:
    """Verify exactly the entries that will be exported, not a second database read."""
    prev = GENESIS
    for e in entries:
        expected = entry_hash(prev, e.ts, e.event_type, e.actor, e.subject, e.payload)
        if e.prev_hash != prev or e.entry_hash != expected:
            return {"ok": False, "entries": len(entries), "broken_at_seq": e.seq}
        prev = e.entry_hash
    return {"ok": True, "entries": len(entries), "tip": prev}


async def verify(session: AsyncSession) -> dict:
    entries = (await session.execute(select(LedgerEntry).order_by(LedgerEntry.seq))).scalars().all()
    return verify_entries(entries)
