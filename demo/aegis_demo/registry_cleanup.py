"""Targeted, recoverable removal of unused generated inventory. Never resets a database."""

import argparse
import asyncio
import json
from datetime import datetime

from sqlalchemy import DateTime, select

from aegis.common.ids import new_id
from aegis.common.settings import Settings
from aegis.control import ledger
from aegis.control.bank_tables import RegistrySeedArchive
from aegis.control.db import Database
from aegis.control.tables import Agent, Approval, DecisionRecord, Mandate
from aegis_demo.bank import digest


async def cleanup(db, *, apply=False):
    if apply:
        async with db.engine.begin() as connection:
            await connection.run_sync(lambda c: RegistrySeedArchive.__table__.create(c, checkfirst=True))
    async with db.sessionmaker() as s, s.begin():
        referenced = set()
        for model in (Mandate, Approval, DecisionRecord):
            referenced.update((await s.scalars(select(model.agent_id))).all())
        all_agents = (await s.scalars(select(Agent))).all()
        for agent in all_agents:
            referenced.update(agent.can_delegate_to or [])
            referenced.update(agent.can_receive_from or [])
        seeded = (await s.scalars(select(Agent).where(Agent.registered_by == "seed").with_for_update())).all()
        targets = [
            a
            for a in seeded
            if a.purpose == "Synthetic registry entry for scale testing."
            and not a.idp_client_id
            and not a.capabilities
            and not a.can_delegate_to
            and not a.can_receive_from
            and not a.last_active_at
            and a.id not in referenced
        ]
        batch = new_id("seed")
        if apply and targets:
            for agent in targets:
                snapshot = {c.name: getattr(agent, c.name) for c in Agent.__table__.columns}
                snapshot = {k: v.isoformat() if isinstance(v, datetime) else v for k, v in snapshot.items()}
                s.add(RegistrySeedArchive(agent_id=agent.id, batch_id=batch, snapshot=snapshot))
                await s.delete(agent)
            await ledger.append(
                s,
                "registry.seed_inventory_removed",
                "system:seed-cleanup",
                batch,
                {
                    "count": len(targets),
                    "agent_ids_hash": digest(sorted(a.id for a in targets)),
                    "selection": (
                        "registered_by=seed; original scale-test purpose; no credentials or activity references"
                    ),
                    "recovery_table": "registry_seed_archive",
                },
            )
        return {
            "applied": apply,
            "eligible": len(targets),
            "removed": len(targets) if apply else 0,
            "protected_seed_records": len(seeded) - len(targets),
            "remaining_registry_agents": len(all_agents) - (len(targets) if apply else 0),
            "batch_id": batch if apply and targets else None,
            "recovery": "Archived snapshots in registry_seed_archive; use --restore-batch <batch_id>.",
        }


async def restore(db, batch):
    count = 0
    async with db.sessionmaker() as s, s.begin():
        rows = (await s.scalars(select(RegistrySeedArchive).where(RegistrySeedArchive.batch_id == batch))).all()
        for row in rows:
            if await s.get(Agent, row.agent_id) is not None:
                continue
            if await s.scalar(select(Agent.id).where(Agent.name == row.snapshot["name"])):
                continue
            values = dict(row.snapshot)
            for col in Agent.__table__.columns:
                if isinstance(col.type, DateTime) and values[col.name] is not None:
                    values[col.name] = datetime.fromisoformat(values[col.name])
            s.add(Agent(**values))
            count += 1
        if count:
            await ledger.append(s, "registry.seed_inventory_restored", "system:seed-cleanup", batch, {"count": count})
    return {"restored": count, "batch_id": batch}


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--restore-batch")
    args = parser.parse_args()
    settings = Settings.from_env()
    db = Database(settings.database_url, settings.database_schema)
    try:
        result = await restore(db, args.restore_batch) if args.restore_batch else await cleanup(db, apply=args.apply)
        print(json.dumps(result, indent=2))
    finally:
        await db.engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
