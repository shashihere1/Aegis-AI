from aegis.control import ledger
from aegis.control.db import Database
from aegis.control.tables import LedgerEntry


async def test_hash_chain_detects_tampering():
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.create_all()
    async with db.sessionmaker() as s:
        for i in range(5):
            await ledger.append(s, "test.event", "tester", f"subject-{i}", {"n": i})
        await s.commit()
        assert (await ledger.verify(s)) | {"tip": None} == {"ok": True, "entries": 5, "tip": None}

        entry = await s.get(LedgerEntry, 3)
        entry.payload = {"n": 999}  # an insider edits evidence
        await s.commit()
        assert await ledger.verify(s) == {"ok": False, "entries": 5, "broken_at_seq": 3}
