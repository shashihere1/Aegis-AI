"""Policy-fingerprint width regression. PostgreSQL verification uses only its own UUID namespace."""

import os
import re
import uuid

import pytest
from sqlalchemy import MetaData, String, inspect, text

from aegis.common.hashing import sha256_hex
from aegis.common.settings import Settings
from aegis.control.db import Database
from aegis.control.tables import DecisionRecord, LlmReservation


def test_policy_fingerprint_fits_all_receipt_columns():
    fingerprint = sha256_hex({"engine": "python-model-controls", "deployment": "offline"})
    assert len(fingerprint) == 64
    for table in (DecisionRecord.__table__, LlmReservation.__table__):
        assert table.c.policy_version.type.length >= len(fingerprint)


@pytest.mark.skipif(os.getenv("AEGIS_TEST_POSTGRES") != "1", reason="Opt-in real PostgreSQL regression")
async def test_postgres_upgrades_legacy_receipt_width_without_losing_rows():
    settings = Settings.from_env()
    assert settings.database_url.startswith("postgresql+asyncpg://")
    schema = "aegis_width_test_" + uuid.uuid4().hex
    assert re.fullmatch(r"aegis_width_test_[a-f0-9]{32}", schema)
    admin = Database(settings.database_url)
    db = Database(settings.database_url, schema)
    created = False
    try:
        async with admin.engine.begin() as conn:
            await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
            created = True
        # Reproduce an existing database's old 40-character column, not merely a fresh 64-character schema.
        legacy_metadata = MetaData()
        legacy = DecisionRecord.__table__.to_metadata(legacy_metadata)
        legacy.c.policy_version.type = String(40)
        async with db.engine.begin() as conn:
            await conn.run_sync(legacy_metadata.create_all)
        async with db.sessionmaker() as s:
            s.add(DecisionRecord(id="legacy_receipt", action="offline.read", decision="allow", policy_version="old"))
            await s.commit()
        await db.create_all()
        await db.upgrade_schema()  # Repeating the upgrade must be safe.
        async with db.engine.connect() as conn:
            columns = await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_columns("decisions"))
            assert next(c["type"].length for c in columns if c["name"] == "policy_version") == 64
        fingerprint = sha256_hex({"engine": "python-model-controls", "deployment": "offline"})
        async with db.sessionmaker() as s:
            assert (await s.get(DecisionRecord, "legacy_receipt")).policy_version == "old"
            s.add(DecisionRecord(id="model_receipt", action="llm.chat", decision="allow", policy_version=fingerprint))
            await s.commit()
        async with db.sessionmaker() as s:
            assert (await s.get(DecisionRecord, "model_receipt")).policy_version == fingerprint
            assert (await s.get(DecisionRecord, "legacy_receipt")).policy_version == "old"
    finally:
        await db.engine.dispose()
        # Only remove this test's explicitly created, validated namespace. Never remove app data.
        if created:
            assert re.fullmatch(r"aegis_width_test_[a-f0-9]{32}", schema)
            async with admin.engine.begin() as conn:
                await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.engine.dispose()
