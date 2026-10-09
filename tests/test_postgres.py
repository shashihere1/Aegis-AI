"""Opt-in real PostgreSQL integration; a unique test schema never touches demo data.

PowerShell: $env:AEGIS_TEST_POSTGRES='1'; python -m pytest tests/test_postgres.py -q
"""

import asyncio
import os
import re
import uuid

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from aegis.common.settings import Settings
from aegis.control import ledger
from aegis.control.db import Database
from aegis.control.evidence_verify import verify_pack
from aegis.control.tables import Agent, DecisionRecord, PolicyVersion, TraceSpan
from aegis_demo.testing import BASE, FAKE_LLM_URL, running_world

pytestmark = pytest.mark.skipif(os.getenv("AEGIS_TEST_POSTGRES") != "1", reason="Opt-in real PostgreSQL test")


async def test_postgres_restart_policy_cases_keys_concurrency_and_evidence(tmp_path):
    settings = Settings.from_env()
    assert settings.database_url.startswith("postgresql+asyncpg://")
    schema = "aegis_test_" + uuid.uuid4().hex
    assert re.fullmatch(r"aegis_test_[a-f0-9]{32}", schema)
    admin = Database(settings.database_url)
    async with admin.engine.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    options = settings.model_dump() | {
        "control_url": BASE,
        "gateway_url": f"{BASE}/gw",
        "cache_seconds": 0,
        "database_schema": schema,
        "signing_key_path": str(tmp_path / "sts.pem"),
        "idp_key_path": str(tmp_path / "idp.pem"),
        "identity_state_dir": str(tmp_path / "identities"),
        "llm_upstream_url": FAKE_LLM_URL,
    }
    try:
        async with running_world(**options) as world:
            assert (await world.http.get(f"{BASE}/health")).json()["database"] == "postgresql"
            initial = (await world.api("priya.raman", "GET", "/v1/policies")).json()
            config = initial["data"]
            config["thresholds"]["payments"]["hitl_amount_eur"] = 2000
            policy = (
                await world.api(
                    "priya.raman",
                    "POST",
                    "/v1/policies/versions",
                    json={
                        "name": "PostgreSQL persistent policy",
                        "justification": "Integration test independent review",
                        "configuration": config,
                    },
                )
            ).json()
            vid = policy["id"]
            for action, user, body in [
                ("replay", "priya.raman", {}),
                ("submit", "priya.raman", {}),
                ("approve", "fatima.elamrani", {"justification": "Independent review"}),
                (
                    "activate",
                    "fatima.elamrani",
                    {"justification": "Activate persistent version", "expected_active_version": initial["version"]},
                ),
            ]:
                response = await world.api(user, "POST", f"/v1/policies/{vid}/{action}", json=body)
                assert response.status_code == 200, response.text
            run = (await world.http.post(f"{BASE}/demo/api/scenarios/policy-transfer", json={})).json()
            assert run["status"] == "waiting", run
            approval_id = run["links"]["approval_id"]
            assert (
                await world.api(
                    "sanne.bakker",
                    "POST",
                    f"/v1/approvals/{approval_id}/approve",
                    json={
                        "justification": "Approved test transfer",
                    },
                )
            ).status_code == 200
            for _ in range(60):
                if (await world.http.get(f"{BASE}/demo/api/runs")).json()[0]["status"] == "completed":
                    break
                await asyncio.sleep(0.1)
            assert (await world.http.get(f"{BASE}/demo/api/runs")).json()[0]["status"] == "completed"
            await world.http.post(f"{BASE}/demo/api/scenarios/attack", json={})
            alert = (await world.api("mark.jansen", "GET", "/v1/alerts")).json()[0]
            assert (
                await world.api(
                    "mark.jansen",
                    "PATCH",
                    f"/v1/alerts/{alert['id']}/case",
                    json={
                        "assigned_to": "mark.jansen",
                        "note": "Persisted investigation",
                        "status": "investigating",
                    },
                )
            ).status_code == 200
            ids = dict(world.agent_ids)
            public_key = world.ctx.sts_key.public_pem

            async def concurrent_append(n):
                async with world.ctx.db.sessionmaker() as s:
                    await ledger.append(s, "test.concurrent", "integration", str(n), {"first": True})
                    await asyncio.sleep(0.01)
                    await ledger.append(s, "test.concurrent", "integration", str(n), {"second": True})
                    await s.commit()

            await asyncio.wait_for(asyncio.gather(*(concurrent_append(n) for n in range(8))), timeout=20)
            assert (await world.api("eva.visser", "GET", "/v1/ledger/verify")).json()["ok"]
            async with world.ctx.db.sessionmaker() as s:
                with pytest.raises(DBAPIError, match="append-only"):
                    await s.execute(text("UPDATE ledger_entries SET actor='tampered' WHERE seq=1"))
                await s.rollback()
            await world.ctx.telemetry.flush()
            async with world.ctx.db.sessionmaker() as s:
                decision_count = await s.scalar(select(func.count()).select_from(DecisionRecord))
                span_count = await s.scalar(select(func.count()).select_from(TraceSpan))

        # A second service lifetime uses the same real database, signing keys and disabled identities.
        async with running_world(**options) as world:
            assert world.agent_ids == ids and world.ctx.sts_key.public_pem == public_key
            assert (await world.api("mark.jansen", "GET", "/v1/policies")).json()["version"] == vid
            case = (await world.api("eva.visser", "GET", f"/v1/alerts/{alert['id']}/case")).json()
            assert (
                case["status"] == "investigating" and case["events"][0]["detail"]["note"] == "Persisted investigation"
            )
            async with world.ctx.db.sessionmaker() as s:
                assert await s.scalar(select(func.count()).select_from(Agent)) == 3
                assert await s.scalar(select(func.count()).select_from(PolicyVersion)) == 2
                assert await s.scalar(select(func.count()).select_from(DecisionRecord)) == decision_count
                assert await s.scalar(select(func.count()).select_from(TraceSpan)) >= span_count
            ava = (await world.api("mark.jansen", "GET", f"/v1/agents/{ids['ava']}")).json()
            assert ava["status"] == "suspended" and not world.ctx.idp.clients[ava["idp_client_id"]].enabled
            run = (await world.http.post(f"{BASE}/demo/api/scenarios/policy-transfer", json={})).json()
            assert run["status"] == "blocked"  # restart must not silently resume an unsafe identity
            pack = await world.api("eva.visser", "GET", "/v1/evidence/pack")
            assert pack.status_code == 200 and verify_pack(pack.content)["ok"]
    finally:
        # Only this verified UUID namespace, created by this test, is removed. Never drop the database.
        assert re.fullmatch(r"aegis_test_[a-f0-9]{32}", schema)
        async with admin.engine.begin() as conn:
            exists = await conn.scalar(text("SELECT 1 FROM pg_namespace WHERE nspname=:schema"), {"schema": schema})
            if exists:
                await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.engine.dispose()
