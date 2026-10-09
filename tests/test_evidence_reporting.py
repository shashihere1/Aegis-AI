"""Real evidence generation, privacy, pinned signatures and durable schedules; no paid inference."""

import asyncio
import csv
import hashlib
import io
import json
import os
import re
import uuid
import zipfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from aegis.common.crypto import SigningKey
from aegis.common.settings import Settings
from aegis.control import attestation, evidence_reports, ledger
from aegis.control.db import Database
from aegis.control.evidence_proofs import inclusion_proofs
from aegis.control.evidence_verify import verify_pack
from aegis.control.tables import (
    Alert,
    CaseEvent,
    DecisionRecord,
    EvidenceReport,
    LedgerCheckpoint,
    LedgerEntry,
    Mandate,
    Usage,
)
from aegis_demo.testing import FAKE_LLM_URL, running_world


def contents(body):
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def json_member(body, name):
    return json.loads(contents(body)[name])


def archive_bytes(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()


def resign_manifest(files, key, manifest):
    files["manifest.json"] = json.dumps(manifest).encode()
    files["signature.jws"] = attestation.sign(
        key,
        {
            "typ": attestation.PACK,
            "manifest_sha256": hashlib.sha256(files["manifest.json"]).hexdigest(),
        },
    ).encode()
    return archive_bytes(files)


async def test_legacy_full_chain_v2_pack_still_verifies(world):
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    files = contents(response.content)
    manifest = json.loads(files["manifest.json"])
    entries = json.loads(files["records/ledger.json"])
    assert len(entries) == manifest["ledger"]["entries"]  # default scope includes this entire fresh test world
    manifest["format"] = "aegis-demo-evidence-pack-v2"
    manifest["ledger"] = {"ok": True, "entries": len(entries), "tip": entries[-1]["entry_hash"]}
    verified = verify_pack(resign_manifest(files, world.ctx.evidence_key, manifest), world.ctx.evidence_key.fingerprint)
    assert verified["ok"] and verified["entries"] == len(entries)
    assert "proof_mode" not in verified


async def test_csv_preserves_zero_and_neutralizes_spreadsheet_formulas(world):
    async with world.ctx.db.sessionmaker() as s:
        s.add(
            Usage(
                agent_id=world.agent_ids["ava"],
                model='=HYPERLINK("malicious")',
                input_tokens=0,
                output_tokens=0,
                cost_eur=0.0,
                latency_ms=0.0,
            )
        )
        await s.commit()
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    files = contents(response.content)
    rows = list(csv.DictReader(io.StringIO(files["csv/usage.csv"].decode())))
    assert rows[0]["input_tokens"] == "0" and rows[0]["cost_eur"] == "0.0"
    assert rows[0]["model"].startswith("'=HYPERLINK")
    assert json.loads(files["records/usage.json"])[0]["model"].startswith("=HYPERLINK")


async def test_recomputed_source_hashes_cannot_override_a_prior_checkpoint(world):
    assert (await world.api("eva.visser", "GET", "/v1/evidence/pack")).status_code == 200
    async with world.ctx.db.sessionmaker() as s:
        entries = (await s.scalars(select(LedgerEntry).order_by(LedgerEntry.seq))).all()
        entries[0].payload = {"rewritten": True}
        previous = ledger.GENESIS
        for entry in entries:
            entry.prev_hash = previous
            entry.entry_hash = ledger.entry_hash(
                previous, entry.ts, entry.event_type, entry.actor, entry.subject, entry.payload
            )
            previous = entry.entry_hash
        await s.commit()
    assert (await world.api("eva.visser", "GET", "/v1/evidence/pack")).status_code == 409


async def test_bad_prior_checkpoint_signature_refuses_new_report(world):
    assert (await world.api("eva.visser", "GET", "/v1/evidence/pack")).status_code == 200
    async with world.ctx.db.sessionmaker() as s:
        checkpoint = await s.scalar(select(LedgerCheckpoint).limit(1))
        checkpoint.jws = "malformed.checkpoint.signature"
        await s.commit()
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    assert response.status_code == 409


async def test_control_queries_do_not_treat_generic_logs_as_attestation_evidence(world):
    preview = (await world.api("eva.visser", "GET", "/v1/evidence/summary")).json()
    before = next(c for c in preview["coverage"] if c["id"] == "AEG-C12")
    assert next(s for s in before["sources"] if s["file"] == "records/ledger.json")["count"] == 0
    async with world.ctx.db.sessionmaker() as s:
        row = await ledger.append(s, "attestation.confirmed", "owner", world.agent_ids["ava"], {})
        await s.commit()
        expected = row.seq
    preview = (await world.api("eva.visser", "GET", "/v1/evidence/summary")).json()
    after = next(c for c in preview["coverage"] if c["id"] == "AEG-C12")
    source = next(s for s in after["sources"] if s["file"] == "records/ledger.json")
    assert source["record_ids"] == [expected] and source["count"] == 1 and source["filters"]


async def test_new_reports_are_signed_scoped_saved_and_reviewable(world):
    response = await world.api("eva.visser", "POST", "/v1/evidence/reports", json={"framework": "dora"})
    assert response.status_code == 201, response.text
    meta = response.json()
    assert meta["status"] == "ready" and meta["summary"]["summary_method"] == "deterministic"
    downloaded = await world.api("eva.visser", "GET", f"/v1/evidence/reports/{meta['id']}/download")
    verified = verify_pack(downloaded.content, world.ctx.evidence_key.fingerprint)
    assert verified["key_pinned"] and verified["signatures_checked"]
    assert verified["proof_mode"] == "signed-merkle-inclusion" and not verified["full_chain_recomputed"]
    assert hashlib.sha256(downloaded.content).hexdigest() == meta["sha256"]
    preview = (await world.api("eva.visser", "GET", "/v1/evidence/summary")).json()
    assert preview["latest_checkpoint"]["id"] == json_member(downloaded.content, "manifest.json")["checkpoint_id"]
    files = contents(downloaded.content)
    assert {"csv/decisions.csv", "control_catalog.json", "control_coverage.json", "report.json"} <= files.keys()
    controls = json.loads(files["control_coverage.json"])
    assert controls and all(ref["framework"] == "dora" for c in controls for ref in c["references"])
    assert all(c["assessment"] == "human_review_required" for c in controls)
    assert (await world.api("eva.visser", "GET", "/v1/evidence/reports")).json()[0]["id"] == meta["id"]
    reviewed = await world.api(
        "eva.visser",
        "POST",
        f"/v1/evidence/reports/{meta['id']}/review",
        json={"note": "Reviewed source evidence and known gaps."},
    )
    assert reviewed.status_code == 200 and reviewed.json()["reviewed_by"] == "eva.visser"
    assert (
        await world.api(
            "eva.visser",
            "POST",
            f"/v1/evidence/reports/{meta['id']}/review",
            json={"note": "A duplicate review must be refused."},
        )
    ).status_code == 409
    after = await world.api("eva.visser", "GET", f"/v1/evidence/reports/{meta['id']}/download")
    assert after.content == downloaded.content  # review never rewrites the signed ZIP


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", "/v1/evidence/controls", None),
        ("GET", "/v1/evidence/reports", None),
        ("POST", "/v1/evidence/reports", {}),
        ("GET", "/v1/evidence/schedules", None),
        ("POST", "/v1/evidence/schedules", {"name": "Do not allow", "scope": {}}),
        ("POST", "/v1/evidence/schedules/run", {}),
        ("GET", "/v1/evidence/reports/private/download", None),
        ("POST", "/v1/evidence/reports/private/review", {"note": "Unauthorized review"}),
    ],
)
async def test_report_features_require_auditor(world, method, path, body):
    assert (
        await world.api("mark.jansen", method, path, **({"json": body} if body is not None else {}))
    ).status_code == 403


async def test_agent_scope_omits_unrelated_payloads_but_keeps_valid_proofs(world):
    secret = "UNRELATED-CUSTOMER-SECRET-NEVER-EXPORT"
    async with world.ctx.db.sessionmaker() as s:
        s.add(
            Alert(
                id="alr-unrelated",
                rule_id="DET-99",
                severity="high",
                title=secret,
                agent_id=world.agent_ids["kyc-agent"],
                evidence={"private": secret},
            )
        )
        await ledger.append(s, "unrelated.test", "someone", world.agent_ids["kyc-agent"], {"private": secret})
        await ledger.append(s, "selected.test", "someone", world.agent_ids["ava"], {"selected": True})
        await s.commit()
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack", params={"agent_id": world.agent_ids["ava"]})
    assert response.status_code == 200, response.text
    files = contents(response.content)
    assert all(secret.encode() not in data for data in files.values())
    assert [a["id"] for a in json.loads(files["records/agents.json"])] == [world.agent_ids["ava"]]
    verified = verify_pack(response.content, world.ctx.evidence_key.fingerprint)
    assert verified["source_entries"] > verified["entries"] > 0


async def test_date_scope_does_not_export_out_of_period_ledger_payload(world):
    secret = "OLD-AUDIT-PAYLOAD-EXCLUDED"
    async with world.ctx.db.sessionmaker() as s:
        last = await s.scalar(select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(1))
        ts = "2001-01-01T00:00:00+00:00"
        payload = {"private": secret}
        s.add(
            LedgerEntry(
                ts=ts,
                event_type="old.test",
                actor="old",
                subject=world.agent_ids["ava"],
                payload=payload,
                prev_hash=last.entry_hash,
                entry_hash=ledger.entry_hash(last.entry_hash, ts, "old.test", "old", world.agent_ids["ava"], payload),
            )
        )
        await s.commit()
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    assert response.status_code == 200, response.text
    assert all(secret.encode() not in data for data in contents(response.content).values())
    assert verify_pack(response.content)["source_entries"] > verify_pack(response.content)["entries"]


@pytest.mark.parametrize(
    "body",
    [
        {"from": "2026-10-10", "to": "2026-10-01"},
        {"to": "9999-12-31"},
        {"framework": "invented-regulation"},
        {"unexpected": "reject"},
    ],
)
async def test_invalid_scopes_do_not_publish_reports(world, body):
    response = await world.api("eva.visser", "POST", "/v1/evidence/reports", json=body)
    assert response.status_code == 422, response.text
    assert not (await world.api("eva.visser", "GET", "/v1/evidence/reports")).json()


async def test_unknown_identifiers_and_ephemeral_schedules_fail_closed(world):
    for scope in ({"agent_id": "AGT-NOT-PRESENT"}, {"root_id": "mdt_not_present"}):
        assert (await world.api("eva.visser", "POST", "/v1/evidence/reports", json=scope)).status_code == 404
    assert (
        await world.api("eva.visser", "POST", "/v1/evidence/schedules", json={"name": "No ephemeral schedule"})
    ).status_code == 409


async def test_task_scope_preserves_ancestors_and_recent_case_events_without_other_task_data(world):
    now = datetime.now(UTC)
    old = now - timedelta(days=30)
    ava, kyc = world.agent_ids["ava"], world.agent_ids["kyc-agent"]
    async with world.ctx.db.sessionmaker() as s:
        for mid, root, agent, parent, issued in [
            ("mdt_scope_root", "mdt_scope_root", ava, None, old),
            ("mdt_scope_child", "mdt_scope_root", kyc, "mdt_scope_root", now),
            ("mdt_other_root", "mdt_other_root", ava, None, now),
        ]:
            s.add(
                Mandate(
                    id=mid,
                    root_id=root,
                    parent_id=parent,
                    agent_id=agent,
                    subject="user:jan.devries",
                    chain=[ava] if parent is None else [ava, kyc],
                    intent="Synthetic evidence test",
                    max_data_class="internal",
                    jti=uuid.uuid4().hex,
                    issued_at=issued,
                    expires_at=now + timedelta(minutes=5),
                    status="active",
                )
            )
        for did, mid, root, agent, marker in [
            ("dec_scope_child", "mdt_scope_child", "mdt_scope_root", kyc, "selected"),
            ("dec_other_root", "mdt_other_root", "mdt_other_root", ava, "OTHER-TASK-PRIVATE-INPUT"),
        ]:
            s.add(
                DecisionRecord(
                    id=did,
                    mandate_id=mid,
                    root_id=root,
                    agent_id=agent,
                    action="kyc.verify_document",
                    decision="allow",
                    input_snapshot={"marker": marker},
                )
            )
        s.add(
            Alert(
                id="alr_prior_context",
                rule_id="DET-99",
                severity="high",
                title="Prior task finding",
                agent_id=kyc,
                ts=old,
                evidence={"root_id": "mdt_scope_root"},
            )
        )
        s.add(
            CaseEvent(
                id="case_scope",
                alert_id="alr_prior_context",
                actor="analyst",
                kind="note",
                detail={"note": "Investigated during this period"},
            )
        )
        await ledger.append(
            s, "other.task", "user:jan.devries", "mdt_other_root", {"private": "OTHER-TASK-PRIVATE-INPUT"}
        )
        await ledger.append(s, "selected.task", "user:jan.devries", "mdt_scope_child", {"selected": True})
        await s.commit()
    response = await world.api(
        "eva.visser", "GET", "/v1/evidence/pack", params={"root_id": "mdt_scope_root", "agent_id": kyc}
    )
    assert response.status_code == 200, response.text
    files = contents(response.content)
    assert all(b"OTHER-TASK-PRIVATE-INPUT" not in data for data in files.values())
    assert {m["id"] for m in json.loads(files["records/mandates.json"])} == {"mdt_scope_root", "mdt_scope_child"}
    assert json.loads(files["records/case_events.json"])[0]["id"] == "case_scope"
    assert "mdt_scope_root" in json.loads(files["manifest.json"])["scope"]["prior_context_records"]["mandates"]
    assert verify_pack(response.content, world.ctx.evidence_key.fingerprint)["ok"]
    wrong = await world.api(
        "eva.visser", "GET", "/v1/evidence/pack", params={"root_id": "mdt_other_root", "agent_id": kyc}
    )
    assert wrong.status_code == 422


async def test_wrong_pinned_key_and_invalid_proof_are_rejected(world):
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    with pytest.raises(ValueError, match="not the expected"):
        verify_pack(response.content, SigningKey.generate_ephemeral("wrong").fingerprint)
    files = contents(response.content)
    tree = json.loads(files["ledger_proofs.json"])
    tree["proofs"][0]["siblings"][0] = "0" * 64
    files["ledger_proofs.json"] = json.dumps(tree).encode()
    manifest = json.loads(files["manifest.json"])
    manifest["files"]["ledger_proofs.json"] = {
        "bytes": len(files["ledger_proofs.json"]),
        "sha256": hashlib.sha256(files["ledger_proofs.json"]).hexdigest(),
    }
    files["manifest.json"] = json.dumps(manifest).encode()
    # Even an internally signed manifest with a buggy proof must fail offline validation.
    files["signature.jws"] = attestation.sign(
        world.ctx.evidence_key,
        {
            "typ": attestation.PACK,
            "manifest_sha256": hashlib.sha256(files["manifest.json"]).hexdigest(),
        },
    ).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    with pytest.raises(ValueError, match="inclusion proof"):
        verify_pack(output.getvalue(), world.ctx.evidence_key.fingerprint)


@pytest.mark.parametrize("n", [0, 1, 2, 3, 7, 8, 9])
def test_tree_proofs_include_sparse_and_odd_leaf_counts(n):
    entries = [{"seq": i * 2 + 1, "entry_hash": hashlib.sha256(str(i).encode()).hexdigest()} for i in range(n)]
    proof = inclusion_proofs(entries, entries[::2])
    assert proof["source_entries"] == n and len(proof["proofs"]) == len(entries[::2])
    assert len(proof["root"]) == 64
    for entry, path in zip(entries[::2], proof["proofs"], strict=True):
        value = hashlib.sha256(b"\x00" + f"{entry['seq']}:{entry['entry_hash']}".encode("ascii")).digest()
        cursor = path["index"]
        for sibling in path["siblings"]:
            left, right = (bytes.fromhex(sibling), value) if cursor % 2 else (value, bytes.fromhex(sibling))
            value = hashlib.sha256(b"\x01" + left + right).digest()
            cursor //= 2
        assert value.hex() == proof["root"]


@pytest.mark.parametrize("dialect", ["sqlite", "postgresql"])
async def test_schedule_generation_restart_failure_review_and_concurrency(tmp_path, dialect, monkeypatch):
    schema = ""
    admin = None
    if dialect == "postgresql":
        if os.getenv("AEGIS_TEST_POSTGRES") != "1":
            pytest.skip("Opt-in isolated PostgreSQL evidence reports")
        url = Settings.from_env().database_url
        assert url.startswith("postgresql+asyncpg://")
        schema = "aegis_evidence_test_" + uuid.uuid4().hex
        assert re.fullmatch(r"aegis_evidence_test_[a-f0-9]{32}", schema)
        admin = Database(url)
        async with admin.engine.begin() as conn:
            await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    else:
        url = f"sqlite+aiosqlite:///{tmp_path / 'evidence.sqlite'}"
    options = dict(
        database_url=url,
        database_schema=schema,
        signing_key_path=str(tmp_path / "sts.pem"),
        idp_key_path=str(tmp_path / "idp.pem"),
        evidence_key_path=str(tmp_path / "evidence.pem"),
        identity_state_dir=str(tmp_path / "identities"),
        llm_upstream_url=FAKE_LLM_URL,
        evidence_automation_enabled=True,
    )
    try:
        async with running_world(**options) as world:
            # Exercise the worker deterministically without an unrelated timer racing this test.
            world.ctx.evidence_task.cancel()
            await asyncio.gather(world.ctx.evidence_task, return_exceptions=True)
            peer = replace(world.ctx, evidence_lock=asyncio.Lock()) if dialect == "postgresql" else world.ctx
            await asyncio.gather(
                evidence_reports.automatic_checkpoint(world.ctx), evidence_reports.automatic_checkpoint(peer)
            )
            async with world.ctx.db.sessionmaker() as s:
                initial = (await s.scalars(select(LedgerCheckpoint))).all()
                assert len(initial) == 1
                assert attestation.checkpoint_status(
                    initial[0],
                    (await s.scalars(select(LedgerEntry).order_by(LedgerEntry.seq))).all(),
                    world.ctx.evidence_key,
                )["ok"]
            response = await world.api(
                "eva.visser",
                "POST",
                "/v1/evidence/schedules",
                json={
                    "name": "Hourly DORA evidence",
                    "interval_hours": 1,
                    "scope": {"framework": "dora"},
                },
            )
            assert response.status_code == 201, response.text
            schedule = response.json()
            # Distinct process locks exercise PostgreSQL's SKIP LOCKED, not only one asyncio lock.
            peer = replace(world.ctx, evidence_lock=asyncio.Lock()) if dialect == "postgresql" else world.ctx
            batches = await asyncio.gather(
                evidence_reports.scheduled_cycle(world.ctx), evidence_reports.scheduled_cycle(peer)
            )
            assert sum(len(batch) for batch in batches) == 1
            first = next(batch[0] for batch in batches if batch)
            assert first["status"] == "ready" and first["generated_by"] == evidence_reports.WORKER
            downloaded = await world.api("eva.visser", "GET", f"/v1/evidence/reports/{first['id']}/download")
            body = downloaded.content
            assert verify_pack(body, world.ctx.evidence_key.fingerprint)["ok"]
            key = world.ctx.evidence_key.fingerprint
        async with running_world(**options) as world:
            world.ctx.evidence_task.cancel()
            await asyncio.gather(world.ctx.evidence_task, return_exceptions=True)
            assert world.ctx.evidence_key.fingerprint == key
            restored = await world.api("eva.visser", "GET", f"/v1/evidence/reports/{first['id']}/download")
            assert restored.content == body
            assert (await world.api("eva.visser", "GET", "/v1/evidence/schedules")).json()[0]["id"] == schedule["id"]
            assert await evidence_reports.scheduled_cycle(world.ctx) == []
            due = datetime.fromisoformat(schedule["next_run_at"]) + timedelta(hours=1, seconds=1)
            disabled = replace(
                world.ctx, settings=world.ctx.settings.model_copy(update={"evidence_automation_enabled": False})
            )
            assert await evidence_reports.scheduled_cycle(disabled, due) == []
            # Removing persistent-key configuration must not silently restart saved schedules with an ephemeral key.
            no_key = replace(
                world.ctx,
                settings=world.ctx.settings.model_copy(update={"evidence_key_path": "", "signing_key_path": ""}),
            )
            assert await evidence_reports.scheduled_cycle(no_key, due) == []
            assert await evidence_reports.automatic_checkpoint(no_key, due) is None
            real = evidence_reports.save_report

            async def failed(*args, **kwargs):
                raise RuntimeError("SQL-private-input-must-not-be-stored")

            with monkeypatch.context() as patch:
                patch.setattr(evidence_reports, "save_report", failed)
                failure = (await evidence_reports.scheduled_cycle(world.ctx, due))[0]
            assert failure["status"] == "failed" and failure["error_code"] == "report_generation_failed"
            assert "SQL-private" not in json.dumps(failure)
            assert (
                await world.api("eva.visser", "GET", f"/v1/evidence/reports/{failure['id']}/download")
            ).status_code == 409
            monkeypatch.setattr(evidence_reports, "save_report", real)
            assert await evidence_reports.scheduled_cycle(world.ctx, due) == []
            later = (await evidence_reports.scheduled_cycle(world.ctx, due + timedelta(hours=1)))[0]
            assert later["status"] == "ready"
            assert (
                await world.api(
                    "eva.visser", "PATCH", f"/v1/evidence/schedules/{schedule['id']}", json={"enabled": False}
                )
            ).status_code == 200
            assert await evidence_reports.scheduled_cycle(world.ctx, due + timedelta(days=1)) == []
            reviewed = await world.api(
                "eva.visser",
                "POST",
                f"/v1/evidence/reports/{first['id']}/review",
                json={"note": "Auditor reviewed the unchanged signed artifact."},
            )
            assert reviewed.status_code == 200, reviewed.text
            assert (
                await world.api("eva.visser", "GET", f"/v1/evidence/reports/{first['id']}/download")
            ).content == body
            if dialect == "postgresql":
                async with world.ctx.db.sessionmaker() as s:
                    row = await s.get(EvidenceReport, first["id"])
                    row.review_note = "Attempted rewrite of original review"
                    with pytest.raises(DBAPIError, match="review is immutable"):
                        await s.commit()
                    await s.rollback()
                async with world.ctx.db.sessionmaker() as s:
                    checkpoint = await s.scalar(select(LedgerCheckpoint).limit(1))
                    checkpoint.tip = "0" * 64
                    with pytest.raises(DBAPIError, match="append-only"):
                        await s.commit()
                    await s.rollback()
            async with world.ctx.db.sessionmaker() as s:
                row = await s.get(EvidenceReport, first["id"])
                row.artifact = b"corrupted artifact"
                if dialect == "postgresql":
                    with pytest.raises(DBAPIError, match="immutable"):
                        await s.commit()
                    await s.rollback()
                else:
                    await s.commit()
            assert (
                await world.api("eva.visser", "GET", f"/v1/evidence/reports/{first['id']}/download")
            ).status_code == (200 if dialect == "postgresql" else 409)
            # Hourly checkpoints are signed once, not once per scheduler worker.
            async with world.ctx.db.sessionmaker() as s:
                before = len((await s.scalars(select(LedgerCheckpoint))).all())
            peer = replace(world.ctx, evidence_lock=asyncio.Lock()) if dialect == "postgresql" else world.ctx
            await asyncio.gather(
                evidence_reports.automatic_checkpoint(world.ctx),
                evidence_reports.automatic_checkpoint(peer),
            )
            async with world.ctx.db.sessionmaker() as s:
                checkpoints = (await s.scalars(select(LedgerCheckpoint))).all()
                assert len(checkpoints) == before
                assert attestation.checkpoint_status(
                    checkpoints[-1],
                    (await s.scalars(select(LedgerEntry).order_by(LedgerEntry.seq))).all(),
                    world.ctx.evidence_key,
                )["ok"]
    finally:
        if admin:
            assert re.fullmatch(r"aegis_evidence_test_[a-f0-9]{32}", schema)
            async with admin.engine.begin() as conn:
                await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            await admin.engine.dispose()
