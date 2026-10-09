"""Auditor proof pack: access control, completeness, offline verification and tamper refusal."""

import asyncio
import io
import json
import zipfile

import pytest

from aegis.control.evidence_verify import verify_pack
from aegis.control.tables import Alert, LedgerEntry
from aegis_demo.world import BASE, seed_registry


async def test_auditor_can_download_verifiable_pack(world):
    denied = await world.api("mark.jansen", "GET", "/v1/evidence/pack")
    assert denied.status_code == 403

    preview = await world.api("eva.visser", "GET", "/v1/evidence/summary")
    assert preview.status_code == 200
    assert preview.json()["integrity"]["ok"] is True
    assert preview.json()["counts"]["agents"] == len(world.agent_ids)

    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["cache-control"] == "no-store"
    assert "attachment; filename=" in response.headers["content-disposition"]
    verified = verify_pack(response.content)
    assert verified["ok"] is True
    assert verified["entries"] > 0

    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert {"report.html", "manifest.json", "README.txt", "verify_pack.py",
                "records/agents.json", "records/mandates.json", "records/decisions.json",
                "records/approvals.json", "records/alerts.json", "records/ledger.json"} <= set(archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["ledger"]["tip"] == verified["tip"]
        assert manifest["generated_by"] == "eva.visser"
        assert b"not a certified" in archive.read("report.html")


async def test_report_escapes_alert_titles(world):
    async with world.ctx.db.sessionmaker() as s:
        s.add(Alert(id="alr-html-test", rule_id="DET-99", severity="high",
                    title="<script>alert(1)</script>", agent_id=world.agent_ids["ava"], evidence={}))
        await s.commit()
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        report = archive.read("report.html").decode()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "<script>alert(1)</script>" not in report


async def test_pack_captures_approval_and_attack_story(world):
    transfer = await world.http.post(f"{BASE}/demo/api/scenarios/transfer", json={
        "amount": 25000, "new_beneficiary": True,
    })
    assert transfer.json()["status"] == "waiting"
    approval_id = transfer.json()["links"]["approval_id"]
    approval = await world.api("sanne.bakker", "POST", f"/v1/approvals/{approval_id}/approve",
                               json={"justification": "Demo approval"})
    assert approval.status_code == 200
    for _ in range(40):
        runs = (await world.http.get(f"{BASE}/demo/api/runs")).json()
        if runs[0]["status"] == "completed":
            break
        await asyncio.sleep(0.1)
    assert runs[0]["status"] == "completed"

    attack = await world.http.post(f"{BASE}/demo/api/scenarios/attack", json={})
    assert attack.json()["status"] == "contained"
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    assert verify_pack(response.content)["ok"]
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        approvals = json.loads(archive.read("records/approvals.json"))
        alerts = json.loads(archive.read("records/alerts.json"))
        decisions = json.loads(archive.read("records/decisions.json"))
        report = archive.read("report.html").decode()
    assert any(a["id"] == approval_id and a["status"] == "consumed" and a["approver"] == "sanne.bakker"
               for a in approvals)
    assert any(a["rule_id"] == "DET-02" for a in alerts)
    assert any(d["decision"] == "deny" and any(r["rule"] == "IFC-001" for r in d["reasons"])
               for d in decisions)
    assert "DET-02" in report and approval_id in report


async def test_pack_refuses_a_broken_ledger(world):
    async with world.ctx.db.sessionmaker() as s:
        entry = await s.get(LedgerEntry, 1)
        entry.payload = {"tampered": True}
        await s.commit()
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    assert response.status_code == 409
    assert "verification failed" in response.json()["detail"]


async def test_offline_verifier_catches_changed_file(world):
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    corrupted = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(response.content)) as original, zipfile.ZipFile(corrupted, "w") as changed:
        for name in original.namelist():
            data = original.read(name)
            changed.writestr(name, data + b"changed" if name == "records/alerts.json" else data)
    with pytest.raises(ValueError, match="File hash mismatch: records/alerts.json"):
        verify_pack(corrupted.getvalue())


async def test_pack_includes_full_seeded_inventory(world):
    await seed_registry(world, 1244)
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    assert response.status_code == 200
    assert verify_pack(response.content)["ok"]
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["counts"]["agents"] == 1244 + len(world.agent_ids)
