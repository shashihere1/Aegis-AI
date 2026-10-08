"""Actual policy decisions, replay safety, role separation, cases, risk and real OTel spans."""

import copy
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from aegis.common.crypto import SigningKey
from aegis.control.identity.idp import DevIdp, Persona
from aegis.control.tables import DecisionRecord, PolicyVersion
from aegis_demo import mcp_servers
from aegis_demo.world import BASE


async def draft(world, author="priya.raman", threshold=2000):
    active = (await world.api(author, "GET", "/v1/policies")).json()
    config = copy.deepcopy(active["data"])
    config["thresholds"]["payments"]["hitl_amount_eur"] = threshold
    response = await world.api(
        author,
        "POST",
        "/v1/policies/versions",
        json={
            "name": "Lower threshold",
            "configuration": config,
            "justification": "Review payment exposure",
        },
    )
    assert response.status_code == 201, response.text
    return response.json(), active["version"]


async def test_policy_changes_replay_approval_activation_and_rollback(world):
    before = (await world.http.post(f"{BASE}/demo/api/scenarios/policy-transfer", json={})).json()
    assert before["status"] == "completed"
    count = len(mcp_servers.TRANSFERS)
    version, original = await draft(world)
    vid = version["id"]
    premature = await world.api("priya.raman", "POST", f"/v1/policies/{vid}/submit")
    assert premature.status_code == 409
    report = (await world.api("priya.raman", "POST", f"/v1/policies/{vid}/replay", json={})).json()
    assert report["evaluated"] > 0 and report["changed"] > 0
    assert any(r["before"] == "allow" and r["after"] == "require_approval" for r in report["results"])
    assert len(mcp_servers.TRANSFERS) == count  # replay must never execute a payment
    assert (await world.api("priya.raman", "POST", f"/v1/policies/{vid}/submit")).status_code == 200
    assert (
        await world.api(
            "fatima.elamrani",
            "POST",
            f"/v1/policies/{vid}/activate",
            json={
                "expected_active_version": original,
                "justification": "Activation before approval denied",
            },
        )
    ).status_code == 409
    assert (
        await world.api(
            "fatima.elamrani",
            "POST",
            f"/v1/policies/{vid}/approve",
            json={
                "justification": "Reviewed replay results",
            },
        )
    ).status_code == 200
    assert (
        await world.api(
            "fatima.elamrani",
            "POST",
            f"/v1/policies/{vid}/activate",
            json={
                "expected_active_version": "stale-version",
                "justification": "Stale UI must be rejected",
            },
        )
    ).status_code == 409
    assert (
        await world.api(
            "fatima.elamrani",
            "POST",
            f"/v1/policies/{vid}/activate",
            json={
                "expected_active_version": original,
                "justification": "Activate reviewed configuration",
            },
        )
    ).status_code == 200
    after = (await world.http.post(f"{BASE}/demo/api/scenarios/policy-transfer", json={})).json()
    assert after["status"] == "waiting" and len(mcp_servers.TRANSFERS) == count
    assert (
        await world.api(
            "fatima.elamrani",
            "POST",
            f"/v1/policies/{original}/rollback",
            json={
                "expected_active_version": vid,
                "justification": "Restore previously approved threshold",
            },
        )
    ).status_code == 200
    restored = (await world.http.post(f"{BASE}/demo/api/scenarios/policy-transfer", json={})).json()
    assert restored["status"] == "completed" and len(mcp_servers.TRANSFERS) == count + 1
    decisions = (await world.api("mark.jansen", "GET", "/v1/decisions")).json()
    assert any(d["policy_version"] == vid and d["decision"] == "require_approval" for d in decisions)
    assert (await world.api("eva.visser", "GET", "/v1/ledger/verify")).json()["ok"]


async def test_policy_segregation_and_access_control(world):
    world.ctx.idp.add_persona(Persona("dual.policy", "Dual-role author", ["policy-author", "policy-approver"]))
    version, original = await draft(world, "dual.policy")
    vid = version["id"]
    await world.api("dual.policy", "POST", f"/v1/policies/{vid}/replay", json={})
    await world.api("dual.policy", "POST", f"/v1/policies/{vid}/submit")
    own = await world.api("dual.policy", "POST", f"/v1/policies/{vid}/approve", json={"justification": "Self review"})
    assert own.status_code == 403 and "own policy" in own.text
    await world.api("fatima.elamrani", "POST", f"/v1/policies/{vid}/approve", json={"justification": "Separate review"})
    assert (
        await world.api(
            "dual.policy",
            "POST",
            f"/v1/policies/{vid}/activate",
            json={
                "expected_active_version": original,
                "justification": "Self activation",
            },
        )
    ).status_code == 403
    assert (
        await world.api(
            "mark.jansen",
            "POST",
            "/v1/policies/versions",
            json={
                "name": "Unauthorized",
                "configuration": version["configuration"],
                "justification": "Wrong role",
            },
        )
    ).status_code == 403
    assert (await world.api("jan.devries", "GET", "/v1/policies/versions")).status_code == 403


async def test_invalid_config_and_policy_tamper_fail_closed(world):
    version, _ = await draft(world)
    bad = copy.deepcopy(version["configuration"])
    bad["thresholds"]["payments"]["hitl_amount_eur"] = -1
    assert (
        await world.api(
            "priya.raman",
            "POST",
            "/v1/policies/versions",
            json={
                "name": "Bad config",
                "justification": "Invalid threshold",
                "configuration": bad,
            },
        )
    ).status_code == 422
    async with world.ctx.db.sessionmaker() as s:
        row = await s.get(PolicyVersion, version["id"])
        row.configuration = bad
        await s.commit()
    assert (await world.api("priya.raman", "POST", f"/v1/policies/{version['id']}/replay", json={})).status_code == 409


async def test_case_assignment_notes_evidence_and_validation(world):
    await world.http.post(f"{BASE}/demo/api/scenarios/attack", json={})
    alert = (await world.api("mark.jansen", "GET", "/v1/alerts")).json()[0]
    url = f"/v1/alerts/{alert['id']}/case"
    assert (await world.api("priya.raman", "PATCH", url, json={"note": "Wrong role"})).status_code == 403
    assert (await world.api("mark.jansen", "PATCH", url, json={"status": "resolved"})).status_code == 409
    assert (await world.api("mark.jansen", "PATCH", url, json={"assigned_to": "eva.visser"})).status_code == 422
    assert (await world.api("mark.jansen", "PATCH", url, json={"decision_id": "does-not-exist"})).status_code == 422
    response = await world.api(
        "mark.jansen",
        "PATCH",
        url,
        json={
            "status": "investigating",
            "assigned_to": "mark.jansen",
            "note": "Blocked egress confirmed",
        },
    )
    assert response.status_code == 200
    assert (await world.api("mark.jansen", "PATCH", url, json={"status": "resolved"})).status_code == 422
    case = (await world.api("eva.visser", "GET", url)).json()
    evidence = case["decisions"][0]["id"]
    assert (
        await world.api(
            "mark.jansen",
            "PATCH",
            url,
            json={
                "status": "resolved",
                "note": "Reviewed blocked action; identity remains disabled",
                "decision_id": evidence,
            },
        )
    ).status_code == 200
    case = (await world.api("eva.visser", "GET", url)).json()
    assert case["status"] == "resolved" and case["assigned_to"] == "mark.jansen"
    assert len(case["events"]) == 2 and case["events"][1]["detail"]["decision_id"] == evidence
    assert (await world.api("eva.visser", "GET", "/v1/ledger/verify")).json()["ok"]


async def test_real_shared_trace_across_delegation_and_tools(world):
    result = await world.ava.change_address(world.token("jan.devries"), "C-1001", "D-77", "Amsterdam")
    root = result["task"].root_id
    report = (await world.api("mark.jansen", "GET", f"/v1/traces?root_id={root}")).json()
    spans = report["spans"]
    assert spans and len({s["trace_id"] for s in spans}) == 1
    services = {s["service"] for s in spans}
    assert {"aegis.control", "aegis.gateway", "aegis.agent.kyc", "aegis.mcp.kyc", "aegis.mcp.crm"} <= services
    ids = {s["span_id"] for s in spans}
    assert any(s["parent_id"] in ids for s in spans)
    assert all(s["duration_ms"] >= 0 for s in spans)
    assert report["dropped"] == report["failed_flushes"] == 0
    serialized = json.dumps(spans)
    assert "Bearer " not in serialized and "PRIVATE KEY" not in serialized
    assert "authorization" not in serialized and "jwt" not in serialized.lower()


async def test_risk_warmup_and_real_event_signals(world):
    agent = world.agent_ids["ava"]
    before = (await world.api("mark.jansen", "GET", f"/v1/risk/{agent}")).json()
    assert before["baseline"]["status"] == "warming_up" and before["baseline"]["history_calls"] == 0
    await world.http.post(f"{BASE}/demo/api/scenarios/attack", json={})
    after = (await world.api("mark.jansen", "GET", f"/v1/risk/{agent}")).json()
    assert after["score"] > before["score"]
    assert any(s.get("reason") == "DET-02" for s in after["breakdown"]["signals"])
    assert after["baseline"]["status"] == "warming_up"


async def test_baseline_uses_observed_completed_minutes(world):
    # Backdated records are test fixtures only, never production/demo startup history.
    agent = world.agent_ids["ava"]
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    async with world.ctx.db.sessionmaker() as s:
        for minute in range(1, 7):
            for call in range(4):
                s.add(
                    DecisionRecord(
                        id=f"baseline-{minute}-{call}",
                        agent_id=agent,
                        ts=now - timedelta(minutes=minute),
                        action="crm.get_customer",
                        decision="allow",
                    )
                )
        for call in range(20):
            s.add(
                DecisionRecord(
                    id=f"spike-{call}", agent_id=agent, ts=now, action="documents.read_document", decision="allow"
                )
            )
        await s.commit()
    report = (await world.api("mark.jansen", "GET", f"/v1/risk/{agent}")).json()
    assert report["baseline"]["status"] == "ready"
    assert report["baseline"]["median_calls_per_active_minute"] == 4
    assert report["baseline"]["robust_z_score"] > 3.5
    assert "documents.read_document" in report["baseline"]["new_tools"]


async def test_evidence_contains_governance_cases_risk_and_trace_records(world):
    await world.http.post(f"{BASE}/demo/api/scenarios/attack", json={})
    alert = (await world.api("mark.jansen", "GET", "/v1/alerts")).json()[0]
    await world.api("mark.jansen", "PATCH", f"/v1/alerts/{alert['id']}/case", json={"note": "Reviewed blocked action"})
    await world.ctx.telemetry.flush()
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert {
            "records/policies.json",
            "records/policy_state.json",
            "records/case_events.json",
            "records/risk.json",
            "records/traces.json",
        } <= set(archive.namelist())
        assert json.loads(archive.read("records/case_events.json"))
        assert json.loads(archive.read("records/traces.json"))


def test_persistent_dev_identities_and_path_validation(tmp_path):
    key = SigningKey.load_or_generate(str(tmp_path / "idp.pem"), "test")
    first = DevIdp("http://local/idp", key, str(tmp_path / "identities"))
    first.add_persona(Persona("test.owner", "Owner", ["agent-owner"]))
    client, private = first.provision_agent_identity("AGT-TEST", "Persistent agent")
    first.set_enabled(client, False)
    first.mark_leaver("test.owner")
    second = DevIdp(
        "http://local/idp", SigningKey.load_or_generate(str(tmp_path / "idp.pem"), "test"), str(tmp_path / "identities")
    )
    second.add_persona(Persona("test.owner", "Owner", ["agent-owner"]))
    assert second.development_private_key(client) == private
    assert not second.clients[client].enabled and second.personas["test.owner"].status == "left"
    with pytest.raises(ValueError):
        second.register_unmanaged_client("../escape", "Invalid")
    with pytest.raises(ValueError):
        second.development_private_key("../escape")
