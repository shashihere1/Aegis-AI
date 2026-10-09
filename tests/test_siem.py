"""Independent receiver, durable outbox and HTTP delivery tests; no cloud calls or user DB writes."""

import asyncio
import json
import socket
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import uvicorn
from sqlalchemy import func, select

from aegis.common.hashing import sha256_hex
from aegis.common.settings import Settings
from aegis.control.app import create_app as control_app
from aegis.control.siem import connector_token, deliver_one, validate_destination
from aegis.control.soc import raise_alert
from aegis.control.tables import Alert, LedgerEntry, SiemDelivery
from aegis_demo.siem import create_app, provision

TOKEN = "offline-test-ingest-credential-" + "x" * 32


def enable(world):
    world.ctx.settings.siem_enabled = True
    world.ctx.settings.siem_token = TOKEN
    world.ctx.settings.siem_max_attempts = 2


async def alert(world):
    async with world.ctx.db.sessionmaker() as s:
        row = await raise_alert(
            world.ctx,
            s,
            "DET-15",
            "high",
            "Untrusted title secret=do-not-export",
            world.agent_ids["ava"],
            {
                "root_id": "mdt_offline",
                "decision": "dec_offline",
                "reasons": [{"rule": "DLG-004", "message": "Do not export this arbitrary text"}],
                "raw_prompt": "sensitive",
                "arguments": {"iban": "sensitive"},
                "private_key": "secret",
            },
        )
        await s.commit()
        return row.id


async def due(world, event_id):
    async with world.ctx.db.sessionmaker() as s:
        row = await s.get(SiemDelivery, event_id)
        row.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()


async def test_independent_loopback_receiver_real_http_delivery_and_deduplication(world, tmp_path):
    enable(world)
    app = create_app(TOKEN, tmp_path / "receiver.sqlite3")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(100):
            if server.started:
                break
            if serving.done():
                serving.result()
            await asyncio.sleep(0.01)
        assert server.started
        world.ctx.settings.siem_url = f"http://127.0.0.1:{port}/events"
        event_id = await alert(world)
        async with httpx.AsyncClient(trust_env=False) as client:
            assert await deliver_one(world.ctx, client, TOKEN)
            assert not await deliver_one(world.ctx, client, TOKEN)
            async with world.ctx.db.sessionmaker() as s:
                row = await s.get(SiemDelivery, event_id)
                assert row.status == "delivered" and row.attempts == 1 and row.latency_ms >= 0
                payload = row.payload
                assert "secret" not in json.dumps(payload) and "sensitive" not in json.dumps(payload)
                assert row.payload_hash == sha256_hex(payload)
                assert (
                    await s.scalar(
                        select(func.count())
                        .select_from(LedgerEntry)
                        .where(LedgerEntry.event_type == "siem.alert_delivered")
                    )
                    == 1
                )
            headers = {"Authorization": f"Bearer {TOKEN}", "Idempotency-Key": event_id}
            response = await client.post(world.ctx.settings.siem_url, json=payload, headers=headers)
            assert response.status_code == 200 and response.json()["accepted"]
            received = (await client.get(world.ctx.settings.siem_url)).json()["items"]
            assert len(received) == 1 and received[0]["event"]["event_id"] == event_id
            modified = {**payload, "severity": "low"}
            assert (await client.post(world.ctx.settings.siem_url, json=modified, headers=headers)).status_code == 409
            assert (await client.post(world.ctx.settings.siem_url, json=payload)).status_code == 401
        assert (await world.api("jan.devries", "GET", "/v1/siem/deliveries")).status_code == 403
        report = (await world.api("mark.jansen", "GET", "/v1/siem/deliveries")).json()
        assert report["items"][0]["status"] == "delivered" and TOKEN not in json.dumps(report)
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving, 5)
        sock.close()


async def test_forwarding_failure_does_not_change_enforcement_and_manual_retry_is_protected(world, tmp_path):
    enable(world)
    event_id = await alert(world)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(503, text=TOKEN))) as client:
        assert await deliver_one(world.ctx, client, TOKEN)
        async with world.ctx.db.sessionmaker() as s:
            row = await s.get(SiemDelivery, event_id)
            assert row.status == "pending" and row.last_error == "http_503" and row.delivered_at is None
        await due(world, event_id)
        await deliver_one(world.ctx, client, TOKEN)
    retry = f"/v1/siem/deliveries/{event_id}/retry"
    assert (await world.api("jan.devries", "POST", retry)).status_code == 403
    assert (await world.api("mark.jansen", "POST", retry)).status_code == 200
    assert (await world.api("mark.jansen", "POST", retry)).status_code == 409
    receiver = create_app(TOKEN, tmp_path / "retry.sqlite3")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=receiver)) as client:
        await deliver_one(world.ctx, client, TOKEN)
    async with world.ctx.db.sessionmaker() as s:
        row = await s.get(SiemDelivery, event_id)
        assert row.status == "delivered" and row.attempts == 1
    assert (await world.api("mark.jansen", "POST", retry)).status_code == 409
    assert (await world.api("mark.jansen", "GET", "/health")).status_code == 200


async def test_outbox_rolls_back_with_alert_and_expired_lease_recovers(world, tmp_path):
    enable(world)
    async with world.ctx.db.sessionmaker() as s:
        row = await raise_alert(world.ctx, s, "DET-15", "high", "Test", world.agent_ids["ava"], {})
        await s.flush()
        event_id = row.id
        await s.rollback()
    async with world.ctx.db.sessionmaker() as s:
        assert await s.get(Alert, event_id) is None and await s.get(SiemDelivery, event_id) is None
    event_id = await alert(world)
    async with world.ctx.db.sessionmaker() as s:
        row = await s.get(SiemDelivery, event_id)
        row.status, row.lease_id, row.attempts = "sending", "old-process-lease", 1
        row.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()
    receiver = create_app(TOKEN, tmp_path / "recover.sqlite3")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=receiver)) as client:
        assert await deliver_one(world.ctx, client, TOKEN)
    async with world.ctx.db.sessionmaker() as s:
        row = await s.get(SiemDelivery, event_id)
        assert row.status == "delivered" and row.attempts == 2 and row.lease_id is None


async def test_wrong_acknowledgement_and_redirect_are_not_delivery(world):
    enable(world)
    event_id = await alert(world)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"accepted": True, "event_id": "wrong", "payload_hash": "wrong"})
        )
    ) as client:
        await deliver_one(world.ctx, client, TOKEN)
    async with world.ctx.db.sessionmaker() as s:
        row = await s.get(SiemDelivery, event_id)
        assert row.status == "pending" and row.last_error == "invalid_acknowledgement"
    await due(world, event_id)
    async with httpx.AsyncClient(
        follow_redirects=False,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(307, headers={"Location": "https://unapproved.example/events"})
        ),
    ) as client:
        await deliver_one(world.ctx, client, TOKEN)
    async with world.ctx.db.sessionmaker() as s:
        row = await s.get(SiemDelivery, event_id)
        assert row.status == "failed" and row.last_error == "http_307"


def test_mock_siem_provisioning_is_idempotent_and_never_overwrites_tokens(tmp_path):
    connection = provision(tmp_path / "siem")
    original = (tmp_path / "siem" / "token").read_text()
    provision(tmp_path / "siem")
    assert (tmp_path / "siem" / "token").read_text() == original
    settings = type(
        "Settings", (), {"siem_token": "", "siem_token_path": json.loads(connection.read_text())["siem_token_path"]}
    )()
    assert connector_token(settings) == original
    with pytest.raises(ValueError, match="not overwritten"):
        provision(tmp_path / "siem", port=8012)


def test_destination_validation_rejects_credential_redirect_style_and_nonlocal_http():
    for value in (
        "http://169.254.169.254/events",
        "http://localhost/events",
        "https://user:secret@example.com/events",
        "https://example.com/events?token=secret",
        "file:///tmp/event",
        "http://127.0.0.1/events#fragment",
    ):
        with pytest.raises(ValueError):
            validate_destination(value)
    validate_destination("http://127.0.0.1:8011/events")
    validate_destination("https://approved.example/events")


async def test_control_lifespan_worker_automatically_forwards_committed_alert(tmp_path):
    receiver = create_app(TOKEN, tmp_path / "background-receiver.sqlite3")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(receiver, log_level="error", lifespan="off"))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(100):
            if server.started:
                break
            if serving.done():
                serving.result()
            await asyncio.sleep(0.01)
        assert server.started
        settings = Settings(
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'outbox.sqlite'}",
            siem_enabled=True,
            siem_url=f"http://127.0.0.1:{port}/events",
            siem_token=TOKEN,
            siem_poll_seconds=0.1,
            attestation_interval_days=0,
            evidence_automation_enabled=False,
        )
        async with httpx.AsyncClient() as shared:
            control = control_app(settings, shared)
            async with control.router.lifespan_context(control):
                c = control.state.ctx
                async with c.db.sessionmaker() as s:
                    row = await raise_alert(c, s, "DET-15", "high", "Bounded enforcement alert", None, {})
                    await s.commit()
                    event_id = row.id
                for _ in range(150):
                    async with c.db.sessionmaker() as s:
                        delivery = await s.get(SiemDelivery, event_id)
                        if delivery.status == "delivered":
                            break
                    await asyncio.sleep(0.02)
                assert delivery.status == "delivered" and delivery.latency_ms < 5000
                async with httpx.AsyncClient(trust_env=False) as client:
                    items = (await client.get(settings.siem_url)).json()["items"]
                assert len(items) == 1 and items[0]["event"]["event_id"] == event_id
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving, 5)
        sock.close()
