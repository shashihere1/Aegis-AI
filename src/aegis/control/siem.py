"""Durable, at-least-once outbound alert forwarding; never a prerequisite for authorization.

The JSON envelope is OCSF-inspired, not a certified OCSF or Sentinel connector. Only an
explicit allowlist of identifiers, rules and numeric budget evidence leaves Aegis.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, update

from aegis.common.hashing import sha256_hex
from aegis.common.ids import new_id
from aegis.control import ledger
from aegis.control.auth import require_roles
from aegis.control.tables import SiemDelivery

log = logging.getLogger("aegis.siem")
SIEM_READERS = ("soc-analyst", "auditor", "admin", "risk-approver")
SAFE_TITLES = {
    "DET-15": "Delegation permission widening blocked",
    "DET-16": "Estimated model budget reached 80%",
    "DET-17": "Model request blocked by estimated daily budget",
    "DET-01": "Prompt injection detected",
    "DET-02": "Exfiltration attempt blocked",
    "DET-04": "Burst of denied actions",
    "DET-05": "Revoked or expired credential presented",
    "DET-03": "Tool definition drift detected",
}


def validate_destination(url: str) -> None:
    p = urlsplit(url)
    if (
        not p.hostname
        or p.username
        or p.password
        or p.query
        or p.fragment
        or p.port == 0
        or not (p.scheme == "https" or (p.scheme == "http" and p.hostname in {"127.0.0.1", "::1"}))
    ):
        raise ValueError("SIEM requires HTTPS, or HTTP to the literal loopback mock address, without URL credentials.")


def connector_token(settings) -> str:
    token = settings.siem_token
    if not token and settings.siem_token_path:
        token = Path(settings.siem_token_path).read_text(encoding="utf-8").strip()
    if len(token) < 32 or not token.isascii() or any(ch.isspace() for ch in token):
        raise ValueError("Configure a protected SIEM token of at least 32 characters.")
    return token


def aware(ts):
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


async def enqueue(c, s, alert) -> None:
    if not c.settings.siem_enabled:
        return
    evidence = alert.evidence or {}
    now = datetime.now(UTC)
    payload = {
        "schema": "aegis.alert.v1",
        "metadata": {"product": "Aegis", "format": "OCSF-inspired demo envelope"},
        "event_id": alert.id,
        "time": aware(alert.ts or now).isoformat(),
        "severity": alert.severity,
        "finding": {"rule_id": alert.rule_id, "title": SAFE_TITLES.get(alert.rule_id, "Aegis security detection")},
        "actor": {"agent_id": alert.agent_id},
        "correlation": {key: evidence.get(key) for key in ("decision", "root_id", "mandate_id", "trace_id")},
        "evidence": {
            "reason_rules": [str(r.get("rule", ""))[:80] for r in evidence.get("reasons", []) if isinstance(r, dict)],
            **{
                key: evidence[key]
                for key in ("used_or_reserved_eur", "daily_budget_eur", "requested_estimate_eur")
                if isinstance(evidence.get(key), (int, float))
            },
        },
        "response": [
            {"action": action.get("action"), "agent_id": action.get("agent")} for action in alert.actions_taken or []
        ],
    }
    # Never export prompts, raw tool output/arguments, user tokens, keys or the full evidence dictionary.
    s.add(
        SiemDelivery(
            alert_id=alert.id,
            destination=c.settings.siem_url,
            payload=payload,
            payload_hash=sha256_hex(payload),
            created_at=now,
            next_attempt_at=now,
        )
    )


def delivery_dict(row) -> dict:
    return {
        "alert_id": row.alert_id,
        "status": row.status,
        "attempts": row.attempts,
        "created_at": row.created_at,
        "delivered_at": row.delivered_at,
        "latency_ms": row.latency_ms,
        "last_error": row.last_error,
    }


async def deliver_one(c, client, token: str) -> bool:
    """Claim durably before network IO. Expired leases recover after a crash; CAS prevents stale completion."""
    now = datetime.now(UTC)
    async with c.db.sessionmaker() as s:
        query = (
            select(SiemDelivery)
            .where(SiemDelivery.status.in_(["pending", "sending"]), SiemDelivery.next_attempt_at <= now)
            .order_by(SiemDelivery.created_at)
            .limit(1)
        )
        if s.bind.dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        row = await s.scalar(query)
        if row is None:
            return False
        # Do not send queued events to a newly configured host with the old destination's credential.
        if row.destination != c.settings.siem_url:
            row.status, row.last_error = "failed", "destination_changed"
            await s.commit()
            return True
        if row.attempts >= c.settings.siem_max_attempts:
            row.status, row.last_error = "failed", "lease_expired_after_max_attempts"
            await s.commit()
            return True
        lease = new_id("send")
        row.status, row.lease_id, row.attempts = "sending", lease, row.attempts + 1
        row.next_attempt_at = now + timedelta(seconds=c.settings.siem_timeout_seconds + 10)
        alert_id, payload, digest, attempts = row.alert_id, row.payload, row.payload_hash, row.attempts
        created = aware(row.created_at)
        await s.commit()
    error = None
    try:
        response = await client.post(
            c.settings.siem_url,
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": alert_id},
            timeout=c.settings.siem_timeout_seconds,
        )
        if response.status_code not in {200, 201}:
            error = f"http_{response.status_code}"
        else:
            acknowledgement = response.json()
            if (
                not isinstance(acknowledgement, dict)
                or acknowledgement.get("event_id") != alert_id
                or acknowledgement.get("payload_hash") != digest
                or acknowledgement.get("accepted") is not True
            ):
                error = "invalid_acknowledgement"
    except httpx.HTTPError, ValueError:
        error = "network_or_invalid_response"  # never log response text, URL credentials or exceptions
    delivered = datetime.now(UTC)
    values = {"lease_id": None, "last_error": error}
    if error is None:
        values.update(
            status="delivered",
            delivered_at=delivered,
            latency_ms=round((delivered - created).total_seconds() * 1000, 1),
        )
    else:
        values.update(
            status="failed" if attempts >= c.settings.siem_max_attempts else "pending",
            next_attempt_at=delivered + timedelta(seconds=min(60, 2 ** min(attempts, 6))),
        )
    async with c.db.sessionmaker() as s:
        result = await s.execute(
            update(SiemDelivery)
            .where(SiemDelivery.alert_id == alert_id, SiemDelivery.lease_id == lease)
            .values(**values)
        )
        if result.rowcount and error is None:
            await ledger.append(
                s,
                "siem.alert_delivered",
                "siem-exporter",
                alert_id,
                {"payload_hash": digest, "attempts": attempts, "latency_ms": values["latency_ms"]},
            )
        await s.commit()
    return True


async def run_worker(c):
    token = connector_token(c.settings)
    # Real HTTP client, independent of the demo's in-process ASGI transport. No proxy or redirects.
    async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
        while True:
            try:
                for _ in range(20):
                    if not await deliver_one(c, client, token):
                        break
            except Exception:
                log.warning("SIEM worker temporarily unavailable; committed outbox entries remain queued.")
            await asyncio.sleep(c.settings.siem_poll_seconds)


def router():
    r = APIRouter(prefix="/v1/siem", tags=["alert forwarding"])

    @r.get("/deliveries", dependencies=[Depends(require_roles(*SIEM_READERS))])
    async def deliveries(request: Request, limit: int = Query(default=100, ge=1, le=500)):
        c = request.app.state.ctx
        async with c.db.sessionmaker() as s:
            rows = list(await s.scalars(select(SiemDelivery).order_by(SiemDelivery.created_at.desc()).limit(limit)))
        return {
            "enabled": c.settings.siem_enabled,
            "items": [delivery_dict(row) for row in rows],
            "note": "Acknowledged delivery to a JSON receiver; not a Sentinel/Splunk integration.",
        }

    @r.post("/deliveries/{alert_id}/retry")
    async def retry(alert_id: str, request: Request, user=Depends(require_roles("soc-analyst", "admin"))):
        c = request.app.state.ctx
        if not c.settings.siem_enabled:
            raise HTTPException(409, "Alert forwarding is disabled.")
        async with c.db.sessionmaker() as s:
            row = await s.get(SiemDelivery, alert_id)
            if row is None:
                raise HTTPException(404, "No queued delivery for this alert.")
            if row.destination != c.settings.siem_url:
                raise HTTPException(409, "Restore the approved destination before retrying this event.")
            # Never reset an in-flight or already acknowledged delivery.
            result = await s.execute(
                update(SiemDelivery)
                .where(SiemDelivery.alert_id == alert_id, SiemDelivery.status == "failed")
                .values(status="pending", attempts=0, last_error=None, next_attempt_at=datetime.now(UTC), lease_id=None)
            )
            if not result.rowcount:
                raise HTTPException(409, "Only failed deliveries can be explicitly retried.")
            await ledger.append(s, "siem.delivery_requeued", user.username, alert_id, {})
            await s.commit()
        return {"queued": True}

    return r
