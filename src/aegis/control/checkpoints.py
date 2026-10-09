"""Signed ledger checkpoints and external anchoring.

A checkpoint is the ledger's tip at an entry number, signed with the dedicated ledger key. Each checkpoint names the
previous one, so they form their own chain. Rewriting history before a checkpoint, even with every hash recomputed,
no longer verifies. When `tsa_url` is set, the hash of each signed checkpoint (never ledger content) is sent to an
RFC 3161 timestamp authority, whose signed token proves the checkpoint existed at that time.
"""

import asyncio
import base64
import hashlib
import logging
import secrets
import time
from datetime import UTC, datetime

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import ControlContext, session
from aegis.control.evidence_verify import SHA256, parse_timestamp_response, verify_timestamp_signature
from aegis.control.tables import LedgerCheckpoint, LedgerEntry

log = logging.getLogger("aegis.ledger")

CHECKPOINT_TYPE = "aegis-ledger-checkpoint"


class LedgerBroken(Exception):
    def __init__(self, seq: int):
        super().__init__(f"audit ledger broken at entry {seq}")
        self.seq = seq


class AnchorMismatch(Exception):
    """The timestamp authority answered, but not for what was asked."""


# ---- DER encoding for the RFC 3161 request ---------------------------------------------------------------


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def der_int(n: int) -> bytes:
    return _der(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def der_oid(dotted: str) -> bytes:
    a, b, *rest = (int(p) for p in dotted.split("."))
    body = b""
    for value in [40 * a + b, *rest]:
        chunk = [value & 0x7F]
        while value := value >> 7:
            chunk.append(0x80 | (value & 0x7F))
        body += bytes(reversed(chunk))
    return _der(0x06, body)


def der_seq(*items: bytes) -> bytes:
    return _der(0x30, b"".join(items))


def timestamp_request(digest: bytes, nonce: int) -> bytes:
    """TimeStampReq (RFC 3161 §2.4.1) for a SHA-256 digest, asking for the TSA certificate in the token."""
    imprint = der_seq(der_seq(der_oid(SHA256), b"\x05\x00"), _der(0x04, digest))
    return der_seq(der_int(1), imprint, der_int(nonce), b"\x01\x01\xff")


# ---- checkpoints ------------------------------------------------------------------------------------------


def checkpoint_digest(cp: LedgerCheckpoint) -> bytes:
    return hashlib.sha256(cp.jws.encode()).digest()


def trusted_keys(c: ControlContext) -> set[str]:
    """The current ledger key plus any retired keys an operator explicitly still trusts."""
    extra = {k.strip() for k in c.settings.ledger_trusted_keys.split(",") if k.strip()}
    return {c.ledger_key.fingerprint} | extra


def checkpoint_dict(cp: LedgerCheckpoint) -> dict:
    return {
        "number": cp.number,
        "created_at": cp.created_at,
        "upto_seq": cp.upto_seq,
        "entries": cp.entries,
        "tip": cp.tip,
        "prev": cp.prev,
        "key_fingerprint": cp.key_fingerprint,
        "anchor_status": cp.anchor_status,
        "anchored_at": cp.anchored_at,
        "tsa_signer": cp.tsa_signer,
        "anchor_error": cp.anchor_error,
    }


async def _latest(s: AsyncSession) -> LedgerCheckpoint | None:
    return (await s.scalars(select(LedgerCheckpoint).order_by(LedgerCheckpoint.number.desc()).limit(1))).first()


async def create(c: ControlContext) -> LedgerCheckpoint | None:
    """Sign the current tip if there are new entries. Refuses to sign a chain that does not verify."""
    async with c.checkpoint_lock, c.db.sessionmaker() as s:
        if s.bind.dialect.name == "postgresql":
            await s.execute(text("SELECT pg_advisory_xact_lock(724356913)"))
        last = await _latest(s)
        if last is not None:
            at_last = await s.get(LedgerEntry, last.upto_seq)
            if at_last is None or at_last.entry_hash != last.tip:
                raise LedgerBroken(last.upto_seq)
        new = (
            await s.scalars(
                select(LedgerEntry).where(LedgerEntry.seq > (last.upto_seq if last else 0)).order_by(LedgerEntry.seq)
            )
        ).all()
        if not new:
            return last
        prev_hash = last.tip if last else ledger.GENESIS
        for e in new:
            if e.prev_hash != prev_hash or e.entry_hash != ledger.entry_hash(
                prev_hash, e.ts, e.event_type, e.actor, e.subject, e.payload
            ):
                raise LedgerBroken(e.seq)
            prev_hash = e.entry_hash
        key = c.ledger_key
        claims = {
            "typ": CHECKPOINT_TYPE,
            "iss": f"{c.settings.control_url}/ledger",
            "number": (last.number + 1) if last else 1,
            "upto_seq": new[-1].seq,
            "entries": (last.entries if last else 0) + len(new),
            "tip": new[-1].entry_hash,
            "prev": hashlib.sha256(last.jws.encode()).hexdigest() if last else ledger.GENESIS,
            "key_fingerprint": key.fingerprint,
            "iat": int(time.time()),
        }
        cp = LedgerCheckpoint(
            number=claims["number"],
            created_at=datetime.now(UTC).isoformat(),
            upto_seq=claims["upto_seq"],
            entries=claims["entries"],
            tip=claims["tip"],
            prev=claims["prev"],
            key_fingerprint=key.fingerprint,
            public_pem=key.public_pem,
            jws=key.sign(claims),
            anchor_status="pending" if c.settings.tsa_url else "not_configured",
            tsa_url=c.settings.tsa_url or None,
        )
        s.add(cp)
        await s.commit()
        return cp


async def anchor_pending(c: ControlContext, numbers: list[int] | None = None) -> int:
    """Timestamp pending checkpoints at the TSA. A failure leaves them pending for the next attempt."""
    if not c.settings.tsa_url or c.tsa_http is None:
        return 0
    anchored = 0
    async with c.db.sessionmaker() as s:
        query = select(LedgerCheckpoint).where(LedgerCheckpoint.anchor_status == "pending")
        if numbers:
            query = query.where(LedgerCheckpoint.number.in_(numbers))
        for cp in (await s.scalars(query.order_by(LedgerCheckpoint.number))).all():
            digest, nonce = checkpoint_digest(cp), secrets.randbits(63)
            cp.anchor_attempts += 1
            try:
                response = await c.tsa_http.post(
                    c.settings.tsa_url,
                    content=timestamp_request(digest, nonce),
                    headers={"content-type": "application/timestamp-query", "accept": "application/timestamp-reply"},
                    timeout=c.settings.tsa_timeout_seconds,
                )
                response.raise_for_status()
                token = parse_timestamp_response(response.content)
                if token["imprint_alg"] != SHA256 or token["imprint"] != digest or token["nonce"] != nonce:
                    raise AnchorMismatch("the timestamp does not cover this checkpoint")
                check = verify_timestamp_signature(token)
                if check["status"] == "invalid":
                    raise AnchorMismatch(check["reason"])
            except Exception as exc:  # retried later; only the error type is kept (messages can name hosts)
                cp.anchor_error = type(exc).__name__
                log.warning("anchoring checkpoint %s failed: %s", cp.number, exc)
                continue
            cp.anchor_status, cp.anchor_error = "anchored", None
            cp.anchored_at, cp.tsa_signer = token["gen_time"], check.get("signer")
            cp.tsa_response = base64.b64encode(response.content).decode()
            anchored += 1
        await s.commit()
    return anchored


async def checkpoint_periodically(c: ControlContext) -> None:
    interval = c.settings.ledger_checkpoint_interval
    while True:
        try:
            await create(c)
            await anchor_pending(c)
        except LedgerBroken as exc:
            log.error("not signing the ledger: %s", exc)
        except Exception as exc:
            log.warning("ledger checkpoint failed: %s", exc)
        await asyncio.sleep(interval)


def verify(entries: list[LedgerEntry], checkpoints: list[LedgerCheckpoint], trusted: set[str]) -> dict:
    """The hash chain, then every signed checkpoint against it. A rewritten history fails at the first
    checkpoint it contradicts, even when every hash after the edit was recomputed."""
    result = ledger.verify_entries(entries)
    if not result["ok"]:
        return result
    tips = {e.seq: (e.entry_hash, i) for i, e in enumerate(entries, 1)}
    prev = ledger.GENESIS
    for expected, cp in enumerate(checkpoints, 1):
        failure = {"ok": False, "entries": len(entries), "checkpoint": cp.number, "at_seq": cp.upto_seq}
        if cp.number != expected:
            return {**failure, "checkpoint": expected, "reason": "a signed checkpoint is missing"}
        if cp.key_fingerprint not in trusted:
            return {**failure, "reason": "checkpoint signed by an untrusted key"}
        try:
            claims = jwt.decode(cp.jws, cp.public_pem, algorithms=["ES256"], options={"require": ["iat"]})
        except jwt.InvalidTokenError:
            return {**failure, "reason": "checkpoint signature does not verify"}
        if claims.get("key_fingerprint") != cp.key_fingerprint or any(
            claims.get(k) != getattr(cp, k) for k in ("number", "upto_seq", "entries", "tip", "prev")
        ):
            return {**failure, "reason": "checkpoint does not match its signed content"}
        if cp.prev != prev:
            return {**failure, "reason": "checkpoint chain broken"}
        if tips.get(cp.upto_seq) != (cp.tip, cp.entries):
            return {**failure, "reason": "ledger history differs from this signed checkpoint"}
        prev = hashlib.sha256(cp.jws.encode()).hexdigest()
    last = checkpoints[-1] if checkpoints else None
    return {
        **result,
        "checkpoints": len(checkpoints),
        "signed_upto_seq": last.upto_seq if last else None,
        "unsigned_tail": len(entries) - (last.entries if last else 0),
        "anchored": sum(cp.anchor_status == "anchored" for cp in checkpoints),
    }


async def load(s: AsyncSession) -> tuple[list[LedgerEntry], list[LedgerCheckpoint]]:
    entries = (await s.scalars(select(LedgerEntry).order_by(LedgerEntry.seq))).all()
    cps = (await s.scalars(select(LedgerCheckpoint).order_by(LedgerCheckpoint.number))).all()
    return list(entries), list(cps)


def router() -> APIRouter:
    r = APIRouter(tags=["evidence"])

    @r.get("/.well-known/aegis-ledger-key")
    async def published_key(request: Request):
        """The public half of the ledger key, published so auditors can pin it independently of any pack."""
        key = request.app.state.ctx.ledger_key
        return {"alg": "ES256", "fingerprint": key.fingerprint, "public_pem": key.public_pem}

    @r.get("/v1/ledger/checkpoints", dependencies=[Depends(require_roles(*OPERATORS))])
    async def list_checkpoints(request: Request, limit: int = 20, s: AsyncSession = Depends(session)):
        c: ControlContext = request.app.state.ctx
        rows = (
            await s.scalars(select(LedgerCheckpoint).order_by(LedgerCheckpoint.number.desc()).limit(min(limit, 200)))
        ).all()
        return {
            "key": {"fingerprint": c.ledger_key.fingerprint, "persistent": bool(c.settings.ledger_signing_key_path)},
            "interval_seconds": c.settings.ledger_checkpoint_interval,
            "anchoring": {"configured": bool(c.settings.tsa_url), "tsa_url": c.settings.tsa_url or None},
            "checkpoints": [checkpoint_dict(cp) for cp in rows],
        }

    @r.post("/v1/ledger/checkpoints")
    async def checkpoint_now(request: Request, _=Depends(require_roles("auditor", "admin"))):
        c: ControlContext = request.app.state.ctx
        try:
            cp = await create(c)
        except LedgerBroken as exc:
            raise HTTPException(409, f"The ledger does not verify at entry {exc.seq}; it was not signed") from exc
        if cp is None:
            raise HTTPException(409, "The ledger has no entries to sign yet")
        await anchor_pending(c, [cp.number])
        async with c.db.sessionmaker() as s:
            return checkpoint_dict(await s.get(LedgerCheckpoint, cp.id))

    return r
