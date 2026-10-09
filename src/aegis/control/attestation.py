"""Signed evidence: ledger checkpoints and evidence-pack signatures, made with the dedicated evidence key.

A checkpoint is a compact ES256 JWS saying "at time T the audit ledger held N entries ending in hash H". It is stored
and exported, so if anyone later rewrites the chain (even recomputing every hash), the signed checkpoint no longer
matches. The JWS header's `kid` is the key's RFC 7638 thumbprint, so a verifier can pin the exact key.

What this does not give: the key is a local PEM file (no HSM or Key Vault) and there is no trusted timestamp, so it
proves "signed by the holder of this key", not "signed no later than T" to a third party.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common import crypto
from aegis.common.crypto import SigningKey
from aegis.control import ledger
from aegis.control.tables import LedgerCheckpoint, LedgerEntry

CHECKPOINT = "aegis-ledger-checkpoint"
PACK = "aegis-evidence-pack"


def public_key(key: SigningKey) -> dict[str, Any]:
    """The evidence key's public half as a JWK whose kid is its thumbprint (the value to pin)."""
    return crypto.public_jwk(key.public_pem)


def sign(key: SigningKey, claims: dict[str, Any]) -> str:
    return jwt.encode(claims, key.private_pem, algorithm=crypto.ALGORITHM, headers={"kid": key.fingerprint})


def verify(token: str, key: SigningKey, kind: str) -> dict[str, Any]:
    """Claims of a JWS this key signed for `kind`; raises jwt.InvalidTokenError otherwise."""
    if crypto.unverified_header(token).get("kid") != key.fingerprint:
        raise jwt.InvalidTokenError("signed by a different evidence key")
    claims = jwt.decode(token, key.public_pem, algorithms=[crypto.ALGORITHM], options={"require": ["iat"]})
    if claims.get("typ") != kind:
        raise jwt.InvalidTokenError(f"not an {kind} signature")
    return claims


async def create_checkpoint(s: AsyncSession, key: SigningKey, actor: str, issuer: str) -> LedgerCheckpoint:
    """Sign the ledger as it stands now. Refuses (ValueError) to vouch for a chain that does not verify."""
    entries = (await s.execute(select(LedgerEntry).order_by(LedgerEntry.seq))).scalars().all()
    integrity = ledger.verify_entries(entries)
    if not integrity["ok"]:
        raise ValueError(f"the audit ledger does not verify (broken at entry {integrity['broken_at_seq']})")
    return await record_checkpoint(s, key, actor, issuer, integrity["entries"], integrity["tip"])


async def record_checkpoint(
    s: AsyncSession, key: SigningKey, actor: str, issuer: str, entries: int, tip: str
) -> LedgerCheckpoint:
    """Store a signed checkpoint for a chain state the caller has already verified."""
    now = datetime.now(UTC)
    ts = now.isoformat()
    claims = {"typ": CHECKPOINT, "iss": issuer, "iat": int(now.timestamp()), "ts": ts, "entries": entries,
              "tip": tip, "signed_by": actor}
    row = LedgerCheckpoint(entries=entries, tip=tip, ts=ts, signed_by=actor, key_fingerprint=key.fingerprint,
                           jws=sign(key, claims))
    s.add(row)
    await s.flush()
    return row


def checkpoint_status(checkpoint: LedgerCheckpoint, entries: list[LedgerEntry], key: SigningKey) -> dict[str, Any]:
    """Does this checkpoint's signature hold, and does today's chain still contain the state it signed?"""
    out = {"id": checkpoint.id, "entries": checkpoint.entries, "tip": checkpoint.tip, "ts": checkpoint.ts,
           "signed_by": checkpoint.signed_by, "key_fingerprint": checkpoint.key_fingerprint}
    try:
        claims = verify(checkpoint.jws, key, CHECKPOINT)
    except jwt.InvalidTokenError as exc:
        return out | {"ok": False, "problem": f"signature: {exc}"}
    if (claims["entries"], claims["tip"], claims["ts"]) != (checkpoint.entries, checkpoint.tip, checkpoint.ts):
        return out | {"ok": False, "problem": "the stored row differs from what was signed"}
    if checkpoint.entries > len(entries):
        return out | {"ok": False, "problem": f"the ledger now has fewer than {checkpoint.entries} entries"}
    tip = entries[checkpoint.entries - 1].entry_hash if checkpoint.entries else ledger.GENESIS
    if tip != checkpoint.tip:
        return out | {"ok": False, "problem": f"the ledger was rewritten at or before entry {checkpoint.entries}"}
    return out | {"ok": True}


def checkpoint_record(row: LedgerCheckpoint) -> dict[str, Any]:
    return {"id": row.id, "entries": row.entries, "tip": row.tip, "ts": row.ts, "signed_by": row.signed_by,
            "key_fingerprint": row.key_fingerprint, "jws": row.jws}
