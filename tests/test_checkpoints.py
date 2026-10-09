"""Signed ledger checkpoints, external RFC 3161 anchoring, and the signed evidence pack."""

import asyncio
import hashlib
import io
import json
import zipfile

import pytest
from sqlalchemy import select

from aegis.common.crypto import SigningKey
from aegis.control import checkpoints, evidence_verify, ledger
from aegis.control.evidence_verify import key_fingerprint, parse_timestamp_response, verify_pack
from aegis.control.tables import LedgerCheckpoint, LedgerEntry
from fake_tsa import FakeTsa

TSA_URL = "http://tsa.test/"


async def rewrite_history(world, seq: int) -> None:
    """The insider attack: change one entry and recompute every later hash so the chain looks intact."""
    async with world.ctx.db.sessionmaker() as s:
        entries = (await s.scalars(select(LedgerEntry).order_by(LedgerEntry.seq))).all()
        prev = ledger.GENESIS
        for e in entries:
            if e.seq == seq:
                e.payload = {**e.payload, "rewritten": True}
            if e.seq >= seq:
                e.prev_hash = prev
                e.entry_hash = ledger.entry_hash(prev, e.ts, e.event_type, e.actor, e.subject, e.payload)
            prev = e.entry_hash
        await s.commit()


async def checkpoint_rows(world) -> list[LedgerCheckpoint]:
    async with world.ctx.db.sessionmaker() as s:
        return list((await s.scalars(select(LedgerCheckpoint).order_by(LedgerCheckpoint.number))).all())


async def download(world) -> bytes:
    response = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    assert response.status_code == 200, response.text
    return response.content


def use_tsa(world, tsa: FakeTsa) -> None:
    world.ctx.settings = world.ctx.settings.model_copy(update={"tsa_url": TSA_URL})
    world.ctx.tsa_http = tsa.client()


def test_verifier_computes_the_same_key_fingerprint_as_the_server():
    key = SigningKey.generate_ephemeral("ledger-1")
    assert key_fingerprint(key.public_pem) == key.fingerprint


async def test_checkpoints_sign_the_tip_and_chain_to_each_other(world):
    first = await checkpoints.create(world.ctx)
    assert first.number == 1 and first.prev == ledger.GENESIS
    assert first.key_fingerprint == world.ctx.ledger_key.fingerprint and first.anchor_status == "not_configured"
    assert (await checkpoints.create(world.ctx)).number == 1  # nothing new: no new checkpoint

    await world.api("mark.jansen", "POST", "/v1/discovery/scan")  # any governed action appends to the ledger
    world.ctx.idp.register_unmanaged_client("rogue-bot", "Rogue bot")
    await world.api("mark.jansen", "POST", "/v1/discovery/scan")
    second = await checkpoints.create(world.ctx)
    assert second.number == 2 and second.prev == hashlib.sha256(first.jws.encode()).hexdigest()
    assert second.upto_seq > first.upto_seq

    verified = (await world.api("mark.jansen", "GET", "/v1/ledger/verify")).json()
    assert verified["ok"] and verified["checkpoints"] == 2 and verified["signed_upto_seq"] == second.upto_seq


async def test_rewritten_history_is_caught_although_every_hash_was_recomputed(world):
    await checkpoints.create(world.ctx)
    await rewrite_history(world, 3)

    async with world.ctx.db.sessionmaker() as s:
        assert (await ledger.verify(s))["ok"] is True  # the plain hash chain is fooled
    verified = (await world.api("mark.jansen", "GET", "/v1/ledger/verify")).json()
    assert verified["ok"] is False and verified["checkpoint"] == 1
    assert verified["reason"] == "ledger history differs from this signed checkpoint"

    refused = await world.api("eva.visser", "GET", "/v1/evidence/pack")
    assert refused.status_code == 409 and "verification failed" in refused.json()["detail"]
    with pytest.raises(checkpoints.LedgerBroken):  # and Aegis will not sign the rewritten tip
        await checkpoints.create(world.ctx)


async def test_a_checkpoint_resigned_with_another_key_is_not_trusted(world):
    cp = await checkpoints.create(world.ctx)
    attacker = SigningKey.generate_ephemeral("ledger-1")
    claims = {k: getattr(cp, k) for k in ("number", "upto_seq", "entries", "tip", "prev")}
    async with world.ctx.db.sessionmaker() as s:
        row = await s.get(LedgerCheckpoint, cp.id)
        row.public_pem, row.key_fingerprint = attacker.public_pem, attacker.fingerprint
        row.jws = attacker.sign({**claims, "typ": "aegis-ledger-checkpoint", "key_fingerprint": attacker.fingerprint,
                                 "iat": 1})
        await s.commit()
    verified = (await world.api("mark.jansen", "GET", "/v1/ledger/verify")).json()
    assert verified["ok"] is False and verified["reason"] == "checkpoint signed by an untrusted key"


async def test_a_deleted_checkpoint_is_noticed(world):
    await checkpoints.create(world.ctx)
    world.ctx.idp.register_unmanaged_client("rogue-bot", "Rogue bot")
    await world.api("mark.jansen", "POST", "/v1/discovery/scan")
    await checkpoints.create(world.ctx)
    async with world.ctx.db.sessionmaker() as s:
        await s.delete((await s.scalars(select(LedgerCheckpoint).where(LedgerCheckpoint.number == 1))).one())
        await s.commit()
    verified = (await world.api("mark.jansen", "GET", "/v1/ledger/verify")).json()
    assert verified["ok"] is False and verified["reason"] == "a signed checkpoint is missing"


async def test_signed_pack_verifies_and_pins_the_published_key(world):
    published = (await world.http.get(f"{world.settings.control_url}/.well-known/aegis-ledger-key")).json()
    assert published["fingerprint"] == world.ctx.ledger_key.fingerprint

    result = verify_pack(await download(world), expect_key=published["fingerprint"])
    assert result["signed"] and result["signatures_checked"]
    assert result["keys"] == [published["fingerprint"]] and result["manifest_key"] == published["fingerprint"]
    assert result["checkpoints"] >= 1 and result["unsigned_tail"] == 0 and result["anchored"] == 0

    other = SigningKey.generate_ephemeral("x").fingerprint
    with pytest.raises(ValueError, match="expected key"):
        verify_pack(await download(world), expect_key=other)


def rewrite_member(pack: bytes, name: str, change) -> bytes:
    """Change one file, then recompute its hash in the manifest, as a careful forger would."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(pack)) as original, zipfile.ZipFile(out, "w") as changed:
        manifest = json.loads(original.read("manifest.json"))
        data = change(original.read(name))
        manifest["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        for member in original.namelist():
            if member == "manifest.json":
                changed.writestr(member, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            else:
                changed.writestr(member, data if member == name else original.read(member))
    return out.getvalue()


async def test_a_forger_who_recomputes_the_manifest_is_still_caught(world):
    def new_owner(data: bytes) -> bytes:
        assert b'"owner": "niels.vandijk"' in data
        return data.replace(b'"owner": "niels.vandijk"', b'"owner": "someone.else"', 1)

    forged = rewrite_member(await download(world), "records/agents.json", new_owner)
    with pytest.raises(ValueError, match="Manifest signature does not cover this manifest"):
        verify_pack(forged)


async def test_without_cryptography_the_verifier_says_signatures_were_not_checked(world, monkeypatch):
    pack = await download(world)
    monkeypatch.setattr(evidence_verify, "x509", None)
    result = verify_pack(pack)
    assert result["ok"] and result["signatures_checked"] is False


async def test_checkpoint_is_timestamped_by_an_external_authority(world):
    tsa = FakeTsa()
    use_tsa(world, tsa)
    made = await world.api("eva.visser", "POST", "/v1/ledger/checkpoints")
    assert made.status_code == 200
    cp = made.json()
    assert cp["anchor_status"] == "anchored" and cp["anchored_at"].endswith("Z")
    assert cp["tsa_signer"] == "CN=Aegis Test TSA"

    [row] = await checkpoint_rows(world)
    [request] = tsa.requests  # only a digest leaves the bank, never ledger content
    assert hashlib.sha256(row.jws.encode()).digest() in request and len(request) < 100

    result = verify_pack(await download(world))
    assert result["anchored"] >= 1
    anchor = result["anchors"][0]
    assert anchor["status"] == "valid" and anchor["signer"] == "CN=Aegis Test TSA" and anchor["checkpoint"] == 1


async def test_unreachable_authority_leaves_the_checkpoint_pending_then_retries(world):
    tsa = FakeTsa()
    tsa.mode = "down"
    use_tsa(world, tsa)
    cp = (await world.api("eva.visser", "POST", "/v1/ledger/checkpoints")).json()
    assert cp["anchor_status"] == "pending" and cp["anchor_error"] == "ConnectError"
    assert verify_pack(await download(world))["anchored"] == 0  # signed, honestly not anchored

    tsa.mode = "ok"
    assert await checkpoints.anchor_pending(world.ctx) >= 1
    assert all(r.anchor_status == "anchored" for r in await checkpoint_rows(world))


@pytest.mark.parametrize("mode, error", [("wrong_imprint", "AnchorMismatch"), ("refuse", "ValueError")])
async def test_a_timestamp_that_does_not_cover_the_checkpoint_is_rejected(world, mode, error):
    tsa = FakeTsa()
    tsa.mode = mode
    use_tsa(world, tsa)
    cp = (await world.api("eva.visser", "POST", "/v1/ledger/checkpoints")).json()
    assert cp["anchor_status"] == "pending" and cp["anchor_error"] == error


def test_a_tampered_timestamp_token_fails_its_signature_check():
    tsa = FakeTsa()
    digest = hashlib.sha256(b"checkpoint").digest()
    response = tsa.respond(checkpoints.timestamp_request(digest, 7))
    token = parse_timestamp_response(response)
    assert evidence_verify.verify_timestamp_signature(token)["status"] == "valid"
    assert token["imprint"] == digest and token["nonce"] == 7
    forged = {**token, "signature": token["signature"][:-1] + bytes([token["signature"][-1] ^ 1])}
    assert evidence_verify.verify_timestamp_signature(forged)["status"] == "invalid"
    altered = {**token, "tst_info": token["tst_info"].replace(digest, hashlib.sha256(b"x").digest())}
    assert evidence_verify.verify_timestamp_signature(altered)["status"] == "invalid"


async def test_background_loop_signs_new_entries(world):
    world.ctx.settings = world.ctx.settings.model_copy(update={"ledger_checkpoint_interval": 1})
    loop = asyncio.create_task(checkpoints.checkpoint_periodically(world.ctx))
    try:
        for _ in range(50):
            if await checkpoint_rows(world):
                break
            await asyncio.sleep(0.05)
        assert len(await checkpoint_rows(world)) == 1
    finally:
        loop.cancel()
        with pytest.raises(asyncio.CancelledError):
            await loop


async def test_only_staff_see_checkpoints_and_only_auditors_or_admins_create_them(world):
    assert (await world.api("jan.devries", "GET", "/v1/ledger/checkpoints")).status_code == 403
    assert (await world.api("mark.jansen", "POST", "/v1/ledger/checkpoints")).status_code == 403
    listed = (await world.api("mark.jansen", "GET", "/v1/ledger/checkpoints")).json()
    assert listed["key"]["fingerprint"] == world.ctx.ledger_key.fingerprint
    assert listed["anchoring"] == {"configured": False, "tsa_url": None}
