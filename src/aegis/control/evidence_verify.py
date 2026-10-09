"""Standalone verifier embedded in Aegis demo evidence packs.

Usage after extracting this file from the ZIP:

    python verify_pack.py aegis-evidence-....zip --key <evidence-key-fingerprint>

It checks the ES256 signature, file hashes/counts and signed source checkpoint. V3 packs disclose selected
ledger entries using Merkle inclusion proofs; the server verifies the full source chain, while this verifier
does NOT recompute undisclosed contents. Older V2 packs still receive full-chain verification. Pass --key with
the fingerprint Aegis publishes at
/v1/evidence/key (or one you recorded earlier) to prove WHO signed the pack; without it the pack is only proven
intact and self-consistent. Hashing uses the standard library; the signature check needs the `cryptography` package
(pip install cryptography). --skip-signatures checks everything else when that package is unavailable.
"""

import argparse
import base64
import hashlib
import io
import json
import sys
import zipfile

FORMAT = "aegis-demo-evidence-pack-v2"
SCOPED_FORMAT = "aegis-scoped-evidence-pack-v3"
GENESIS = "0" * 64


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _entry_hash(previous: str, entry: dict) -> str:
    value = {"prev": previous, "ts": entry["ts"], "type": entry["event_type"],
             "actor": entry["actor"], "subject": entry["subject"], "payload": entry["payload"]}
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return _digest(canonical.encode("utf-8"))


def thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of an EC public key: the evidence key's fingerprint."""
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()


def verify_jws(token: str, jwk: dict) -> dict:
    """Claims of a compact ES256 JWS made by this P-256 key; raise ValueError if the signature does not hold."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ImportError as exc:
        raise ValueError("signature check needs the 'cryptography' package (pip install cryptography); "
                         "or run with --skip-signatures") from exc
    try:
        head, body, signature = token.strip().split(".")
        header = json.loads(_b64decode(head))
        raw = _b64decode(signature)
    except (ValueError, TypeError) as exc:
        raise ValueError("malformed signature") from exc
    if header.get("alg") != "ES256" or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or len(raw) != 64:
        raise ValueError("unexpected signature algorithm or key type")
    if header.get("kid") != thumbprint(jwk):
        raise ValueError("signed by a different key")
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_b64decode(jwk["x"]), "big"), int.from_bytes(_b64decode(jwk["y"]), "big"), ec.SECP256R1()
    )
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        numbers.public_key().verify(der, f"{head}.{body}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("signature does not verify") from exc
    return json.loads(_b64decode(body))


def verify_pack(source, expected_key: str | None = None, check_signatures: bool = True) -> dict:
    """Verify signature, member hashes, record counts, the audit chain and its checkpoints; raise on a mismatch."""
    if isinstance(source, bytes):
        source = io.BytesIO(source)
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or not {"manifest.json", "signature.jws"} <= set(names):
            raise ValueError("Duplicate members, or missing manifest or signature")
        manifest_bytes = archive.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        if manifest.get("format") not in (FORMAT, SCOPED_FORMAT):
            raise ValueError("Unsupported evidence pack format")
        if set(names) != set(manifest["files"]) | {"manifest.json", "signature.jws"}:
            raise ValueError("Archive member list does not match manifest")

        jwk = manifest["evidence_key"]["jwk"]
        fingerprint = thumbprint(jwk)
        if fingerprint != manifest["evidence_key"]["fingerprint"]:
            raise ValueError("Evidence key fingerprint does not match its key")
        if expected_key is not None and fingerprint != expected_key.strip():
            raise ValueError(f"Signed by key {fingerprint}, not the expected {expected_key.strip()}")
        if check_signatures:
            claims = verify_jws(archive.read("signature.jws").decode("ascii"), jwk)
            if claims.get("typ") != "aegis-evidence-pack" or claims.get("manifest_sha256") != _digest(manifest_bytes):
                raise ValueError("Signature does not cover this manifest")

        for name, metadata in manifest["files"].items():
            data = archive.read(name)
            if len(data) != metadata["bytes"] or _digest(data) != metadata["sha256"]:
                raise ValueError(f"File hash mismatch: {name}")
        for key, count in manifest["counts"].items():
            records = json.loads(archive.read(f"records/{key}.json"))
            if len(records) != count:
                raise ValueError(f"Record count mismatch: {key}")

        if manifest["format"] == SCOPED_FORMAT:
            return verify_scoped(archive, manifest, jwk, fingerprint, expected_key, check_signatures)

        entries = json.loads(archive.read("records/ledger.json"))
        previous = GENESIS
        for entry in entries:
            if entry["prev_hash"] != previous or entry["entry_hash"] != _entry_hash(previous, entry):
                raise ValueError(f"Audit chain broken at entry {entry['seq']}")
            previous = entry["entry_hash"]
        if manifest["ledger"] != {"ok": True, "entries": len(entries), "tip": previous}:
            raise ValueError("Ledger checkpoint does not match exported entries")

        checkpoints = json.loads(archive.read("records/checkpoints.json"))
        if manifest["checkpoint_id"] not in {c["id"] for c in checkpoints}:
            raise ValueError("The export's own checkpoint is missing")
        verified = other_key = 0
        for checkpoint in checkpoints:
            n = checkpoint["entries"]
            tip = entries[n - 1]["entry_hash"] if 0 < n <= len(entries) else GENESIS if n == 0 else None
            if tip != checkpoint["tip"]:
                raise ValueError(f"Ledger was rewritten after checkpoint {checkpoint['id']}")
            if checkpoint["key_fingerprint"] != fingerprint:
                other_key += 1  # signed before a key rotation; its key is not in this pack
                continue
            if check_signatures:
                claims = verify_jws(checkpoint["jws"], jwk)
                signed = (claims.get("typ"), claims.get("entries"), claims.get("tip"), claims.get("ts"))
                if signed != ("aegis-ledger-checkpoint", n, checkpoint["tip"], checkpoint["ts"]):
                    raise ValueError(f"Checkpoint {checkpoint['id']} differs from what was signed")
            verified += 1
        return {
            "ok": True,
            "files": len(manifest["files"]),
            "entries": len(entries),
            "tip": previous,
            "key": fingerprint,
            "key_pinned": expected_key is not None,
            "signatures_checked": check_signatures,
            "checkpoints": verified,
            "checkpoints_other_key": other_key,
        }


def verify_scoped(archive, manifest, jwk, fingerprint, expected_key, signatures):
    """Verify selective disclosure against a signed root, not the undisclosed contents of the source chain."""
    entries = json.loads(archive.read("records/ledger.json"))
    tree = json.loads(archive.read("ledger_proofs.json"))
    anchor = manifest["ledger"]
    n = tree["source_entries"]
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise ValueError("Invalid source ledger length")
    if (tree["algorithm"] != "sha256-domain-separated-v1" or anchor.get("ok") is not True
            or anchor.get("proof_mode") != "signed-merkle-inclusion" or anchor["entries"] != n
            or anchor["merkle_root"] != tree["root"] or anchor["disclosed_entries"] != len(entries)
            or len(tree["proofs"]) != len(entries)):
        raise ValueError("Ledger inclusion anchor mismatch")
    if n == 0 and (entries or tree["root"] != _digest(b"\x00aegis-empty-ledger") or anchor["tip"] != GENESIS):
        raise ValueError("Invalid empty ledger proof")
    previous_seq = previous_index = -1
    previous_hash = None
    for entry, proof in zip(entries, tree["proofs"], strict=True):
        seq, index = entry["seq"], proof["index"]
        if not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(index, int) or isinstance(index, bool):
            raise ValueError("Ledger sequence and proof index must be integers")
        if (proof["seq"] != seq or seq <= previous_seq or not previous_index < index < n
                or entry["entry_hash"] != _entry_hash(entry["prev_hash"], entry)):
            raise ValueError("Invalid disclosed ledger entry or proof order")
        value = _digest(b"\x00" + f"{seq}:{entry['entry_hash']}".encode("ascii"))
        cursor, width = index, n
        for sibling in proof["siblings"]:
            if width <= 1:
                raise ValueError("Unexpected ledger proof depth")
            left, right = (sibling, value) if cursor % 2 else (value, sibling)
            if cursor % 2 == 0 and cursor + 1 >= width and sibling != value:
                raise ValueError("Invalid odd ledger-tree node")
            value = _digest(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))
            cursor //= 2
            width = (width + 1) // 2
        if width != 1 or value != tree["root"]:
            raise ValueError("Ledger inclusion proof does not verify")
        if index == 0 and entry["prev_hash"] != GENESIS:
            raise ValueError("Invalid ledger genesis")
        if previous_hash is not None and index == previous_index + 1 and entry["prev_hash"] != previous_hash:
            raise ValueError("Disclosed adjacent entries do not chain")
        if index == n - 1 and entry["entry_hash"] != anchor["tip"]:
            raise ValueError("Ledger tip mismatch")
        previous_seq, previous_index, previous_hash = seq, index, entry["entry_hash"]
    checkpoints = json.loads(archive.read("records/checkpoints.json"))
    own = [c for c in checkpoints if c["id"] == manifest["checkpoint_id"]]
    if len(own) != 1:
        raise ValueError("The export's own checkpoint is missing or duplicated")
    checkpoint = own[0]
    if (checkpoint["entries"], checkpoint["tip"], checkpoint["key_fingerprint"]) != (n, anchor["tip"], fingerprint):
        raise ValueError("Source checkpoint differs from ledger anchor")
    if signatures:
        claims = verify_jws(checkpoint["jws"], jwk)
        if (claims.get("typ"), claims.get("entries"), claims.get("tip"), claims.get("ts"), claims.get("signed_by")) != (
            "aegis-ledger-checkpoint", n, anchor["tip"], checkpoint["ts"], checkpoint["signed_by"]
        ):
            raise ValueError("Source checkpoint differs from its signature")
    return {"ok": True, "files": len(manifest["files"]), "entries": len(entries), "source_entries": n,
            "tip": anchor["tip"], "key": fingerprint, "key_pinned": expected_key is not None,
            "signatures_checked": signatures, "checkpoints": 1, "checkpoints_other_key": 0,
            "proof_mode": "signed-merkle-inclusion", "full_chain_recomputed": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify an Aegis evidence pack")
    parser.add_argument("pack")
    parser.add_argument("--key", help="expected evidence-key fingerprint (from /v1/evidence/key)")
    parser.add_argument("--skip-signatures", action="store_true", help="check hashes and chain only")
    args = parser.parse_args(argv)
    try:
        result = verify_pack(args.pack, args.key, check_signatures=not args.skip_signatures)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(f"FAILED: {exc}")
        return 1
    signed = "signature verified" if result["signatures_checked"] else "SIGNATURES NOT CHECKED"
    who = "key pinned" if result["key_pinned"] else "key NOT pinned: compare it with /v1/evidence/key"
    print(f"VERIFIED: {result['files']} files, {result['entries']} ledger entries, tip {result['tip']}")
    print(f"  {signed}; evidence key {result['key']} ({who})")
    earlier = f"; {result['checkpoints_other_key']} signed by an earlier key" if result["checkpoints_other_key"] else ""
    print(f"  {result['checkpoints']} signed checkpoints match the chain{earlier}")
    if result.get("proof_mode") == "signed-merkle-inclusion":
        print(f"  {result['entries']} disclosed entries included in {result['source_entries']} source entries; "
              "undisclosed chain contents were verified by the server, not recomputed here")
    return 0


if __name__ == "__main__":
    sys.exit(main())
