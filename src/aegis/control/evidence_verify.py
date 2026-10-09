"""Standalone verifier embedded in Aegis demo evidence packs.

Usage after extracting this file from the ZIP:

    python verify_pack.py aegis-evidence-....zip --key <evidence-key-fingerprint>

It checks the ES256 signature on the manifest, every file hash and record count, the audit ledger's hash chain, and
every signed ledger checkpoint against that chain. Pass --key with the fingerprint Aegis publishes at
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
        if manifest.get("format") != FORMAT:
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
