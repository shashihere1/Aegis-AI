"""Standalone verifier embedded in Aegis evidence packs.

The file hashes and the audit chain are checked with the Python standard library alone. Signatures (signed ledger
checkpoints, the signed manifest and RFC 3161 timestamp tokens) are checked when the `cryptography` package is
installed; without it the result says plainly that signatures were not checked.

Usage after extracting this file from the ZIP:
    python verify_pack.py aegis-evidence-....zip [--expect-key <ledger key fingerprint>]
"""

import base64
import hashlib
import io
import json
import sys
import zipfile
from datetime import datetime

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
except ImportError:  # the chain and hashes still verify; signatures are reported as not checked
    x509 = None

GENESIS = "0" * 64
V1, V2 = "aegis-demo-evidence-pack-v1", "aegis-evidence-pack-v2"

SIGNED_DATA = "1.2.840.113549.1.7.2"
TST_INFO = "1.2.840.113549.1.9.16.1.4"
MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
SHA256 = "2.16.840.1.101.3.4.2.1"
HASH_NAMES = {"1.3.14.3.2.26": "SHA1", SHA256: "SHA256", "2.16.840.1.101.3.4.2.2": "SHA384",
              "2.16.840.1.101.3.4.2.3": "SHA512"}
RSA_SIGNATURES = {"1.2.840.113549.1.1.1": None, "1.2.840.113549.1.1.5": "SHA1", "1.2.840.113549.1.1.11": "SHA256",
                  "1.2.840.113549.1.1.12": "SHA384", "1.2.840.113549.1.1.13": "SHA512"}
EC_SIGNATURES = {"1.2.840.10045.4.3.2": "SHA256", "1.2.840.10045.4.3.3": "SHA384", "1.2.840.10045.4.3.4": "SHA512"}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry_hash(previous: str, entry: dict) -> str:
    value = {"prev": previous, "ts": entry["ts"], "type": entry["event_type"],
             "actor": entry["actor"], "subject": entry["subject"], "payload": entry["payload"]}
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return _digest(canonical.encode("utf-8"))


# ---- minimal DER reader (enough for RFC 3161 timestamp tokens) ----------------------------------------------


class Der:
    """One DER element: tag, the bytes of its value, and its full encoding."""

    def __init__(self, data: bytes, pos: int = 0, limit: int | None = None):
        limit = len(data) if limit is None else limit
        if pos + 2 > limit:
            raise ValueError("Truncated DER")
        self.tag = data[pos]
        if self.tag & 0x1F == 0x1F:
            raise ValueError("Multi-byte DER tags are not supported")
        length, start = data[pos + 1], pos + 2
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4:
                raise ValueError("Unsupported DER length")
            length, start = int.from_bytes(data[start:start + count], "big"), start + count
        self.end = start + length
        if self.end > limit:
            raise ValueError("Truncated DER")
        self.data, self.pos, self.start = data, pos, start

    @property
    def value(self) -> bytes:
        return self.data[self.start:self.end]

    @property
    def raw(self) -> bytes:
        return self.data[self.pos:self.end]

    def children(self) -> list["Der"]:
        out, pos = [], self.start
        while pos < self.end:
            child = Der(self.data, pos, self.end)
            out.append(child)
            pos = child.end
        return out


def _oid(value: bytes) -> str:
    parts, n = [], 0
    for byte in value:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(n)
            n = 0
    head = min(parts[0] // 40, 2)
    return ".".join(str(p) for p in [head, parts[0] - 40 * head, *parts[1:]])


def _generalized_time(value: bytes) -> str:
    text = value.decode("ascii")
    if not text.endswith("Z"):
        raise ValueError("Timestamp time is not in UTC")
    main, _, fraction = text[:-1].partition(".")
    moment = datetime.strptime(main, "%Y%m%d%H%M%S")
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + (f".{fraction}" if fraction else "") + "Z"


def parse_timestamp_token(token: bytes) -> dict:
    """The fields of an RFC 3161 TimeStampToken (CMS SignedData around a TSTInfo) needed to check it."""
    content_type, content = Der(token).children()[:2]
    if _oid(content_type.value) != SIGNED_DATA or content.tag != 0xA0:
        raise ValueError("Timestamp token is not CMS SignedData")
    signed = content.children()[0].children()
    e_type, e_content = signed[2].children()[:2]
    if _oid(e_type.value) != TST_INFO:
        raise ValueError("Timestamp token does not contain a TSTInfo")
    tst_info = e_content.children()[0].value
    fields = Der(tst_info).children()
    imprint = fields[2].children()
    certificates, signer_infos = [], []
    for element in signed[3:]:
        if element.tag == 0xA0:
            certificates = [c.raw for c in element.children() if c.tag == 0x30]
        elif element.tag == 0x31:
            signer_infos = element.children()
    if not signer_infos:
        raise ValueError("Timestamp token has no signer")
    signer = signer_infos[0].children()
    index, signed_attrs, message_digest = 3, None, None
    if signer[3].tag == 0xA0:
        signed_attrs = b"\x31" + signer[3].raw[1:]  # signed as an explicit SET OF (RFC 5652 §5.4)
        for attribute in signer[3].children():
            oid, values = attribute.children()[:2]
            if _oid(oid.value) == MESSAGE_DIGEST:
                message_digest = values.children()[0].value
        index = 4
    sid = signer[1]
    serial = int.from_bytes(sid.children()[1].value, "big") if sid.tag == 0x30 else None
    return {
        "imprint_alg": _oid(imprint[0].children()[0].value),
        "imprint": imprint[1].value,
        "serial": int.from_bytes(fields[3].value, "big"),
        "gen_time": _generalized_time(fields[4].value),
        "nonce": next((int.from_bytes(f.value, "big") for f in fields[5:] if f.tag == 0x02), None),
        "tst_info": tst_info,
        "certificates": certificates,
        "signer_serial": serial,
        "digest_alg": _oid(signer[2].children()[0].value),
        "signed_attrs": signed_attrs,
        "message_digest": message_digest,
        "signature_alg": _oid(signer[index].children()[0].value),
        "signature": signer[index + 1].value,
    }


def parse_timestamp_response(response: bytes) -> dict:
    """An RFC 3161 TimeStampResp: refuse anything but granted, then parse its token."""
    parts = Der(response).children()
    status = int.from_bytes(parts[0].children()[0].value, "big")
    if status not in (0, 1):
        raise ValueError(f"The timestamp authority refused the request (status {status})")
    if len(parts) < 2:
        raise ValueError("Timestamp response carries no token")
    return parse_timestamp_token(parts[1].raw)


def verify_timestamp_signature(token: dict) -> dict:
    """Check the TSA's signature over the token with the certificate inside it.

    This proves the token was signed by that certificate's key. Whether that certificate belongs to a trusted
    timestamp authority is a separate chain check (openssl ts -verify ... -CAfile <tsa-ca.pem>)."""
    if x509 is None:
        return {"status": "not checked", "reason": "install the 'cryptography' package to check signatures"}
    algorithm = HASH_NAMES.get(token["digest_alg"])
    if algorithm is None or token["signed_attrs"] is None or token["message_digest"] is None:
        return {"status": "not checked", "reason": "unsupported token layout; verify with openssl ts -verify"}
    if hashlib.new(algorithm.lower(), token["tst_info"]).digest() != token["message_digest"]:
        return {"status": "invalid", "reason": "token content does not match its signed digest"}
    if not token["certificates"]:
        return {"status": "not checked", "reason": "token carries no TSA certificate; verify with openssl ts -verify"}
    for der_cert in token["certificates"]:
        cert = x509.load_der_x509_certificate(der_cert)
        if token["signer_serial"] is not None and cert.serial_number != token["signer_serial"]:
            continue
        key, alg = cert.public_key(), token["signature_alg"]
        try:
            if isinstance(key, rsa.RSAPublicKey) and alg in RSA_SIGNATURES:
                chosen = getattr(hashes, RSA_SIGNATURES[alg] or algorithm)()
                key.verify(token["signature"], token["signed_attrs"], padding.PKCS1v15(), chosen)
            elif isinstance(key, ec.EllipticCurvePublicKey) and alg in EC_SIGNATURES:
                key.verify(token["signature"], token["signed_attrs"], ec.ECDSA(getattr(hashes, EC_SIGNATURES[alg])()))
            else:
                return {"status": "not checked", "reason": f"signature algorithm {alg} not supported here"}
        except InvalidSignature:
            continue
        return {"status": "valid", "signer": cert.subject.rfc4514_string(),
                "cert_sha256": cert.fingerprint(hashes.SHA256()).hex()}
    return {"status": "invalid", "reason": "no certificate in the token verifies its signature"}


# ---- ES256 JWS (ledger checkpoints and the manifest signature) ------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jws_claims(token: str) -> dict:
    """The claims of a compact JWS without checking its signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a compact JWS")
    return json.loads(_b64url_decode(parts[1]))


def key_fingerprint(public_pem: str) -> str:
    """RFC 7638 thumbprint of a P-256 public key; the same value the Aegis server publishes."""
    numbers = serialization.load_pem_public_key(public_pem.encode()).public_numbers()
    jwk = {"crv": "P-256", "kty": "EC", "x": _b64url(numbers.x.to_bytes(32, "big")),
           "y": _b64url(numbers.y.to_bytes(32, "big"))}
    return _b64url(hashlib.sha256(json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()).digest())


def verify_jws(token: str, public_pem: str) -> dict:
    header, payload, signature = token.split(".")
    if json.loads(_b64url_decode(header)).get("alg") != "ES256":
        raise ValueError("Unexpected signature algorithm")
    raw = _b64url_decode(signature)
    if len(raw) != 64:
        raise ValueError("Malformed ES256 signature")
    key = serialization.load_pem_public_key(public_pem.encode())
    try:
        key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   f"{header}.{payload}".encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("Signature does not verify") from exc
    return json.loads(_b64url_decode(payload))


# ---- the pack -------------------------------------------------------------------------------------------------

CHECKPOINT_CLAIMS = ("number", "upto_seq", "entries", "tip", "prev", "key_fingerprint")


def _verify_checkpoints(checkpoints, keys, tips, read, signatures, expect_key):
    prev, used, anchors = GENESIS, set(), []
    for number, cp in enumerate(checkpoints, 1):
        if cp["number"] != number:
            raise ValueError(f"Signed checkpoint {number} is missing")
        fingerprint = cp["key_fingerprint"]
        if signatures:
            pem = keys.get(fingerprint)
            if pem is None or key_fingerprint(pem) != fingerprint:
                raise ValueError(f"Checkpoint {number} names a key that is not in the pack")
            claims = verify_jws(cp["jws"], pem)
        else:
            claims = jws_claims(cp["jws"])
        if expect_key and fingerprint != expect_key:
            raise ValueError(f"Checkpoint {number} is signed by key {fingerprint}, not the expected key")
        if any(claims.get(k) != cp[k] for k in CHECKPOINT_CLAIMS) or claims.get("typ") != "aegis-ledger-checkpoint":
            raise ValueError(f"Checkpoint {number} does not match its signed content")
        if cp["prev"] != prev:
            raise ValueError(f"Checkpoint chain broken at checkpoint {number}")
        if tips.get(cp["upto_seq"]) != (cp["tip"], cp["entries"]):
            raise ValueError(f"Ledger history differs from signed checkpoint {number} (entry {cp['upto_seq']})")
        prev = _digest(cp["jws"].encode())
        used.add(fingerprint)
        if cp["anchor_status"] == "anchored":
            token = parse_timestamp_response(read(cp["anchor_file"]))
            if token["imprint_alg"] != SHA256 or token["imprint"] != hashlib.sha256(cp["jws"].encode()).digest():
                raise ValueError(f"Timestamp for checkpoint {number} does not cover that checkpoint")
            check = verify_timestamp_signature(token)
            if check["status"] == "invalid":
                raise ValueError(f"Timestamp for checkpoint {number}: {check['reason']}")
            anchors.append({"checkpoint": number, "gen_time": token["gen_time"], "file": cp["anchor_file"],
                            "digest": hashlib.sha256(cp["jws"].encode()).hexdigest(), **check})
    return used, anchors


def verify_pack(source: str | bytes | io.BytesIO, expect_key: str | None = None) -> dict:
    """Verify member hashes, record counts, the audit chain and, for signed packs, every signature."""
    if isinstance(source, bytes):
        source = io.BytesIO(source)
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or "manifest.json" not in names:
            raise ValueError("Duplicate members or missing manifest")
        manifest_bytes = archive.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        fmt = manifest.get("format")
        if fmt not in (V1, V2):
            raise ValueError("Unsupported evidence pack format")
        expected = set(manifest["files"]) | {"manifest.json"} | ({"manifest.sig"} if fmt == V2 else set())
        if set(names) != expected:
            raise ValueError("Archive member list does not match manifest")
        for name, metadata in manifest["files"].items():
            data = archive.read(name)
            if len(data) != metadata["bytes"] or _digest(data) != metadata["sha256"]:
                raise ValueError(f"File hash mismatch: {name}")
        for key, count in manifest["counts"].items():
            records = json.loads(archive.read(f"records/{key}.json"))
            if len(records) != count:
                raise ValueError(f"Record count mismatch: {key}")
        entries = json.loads(archive.read("records/ledger.json"))
        previous, tips = GENESIS, {}
        for index, entry in enumerate(entries, 1):
            if entry["prev_hash"] != previous or entry["entry_hash"] != _entry_hash(previous, entry):
                raise ValueError(f"Audit chain broken at entry {entry['seq']}")
            previous = entry["entry_hash"]
            tips[entry["seq"]] = (previous, index)
        if {k: manifest["ledger"].get(k) for k in ("ok", "entries", "tip")} != {
                "ok": True, "entries": len(entries), "tip": previous}:
            raise ValueError("Ledger summary does not match exported entries")
        result = {"ok": True, "format": fmt, "files": len(manifest["files"]), "entries": len(entries),
                  "tip": previous}
        if fmt == V1:
            return {**result, "signed": False}

        signatures = x509 is not None
        keys = json.loads(archive.read("keys/ledger-keys.json"))
        signature = archive.read("manifest.sig").decode().strip()
        if signatures:
            fingerprint = jws_claims(signature).get("key_fingerprint")
            pem = keys.get(fingerprint)
            if pem is None or key_fingerprint(pem) != fingerprint:
                raise ValueError("Manifest signature names a key that is not in the pack")
            claims = verify_jws(signature, pem)
        else:
            claims = jws_claims(signature)
        if claims.get("typ") != "aegis-evidence-manifest" or claims.get("manifest_sha256") != _digest(manifest_bytes):
            raise ValueError("Manifest signature does not cover this manifest")
        if expect_key and claims.get("key_fingerprint") != expect_key:
            raise ValueError("Manifest is not signed by the expected key")
        checkpoints = json.loads(archive.read("records/checkpoints.json"))
        used, anchors = _verify_checkpoints(checkpoints, keys, tips, archive.read, signatures, expect_key)
        last = checkpoints[-1]["entries"] if checkpoints else 0
        return {**result, "signed": True, "signatures_checked": signatures,
                "manifest_key": claims["key_fingerprint"], "keys": sorted(used | {claims["key_fingerprint"]}),
                "checkpoints": len(checkpoints), "unsigned_tail": len(entries) - last,
                "anchored": len(anchors), "anchors": anchors}


def _report(result: dict) -> str:
    lines = [f"VERIFIED: {result['files']} files, {result['entries']} ledger entries, tip {result['tip']}"]
    if not result["signed"]:
        return "\n".join([*lines, "This pack format carries no signatures or timestamps."])
    if result["signatures_checked"]:
        lines.append(f"Signatures: valid, ledger key {', '.join(result['keys'])}")
        lines.append("  Compare this fingerprint with the one the bank publishes (/.well-known/aegis-ledger-key).")
    else:
        lines.append("Signatures: NOT CHECKED - install the 'cryptography' package and run again.")
    lines.append(f"Checkpoints: {result['checkpoints']} signed; {result['unsigned_tail']} later entries are covered "
                 f"only by the signed manifest.")
    if not result["anchored"]:
        lines.append("External timestamps: none in this pack.")
    for anchor in result["anchors"]:
        who = anchor.get("signer", anchor.get("reason", ""))
        lines.append(f"  checkpoint {anchor['checkpoint']}: timestamped {anchor['gen_time']} - TSA signature "
                     f"{anchor['status']} ({who})")
    if result["anchors"]:
        last = result["anchors"][-1]
        lines.append("  To also check the TSA certificate chain: openssl ts -verify -in <extracted "
                     f"{last['file']}> -digest {last['digest']} -CAfile <tsa-ca.pem>")
    return "\n".join(lines)


if __name__ == "__main__":
    args = sys.argv[1:]
    expect = None
    if len(args) == 3 and args[1] == "--expect-key":
        expect = args[2]
    elif len(args) != 1:
        raise SystemExit("Usage: python verify_pack.py <evidence-pack.zip> [--expect-key <fingerprint>]")
    try:
        print(_report(verify_pack(args[0], expect)))
    except (OSError, ValueError, KeyError, TypeError, IndexError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"FAILED: {exc}") from exc
