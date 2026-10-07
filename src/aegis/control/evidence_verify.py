"""Standalone verifier embedded in Aegis demo evidence packs (Python standard library only).

Usage after extracting this file from the ZIP: python verify_pack.py aegis-evidence-....zip
"""

import hashlib
import io
import json
import sys
import zipfile


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry_hash(previous: str, entry: dict) -> str:
    value = {"prev": previous, "ts": entry["ts"], "type": entry["event_type"],
             "actor": entry["actor"], "subject": entry["subject"], "payload": entry["payload"]}
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return _digest(canonical.encode("utf-8"))


def verify_pack(source: str | bytes | io.BytesIO) -> dict:
    """Verify member hashes, record counts and the exported audit chain; raise on a mismatch."""
    if isinstance(source, bytes):
        source = io.BytesIO(source)
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or "manifest.json" not in names:
            raise ValueError("Duplicate members or missing manifest")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("format") != "aegis-demo-evidence-pack-v1":
            raise ValueError("Unsupported evidence pack format")
        expected = set(manifest["files"]) | {"manifest.json"}
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
        previous = "0" * 64
        for entry in entries:
            if entry["prev_hash"] != previous or entry["entry_hash"] != _entry_hash(previous, entry):
                raise ValueError(f"Audit chain broken at entry {entry['seq']}")
            previous = entry["entry_hash"]
        if manifest["ledger"] != {"ok": True, "entries": len(entries), "tip": previous}:
            raise ValueError("Ledger checkpoint does not match exported entries")
        return {"ok": True, "files": len(manifest["files"]), "entries": len(entries), "tip": previous}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python verify_pack.py <evidence-pack.zip>")
    try:
        result = verify_pack(sys.argv[1])
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"FAILED: {exc}") from exc
    print(f"VERIFIED: {result['files']} files, {result['entries']} ledger entries, tip {result['tip']}")
