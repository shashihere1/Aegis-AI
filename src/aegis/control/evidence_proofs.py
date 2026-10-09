"""Signed-pack Merkle inclusion proofs: disclose selected ledger entries, not unrelated payloads.

The server verifies the complete hash chain before constructing this tree. The manifest signature binds
its root, source length and chain tip. A recipient verifies inclusion, not undisclosed chain contents.
"""

import hashlib


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf(entry: dict) -> str:
    return digest(b"\x00" + f"{entry['seq']}:{entry['entry_hash']}".encode("ascii"))


def parent(left: str, right: str) -> str:
    return digest(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))


def inclusion_proofs(entries: list[dict], selected: list[dict]) -> dict:
    levels = [[leaf(e) for e in entries]]
    while len(levels[-1]) > 1:
        level = levels[-1]
        levels.append([parent(level[i], level[min(i + 1, len(level) - 1)]) for i in range(0, len(level), 2)])
    positions = {entry["seq"]: i for i, entry in enumerate(entries)}
    proofs = []
    for entry in selected:
        index = positions[entry["seq"]]
        cursor = index
        siblings = []
        for level in levels[:-1]:
            siblings.append(level[min(cursor ^ 1, len(level) - 1)])
            cursor //= 2
        proofs.append({"seq": entry["seq"], "index": index, "siblings": siblings})
    return {
        "algorithm": "sha256-domain-separated-v1",
        "source_entries": len(entries),
        "root": levels[-1][0] if entries else digest(b"\x00aegis-empty-ledger"),
        "proofs": proofs,
    }
