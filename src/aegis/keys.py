"""Explicit signing-key provisioning, kept separate from normal startup.

Normal startup strictly *loads* persistent signing keys and fails closed if one is missing
(see `aegis.common.crypto.SigningKey.ensure`). First-time *creation* is an explicit, auditable
step an operator runs once:

    python -m aegis.keys init     # create any missing persistent keys (atomic, mode 0600)
    python -m aegis.keys show     # strictly load and print public-key fingerprints

Only public-key fingerprints are ever printed or logged; private key material never leaves disk.

Backup and recovery (local PostgreSQL console):
  - Back up the files at AEGIS_SIGNING_KEY_PATH and AEGIS_IDP_KEY_PATH (default .local/keys/*.pem)
    to an encrypted, access-controlled location. They are the signing identity: losing them
    invalidates every already-issued token and breaks evidence verification.
  - To recover, restore the files to the same paths and run `python -m aegis.keys show`; the
    printed fingerprints must match the ones recorded before the loss.
  - In production the keys live in Azure Key Vault instead (increments 2-3); do not rely on files.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aegis.common.crypto import SigningKey, SigningKeyError
from aegis.common.settings import Settings

# role -> (Settings field holding the file path, key id label)
KEY_ROLES = (
    ("sts", "signing_key_path", "sts-1"),
    ("idp", "idp_key_path", "idp-1"),
    ("ledger", "ledger_signing_key_path", "ledger-1"),
)


def provision(settings: Settings, *, create: bool) -> dict[str, dict[str, str]]:
    """Ensure each configured persistent key exists (``create=True``) or strictly load it.

    Returns ``{role: {kid, fingerprint, path, mode}}`` with public information only. Raises
    ``SigningKeyError`` when ``create`` is False and a configured key file is missing or malformed.
    """
    report: dict[str, dict[str, str]] = {}
    for role, field, kid in KEY_ROLES:
        path = getattr(settings, field)
        key = SigningKey.ensure(path, kid, create=create)
        report[role] = {
            "kid": key.kid,
            "fingerprint": key.fingerprint,
            "path": path or "(ephemeral)",
            "mode": "persistent" if path else "ephemeral",
        }
    if settings.identity_state_dir:
        Path(settings.identity_state_dir).mkdir(parents=True, exist_ok=True)
    return report


def _print(report: dict[str, dict[str, str]]) -> None:
    for role, info in report.items():
        print(
            f"{role:6}  {info['mode']:10}  kid={info['kid']:8}  "
            f"fingerprint={info['fingerprint']}  {info['path']}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegis.keys", description="Provision and inspect Aegis signing keys."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create any missing persistent signing keys (atomic, mode 0600)")
    sub.add_parser("show", help="strictly load persistent keys and print public-key fingerprints")
    args = parser.parse_args(argv)

    settings = Settings.from_env()
    try:
        report = provision(settings, create=args.command == "init")
    except SigningKeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
