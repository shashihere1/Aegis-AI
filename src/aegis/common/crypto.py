"""ES256 signing keys, JWT issue/verify and JWKS export."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ALGORITHM = "ES256"


def generate_private_key_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def public_pem_from_private(private_pem: str) -> str:
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def public_jwk(public_pem: str) -> dict[str, Any]:
    """The public half of an ES256 key as a JWK with a stable key id (RFC 7638 thumbprint)."""
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(serialization.load_pem_public_key(public_pem.encode())))
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    kid = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()
    return {**jwk, "kid": kid, "use": "sig", "alg": ALGORITHM}


def key_id(private_pem: str) -> str:
    """Key id of a private key's public half; provider and agent derive the same value independently."""
    return public_jwk(public_pem_from_private(private_pem))["kid"]


log = logging.getLogger("aegis.crypto")


class SigningKeyError(RuntimeError):
    """A configured persistent signing key is missing, unreadable or malformed.

    Raised instead of silently minting a new key, so a lost or mis-mounted key fails startup
    loudly rather than quietly changing the signing identity (which would invalidate every
    already-issued token and break evidence verification).
    """


def _validate_private_pem(private_pem: str) -> None:
    """Confirm the PEM is a usable EC (ES256) private key; raise SigningKeyError otherwise."""
    try:
        key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError(f"not a valid PEM private key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SigningKeyError("signing key is not an elliptic-curve (ES256) private key")


def _restrict(path: Path, mode: int) -> None:
    """Best-effort tighten of file/directory permissions. POSIX enforces the mode; Windows relies on
    the parent directory ACL (see the PostgreSQL setup, which restricts .local to the user and SYSTEM)."""
    if os.name == "posix":
        try:
            os.chmod(path, mode)
        except OSError:  # pragma: no cover - platform dependent
            pass


def _warn_if_readable_by_others(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode
    except OSError:  # pragma: no cover
        return
    if mode & 0o077:
        log.warning("signing key %s is readable by group/other; tighten it to 0600", path)


class SigningKey:
    """One ES256 key pair with a key id.

    A key is either *ephemeral* (in memory, regenerated every start - development and tests) or
    *persistent* (a PEM file whose identity must survive restarts). Persistent keys are created once
    through an explicit provisioning step (`python -m aegis.keys init`); normal startup only ever
    loads them and fails closed if one is missing. Production keys live in Azure Key Vault
    (see SECURITY.md).
    """

    def __init__(self, private_pem: str, kid: str):
        self.kid = kid
        self.private_pem = private_pem
        self.public_pem = public_pem_from_private(private_pem)

    def __repr__(self) -> str:  # never let a private key leak into logs or tracebacks
        return f"SigningKey(kid={self.kid!r}, fingerprint={self.fingerprint!r})"

    # -- construction ----------------------------------------------------------
    @classmethod
    def generate_ephemeral(cls, kid: str) -> SigningKey:
        """A fresh in-memory key. The signing identity changes on every restart (dev/tests only)."""
        return cls(generate_private_key_pem(), kid)

    @classmethod
    def create_file(cls, path: str, kid: str) -> SigningKey:
        """Create a persistent key file atomically at mode 0600, or load the existing one.

        Uses ``O_CREAT | O_EXCL`` so that if several processes start together, exactly one writes the
        key and every other process loads that same key instead of generating a different one.
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        _restrict(target.parent, 0o700)
        private_pem = generate_private_key_pem()
        try:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return cls.load_file(path, kid)  # another process won the race; use its key
        try:
            os.write(fd, private_pem.encode())
        finally:
            os.close(fd)
        _restrict(target, 0o600)
        return cls(private_pem, kid)

    @classmethod
    def load_file(cls, path: str, kid: str) -> SigningKey:
        """Strictly load a persistent key. Raise SigningKeyError if it is missing or malformed."""
        target = Path(path)
        if not target.exists():
            raise SigningKeyError(
                f"expected signing key '{kid}' at {path} is missing; create it once with "
                f"`python -m aegis.keys init` - startup will not mint a replacement identity"
            )
        _warn_if_readable_by_others(target)
        try:
            private_pem = target.read_text(encoding="utf-8")
        except OSError as exc:
            raise SigningKeyError(f"signing key '{kid}' at {path} could not be read: {exc}") from exc
        _validate_private_pem(private_pem)
        return cls(private_pem, kid)

    @classmethod
    def ensure(cls, path: str, kid: str, *, create: bool = False) -> SigningKey:
        """Resolve the key for ``path``.

        - empty ``path``                      -> ephemeral in-memory key (development and tests)
        - file present                        -> strict load (identity preserved across restarts)
        - file absent and ``create`` is True  -> create it atomically (explicit provisioning)
        - file absent and ``create`` is False -> fail closed (normal startup never generates one)
        """
        if not path:
            return cls.generate_ephemeral(kid)
        if Path(path).exists():
            return cls.load_file(path, kid)
        if create:
            return cls.create_file(path, kid)
        raise SigningKeyError(
            f"expected signing key '{kid}' at {path} is missing; run `python -m aegis.keys init` "
            f"before starting the service (startup will not generate a new signing identity)"
        )

    @classmethod
    def load_or_generate(cls, path: str, kid: str) -> SigningKey:
        """Deprecated: prefer `ensure`. Equivalent to create-on-first-use (development convenience)."""
        return cls.ensure(path, kid, create=True)

    # -- use -------------------------------------------------------------------
    @property
    def fingerprint(self) -> str:
        """RFC 7638 thumbprint of the public key: a stable content fingerprint, safe to log.

        Unlike ``kid`` (a human label such as 'sts-1'), this changes if and only if the key material
        changes, so operators can record it, restart, and confirm the identity is unchanged.
        """
        return public_jwk(self.public_pem)["kid"]

    def sign(self, claims: dict[str, Any]) -> str:
        return jwt.encode(claims, self.private_pem, algorithm=ALGORITHM, headers={"kid": self.kid})

    def jwk(self) -> dict[str, Any]:
        public_key = serialization.load_pem_public_key(self.public_pem.encode())
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(public_key))
        return {**jwk, "kid": self.kid, "use": "sig", "alg": ALGORITHM}


def verify(token: str, public_pem: str, audience: str | None = None, issuer: str | None = None) -> dict:
    options = {"require": ["exp", "iat"], "verify_aud": audience is not None}
    return jwt.decode(token, public_pem, algorithms=[ALGORITHM], audience=audience, issuer=issuer, options=options)


def unverified_header(token: str) -> dict:
    return jwt.get_unverified_header(token)


def new_jti(prefix: str = "tok") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def now() -> int:
    return int(time.time())
