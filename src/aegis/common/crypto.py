"""ES256 signing keys, JWT issue/verify and JWKS export."""

import base64
import hashlib
import json
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


class SigningKey:
    """One ES256 key pair with a key id. Production keys live in Azure Key Vault (see SECURITY.md)."""

    def __init__(self, private_pem: str, kid: str):
        self.kid = kid
        self.private_pem = private_pem
        self.public_pem = public_pem_from_private(private_pem)

    @classmethod
    def load_or_generate(cls, path: str, kid: str) -> SigningKey:
        if path and Path(path).exists():
            return cls(Path(path).read_text(), kid)
        private = generate_private_key_pem()
        if path:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(private, encoding="utf-8")
        return cls(private, kid)

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
