"""Asymmetric service identity for data-plane → control-plane calls (RFC 7523, private_key_jwt).

The Gateway holds a private ES256 key and signs a short-lived assertion for every internal call.
The control plane holds only the Gateway's *public* key and verifies it, so it can never mint a
Gateway token: there is no shared secret whose leak would let either side (or its config, logs or a
memory dump) forge the other's identity. This is the same mechanism agents use to sign in at the IdP,
applied to the one trust boundary that previously rested on a single static header secret.
"""

from aegis.common import crypto
from aegis.common.crypto import SigningKey

SERVICE_ISSUER = "aegis-gateway"
SERVICE_AUDIENCE = "aegis-control-internal"
SERVICE_TOKEN_TTL = 60  # seconds; a captured assertion is useless after this. TLS/mTLS stops capture in transit.


def mint_service_token(key: SigningKey) -> str:
    """The Gateway signs a fresh assertion per call with its private key."""
    now = crypto.now()
    return key.sign(
        {
            "iss": SERVICE_ISSUER,
            "sub": SERVICE_ISSUER,
            "aud": SERVICE_AUDIENCE,
            "iat": now,
            "exp": now + SERVICE_TOKEN_TTL,
            "jti": crypto.new_jti("svc"),
        }
    )


def verify_service_token(token: str, gateway_public_pem: str) -> dict:
    """The control plane verifies with the Gateway's public key only (raises jwt.InvalidTokenError)."""
    return crypto.verify(token, gateway_public_pem, audience=SERVICE_AUDIENCE, issuer=SERVICE_ISSUER)
