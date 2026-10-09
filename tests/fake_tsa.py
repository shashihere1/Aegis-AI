"""A stand-in RFC 3161 timestamp authority: real DER, a real ECDSA signature and a self-signed certificate."""

import hashlib
from datetime import UTC, datetime, timedelta

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from aegis.control.checkpoints import _der, der_int, der_oid, der_seq
from aegis.control.evidence_verify import SHA256, SIGNED_DATA, TST_INFO, Der

CONTENT_TYPE = "1.2.840.113549.1.9.3"
MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
ECDSA_SHA256 = "1.2.840.10045.4.3.2"


def der_set(*items: bytes) -> bytes:
    return _der(0x31, b"".join(items))


class FakeTsa:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegis Test TSA")])
        now = datetime.now(UTC)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(4242)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(self.key, hashes.SHA256())
        )
        self.mode = "ok"  # ok | down | refuse | wrong_imprint
        self.requests: list[bytes] = []
        self.serial = 0

    def respond(self, request: bytes) -> bytes:
        req = Der(request).children()
        imprint = req[1].raw
        nonce = next(int.from_bytes(f.value, "big") for f in req[2:] if f.tag == 0x02)
        if self.mode == "wrong_imprint":
            imprint = der_seq(der_seq(der_oid(SHA256), b"\x05\x00"), _der(0x04, hashlib.sha256(b"other").digest()))
        if self.mode == "refuse":
            return der_seq(der_seq(der_int(2)))
        self.serial += 1
        gen_time = datetime.now(UTC).strftime("%Y%m%d%H%M%S").encode() + b"Z"
        tst_info = der_seq(der_int(1), der_oid("1.2.3.4.1"), imprint, der_int(self.serial), _der(0x18, gen_time),
                           der_int(nonce))
        attrs = (der_seq(der_oid(CONTENT_TYPE), der_set(der_oid(TST_INFO)))
                 + der_seq(der_oid(MESSAGE_DIGEST), der_set(_der(0x04, hashlib.sha256(tst_info).digest()))))
        signature = self.key.sign(_der(0x31, attrs), ec.ECDSA(hashes.SHA256()))
        signer = der_seq(
            der_int(1),
            der_seq(self.cert.issuer.public_bytes(), der_int(self.cert.serial_number)),
            der_seq(der_oid(SHA256)),
            _der(0xA0, attrs),
            der_seq(der_oid(ECDSA_SHA256)),
            _der(0x04, signature),
        )
        signed_data = der_seq(
            der_int(3),
            der_set(der_seq(der_oid(SHA256))),
            der_seq(der_oid(TST_INFO), _der(0xA0, _der(0x04, tst_info))),
            _der(0xA0, self.cert.public_bytes(Encoding.DER)),
            der_set(signer),
        )
        token = der_seq(der_oid(SIGNED_DATA), _der(0xA0, signed_data))
        return der_seq(der_seq(der_int(0)), token)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request.content)
        if self.mode == "down":
            raise httpx.ConnectError("timestamp authority unreachable", request=request)
        return httpx.Response(200, content=self.respond(request.content),
                              headers={"content-type": "application/timestamp-reply"})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))
