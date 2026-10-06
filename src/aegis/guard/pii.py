"""PII recognizers and redaction (plan §8.7). Pattern-based, so no model download is needed.

Entity names follow Microsoft Presidio so the Presidio analyzer can replace this module later.
"""

import re
from typing import Any

_BSN = re.compile(r"(?<!\d)(\d{9})(?!\d)")
_IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?)\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<![\w+])(?:\+31|0031|0)\s?(?:6|[1-9]\d)(?:[\s-]?\d){7,8}(?!\d)")

DEFAULT_ENTITIES = ["BSN", "IBAN_CODE", "EMAIL_ADDRESS", "PHONE_NUMBER"]


def is_valid_bsn(digits: str) -> bool:
    """Dutch citizen service number: 9 digits passing the '11-proof' (elfproef)."""
    if len(digits) != 9 or not digits.isdigit():
        return False
    weights = [9, 8, 7, 6, 5, 4, 3, 2, -1]
    total = sum(int(d) * w for d, w in zip(digits, weights, strict=True))
    return total % 11 == 0 and digits != "000000000"


def is_valid_iban(value: str) -> bool:
    iban = value.replace(" ", "").upper()
    if not 15 <= len(iban) <= 34:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def find(text: str, entities: list[str] | None = None) -> list[tuple[str, int, int]]:
    entities = entities or DEFAULT_ENTITIES
    spans: list[tuple[str, int, int]] = []
    if "IBAN_CODE" in entities:
        spans += [("IBAN_CODE", m.start(1), m.end(1)) for m in _IBAN.finditer(text) if is_valid_iban(m.group(1))]
    if "BSN" in entities:
        spans += [("BSN", m.start(1), m.end(1)) for m in _BSN.finditer(text) if is_valid_bsn(m.group(1))]
    if "EMAIL_ADDRESS" in entities:
        spans += [("EMAIL_ADDRESS", m.start(), m.end()) for m in _EMAIL.finditer(text)]
    if "PHONE_NUMBER" in entities:
        spans += [("PHONE_NUMBER", m.start(), m.end()) for m in _PHONE.finditer(text)]
    # Drop spans nested inside an earlier, longer one (e.g. digits inside an IBAN).
    spans.sort(key=lambda s: (s[1], -(s[2] - s[1])))
    kept: list[tuple[str, int, int]] = []
    for span in spans:
        if not kept or span[1] >= kept[-1][2]:
            kept.append(span)
    return kept


def redact_text(text: str, entities: list[str] | None = None) -> tuple[str, int]:
    spans = find(text, entities)
    for entity, start, end in reversed(spans):
        text = text[:start] + f"<{entity}>" + text[end:]
    return text, len(spans)


def redact(value: Any, entities: list[str] | None = None) -> tuple[Any, int]:
    """Redact strings anywhere inside a JSON-like structure. Returns (redacted, count)."""
    if isinstance(value, str):
        return redact_text(value, entities)
    if isinstance(value, list):
        out, total = [], 0
        for item in value:
            red, n = redact(item, entities)
            out.append(red)
            total += n
        return out, total
    if isinstance(value, dict):
        out, total = {}, 0
        for key, item in value.items():
            red, n = redact(item, entities)
            out[key] = red
            total += n
        return out, total
    return value, 0
