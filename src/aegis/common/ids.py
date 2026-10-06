import secrets
import uuid


def agent_id(name: str = "") -> str:
    """Aegis ID in the prototype's format, e.g. AGT-5E72-9A1C."""
    return f"AGT-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"
