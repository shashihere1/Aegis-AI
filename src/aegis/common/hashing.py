import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(value: Any) -> str:
    data = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def action_hash(tool: str, arguments: dict, mandate_id: str) -> str:
    """An approval authorises this tool, these exact arguments, within this mandate - nothing else."""
    return sha256_hex({"tool": tool, "arguments": arguments, "mandate": mandate_id})


def tool_definition_hash(tool: dict) -> str:
    """Pin of an MCP tool definition: name, description, input schema and annotations."""
    return sha256_hex(
        {
            "name": tool.get("name"),
            "description": tool.get("description") or "",
            "inputSchema": tool.get("inputSchema") or {},
            "annotations": tool.get("annotations") or {},
        }
    )
