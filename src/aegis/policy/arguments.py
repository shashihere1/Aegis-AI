"""Checks on tool arguments before any policy engine sees them.

Agents (and the models behind them) choose tool arguments, so these are untrusted input. The gateway refuses arguments
that are too large or deeply nested (they could stall a policy engine), and numbers no engine can compare reliably:
NaN or infinity (also written as text, which Python would happily parse) and numbers too precise to survive the
15-significant-digit round trip every engine supports. A refusal is a recorded deny (ARG-002), like any other.
"""

import json
import math

MAX_BYTES = 64 * 1024
MAX_DEPTH = 16
MAX_NODES = 2000
MAX_SAFE_INTEGER = 2**53  # integers beyond this lose precision in JSON numbers and some engines
NON_FINITE_WORDS = {"nan", "+nan", "-nan", "inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"}


def argument_problem(arguments) -> str | None:
    """Why these arguments are refused, or None when they are acceptable."""
    try:
        encoded = json.dumps(arguments, allow_nan=False)
    except TypeError, ValueError:
        return "they contain a value that is not valid JSON (for example NaN or Infinity)"
    if len(encoded.encode("utf-8")) > MAX_BYTES:
        return f"they are larger than {MAX_BYTES // 1024} KB"
    nodes = 0
    stack = [(arguments, 1)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            return f"they contain more than {MAX_NODES} values"
        if depth > MAX_DEPTH:
            return f"they are nested more than {MAX_DEPTH} levels deep"
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
        elif isinstance(value, str):
            if value.strip().lower() in NON_FINITE_WORDS:
                return "they contain a non-finite number written as text"
        elif isinstance(value, bool):
            continue
        elif isinstance(value, int):
            if abs(value) > MAX_SAFE_INTEGER:
                return "they contain an integer too large to compare exactly"
        elif isinstance(value, float):
            if not math.isfinite(value):
                return "they contain a non-finite number"
            if float(f"{value:.15g}") != value:
                return "they contain a number with more precision than policy engines compare reliably"
    return None


def refuse_arguments(version: str, problem: str) -> dict:
    return {
        "decision": "deny",
        "reasons": [{"rule": "ARG-002", "message": f"Tool arguments refused: {problem}"}],
        "obligations": [],
        "policy_version": version,
    }
