"""Prompt-injection and tool-poisoning heuristics (plan §8.7, layer L4).

Detection is a *signal*: enforcement is done by deterministic policy (purpose, taint, egress),
so a missed detection never on its own lets an attack through. An ML classifier or an Azure
OpenAI judge can be added behind the same `scan_text` contract.
"""

import re
from dataclasses import dataclass, field

_RULES: list[tuple[str, float, re.Pattern]] = [
    ("override-instructions", 0.9, re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|all|earlier|system)\b"
        r".{0,20}\b(instructions?|rules?|prompts?|guidelines?)", re.IGNORECASE | re.DOTALL)),
    ("role-hijack", 0.7, re.compile(r"\b(you are now|act as|new instructions?|system prompt)\b", re.IGNORECASE)),
    ("exfiltration-request", 0.8, re.compile(
        r"\b(send|email|forward|upload|post|transfer)\b.{0,60}\b(all|every|entire|full)\b.{0,40}"
        r"\b(customer|client|records?|data|accounts?|documents?)\b", re.IGNORECASE | re.DOTALL)),
    ("concealment", 0.6, re.compile(r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|reveal)\b", re.IGNORECASE)),
    ("markdown-exfil", 0.8, re.compile(r"!\[[^\]]*\]\(https?://[^)]*\?[^)]*=", re.IGNORECASE)),
    ("hidden-unicode", 0.9, re.compile("[\U000e0000-\U000e007f\u200b-\u200f\u2060\ufeff]")),
    ("base64-blob", 0.4, re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")),
]

# Extra patterns that only make sense inside a tool *description* (tool poisoning).
_TOOL_RULES: list[tuple[str, float, re.Pattern]] = [
    ("tool-cross-reference", 0.7, re.compile(
        r"\b(before|after|also|first)\b.{0,30}\b(call|use|invoke|run)\b.{0,30}\btool\b", re.IGNORECASE | re.DOTALL)),
    ("tool-important-tag", 0.8, re.compile(r"<\s*(important|system|secret)\s*>", re.IGNORECASE)),
    ("tool-credential-request", 0.9,
     re.compile(r"\b(api[_ ]?key|password|token|ssh|\.env|credentials?)\b", re.IGNORECASE)),
]

THRESHOLD = 0.5


@dataclass
class GuardResult:
    score: float = 0.0
    findings: list[dict] = field(default_factory=list)

    @property
    def injection(self) -> bool:
        return self.score >= THRESHOLD


def _scan(text: str, rules) -> GuardResult:
    result = GuardResult()
    for name, weight, pattern in rules:
        match = pattern.search(text)
        if match:
            result.findings.append({"rule": name, "weight": weight, "snippet": match.group(0)[:80]})
            result.score = max(result.score, weight)
    return result


def scan_text(text: str) -> GuardResult:
    return _scan(text or "", _RULES)


def scan_tool_description(description: str) -> GuardResult:
    return _scan(description or "", _RULES + _TOOL_RULES)
