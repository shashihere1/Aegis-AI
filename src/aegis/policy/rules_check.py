"""Automatic checks a proposed Rego change must pass before it can be submitted for approval (plan §8.4, D3.3).

The checks are deliberately mechanical, so a reviewer spends their attention on the diff and the replay, not on
whether the policy compiles:

1. Shape: module names, sizes, and every runtime module in the ``aegis.tool_call`` package (OPA treats ``system.*``
   packages as server configuration, so a policy module must never declare one).
2. Builtins: no network calls (``http.send``, ``net.lookup_ip_addr``), no server introspection (``opa.runtime``) and no
   non-deterministic values (time, randomness, UUIDs), because a decision must be reproducible for replay and evidence.
   The scan covers the raw text, comments included: a mention in a comment is refused too, rather than risk a
   comment-stripping bug letting a real call through.
3. It compiles, and ``data.aegis.tool_call.decision`` returns a well-formed verdict.
4. Every policy case (``config/policy_tests``, generated from the same cases as the Rego unit tests) still decides as
   expected. The cases travel with the version: changing a rule's behaviour on purpose means updating its cases in the
   same draft, which the reviewer then sees.
"""

import re
from datetime import UTC, datetime
from pathlib import Path

from aegis.common.hashing import sha256_hex
from aegis.policy.engines import PolicyUnavailable, RegoRuntime, normalize

ENTRY_PACKAGE = "aegis.tool_call"
MODULE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,59}\.rego")
MAX_MODULES = 10
MAX_MODULE_BYTES = 128_000
MAX_TOTAL_BYTES = 256_000
MAX_CASES = 500
PACKAGE = re.compile(r"^[ \t]*package[ \t]+([A-Za-z_][A-Za-z0-9_.]*)", re.M)
FORBIDDEN = {
    "http.send": "makes network calls",
    "net.lookup_ip_addr": "makes network calls",
    "opa.runtime": "reads the policy server's own configuration",
    "time.now_ns": "is not reproducible, so replay and evidence would not hold",
    "rand.intn": "is not reproducible, so replay and evidence would not hold",
    "uuid.rfc4122": "is not reproducible, so replay and evidence would not hold",
}
FORBIDDEN_PATTERNS = {name: re.compile(r"(?<![\w.])" + re.escape(name) + r"(?![\w])") for name in FORBIDDEN}
DECISIONS = {"allow", "deny", "require_approval"}


def repository_cases_file(policy_dir: str) -> Path:
    return Path(policy_dir).resolve().parent / "policy_tests" / "tool_call_cases.json"


def bundle_hash(modules: dict[str, str], cases: list[dict]) -> str:
    return sha256_hex({"modules": modules, "cases": cases})


def _compile_message(exc: Exception) -> str:
    """regopy reports parse errors as an s-expression; keep the file, position and message a person can act on."""
    text = str(exc)
    found = re.findall(r"\(error \d+:([^|]*)\|(\d+)\|\d+\s*\(errormsg \d+:([^)]*)\)", text)
    if found:
        return "; ".join(f"{module}.rego (offset {offset}): {message}" for module, offset, message in found[:5])
    return f"{type(exc).__name__}: {text.splitlines()[0][:200]}" if text else type(exc).__name__


def _shape_problems(modules: dict[str, str], cases: list[dict]) -> list[str]:
    problems = []
    if not modules:
        return ["the policy has no Rego modules"]
    if len(modules) > MAX_MODULES:
        problems.append(f"at most {MAX_MODULES} Rego modules are allowed, got {len(modules)}")
    total = 0
    for name, text in modules.items():
        if not MODULE_NAME.fullmatch(name):
            problems.append(f"{name!r}: a module name is letters, digits, '_' or '-' ending in .rego")
        if name.endswith("_test.rego"):
            problems.append(f"{name}: test modules are not part of a policy version; put expectations in its cases")
        if not isinstance(text, str) or not text.strip():
            problems.append(f"{name}: the module is empty")
            continue
        size = len(text.encode("utf-8"))
        total += size
        if size > MAX_MODULE_BYTES:
            problems.append(f"{name}: {size} bytes is over the {MAX_MODULE_BYTES}-byte limit")
        packages = PACKAGE.findall(text)
        if len(packages) != 1:
            problems.append(f"{name}: a module declares exactly one package, found {len(packages)}")
        elif packages[0] != ENTRY_PACKAGE and not packages[0].startswith(ENTRY_PACKAGE + "."):
            problems.append(f"{name}: package {packages[0]} is outside {ENTRY_PACKAGE}")
        for builtin, why in FORBIDDEN.items():
            if FORBIDDEN_PATTERNS[builtin].search(text):
                problems.append(f"{name}: {builtin} is not allowed in a policy (it {why})")
    if total > MAX_TOTAL_BYTES:
        problems.append(f"the policy is {total} bytes, over the {MAX_TOTAL_BYTES}-byte limit")
    if not cases:
        problems.append("a policy version needs at least one test case")
    elif len(cases) > MAX_CASES:
        problems.append(f"at most {MAX_CASES} test cases are allowed, got {len(cases)}")
    for index, item in enumerate(cases[:MAX_CASES]):
        label = item.get("name", f"#{index}") if isinstance(item, dict) else f"#{index}"
        if not isinstance(item, dict) or not isinstance(item.get("input"), dict):
            problems.append(f"case {label}: needs an object 'input'")
        elif item.get("decision") not in DECISIONS:
            problems.append(f"case {label}: 'decision' must be one of {sorted(DECISIONS)}")
        elif item.get("match", "exact") not in {"exact", "include"}:
            problems.append(f"case {label}: 'match' is 'exact' or 'include'")
        elif not isinstance(item.get("rules", []), list):
            problems.append(f"case {label}: 'rules' must be a list of rule ids")
    return problems


def _case_failure(item: dict, verdict: dict) -> str | None:
    rules = {r["rule"] for r in verdict["reasons"]}
    wanted = set(item.get("rules", []))
    if verdict["decision"] != item["decision"]:
        return f"decided {verdict['decision']}, expected {item['decision']}"
    if item.get("match", "exact") == "exact" and rules != wanted:
        return f"reasons {sorted(rules)}, expected {sorted(wanted)}"
    if item.get("match") == "include" and not wanted <= rules:
        return f"reasons {sorted(rules)} miss {sorted(wanted - rules)}"
    if "obligations" in item:
        kinds = sorted({o["type"] for o in verdict["obligations"]})
        if kinds != sorted(item["obligations"]):
            return f"obligations {kinds}, expected {sorted(item['obligations'])}"
    return None


def check_rules(policy_dir: str, modules: dict[str, str], cases: list[dict]) -> dict:
    """Run every check and return a report; ``passed`` is True only when nothing failed. Never raises."""
    report = {
        "passed": False,
        "problems": [],
        "cases": {"total": len(cases) if isinstance(cases, list) else 0, "passed": 0, "failed": []},
        "bundle_hash": bundle_hash(modules, cases),
        "checked_at": datetime.now(UTC).isoformat(),
    }
    problems = _shape_problems(modules, cases if isinstance(cases, list) else [])
    if problems:  # nothing unsafe or malformed is ever compiled
        report["problems"] = problems[:50]
        return report
    try:
        runtime = RegoRuntime(policy_dir, modules, size=1)
    except Exception as exc:  # regopy raises its own errors for a module that does not parse
        report["problems"] = [f"the Rego does not compile: {_compile_message(exc)}"]
        return report
    try:
        normalize(runtime.query({}), "check")  # an empty input must still produce a (deny) verdict
    except PolicyUnavailable as exc:
        report["problems"] = [
            f"data.aegis.tool_call.decision did not return a valid decision ({exc}); check for an unknown function, "
            "a missing 'decision' rule or a rule that conflicts with another"
        ]
        return report
    failed = []
    for item in cases:
        try:
            failure = _case_failure(item, normalize(runtime.query(item["input"]), "check"))
        except PolicyUnavailable as exc:
            failure = f"could not be evaluated ({exc})"
        if failure:
            failed.append({"name": item.get("name", "?"), "problem": failure})
    report["cases"].update(passed=len(cases) - len(failed), failed=failed[:50])
    if failed:
        report["problems"] = [f"{len(failed)} of {len(cases)} test cases fail"]
    report["passed"] = not report["problems"]
    return report
