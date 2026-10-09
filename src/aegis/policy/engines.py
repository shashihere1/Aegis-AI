"""The three policy engines behind one interface (plan §8.4), and the checks every verdict passes.

- ``python``: :class:`aegis.policy.engine.PythonEngine`, an in-process mirror of the Rego rules. That module is left
  untouched on purpose: its file hash is the governed evaluator identity stored with every approved policy version.
- ``rego``:   the authoritative ``config/policies/tool_call.rego`` evaluated in-process by regopy (rego-cpp),
  so the real Rego runs on any laptop without an OPA binary.
- ``opa``:    the same Rego evaluated by an Open Policy Agent server through its REST API. Before trusting a decision,
  Aegis checks that the server runs exactly the Rego this control plane approved.

Every engine receives the governed, approved configuration with each decision (as ``input.policy_data`` for Rego), so
activating or rolling back a policy version applies immediately and the decision records the version that decided.
Anything that is not a well-formed verdict raises :class:`PolicyUnavailable`; the gateway turns that into a recorded
deny (fail closed). See tests/test_policy_engines.py, tests/test_policy_differential.py and tests/test_opa_engine.py.
"""

import asyncio
import json
import queue
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from aegis.common.hashing import sha256_hex
from aegis.policy.engine import PythonEngine, policy_version

QUERY = "data.aegis.tool_call.decision"
OPA_DECISION_PATH = "/v1/data/aegis/tool_call/decision"
ENGINES = ("python", "rego", "opa")
DECISIONS = {"allow", "deny", "require_approval"}
OBLIGATION_ORDER = {"redact": 0, "rate_limit": 1}  # the order the Python engine emits them in
OPA_VERIFY_TTL = 30.0  # seconds a successful "OPA runs our Rego" check is trusted
POOL_SIZE = 4  # regopy interpreters per policy; each query takes about 20 ms and regopy releases the GIL


class PolicyUnavailable(Exception):
    """The policy decision point could not produce a decision Aegis can trust. Callers must fail closed."""


# ---- the Rego Aegis approves -------------------------------------------------


def runtime_modules(policy_dir: str) -> list[Path]:
    """The Rego files that make decisions: every *.rego except *_test.rego (unit tests for `opa test`)."""
    return sorted(p for p in Path(policy_dir).glob("*.rego") if not p.name.endswith("_test.rego"))


def module_text(path: Path) -> str:
    """A Rego file's text with line endings normalised, so the same policy has the same fingerprint on every checkout
    (Windows checkouts often convert LF to CRLF) and compares equal to what OPA reports after the same normalisation."""
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


_SOURCES: dict[str, tuple[tuple, dict[str, str]]] = {}


def rego_sources(policy_dir: str) -> dict[str, str]:
    """The runtime Rego by file name. Re-read only when a file's size or modification time changes, so the per-decision
    "is this still the approved Rego?" check costs a few stat() calls instead of reading and hashing files."""
    modules = runtime_modules(policy_dir)
    signature = tuple((m.name, m.stat().st_mtime_ns, m.stat().st_size) for m in modules)
    key = str(Path(policy_dir).resolve())
    cached = _SOURCES.get(key)
    if cached is None or cached[0] != signature:
        cached = (signature, {m.name: module_text(m) for m in modules})
        _SOURCES[key] = cached
    return dict(cached[1])


def test_sources(policy_dir: str) -> dict[str, str]:
    """This repository's own Rego unit tests (package aegis.tool_call_test), by file name."""
    return {m.name: module_text(m) for m in sorted(Path(policy_dir).glob("*_test.rego"))}


def rego_fingerprint(sources: dict[str, str]) -> str:
    return sha256_hex(sources)


# ---- verdicts -----------------------------------------------------------------


def normalize(result: Any, version: str) -> dict:
    """Validate an engine's raw result and put it in the canonical shape; anything unexpected is refused."""
    if not isinstance(result, dict):
        raise PolicyUnavailable("the policy engine returned no decision")
    decision = result.get("decision")
    if decision not in DECISIONS:
        raise PolicyUnavailable(f"the policy engine returned an unknown decision: {decision!r}")
    reasons, obligations = result.get("reasons", []), result.get("obligations", [])
    if not isinstance(reasons, list) or not isinstance(obligations, list):
        raise PolicyUnavailable("the policy engine returned malformed reasons or obligations")
    for reason in reasons:
        if not (
            isinstance(reason, dict) and isinstance(reason.get("rule"), str) and isinstance(reason.get("message"), str)
        ):
            raise PolicyUnavailable("the policy engine returned a malformed reason")
    for obligation in obligations:
        kind = obligation.get("type") if isinstance(obligation, dict) else None
        if kind == "redact":
            if not (
                isinstance(obligation.get("entities"), list) and all(isinstance(e, str) for e in obligation["entities"])
            ):
                raise PolicyUnavailable("the policy engine returned a malformed redact obligation")
        elif kind == "rate_limit":
            limit = obligation.get("limit")
            if (
                not isinstance(obligation.get("key"), str)
                or isinstance(limit, bool)
                or not isinstance(limit, int | float)
            ):
                raise PolicyUnavailable("the policy engine returned a malformed rate_limit obligation")
        else:
            raise PolicyUnavailable(f"the policy engine returned an unknown obligation: {kind!r}")
    if decision == "deny" and not reasons:
        raise PolicyUnavailable("the policy engine denied without a reason")
    return {
        "decision": decision,
        "reasons": sorted(reasons, key=lambda r: (r["rule"], r["message"])),
        "obligations": [] if decision == "deny" else sorted(obligations, key=lambda o: OBLIGATION_ORDER[o["type"]]),
        "policy_version": version,
    }


def fail_closed(version: str, error: BaseException) -> dict:
    """The verdict used when no trustworthy decision exists: deny, with a reason that says why."""
    return {
        "decision": "deny",
        "reasons": [
            {"rule": "PDP-001", "message": f"Policy decision point unavailable ({type(error).__name__}); refused"}
        ],
        "obligations": [],
        "policy_version": version,
    }


# ---- rego: the authoritative Rego, in-process -------------------------------------


class RegoRuntime:
    """The policy loaded into a small pool of regopy interpreters.

    rego-cpp is not documented as thread-safe, so each interpreter serves one query at a time; a query takes about
    20 ms, and regopy releases the GIL, so a few interpreters let decisions run in parallel. An interpreter that raised
    a native error is discarded, never reused. The runtime evaluates exactly the ``sources`` it was built from: the
    caller hashes those same sources to check they are the approved Rego, so what is checked is what runs.
    """

    def __init__(self, policy_dir: str, sources: dict[str, str] | None = None, size: int = POOL_SIZE):
        try:
            import regopy
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise RuntimeError("policy_engine=rego needs regopy: pip install regopy (see requirements.lock)") from exc
        self._regopy = regopy
        self.sources = dict(sources) if sources is not None else rego_sources(policy_dir)
        if not self.sources:
            raise RuntimeError(f"no Rego policy found in {policy_dir}")
        self.fingerprint = rego_fingerprint(self.sources)
        self.data_json = (Path(policy_dir) / "data.json").read_text(encoding="utf-8")
        self.size = max(1, size)
        self.broken = False  # kept for callers; a failing interpreter is replaced on its own
        self._idle: queue.LifoQueue = queue.LifoQueue()
        self._created = 0
        self._lock = threading.Lock()
        self._idle.put(self._build())  # build one now so a broken policy fails at once, not on first use
        self._created = 1

    def _build(self):
        interpreter = self._regopy.Interpreter()
        for name, text in self.sources.items():
            interpreter.add_module(name.removesuffix(".rego"), text)
        interpreter.add_data_json(self.data_json)
        return interpreter

    def _acquire(self):
        try:
            return self._idle.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            if self._created < self.size:
                self._created += 1
                try:
                    return self._build()
                except Exception:
                    self._created -= 1
                    raise
        return self._idle.get()

    def query(self, policy_input: dict) -> Any:
        try:
            payload = json.dumps(policy_input, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise PolicyUnavailable("the policy input is not valid JSON") from exc
        interpreter = self._acquire()
        healthy = True
        try:
            interpreter.set_input_term(payload)
            output = interpreter.query(QUERY)
            if not output.ok():  # check before str(): a failed output can crash when printed
                raise PolicyUnavailable("the Rego policy produced no result")
            parsed = json.loads(str(output))
        except PolicyUnavailable:
            raise
        except Exception as exc:  # regopy raises assorted errors, including native access violations
            healthy = False
            raise PolicyUnavailable(f"Rego evaluation failed: {type(exc).__name__}") from exc
        finally:
            if healthy:
                self._idle.put(interpreter)
            else:
                with self._lock:
                    self._created -= 1  # discard it; a fresh one is built when needed
        expressions = parsed.get("expressions") if isinstance(parsed, dict) else None
        if not expressions or not isinstance(expressions, list):
            raise PolicyUnavailable("the Rego policy produced no decision")
        return expressions[0]


_RUNTIMES: dict[tuple[str, str], RegoRuntime] = {}
_RUNTIMES_LOCK = threading.Lock()


def rego_runtime(policy_dir: str, sources: dict[str, str] | None = None) -> RegoRuntime:
    """The runtime for these exact sources (cached). Runtimes for older versions of the same policy are dropped."""
    sources = sources if sources is not None else rego_sources(policy_dir)
    directory = str(Path(policy_dir).resolve())
    key = (directory, rego_fingerprint(sources))
    with _RUNTIMES_LOCK:
        if key not in _RUNTIMES:
            for stale in [k for k in _RUNTIMES if k[0] == directory]:
                del _RUNTIMES[stale]
            _RUNTIMES[key] = RegoRuntime(policy_dir, sources)
        return _RUNTIMES[key]


def with_policy_data(policy_input: dict, data: dict) -> dict:
    # Always overwritten: whatever arrives in the input, the governed configuration is what Rego reads.
    return {**policy_input, "policy_data": data}


def file_data(policy_dir: str) -> dict:
    return json.loads((Path(policy_dir) / "data.json").read_text(encoding="utf-8"))


class RegoEngine:
    kind = "rego"

    def __init__(
        self,
        policy_dir: str,
        data: dict | None = None,
        version: str | None = None,
        *,
        sources: dict[str, str] | None = None,
    ):
        self.policy_dir = policy_dir
        self.sources = sources
        self.data = data if data is not None else file_data(policy_dir)
        self.version = version or policy_version(policy_dir)

    def decide(self, policy_input: dict) -> dict:
        runtime = rego_runtime(self.policy_dir, self.sources)
        return normalize(runtime.query(with_policy_data(policy_input, self.data)), self.version)

    async def evaluate(self, policy_input: dict) -> dict:
        return await asyncio.to_thread(self.decide, policy_input)


# ---- opa: the same Rego, in an OPA server ---------------------------------------------

_OPA_VERIFIED: dict[tuple[str, str], float] = {}


class OpaEngine:
    kind = "opa"

    def __init__(
        self,
        opa_url: str,
        policy_dir: str,
        http: httpx.AsyncClient,
        data: dict | None = None,
        version: str | None = None,
        *,
        timeout: float = 2.0,
        token: str = "",
        sources: dict[str, str] | None = None,
    ):
        self.base = opa_url.rstrip("/")
        self.url = f"{self.base}{OPA_DECISION_PATH}"
        self.http = http
        self.data = data if data is not None else file_data(policy_dir)
        self.version = version or policy_version(policy_dir)
        self.timeout = timeout
        # Sent as a bearer token; meant for an authenticating proxy in front of OPA. (OPA enforcing tokens itself needs
        # a system.authz policy, which the loaded-policy check below would refuse as an extra module.)
        self.headers = {"authorization": f"Bearer {token}"} if token else {}
        self.expected = dict(sources) if sources is not None else rego_sources(policy_dir)
        self.known_tests = test_sources(policy_dir)
        self.fingerprint = rego_fingerprint(self.expected)

    async def _get_json(self, method: str, url: str, **kwargs) -> Any:
        try:
            response = await asyncio.wait_for(
                self.http.request(method, url, headers=self.headers, timeout=self.timeout, **kwargs), self.timeout
            )
        except (httpx.HTTPError, TimeoutError) as exc:
            raise PolicyUnavailable(f"OPA at {self.base} is unreachable: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise PolicyUnavailable(f"OPA answered HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise PolicyUnavailable("OPA answered with something that is not JSON") from exc

    async def verify_policy(self) -> None:
        """Refuse to use an OPA whose loaded Rego is not exactly the approved policy (checked at most every 30 s).

        OPA may load the runtime modules and, optionally, this repository's own Rego unit tests byte for byte. Any other
        module is refused, whatever its name: an extra module could add rules to the decision package.
        """
        key = (self.base, self.fingerprint)
        if _OPA_VERIFIED.get(key, 0.0) > time.monotonic():
            return
        body = await self._get_json("GET", f"{self.base}/v1/policies")
        modules = body.get("result") if isinstance(body, dict) else None
        if not isinstance(modules, list):
            raise PolicyUnavailable("OPA did not list its loaded policies")
        loaded: dict[str, str] = {}
        for module in modules:
            name = Path(str(module.get("id", "") if isinstance(module, dict) else "")).name
            raw = module.get("raw", "") if isinstance(module, dict) else ""
            raw = raw.replace("\r\n", "\n") if isinstance(raw, str) else ""  # same normalisation as our side
            if self.known_tests.get(name) == raw:
                continue  # our own unit tests, unchanged: harmless (package aegis.tool_call_test)
            if name in loaded:
                raise PolicyUnavailable(f"OPA loaded two modules named {name}")
            loaded[name] = raw
        if loaded != self.expected:
            missing, extra = sorted(set(self.expected) - set(loaded)), sorted(set(loaded) - set(self.expected))
            detail = (
                f"missing {missing}"
                if missing
                else f"unexpected {extra}"
                if extra
                else "its Rego differs from the approved policy"
            )
            raise PolicyUnavailable(f"OPA does not run the approved policy: {detail}")
        _OPA_VERIFIED[key] = time.monotonic() + OPA_VERIFY_TTL

    async def evaluate(self, policy_input: dict) -> dict:
        await self.verify_policy()
        body = await self._get_json("POST", self.url, json={"input": with_policy_data(policy_input, self.data)})
        if not isinstance(body, dict) or "result" not in body:
            raise PolicyUnavailable("OPA returned no decision; is the aegis.tool_call policy loaded?")
        return normalize(body["result"], self.version)


def forget_opa_verification() -> None:
    """For tests and after deploying new Rego: re-check OPA's loaded policy on the next decision."""
    _OPA_VERIFIED.clear()


# ---- choosing an engine ---------------------------------------------------------------


def evaluator(
    kind: str,
    policy_dir: str,
    data: dict | None,
    version: str | None,
    *,
    http: httpx.AsyncClient | None = None,
    opa_url: str = "",
    opa_timeout: float = 2.0,
    opa_token: str = "",
    sources: dict[str, str] | None = None,
):
    """An engine bound to one policy configuration and the version id it should stamp on decisions. ``sources`` is the
    Rego the caller already checked against the approved version; the engine evaluates (or verifies) exactly that."""
    if kind == "python":
        return PythonEngine(policy_dir, data, version)
    if kind == "rego":
        return RegoEngine(policy_dir, data, version, sources=sources)
    if kind == "opa":
        if http is None or not opa_url:
            raise ValueError("policy_engine=opa needs an HTTP client and AEGIS_OPA_URL")
        return OpaEngine(
            opa_url, policy_dir, http, data, version, timeout=opa_timeout, token=opa_token, sources=sources
        )
    raise ValueError(f"unknown policy engine {kind!r}; choose one of {', '.join(ENGINES)}")


def rego_available() -> bool:
    try:
        import regopy  # noqa: F401
    except ImportError:
        return False
    return True
