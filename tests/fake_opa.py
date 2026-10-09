"""A stand-in for an OPA server, answering OPA's REST API with the REAL Rego evaluated by regopy.

It lets the OPA client be tested without an OPA binary: decisions, the loaded-policy check, and every failure mode.
Switches: `down` (503), `delay` (seconds before answering), `no_result`, `not_json`, `result` (force a result),
`modules` (what /v1/policies reports), `read_only` (refuse writes), and counters `decision_calls`, `policy_calls`,
`authorizations`, `writes`. PUT / DELETE /v1/policies/{id} compile the result first and refuse it (400) if it does not
compile, as OPA does. `empty=True` starts it with no policy loaded, like `opa run --server` with no files.
"""

import asyncio
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from aegis.policy.engines import RegoRuntime, runtime_modules


class FakeOpa:
    def __init__(self, policy_dir: str, line_endings: str = "\n", empty: bool = False):
        self.policy_dir = policy_dir
        self.runtime = None if empty else RegoRuntime(policy_dir)
        root = Path(policy_dir).resolve()

        # OPA reports module ids as the paths it loaded and `raw` as the file bytes, so a Windows checkout reports CRLF.
        # Test modules may be loaded too and must be ignored.
        def raw(path: Path) -> str:
            return path.read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\n", line_endings)

        self.modules = [] if empty else [{"id": str(p.resolve()), "raw": raw(p)} for p in runtime_modules(policy_dir)]
        self.modules += [] if empty else [{"id": str(p), "raw": raw(p)} for p in sorted(root.glob("*_test.rego"))]
        self.down = False
        self.delay = 0.0
        self.no_result = False
        self.not_json = False
        self.result = None
        self.decision_calls = 0
        self.policy_calls = 0
        self.authorizations: list[str] = []
        self.inputs: list[dict] = []
        self.writes: list[tuple[str, str]] = []  # (method, module id) for every accepted PUT / DELETE
        self.read_only = False  # answer writes with 403, like an authenticating proxy that only allows reads
        self.app = Starlette(
            routes=[
                Route("/v1/data/aegis/tool_call/decision", self.decision, methods=["POST"]),
                Route("/v1/policies", self.policies),
                Route("/v1/policies/{module_id:path}", self.write_policy, methods=["PUT", "DELETE"]),
                Route("/health", self.health),
            ]
        )

    def _rebuild(self, modules: list[dict]):
        """Compile like OPA does on every write: the runtime is every module that is not a test."""
        runtime = [m for m in modules if not m["id"].endswith("_test.rego")]
        sources = {Path(m["id"]).name: m["raw"].replace("\r\n", "\n") for m in runtime}
        return RegoRuntime(self.policy_dir, sources) if sources else None

    async def write_policy(self, request: Request):
        if (early := await self._common(request)) is not None:
            return early
        if self.read_only:
            return JSONResponse({"code": "unauthorized", "message": "writes are not allowed"}, 403)
        module_id = request.path_params["module_id"]
        if request.method == "DELETE":
            if not any(m["id"] == module_id for m in self.modules):
                return JSONResponse({"code": "resource_not_found", "message": f"policy id {module_id!r}"}, 404)
            modules = [m for m in self.modules if m["id"] != module_id]
        else:
            raw = (await request.body()).decode("utf-8")
            others = [m for m in self.modules if m["id"] != module_id]
            modules = others + [{"id": module_id, "raw": raw}]
        try:
            runtime = self._rebuild(modules)
        except Exception:
            error = {"code": "invalid_parameter", "message": "error(s) occurred while compiling module(s)"}
            return JSONResponse(error, 400)
        self.modules, self.runtime = modules, runtime
        self.writes.append((request.method, module_id))
        return JSONResponse({})

    async def _common(self, request: Request):
        self.authorizations.append(request.headers.get("authorization", ""))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.down:
            return JSONResponse({"code": "internal_error"}, 503)
        if self.not_json:
            return PlainTextResponse("<html>proxy error</html>")
        return None

    async def decision(self, request: Request):
        self.decision_calls += 1
        if (early := await self._common(request)) is not None:
            return early
        body = await request.json()
        self.inputs.append(body.get("input"))
        if self.no_result:
            return JSONResponse({})  # what OPA answers when the queried rule does not exist
        if self.result is not None:
            return JSONResponse({"result": self.result})
        if self.runtime is None:
            return JSONResponse({})  # no policy loaded: OPA answers without a result
        return JSONResponse({"result": self.runtime.query(body["input"])})

    async def policies(self, request: Request):
        self.policy_calls += 1
        if (early := await self._common(request)) is not None:
            return early
        return JSONResponse({"result": self.modules})

    async def health(self, request: Request):
        return JSONResponse({})
