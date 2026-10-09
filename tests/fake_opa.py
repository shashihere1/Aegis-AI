"""A stand-in for an OPA server, answering OPA's REST API with the REAL Rego evaluated by regopy.

It lets the OPA client be tested without an OPA binary: decisions, the loaded-policy check, and every failure mode.
Switches: `down` (503), `delay` (seconds before answering), `no_result`, `not_json`, `result` (force a result),
`modules` (what /v1/policies reports), and counters `decision_calls`, `policy_calls`, `authorizations`.
"""

import asyncio
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from aegis.policy.engines import RegoRuntime, runtime_modules


class FakeOpa:
    def __init__(self, policy_dir: str, line_endings: str = "\n"):
        self.policy_dir = policy_dir
        self.runtime = RegoRuntime(policy_dir)
        root = Path(policy_dir).resolve()

        # OPA reports module ids as the paths it loaded and `raw` as the file bytes, so a Windows checkout reports CRLF.
        # Test modules may be loaded too and must be ignored.
        def raw(path: Path) -> str:
            return path.read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\n", line_endings)

        self.modules = [{"id": str(p.resolve()), "raw": raw(p)} for p in runtime_modules(policy_dir)]
        self.modules += [{"id": str(p), "raw": raw(p)} for p in sorted(root.glob("*_test.rego"))]
        self.down = False
        self.delay = 0.0
        self.no_result = False
        self.not_json = False
        self.result = None
        self.decision_calls = 0
        self.policy_calls = 0
        self.authorizations: list[str] = []
        self.inputs: list[dict] = []
        self.app = Starlette(
            routes=[
                Route("/v1/data/aegis/tool_call/decision", self.decision, methods=["POST"]),
                Route("/v1/policies", self.policies),
                Route("/health", self.health),
            ]
        )

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
        return JSONResponse({"result": self.runtime.query(body["input"])})

    async def policies(self, request: Request):
        self.policy_calls += 1
        if (early := await self._common(request)) is not None:
            return early
        return JSONResponse({"result": self.modules})

    async def health(self, request: Request):
        return JSONResponse({})
