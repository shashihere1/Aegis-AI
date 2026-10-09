"""The Gateway's client for the control plane's internal API, with short-lived caches."""

import time

import httpx
import jwt

from aegis.common.crypto import SigningKey
from aegis.common.service_identity import mint_service_token
from aegis.telemetry import tracing_headers


class ControlPlaneClient:
    def __init__(self, http: httpx.AsyncClient, control_url: str, service_key: SigningKey, cache_seconds: float):
        self.http = http
        self.base = control_url.rstrip("/")
        self._service_key = service_key
        self.cache_seconds = cache_seconds
        self._cache: dict[str, tuple[float, object]] = {}
        self._sts_key = None

    def _service_headers(self) -> dict:
        # A fresh asymmetric assertion per call; the control plane verifies it with our public key only.
        return {"x-aegis-internal": mint_service_token(self._service_key)}

    async def _get(self, path: str, cache: bool = True):
        hit = self._cache.get(path)
        if cache and hit and time.monotonic() - hit[0] < self.cache_seconds:
            return hit[1]
        response = await self.http.get(f"{self.base}{path}", headers=tracing_headers(self._service_headers()))
        if response.status_code == 404:
            return None
        response.raise_for_status()
        value = response.json()
        self._cache[path] = (time.monotonic(), value)
        return value

    async def _post(self, path: str, payload: dict) -> dict:
        response = await self.http.post(
            f"{self.base}{path}", headers=tracing_headers(self._service_headers()), json=payload
        )
        response.raise_for_status()
        return response.json()

    async def sts_public_key(self):
        """STS verification key from the public JWKS (keys are fetched once and kept)."""
        if self._sts_key is None:
            jwks = (await self.http.get(f"{self.base}/.well-known/jwks.json", headers=tracing_headers())).json()
            self._sts_key = jwt.PyJWK(jwks["keys"][0]).key
        return self._sts_key

    async def agent(self, agent_id: str) -> dict | None:
        return await self._get(f"/internal/agents/{agent_id}")

    async def server_url(self, server_id: str) -> str | None:
        server = await self._get(f"/internal/servers/{server_id}")
        return server["url"] if server else None

    async def tools(self, server_id: str) -> dict[str, dict]:
        rows = await self._get(f"/internal/tools?server={server_id}") or []
        return {row["name"]: row for row in rows}

    async def decision(self, payload: dict) -> dict:
        return await self._post("/internal/decisions", payload)

    async def event(self, payload: dict) -> None:
        await self._post("/internal/events", payload)

    async def create_approval(self, payload: dict) -> dict:
        return await self._post("/internal/approvals", payload)

    async def approval(self, approval_id: str) -> dict | None:
        return await self._get(f"/internal/approvals/{approval_id}", cache=False)

    async def consume_approval(self, approval_id: str) -> dict:
        return await self._post(f"/internal/approvals/{approval_id}/consume", {})

    async def usage(self, payload: dict) -> None:
        await self._post("/internal/usage", payload)

    async def reserve_llm(self, payload: dict) -> dict:
        return await self._post("/internal/llm/reserve", payload)

    async def settle_llm(self, reservation_id: str, payload: dict) -> dict:
        return await self._post(f"/internal/llm/{reservation_id}/settle", payload)
