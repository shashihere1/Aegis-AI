"""Hot state shared by the control plane and every Gateway replica.

Holds revocations, per-task information-flow (taint) state and rate-limit counters.
PostgreSQL stays the system of record: revocations are also persisted on the mandate rows and
re-loaded at start-up, so restarting the hot store never "un-revokes" a token.
"""

import time
from dataclasses import dataclass, field
from typing import Protocol

from aegis.common.models import data_class_rank


@dataclass
class Taint:
    tainted: bool = False
    max_data_class_read: str = "public"
    external_egress: bool = False
    sources: list[str] = field(default_factory=list)


class HotStore(Protocol):
    async def revoke(self, kind: str, value: str, reason: str) -> None: ...
    async def clear(self, kind: str, value: str) -> None: ...
    async def revoked(self, items: list[tuple[str, str]]) -> str | None: ...
    async def get_taint(self, root_id: str) -> Taint: ...
    async def update_taint(
        self, root_id: str, *, tainted_by: str | None = None, data_class: str | None = None,
        external_egress: bool = False,
    ) -> Taint: ...
    async def rate_hit(self, key: str, limit_per_min: int) -> bool: ...
    async def block_fingerprint(self, fingerprint: str) -> None: ...
    async def is_blocked(self, fingerprint: str) -> bool: ...


class MemoryHotStore:
    """Single-process implementation for local development and tests."""

    def __init__(self) -> None:
        self._revoked: dict[tuple[str, str], str] = {}
        self._taint: dict[str, Taint] = {}
        self._rates: dict[str, list[float]] = {}
        self._blocked: set[str] = set()

    async def revoke(self, kind: str, value: str, reason: str) -> None:
        self._revoked[(kind, value)] = reason

    async def clear(self, kind: str, value: str) -> None:
        self._revoked.pop((kind, value), None)

    async def revoked(self, items: list[tuple[str, str]]) -> str | None:
        for item in items:
            if item in self._revoked:
                return f"{item[0]} {item[1]} revoked: {self._revoked[item]}"
        return None

    async def get_taint(self, root_id: str) -> Taint:
        return self._taint.get(root_id, Taint())

    async def update_taint(self, root_id, *, tainted_by=None, data_class=None, external_egress=False) -> Taint:
        t = self._taint.setdefault(root_id, Taint())
        if tainted_by:
            t.tainted = True
            t.sources.append(tainted_by)
        if data_class and data_class_rank(data_class) > data_class_rank(t.max_data_class_read):
            t.max_data_class_read = data_class
        t.external_egress = t.external_egress or external_egress
        return t

    async def rate_hit(self, key: str, limit_per_min: int) -> bool:
        now = time.monotonic()
        window = [t for t in self._rates.get(key, []) if now - t < 60]
        allowed = len(window) < limit_per_min
        if allowed:
            window.append(now)
        self._rates[key] = window
        return allowed

    async def block_fingerprint(self, fingerprint: str) -> None:
        self._blocked.add(fingerprint)

    async def is_blocked(self, fingerprint: str) -> bool:
        return fingerprint in self._blocked


class ValkeyHotStore:
    """Valkey/Redis implementation for multi-replica deployments (requires the `valkey` extra)."""

    def __init__(self, url: str):
        import redis.asyncio as redis  # optional dependency

        self._r = redis.from_url(url, decode_responses=True)

    async def revoke(self, kind: str, value: str, reason: str) -> None:
        await self._r.set(f"rv:{kind}:{value}", reason)
        await self._r.publish("aegis:revocations", f"{kind}:{value}")

    async def clear(self, kind: str, value: str) -> None:
        await self._r.delete(f"rv:{kind}:{value}")

    async def revoked(self, items: list[tuple[str, str]]) -> str | None:
        keys = [f"rv:{k}:{v}" for k, v in items]
        for key, reason in zip(keys, await self._r.mget(keys), strict=True):
            if reason is not None:
                return f"{key} revoked: {reason}"
        return None

    async def get_taint(self, root_id: str) -> Taint:
        h = await self._r.hgetall(f"taint:{root_id}")
        return Taint(
            tainted=h.get("tainted") == "1",
            max_data_class_read=h.get("max_data_class_read", "public"),
            external_egress=h.get("external_egress") == "1",
            sources=[s for s in h.get("sources", "").split("|") if s],
        )

    async def update_taint(self, root_id, *, tainted_by=None, data_class=None, external_egress=False) -> Taint:
        t = await self.get_taint(root_id)
        if tainted_by:
            t.tainted = True
            t.sources.append(tainted_by)
        if data_class and data_class_rank(data_class) > data_class_rank(t.max_data_class_read):
            t.max_data_class_read = data_class
        t.external_egress = t.external_egress or external_egress
        await self._r.hset(
            f"taint:{root_id}",
            mapping={
                "tainted": "1" if t.tainted else "0",
                "max_data_class_read": t.max_data_class_read,
                "external_egress": "1" if t.external_egress else "0",
                "sources": "|".join(t.sources),
            },
        )
        await self._r.expire(f"taint:{root_id}", 86400)
        return t

    async def rate_hit(self, key: str, limit_per_min: int) -> bool:
        bucket = f"rl:{key}:{int(time.time() // 60)}"
        count = await self._r.incr(bucket)
        await self._r.expire(bucket, 120)
        return count <= limit_per_min

    async def block_fingerprint(self, fingerprint: str) -> None:
        await self._r.sadd("blocked_fingerprints", fingerprint)

    async def is_blocked(self, fingerprint: str) -> bool:
        return bool(await self._r.sismember("blocked_fingerprints", fingerprint))


def make_hotstore(url: str) -> HotStore:
    return ValkeyHotStore(url) if url else MemoryHotStore()
