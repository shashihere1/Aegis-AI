import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from fastapi import Request

from aegis.common.crypto import SigningKey
from aegis.common.settings import REPO_ROOT, Settings
from aegis.control.db import Database
from aegis.control.identity.idp import DevIdp
from aegis.control.identity.oidc import OidcVerifier
from aegis.control.identity.users import UserAuthenticator
from aegis.hotstore import HotStore


@dataclass
class ControlContext:
    settings: Settings
    db: Database
    idp: DevIdp
    sts_key: SigningKey
    hotstore: HotStore
    http: httpx.AsyncClient
    taxonomy: dict[str, list[str]]
    users: UserAuthenticator | None = None  # who is this bearer token? (dev personas and/or OIDC)
    oidc: OidcVerifier | None = None
    builtin_oidc: Any = None  # the demo-only OIDC provider, when enabled
    telemetry: Any = None
    llm_budget_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def sts_issuer(self) -> str:
        return f"{self.settings.control_url}/sts"


def load_taxonomy() -> dict[str, list[str]]:
    data = json.loads(Path(REPO_ROOT / "config" / "taxonomy.json").read_text(encoding="utf-8"))
    return data["categories"]


def ctx(request: Request) -> ControlContext:
    return request.app.state.ctx


async def session(request: Request):
    async with request.app.state.ctx.db.sessionmaker() as s:
        yield s
