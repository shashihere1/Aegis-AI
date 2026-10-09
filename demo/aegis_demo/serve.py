"""Serve the whole demo system on http://127.0.0.1:8000 (control API docs at /docs, Gateway at /gw/docs).

Run: python -m aegis_demo.serve
"""

import argparse
import asyncio
import logging
import os
import secrets

import uvicorn

from aegis.common.settings import Settings
from aegis_demo.world import FAKE_LLM_URL, running_world


class DemoServer:
    """ASGI wrapper that starts the in-process world on lifespan start-up and serves its routes."""

    def __init__(self, ephemeral: bool = False, sso_password: str = "") -> None:
        self.world = None
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self.ephemeral = ephemeral
        self.sso_password = sso_password

    async def _own(self, ready: asyncio.Future) -> None:
        try:
            from_env = Settings.from_env().model_dump()
            # A disposable demo ignores database and other settings, but identity settings (people's SSO and the
            # agents' identity provider) and the policy engine choice still apply.
            sign_in = {
                k: v
                for k, v in from_env.items()
                if k.startswith(("oidc_", "builtin_oidc", "keycloak_", "opa_"))
                or k in {"enable_dev_login", "agent_idp", "agent_token_ttl", "policy_engine"}
            }
            overrides = sign_in if self.ephemeral else from_env
            if not self.ephemeral and not overrides["database_url"].startswith("postgresql"):
                raise RuntimeError(
                    "Run deployment/local-postgres.ps1 first, or explicitly use --ephemeral for a disposable test demo"
                )
            overrides.update(
                control_url="http://127.0.0.1:8000", gateway_url="http://127.0.0.1:8000/gw", cache_seconds=0
            )
            if self.sso_password:
                overrides.update(builtin_oidc=True, builtin_oidc_password=self.sso_password)
            if not overrides.get("azure_openai_endpoint") and not overrides.get("llm_upstream_url"):
                overrides["llm_upstream_url"] = FAKE_LLM_URL
            async with running_world(seed=1244, **overrides) as world:
                ready.set_result(world)
                await self._stop.wait()
        except Exception as exc:
            if not ready.done():
                ready.set_exception(exc)
            raise

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    ready = asyncio.get_running_loop().create_future()
                    self._task = asyncio.create_task(self._own(ready))
                    self.world = await ready
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    self._stop.set()
                    await self._task
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        await self.world.composite(scope, receive, send)


if __name__ == "__main__":
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("mcp").setLevel(logging.WARNING)
    parser = argparse.ArgumentParser(description="Serve the Aegis demo (console at /ui, API docs at /docs).")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--ephemeral", action="store_true", help="Explicit disposable SQLite test mode")
    parser.add_argument("--sso", action="store_true", help="Also run the built-in OpenID Connect provider (demo only)")
    args = parser.parse_args()
    port = args.port
    sso_password = ""
    if args.sso:
        sso_password = os.environ.get("AEGIS_BUILTIN_OIDC_PASSWORD") or secrets.token_urlsafe(9)
        print(
            f"Built-in SSO provider on. Sign in at the console with any demo account (e.g. sanne.bakker); "
            f"password for this run: {sso_password}"
        )
    # TLS: when a certificate and key are configured, uvicorn terminates HTTPS directly. In Azure, TLS is
    # terminated at the Container Apps ingress (and data-plane ↔ control-plane runs over the environment's mTLS),
    # so these are typically left empty there.
    tls = Settings.from_env()
    ssl_kwargs = {}
    scheme = "http"
    if tls.tls_cert_file and tls.tls_key_file:
        ssl_kwargs = {"ssl_certfile": tls.tls_cert_file, "ssl_keyfile": tls.tls_key_file}
        scheme = "https"
    print(f"Aegis console: {scheme}://127.0.0.1:{port}/ui/   ·   API docs: {scheme}://127.0.0.1:{port}/docs")
    server = DemoServer(ephemeral=args.ephemeral, sso_password=sso_password)
    uvicorn.run(server, host="127.0.0.1", port=port, log_level="warning", **ssl_kwargs)
