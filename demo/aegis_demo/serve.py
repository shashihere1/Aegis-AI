"""Serve the whole demo system on http://127.0.0.1:8000 (control API docs at /docs, Gateway at /gw/docs).

Run: python -m aegis_demo.serve
"""

import argparse
import asyncio

import uvicorn

from aegis_demo.world import FAKE_LLM_URL, running_world


class DemoServer:
    """ASGI wrapper that starts the in-process world on lifespan start-up and serves its routes."""

    def __init__(self) -> None:
        self.world = None
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def _own(self, ready: asyncio.Future) -> None:
        async with running_world(seed=1244, llm_upstream_url=FAKE_LLM_URL) as world:
            ready.set_result(world)
            await self._stop.wait()

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
    parser = argparse.ArgumentParser(description="Serve the Aegis demo (console at /ui, API docs at /docs).")
    parser.add_argument("--port", type=int, default=8000)
    port = parser.parse_args().port
    print(f"Aegis console: http://127.0.0.1:{port}/ui   ·   API docs: http://127.0.0.1:{port}/docs")
    uvicorn.run(DemoServer(), host="127.0.0.1", port=port, log_level="warning")
