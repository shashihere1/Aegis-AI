"""Explicit offline fixtures for security regression tests, not the normal application."""

from contextlib import asynccontextmanager

from aegis_demo.world import BASE, FAKE_LLM_URL  # noqa: F401 -- test convenience exports
from aegis_demo.world import running_world as live_world


@asynccontextmanager
async def running_world(*args, **kwargs):
    async with live_world(*args, offline_fixtures=True, **kwargs) as world:
        yield world
