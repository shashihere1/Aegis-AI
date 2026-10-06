import asyncio
import copy
import logging

import pytest

from aegis_demo import data, mcp_servers
from aegis_demo.world import FAKE_LLM_URL, running_world

logging.getLogger("mcp").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

_CUSTOMERS = copy.deepcopy(data.CUSTOMERS)


@pytest.fixture
async def world():
    mcp_servers.SENT_EMAILS.clear()
    mcp_servers.TRANSFERS.clear()
    data.CUSTOMERS.clear()
    data.CUSTOMERS.update(copy.deepcopy(_CUSTOMERS))

    # The MCP SDK's task groups must be entered and exited in the same task, so one task owns the
    # world's whole lifetime while the test runs.
    ready: asyncio.Future = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()

    async def owner():
        async with running_world(llm_upstream_url=FAKE_LLM_URL) as w:
            ready.set_result(w)
            await stop.wait()

    task = asyncio.create_task(owner())
    await asyncio.wait({task, ready}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        task.result()  # surface start-up errors
    yield ready.result()
    stop.set()
    await task
