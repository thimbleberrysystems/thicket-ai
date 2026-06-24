"""Helper to run a fiber: serve a handler, register the fiber's record with a
directory, then serve forever."""

from __future__ import annotations

from . import record
from .directory import DirectoryClient
from .server import serve


async def run_fiber(
    local,
    dir_host,
    dir_port,
    dir_id,
    *,
    kind: str,
    capabilities: list,
    handler,
    host: str = "127.0.0.1",
    ready=None,
):
    server = await serve(host, 0, local, handler)
    bound = server.sockets[0].getsockname()
    endpoint = f"{bound[0]}:{bound[1]}"

    rec = record.self_record(
        local, kind=kind, capabilities=capabilities, locators=[record.locator("tcp", endpoint)]
    )
    dc = await DirectoryClient.connect(dir_host, dir_port, local, dir_id)
    await dc.register(rec)
    await dc.close()

    if ready is not None:
        ready.set_result({"id": local.id, "endpoint": endpoint})

    async with server:
        await server.serve_forever()
