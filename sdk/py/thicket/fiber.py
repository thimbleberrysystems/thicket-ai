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
    profile=None,
    ready=None,
):
    server = await serve(host, 0, local, handler)
    bound = server.sockets[0].getsockname()
    endpoint = f"{bound[0]}:{bound[1]}"

    rec = record.self_record(
        local,
        kind=kind,
        capabilities=capabilities,
        locators=[record.locator("tcp", endpoint)],
        profile=profile,
    )
    dc = await DirectoryClient.connect(dir_host, dir_port, local, dir_id)
    await dc.register(rec)
    await dc.close()

    if ready is not None:
        ready.set_result({"id": local.id, "endpoint": endpoint})

    # Note: close() (not wait_closed()) on teardown — a long-lived handler (e.g. a
    # trigger subscription parked on its event queue) must not block shutdown.
    try:
        await server.serve_forever()
    finally:
        server.close()


def run_main(run, **kwargs):
    """Standalone CLI entry for a fiber module:

        python <fiber>.py <dir_host> <dir_port> <dir_id_hex>

    Generates a fresh identity and serves the fiber's ``run`` against the given
    directory until killed. Lets every fiber be launched as its own process."""
    import asyncio
    import sys

    from .crypto import RootKey
    from .identity import LocalIdentity

    if len(sys.argv) < 4:
        sys.exit(f"usage: python {sys.argv[0]} <dir_host> <dir_port> <dir_id_hex>")
    dir_host, dir_port, dir_id_hex = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    ident = LocalIdentity.from_root(RootKey.generate())
    asyncio.run(run(ident, dir_host, dir_port, bytes.fromhex(dir_id_hex), **kwargs))
