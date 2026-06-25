"""CLI consumer: discover a `model` fiber and stream a generation from it.

The whole discover → connect → stream → decode dance is one ``Client.gather``.
"""

from __future__ import annotations

import asyncio

from thicket import Client


async def generate(dir_host, dir_port, dir_id, local, query: str, *, auth=None, timeout=30.0) -> str:
    async with Client(dir_host, dir_port, dir_id, local=local) as c:
        return await c.gather("model", "generate", query, auth=auth, timeout=timeout)


if __name__ == "__main__":
    import sys

    from thicket import LocalIdentity, RootKey

    dir_host, dir_port, dir_id_hex, query = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    local = LocalIdentity.from_root(RootKey.generate())
    print(asyncio.run(generate(dir_host, dir_port, bytes.fromhex(dir_id_hex), local, query)))
