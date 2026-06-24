"""CLI consumer: discover an `llm` fiber via the directory and stream a
generation from it."""

from __future__ import annotations

import asyncio

from thicket import Conn, DirectoryClient


async def generate(dir_host, dir_port, dir_id, local, query: str, *, auth=None) -> str:
    """Search → resolve → connect → stream. Returns the joined token text."""
    dc = await DirectoryClient.connect(dir_host, dir_port, local, dir_id)
    results = await dc.search(query, kind="model", top_k=5)
    await dc.close()
    if not results:
        raise RuntimeError("no model fiber found")

    rec = results[0]["payload"]
    fiber_id = rec["id"]
    host, port = rec["locators"][0]["endpoint"].split(":")

    conn = await Conn.connect(host, int(port), local, expected_id=fiber_id)
    try:
        tokens = []
        async for chunk in conn.call_stream("generate", query.encode("utf-8"), auth=auth):
            tokens.append(chunk.get("body", b"").decode("utf-8", "replace"))
        return "".join(tokens)
    finally:
        await conn.close()


if __name__ == "__main__":
    import sys

    from thicket import LocalIdentity, RootKey

    dir_host, dir_port, dir_id_hex, query = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    local = LocalIdentity.from_root(RootKey.generate())
    text = asyncio.run(generate(dir_host, dir_port, bytes.fromhex(dir_id_hex), local, query))
    print(text)
