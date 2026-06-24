"""LLM fiber (Wave 1).

Serves the `generate` capability as a token stream. Wave 1 **stubs** the model
call (no real model); the capability schema is the one a real model uses in
Wave 2. Optionally grant-gated.

Run standalone:  python3 llm.py <dir_host> <dir_port> <dir_id_hex>
"""

from __future__ import annotations

import asyncio

from thicket import DirectoryClient, grant, record, serve, unix_now


def stub_model(prompt: str):
    """Deterministic 'tokens' for a prompt (Wave 1 placeholder)."""
    return ["echo: ", prompt, " [done]"]


def make_handler(local, *, model=stub_model, require_grant: bool = False):
    async def handler(conn, payload: dict) -> None:
        if payload.get("capability") != "generate":
            await conn.respond_error(payload, "NotFound", "unknown capability")
            return
        if require_grant:
            auth = payload.get("auth")
            ok = auth is not None and grant.verify(
                auth,
                local.root_public_key,
                local.endorsements,
                conn.peer["working_pub"],
                "generate",
                unix_now(),
            )
            if not ok:
                await conn.respond_error(payload, "Unauthorized", "valid grant required")
                return
        prompt = payload.get("body", b"").decode("utf-8", "replace")
        tokens = model(prompt)
        for i, tok in enumerate(tokens):
            await conn.stream_chunk(payload, i, i == len(tokens) - 1, tok.encode("utf-8"))

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", model=stub_model, require_grant=False, ready=None):
    """Serve `generate`, register with the directory, then serve forever."""
    server = await serve(host, 0, local, make_handler(local, model=model, require_grant=require_grant))
    bound = server.sockets[0].getsockname()
    endpoint = f"{bound[0]}:{bound[1]}"

    rec = record.self_record(
        local,
        kind="model",
        capabilities=[record.capability("model", "text generation", tags=["chat"])],
        locators=[record.locator("tcp", endpoint)],
    )
    dc = await DirectoryClient.connect(dir_host, dir_port, local, dir_id)
    await dc.register(rec)
    await dc.close()

    if ready is not None:
        ready.set_result({"id": local.id, "endpoint": endpoint})

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    import sys

    from thicket import LocalIdentity, RootKey

    dir_host, dir_port, dir_id_hex = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    ident = LocalIdentity.from_root(RootKey.generate())
    asyncio.run(run(ident, dir_host, dir_port, bytes.fromhex(dir_id_hex)))
