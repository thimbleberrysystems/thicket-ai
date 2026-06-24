"""LLM fiber (Wave 1).

Serves the `generate` capability as a token stream. Wave 1 **stubs** the model
call (no real model); the capability schema is the one a real model uses in
Wave 2. Optionally grant-gated.

Run standalone:  python3 llm.py <dir_host> <dir_port> <dir_id_hex>
"""

from __future__ import annotations

import asyncio
import contextlib

from thicket import grant, record, tracing, unix_now
from thicket.fiber import run_fiber


def stub_model(prompt: str):
    """Deterministic 'tokens' for a prompt (Wave 1 placeholder)."""
    return ["echo: ", prompt, " [done]"]


def ollama_model(prompt: str, *, model="qwen2.5:0.5b", host="http://127.0.0.1:11434", timeout=120):
    """Wave 2: real inference via a local Ollama model. Returns one chunk (the
    full completion). What the fiber wraps is the author's choice — Thicket is
    indifferent; the capability schema is unchanged."""
    import json
    import urllib.request

    data = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(
        f"{host}/api/generate", data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return [json.loads(r.read().decode("utf-8"))["response"]]


def make_handler(local, *, model=stub_model, require_grant: bool = False, emitter=None):
    async def handler(conn, payload: dict) -> None:
        if payload.get("capability") != "generate":
            await conn.respond_error(payload, "NotFound", "unknown capability")
            return
        ctx = payload.get("context") or {}
        if tracing.deadline_exceeded(ctx):
            await conn.respond_error(payload, "DeadlineExceeded", "deadline passed before generation")
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
        tokens = await asyncio.to_thread(model, prompt)  # model call may block (e.g. HTTP)
        span = (
            emitter.span(ctx, name="model:generate", kind="model", attrs={"tokens": len(tokens)})
            if emitter
            else contextlib.nullcontext()
        )
        async with span:
            for i, tok in enumerate(tokens):
                await conn.stream_chunk(payload, i, i == len(tokens) - 1, tok.encode("utf-8"))

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", model=stub_model, require_grant=False, ready=None):
    """Serve `generate`, register with the directory, then serve forever."""
    emitter = tracing.SpanEmitter(local, dir_host, dir_port, dir_id)
    try:
        await run_fiber(
            local,
            dir_host,
            dir_port,
            dir_id,
            kind="model",
            capabilities=[record.capability("model", "text generation", tags=["chat"])],
            handler=make_handler(local, model=model, require_grant=require_grant, emitter=emitter),
            host=host,
            ready=ready,
        )
    finally:
        await emitter.close()


if __name__ == "__main__":
    import sys

    from thicket import LocalIdentity, RootKey

    dir_host, dir_port, dir_id_hex = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    ident = LocalIdentity.from_root(RootKey.generate())
    asyncio.run(run(ident, dir_host, dir_port, bytes.fromhex(dir_id_hex)))
