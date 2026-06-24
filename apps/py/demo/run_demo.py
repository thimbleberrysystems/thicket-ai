"""Runnable end-to-end demo — the thing you can actually run.

Boots a directory, a tool fiber, an LLM fiber, and the sum_describer weave, then
invokes the weave as a consumer and prints the result. This is the integration
test's scene lifted into a program:

    cargo build -p thicket-directory --example directory_server   # once
    python apps/py/demo/run_demo.py
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
sys.path.insert(0, os.path.join(REPO, "sdk", "py"))
for _p in ("fibers/py/llm", "fibers/py/tool_calc", "weaves/py/sum_describer"):
    sys.path.insert(0, os.path.join(REPO, *_p.split("/")))

from thicket import Conn, DirectoryClient, LocalIdentity, RootKey, cbor  # noqa: E402

import calc  # noqa: E402
import llm  # noqa: E402
import weave as weave_mod  # noqa: E402


async def _serve(coro, dir_id, host, port, **kw):
    local = LocalIdentity.from_root(RootKey.generate())
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
    await asyncio.wait_for(ready, 10)
    return task


async def demo(a: int = 2, b: int = 3) -> dict:
    """Run the whole scene and return the weave's result dict."""
    if not os.path.exists(DIR_BIN):
        raise SystemExit(
            "build the directory first:\n"
            "  cargo build -p thicket-directory --example directory_server"
        )
    proc = subprocess.Popen([DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    tasks: list = []
    try:
        id_hex, addr = proc.stdout.readline().strip().split()
        dir_id = bytes.fromhex(id_hex)
        host, port = addr.split(":")
        port = int(port)

        for coro in (calc.run, llm.run, weave_mod.run):
            tasks.append(await _serve(coro, dir_id, host, port))

        consumer = LocalIdentity.from_root(RootKey.generate())
        dc = await DirectoryClient.connect(host, port, consumer, dir_id)
        hit = (await dc.search("describe the sum of two numbers", kind="weave"))[0]["payload"]
        await dc.close()

        wh, wp = hit["locators"][0]["endpoint"].split(":")
        conn = await Conn.connect(wh, int(wp), consumer, expected_id=hit["id"])
        resp = await conn.call("describe_sum", cbor.encode({"a": a, "b": b}), timeout=20)
        await conn.close()
        return cbor.decode(resp["payload"]["body"])
    finally:
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        proc.kill()
        proc.wait()
        proc.stdout.close()


if __name__ == "__main__":
    out = asyncio.run(demo())
    print(f"sum         = {out['sum']}")
    print(f"description = {out['description']}")
