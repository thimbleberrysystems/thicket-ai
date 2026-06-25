"""Runnable demo of capability-scoped delegation.

A resource owner grants an agent read+write. The agent delegates **read-only** to
a sub-agent. The sub-agent reads fine — and is *cryptographically* unable to
write, no matter what its prompt says. Authority is enforced by the protocol, not
the prompt.

    cargo build -p thicket-directory --example directory_server   # once
    python apps/py/demo/delegation_demo.py
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
sys.path.insert(0, os.path.join(REPO, "fibers", "py", "tool_fs"))

from thicket import Client, Context, LocalIdentity, RootKey, ThicketError, grant, unix_now  # noqa: E402

import fs as fs_mod  # noqa: E402


async def demo() -> list[str]:
    if not os.path.exists(DIR_BIN):
        raise SystemExit("build the directory first:\n  cargo build -p thicket-directory --example directory_server")
    proc = subprocess.Popen([DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    out: list[str] = []
    task = None
    try:
        id_hex, addr = proc.stdout.readline().strip().split()
        dir_id = bytes.fromhex(id_hex)
        host, port = addr.split(":")
        port = int(port)

        owner = LocalIdentity.from_root(RootKey.generate())  # owns the filesystem tool
        ready = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(fs_mod.run(owner, host, port, dir_id, ready=ready))
        await asyncio.wait_for(ready, 10)
        far = unix_now() + 3600

        agent = LocalIdentity.from_root(RootKey.generate())
        g_agent = grant.issue(owner.id, owner.working, agent.working.public(),
                              grant.caveats(["fs.read", "fs.write"], far))
        out.append("owner  → agent     : granted [fs.read, fs.write]")

        subagent = LocalIdentity.from_root(RootKey.generate())
        actx = Context(agent, (host, port, dir_id), {"trace_id": b"demo"}, tool_grant=g_agent)
        g_sub = actx.delegate(subagent.working.public(), ["fs.read"])
        out.append("agent  → sub-agent : delegated [fs.read]  (read-only)")

        async with Client(host, port, dir_id, local=agent) as ac:
            await ac.call("tool", "fs.write", {"path": "secret.txt", "content": "launch codes"}, auth=g_agent)
            out.append("agent  writes secret.txt                    → ok (agent has write)")

        async with Client(host, port, dir_id, local=subagent) as sc:
            r = await sc.call("tool", "fs.read", {"path": "secret.txt"}, auth=g_sub)
            out.append(f"sub-agent reads secret.txt                   → ok: {r['content']!r}")
            try:
                await sc.call("tool", "fs.write", {"path": "secret.txt", "content": "PWNED"}, auth=g_sub)
                out.append("sub-agent writes secret.txt                  → !! ALLOWED (should not happen)")
            except ThicketError as e:
                out.append(f"sub-agent writes secret.txt                  → DENIED ({e.code}) — cryptographically blocked")
        return out
    finally:
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        proc.kill()
        proc.wait()
        proc.stdout.close()


if __name__ == "__main__":
    for line in asyncio.run(demo()):
        print(line)
