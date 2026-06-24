"""Phase 7 — Federation: discovery across multiple **independent** directories
with no central hub.

Two directory servers run side by side (distinct identities, separate
registries). A fiber registers with directory A, another with directory B. A
``FederatedDirectory`` over both resolves either fiber and a federated search
returns fibers from *both* directories — proving no single directory is
authoritative.
"""

import asyncio
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
for p in ("fibers/py/llm", "fibers/py/tool_calc"):
    sys.path.insert(0, os.path.join(REPO, *p.split("/")))

from thicket import FederatedDirectory, LocalIdentity, RootKey  # noqa: E402

import calc  # noqa: E402
import llm  # noqa: E402


def _spawn_directory(seed):
    proc = subprocess.Popen(
        [DIR_BIN, str(seed)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    id_hex, addr = proc.stdout.readline().strip().split()
    host, port = addr.split(":")
    return proc, bytes.fromhex(id_hex), host, int(port)


async def _serve(coro, dir_id, host, port, **kw):
    local = LocalIdentity.from_root(RootKey.generate())
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
    info = await asyncio.wait_for(ready, 10)
    return local, task, info


async def _stop(*tasks):
    for t in tasks:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class Federation(unittest.TestCase):
    def test_distinct_directories_have_distinct_ids(self):
        a = _spawn_directory(8)
        b = _spawn_directory(18)
        try:
            self.assertNotEqual(a[1], b[1])  # different identities, no shared hub
        finally:
            for proc, *_ in (a, b):
                proc.kill()
                proc.wait()
                proc.stdout.close()

    def test_federated_discovery_across_directories(self):
        a_proc, a_id, a_host, a_port = _spawn_directory(8)
        b_proc, b_id, b_host, b_port = _spawn_directory(18)
        try:

            async def scenario():
                # a tool registers only with directory A; a model only with B
                _, ttask, tinfo = await _serve(calc.run, a_id, a_host, a_port)
                _, ltask, linfo = await _serve(llm.run, b_id, b_host, b_port)
                consumer = LocalIdentity.from_root(RootKey.generate())

                fed = await FederatedDirectory.connect(
                    [(a_host, a_port, a_id), (b_host, b_port, b_id)], consumer
                )
                # resolve reaches across both directories
                tool_rec = await fed.resolve(tinfo["id"])
                llm_rec = await fed.resolve(linfo["id"])
                # a broad search merges results from both
                tool_hits = await fed.search("integer addition", kind="tool", top_k=5)
                model_hits = await fed.search("text generation", kind="model", top_k=5)
                await fed.close()
                await _stop(ttask, ltask)
                return tool_rec, llm_rec, tool_hits, model_hits

            tool_rec, llm_rec, tool_hits, model_hits = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertIsNotNone(tool_rec, "tool (registered in dir A) resolvable via federation")
            self.assertIsNotNone(llm_rec, "model (registered in dir B) resolvable via federation")
            self.assertEqual(tool_rec["payload"]["kind"], "tool")
            self.assertEqual(llm_rec["payload"]["kind"], "model")
            # each fiber is discoverable through the federation though it lives in
            # only one of the two directories
            self.assertTrue(any(h["payload"]["kind"] == "tool" for h in tool_hits))
            self.assertTrue(any(h["payload"]["kind"] == "model" for h in model_hits))
        finally:
            for proc in (a_proc, b_proc):
                proc.kill()
                proc.wait()
                proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
