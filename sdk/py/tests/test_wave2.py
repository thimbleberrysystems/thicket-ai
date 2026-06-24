"""Wave 2 integration: Memory fiber (pass-by-reference), real LLM via Ollama,
and a hand-wired stateful memory+LLM exchange (precursor to a weave)."""

import asyncio
import os
import subprocess
import sys
import unittest
import urllib.request

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
for p in ("fibers/py/llm", "fibers/py/memory", "apps/py/cli"):
    sys.path.insert(0, os.path.join(REPO, *p.split("/")))

from thicket import Conn, LocalIdentity, RootKey  # noqa: E402

import cli  # noqa: E402
import llm  # noqa: E402
import memory  # noqa: E402
from memory import MemoryClient  # noqa: E402


def _ollama_up() -> bool:
    try:
        urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3)
        return True
    except Exception:
        return False


async def _serve(coro_factory, dir_id, host, port, **kw):
    local = LocalIdentity.from_root(RootKey.generate())
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(coro_factory(local, host, port, dir_id, ready=ready, **kw))
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
class Wave2(unittest.TestCase):
    def _directory(self):
        proc = subprocess.Popen(
            [DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        id_hex, addr = proc.stdout.readline().strip().split()
        host, port = addr.split(":")
        return proc, bytes.fromhex(id_hex), host, int(port)

    def test_memory_pass_by_reference(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                mem_local, task, info = await _serve(memory.run, dir_id, host, port)
                mhost, mport = info["endpoint"].split(":")
                consumer = LocalIdentity.from_root(RootKey.generate())
                mc = await MemoryClient.connect(mhost, mport, consumer, mem_local.id)
                await mc.append("s1", {"role": "user", "content": "hello"})
                await mc.append("s1", {"role": "assistant", "content": "world"})
                msgs = await mc.materialize("s1")
                hits = await mc.retrieve("s1", "world")
                await mc.close()
                await _stop(task)
                return msgs, hits

            msgs, hits = asyncio.run(asyncio.wait_for(scenario(), 25))
            self.assertEqual([m["content"] for m in msgs], ["hello", "world"])
            self.assertEqual([m["content"] for m in hits], ["world"])
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_stateful_memory_plus_llm(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                mem_local, mtask, minfo = await _serve(memory.run, dir_id, host, port)
                llm_local, ltask, _ = await _serve(llm.run, dir_id, host, port)
                consumer = LocalIdentity.from_root(RootKey.generate())

                mhost, mport = minfo["endpoint"].split(":")
                mc = await MemoryClient.connect(mhost, mport, consumer, mem_local.id)
                await mc.append("conv", {"role": "user", "content": "hello world"})
                ctx = await mc.materialize("conv")
                prompt = " ".join(m["content"] for m in ctx)

                reply = await cli.generate(host, port, dir_id, consumer, prompt)
                await mc.append("conv", {"role": "assistant", "content": reply})
                final = await mc.materialize("conv")
                await mc.close()
                await _stop(mtask, ltask)
                return final

            final = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(len(final), 2)
            self.assertEqual(final[0]["content"], "hello world")
            self.assertIn("echo:", final[1]["content"])
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    @unittest.skipUnless(_ollama_up(), "ollama not reachable")
    def test_llm_real_inference_via_ollama(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                model = lambda p: llm.ollama_model(p, model="qwen2.5:0.5b")  # noqa: E731
                _, task, _ = await _serve(llm.run, dir_id, host, port, model=model)
                consumer = LocalIdentity.from_root(RootKey.generate())
                text = await cli.generate(
                    host, port, dir_id, consumer, "Reply with one short word.", timeout=150
                )
                await _stop(task)
                return text

            text = asyncio.run(asyncio.wait_for(scenario(), 180))
            # structure, not content: a real model produced a non-empty completion
            self.assertGreater(len(text.strip()), 0)
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
