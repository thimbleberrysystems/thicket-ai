"""Tech debt #5 (persistence) + #6 (metering/quota)."""

import asyncio
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
sys.path.insert(0, os.path.join(REPO, "fibers", "py", "memory"))

from thicket import Client, Fiber, FileStore, LocalIdentity, RootKey, ThicketError  # noqa: E402

import memory as memory_mod  # noqa: E402


class FileStoreUnit(unittest.TestCase):
    def test_roundtrips_through_a_file(self):
        path = os.path.join(tempfile.mkdtemp(), "s.cbor")
        s = FileStore(path)
        self.assertEqual(s.data, {})  # fresh
        s.data[b"k"] = ["a", "b"]  # byte key — needs CBOR, not JSON
        s.save()
        self.assertEqual(FileStore(path).data, {b"k": ["a", "b"]})  # reloaded

    def test_none_path_is_in_memory(self):
        s = FileStore(None)
        s.data["x"] = 1
        s.save()  # no-op, no file


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class QuotaAndPersistence(unittest.TestCase):
    def _directory(self):
        proc = subprocess.Popen([DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        id_hex, addr = proc.stdout.readline().strip().split()
        host, port = addr.split(":")
        return proc, bytes.fromhex(id_hex), host, int(port)

    async def _serve(self, coro, dir_id, host, port, **kw):
        local = LocalIdentity.from_root(RootKey.generate())
        ready = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
        info = await asyncio.wait_for(ready, 10)
        return task, info

    async def _stop(self, task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    def test_capability_cost_enforces_quota(self):
        proc, dir_id, host, port = self._directory()
        meter = Fiber(kind="tool")

        @meter.handles("pay", "a metered action", cost=10)
        async def pay(req):
            return {"ok": True}

        try:

            async def scenario():
                task, _ = await self._serve(meter.run, dir_id, host, port)
                ctx_ok = {"trace_id": b"t", "span_id": b"s", "budget": 50}
                ctx_low = {"trace_id": b"t", "span_id": b"s", "budget": 5}
                async with Client(host, port, dir_id) as c:
                    ok = await c.call("tool", "pay", {}, context=ctx_ok)
                    try:
                        await c.call("tool", "pay", {}, context=ctx_low)
                        low = "ALLOWED"
                    except ThicketError as e:
                        low = e.code
                    free = await c.call("tool", "pay", {})  # no budget -> no quota check
                await self._stop(task)
                return ok, low, free

            ok, low, free = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertTrue(ok["ok"])
            self.assertEqual(low, "QuotaExceeded")  # budget 5 < cost 10
            self.assertTrue(free["ok"])
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_memory_persists_across_restart(self):
        proc, dir_id, host, port = self._directory()
        path = os.path.join(tempfile.mkdtemp(), "mem.cbor")
        try:

            async def scenario():
                consumer = LocalIdentity.from_root(RootKey.generate())
                # instance 1: write, then shut down
                t1, i1 = await self._serve(memory_mod.run, dir_id, host, port, persist=path)
                h1, p1 = i1["endpoint"].split(":")
                mc = await memory_mod.MemoryClient.connect(h1, int(p1), consumer, i1["id"])
                await mc.append("s1", {"content": "remember me"})
                await mc.close()
                await self._stop(t1)

                # instance 2: a fresh fiber at the same path reads what 1 wrote
                t2, i2 = await self._serve(memory_mod.run, dir_id, host, port, persist=path)
                h2, p2 = i2["endpoint"].split(":")
                mc2 = await memory_mod.MemoryClient.connect(h2, int(p2), consumer, i2["id"])
                msgs = await mc2.materialize("s1")
                await mc2.close()
                await self._stop(t2)
                return msgs

            msgs = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(msgs, [{"content": "remember me"}])  # survived the restart
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
