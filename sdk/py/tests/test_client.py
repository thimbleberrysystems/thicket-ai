"""Consumer ergonomics: the public Client discovers + invokes fibers in one
line, and reuses the directory connection + one channel per fiber."""

import asyncio
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
sys.path.insert(0, os.path.join(REPO, "fibers", "py", "tool_calc"))

from thicket import Client, LocalIdentity, RootKey, ThicketError  # noqa: E402

import calc  # noqa: E402


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class ClientErgonomics(unittest.TestCase):
    def _directory(self):
        proc = subprocess.Popen([DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        id_hex, addr = proc.stdout.readline().strip().split()
        host, port = addr.split(":")
        return proc, bytes.fromhex(id_hex), host, int(port)

    async def _serve(self, dir_id, host, port):
        local = LocalIdentity.from_root(RootKey.generate())
        ready = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(calc.run(local, host, port, dir_id, ready=ready))
        await asyncio.wait_for(ready, 10)
        return task

    def test_call_search_and_connection_reuse(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                ttask = await self._serve(dir_id, host, port)
                async with Client(host, port, dir_id) as c:
                    r1 = await c.call("tool", "calc.add", {"a": 2, "b": 3})
                    r2 = await c.call("tool", "calc.add", {"a": 10, "b": 20})  # same fiber
                    reused = len(c._conns)  # one cached channel, not two handshakes
                    hits = await c.search("tool", "addition")
                ttask.cancel()
                try:
                    await ttask
                except asyncio.CancelledError:
                    pass
                return r1, r2, reused, len(hits)

            r1, r2, reused, n_hits = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(r1["result"], 5)
            self.assertEqual(r2["result"], 30)
            self.assertEqual(reused, 1, "two calls to one fiber reuse a single channel")
            self.assertGreaterEqual(n_hits, 1)
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_concurrent_calls_are_multiplexed(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                ttask = await self._serve(dir_id, host, port)
                async with Client(host, port, dir_id) as c:
                    # 12 calls fired concurrently at the SAME fiber over one channel
                    results = await asyncio.gather(
                        *[c.call("tool", "calc.add", {"a": i, "b": i}) for i in range(12)]
                    )
                    channels = len(c._conns)  # all multiplexed over one cached channel
                    pair = await c.gather_all(
                        ("tool", "calc.add", {"a": 1, "b": 2}),
                        ("tool", "calc.add", {"a": 3, "b": 4}),
                    )
                ttask.cancel()
                try:
                    await ttask
                except asyncio.CancelledError:
                    pass
                return results, channels, pair

            results, channels, pair = asyncio.run(asyncio.wait_for(scenario(), 30))
            # correlation-demux keeps 12 concurrent responses correctly matched
            self.assertEqual([r["result"] for r in results], [2 * i for i in range(12)])
            self.assertEqual(channels, 1, "concurrent calls share one multiplexed channel")
            self.assertEqual([p["result"] for p in pair], [3, 7])
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_recovers_from_a_dropped_channel(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                ttask = await self._serve(dir_id, host, port)
                async with Client(host, port, dir_id) as c:
                    r1 = await c.call("tool", "calc.add", {"a": 1, "b": 1})  # caches a channel
                    fid = next(iter(c._conns))
                    await c._conns[fid].close()  # the cached channel dies under us
                    r2 = await c.call("tool", "calc.add", {"a": 2, "b": 2})  # transparently reconnects
                ttask.cancel()
                try:
                    await ttask
                except asyncio.CancelledError:
                    pass
                return r1, r2

            r1, r2 = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(r1["result"], 2)
            self.assertEqual(r2["result"], 4)
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_missing_fiber_raises_thicket_error(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                async with Client(host, port, dir_id) as c:
                    with self.assertRaises(ThicketError):
                        await c.call("tool", "calc.add", {"a": 1, "b": 1})  # nothing registered

            asyncio.run(asyncio.wait_for(scenario(), 20))
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
