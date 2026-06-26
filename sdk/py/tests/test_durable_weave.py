"""Durable execution end to end (gap 3): a durable weave's completed sub-calls
are checkpointed under the run's trace id, so a retry with the same trace resumes
without re-invoking them — built entirely on the `Checkpoint` atom."""

import asyncio
import os
import subprocess
import unittest

from thicket import Client, DictStore, Fiber, LocalIdentity, RootKey

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")

# a stateful tool that counts how many times it's actually invoked
counter = Fiber(kind="tool")


@counter.handles("count.next", "increment and return the counter")
async def _next(req, ctx):
    n = ctx.config.get("n", 0) + 1
    ctx.config["n"] = n
    return {"n": n}


@counter.handles("count.value", "the current counter (without incrementing)")
async def _value(req, ctx):
    return {"n": ctx.config.get("n", 0)}


# a durable weave: one checkpointed sub-call
work = Fiber(kind="weave")


@work.handles("once", "call the counter once, durably", durable=True)
async def _once(req, ctx):
    r = await ctx.call("tool", "count.next", {})
    return {"n": r["n"]}


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class DurableWeave(unittest.TestCase):
    def _directory(self):
        proc = subprocess.Popen([DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        id_hex, addr = proc.stdout.readline().strip().split()
        host, port = addr.split(":")
        return proc, bytes.fromhex(id_hex), host, int(port)

    async def _serve(self, coro, dir_id, host, port, **kw):
        local = LocalIdentity.from_root(RootKey.generate())
        ready = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
        await asyncio.wait_for(ready, 10)
        return task

    async def _stop(self, *tasks):
        for t in tasks:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

    def test_resume_does_not_rerun_completed_step(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                ctask = await self._serve(counter.run, dir_id, host, port)
                wtask = await self._serve(work.run, dir_id, host, port, checkpoints=DictStore())
                run_ctx = {"trace_id": b"RUN-42", "span_id": b"s"}
                async with Client(host, port, dir_id) as c:
                    r1 = await c.call("weave", "once", {}, context=run_ctx)
                    r2 = await c.call("weave", "once", {}, context=run_ctx)  # same trace -> resume
                    counted = await c.call("tool", "count.value", {})
                await self._stop(ctask, wtask)
                return r1, r2, counted

            r1, r2, counted = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(r1, {"n": 1})
            self.assertEqual(r2, {"n": 1}, "the second run replayed the checkpoint")
            self.assertEqual(counted, {"n": 1}, "the counter was invoked exactly once")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
