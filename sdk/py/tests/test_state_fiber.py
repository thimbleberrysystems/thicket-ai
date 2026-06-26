"""Network-native durable execution (gap 3 backend): a run's checkpoint lives on
a `state` fiber, so a durable weave can resume on a *different* instance —
proving the checkpoint is portable, not tied to the weave's process. Built on the
core `Checkpoint` primitive with zero core change."""

import asyncio
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
sys.path.insert(0, os.path.join(REPO, "fibers", "py", "state"))

from thicket import Client, Conn, FiberCheckpointStore, Fiber, LocalIdentity, RootKey, cbor  # noqa: E402

import state as state_mod  # noqa: E402

# a stateful tool that counts how many times it's actually invoked
counter = Fiber(kind="tool")


@counter.handles("count.next", "increment and return the counter")
async def _next(req, ctx):
    n = ctx.config.get("n", 0) + 1
    ctx.config["n"] = n
    return {"n": n}


@counter.handles("count.value", "the current counter")
async def _value(req, ctx):
    return {"n": ctx.config.get("n", 0)}


# a durable weave: one checkpointed sub-call
work = Fiber(kind="weave")


@work.handles("once", "call the counter once, durably", durable=True)
async def _once(req, ctx):
    r = await ctx.call("tool", "count.next", {})
    return {"n": r["n"]}


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class NetworkNativeCheckpoint(unittest.TestCase):
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

    async def _stop(self, *tasks):
        for t in tasks:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

    async def _call(self, info, capability, args, *, context=None):
        h, p = info["endpoint"].split(":")
        conn = await Conn.connect(h, int(p), LocalIdentity.from_root(RootKey.generate()), expected_id=info["id"])
        try:
            resp = await conn.call(capability, cbor.encode(args), context=context, timeout=15)
            return cbor.decode(resp["payload"]["body"])
        finally:
            await conn.close()

    def test_state_fiber_get_set(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                stask, sinfo = await self._serve(state_mod.run, dir_id, host, port)
                miss = await self._call(sinfo, "state.get", {"key": b"k"})
                await self._call(sinfo, "state.set", {"key": b"k", "value": b"hello"})
                hit = await self._call(sinfo, "state.get", {"key": b"k"})
                await self._stop(stask)
                return miss, hit

            miss, hit = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertIsNone(miss["value"])
            self.assertEqual(hit["value"], b"hello")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_fiber_checkpoint_store_roundtrips(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                stask, _ = await self._serve(state_mod.run, dir_id, host, port)
                store = FiberCheckpointStore(Client(host, port, dir_id))
                self.assertIsNone(await store.load(b"run"))
                await store.save(b"run", b"the-checkpoint-blob")
                got = await store.load(b"run")
                await store.close()
                await self._stop(stask)
                return got

            got = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(got, b"the-checkpoint-blob")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_run_resumes_on_a_different_weave_instance(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                stask, _ = await self._serve(state_mod.run, dir_id, host, port)  # the shared checkpoint store
                ctask, cinfo = await self._serve(counter.run, dir_id, host, port)
                run = {"trace_id": b"RUN-PORTABLE", "span_id": b"s"}

                # weave instance 1 runs the step, recording the checkpoint on the state fiber
                store1 = FiberCheckpointStore(Client(host, port, dir_id))
                w1task, w1 = await self._serve(work.run, dir_id, host, port, checkpoints=store1)
                r1 = await self._call(w1, "once", {}, context=run)
                await self._stop(w1task)
                await store1.close()

                # a DIFFERENT weave instance (another "machine"), same state fiber, resumes
                store2 = FiberCheckpointStore(Client(host, port, dir_id))
                w2task, w2 = await self._serve(work.run, dir_id, host, port, checkpoints=store2)
                r2 = await self._call(w2, "once", {}, context=run)
                counted = await self._call(cinfo, "count.value", {})
                await self._stop(w2task)
                await store2.close()

                await self._stop(stask, ctask)
                return r1, r2, counted

            r1, r2, counted = asyncio.run(asyncio.wait_for(scenario(), 40))
            self.assertEqual(r1, {"n": 1})
            self.assertEqual(r2, {"n": 1}, "the second instance resumed from the state fiber")
            self.assertEqual(counted, {"n": 1}, "the counter was invoked exactly once, across both instances")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
