"""Durable-execution atom (gap 3): a step runs at most once per run; resume
replays completed steps without re-executing. Tested in isolation — no network,
no weave — because everything larger just reuses this primitive."""

import asyncio
import os
import tempfile
import unittest

from thicket.checkpoint import Checkpoint, DictStore, FileCheckpointStore


class CheckpointAtom(unittest.TestCase):
    def _resume_scenario(self, store):
        ran = {"a": 0, "b": 0}

        async def a():
            ran["a"] += 1
            return {"sum": 5}

        async def b_fail():
            ran["b"] += 1
            raise RuntimeError("crash after step a")

        async def b_ok():
            ran["b"] += 1
            return {"desc": "five"}

        async def run():
            # run 1: step a succeeds, step b crashes (the workflow dies mid-way)
            cp = await Checkpoint.open(store, b"run-1")
            ra = await cp.step(a)
            with self.assertRaises(RuntimeError):
                await cp.step(b_fail)
            # resume: step a is replayed (not re-run), step b is retried
            cp2 = await Checkpoint.open(store, b"run-1")
            ra2 = await cp2.step(a)
            rb = await cp2.step(b_ok)
            return ra, ra2, rb

        return asyncio.run(run()), ran

    def test_step_memoized_across_resume(self):
        (ra, ra2, rb), ran = self._resume_scenario(DictStore())
        self.assertEqual(ran["a"], 1, "step a ran exactly once (replayed on resume)")
        self.assertEqual(ran["b"], 2, "step b ran twice (crash + retry)")
        self.assertEqual(ra, {"sum": 5})
        self.assertEqual(ra2, {"sum": 5})  # the replayed value
        self.assertEqual(rb, {"desc": "five"})

    def test_durable_across_process_restart(self):
        path = os.path.join(tempfile.mkdtemp(), "cp.cbor")
        ran = {"n": 0}

        async def work():
            ran["n"] += 1
            return {"v": 42}

        async def once():
            cp = await Checkpoint.open(FileCheckpointStore(path), b"job")  # fresh store, same file
            return await cp.step(work)

        r1 = asyncio.run(once())
        r2 = asyncio.run(once())  # a separate "process"
        self.assertEqual(r1, {"v": 42})
        self.assertEqual(r2, {"v": 42})
        self.assertEqual(ran["n"], 1, "the recorded step survived the restart — work ran once")

    def test_explicit_keys(self):
        async def run():
            cp = await Checkpoint.open(DictStore(), b"r")
            await cp.step(lambda: _const("x"), key="alpha")
            again = await cp.step(lambda: _const("y"), key="alpha")  # same key -> replayed
            return again

        self.assertEqual(asyncio.run(run()), "x")


async def _const(v):
    return v


if __name__ == "__main__":
    unittest.main()
