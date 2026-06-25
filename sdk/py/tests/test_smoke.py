"""Smoke + runnability tests — the gap that let a non-runnable example pass CI.

(1) The runnable demo boots the whole system and produces a correct result.
(2) Every fiber module is independently launchable: it exposes ``run`` and a
    ``__main__`` guard so ``python <fiber>.py <dir...>`` works.
"""

import asyncio
import importlib
import inspect
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
for _p in ("apps/py/demo", "fibers/py/llm", "fibers/py/tool_calc", "fibers/py/memory",
           "fibers/py/collector", "fibers/py/trigger", "fibers/py/router",
           "fibers/py/tool_fs", "weaves/py/sum_describer"):
    sys.path.insert(0, os.path.join(REPO, *_p.split("/")))

FIBER_MODULES = ["llm", "calc", "memory", "collector", "trigger", "router", "fs", "weave"]


class Launchable(unittest.TestCase):
    """Every fiber must be runnable as its own process — not only from a test."""

    def test_each_fiber_exposes_run_and_main(self):
        for name in FIBER_MODULES:
            mod = importlib.import_module(name)
            with self.subTest(fiber=name):
                self.assertTrue(hasattr(mod, "run"), f"{name} has no run()")
                self.assertTrue(inspect.iscoroutinefunction(mod.run), f"{name}.run isn't async")
                src = inspect.getsource(mod)
                self.assertIn('if __name__ == "__main__"', src, f"{name} can't be launched standalone")

    def test_run_main_parses_argv_and_invokes_run(self):
        from thicket.fiber import run_main

        seen = {}

        async def fake_run(local, host, port, dir_id, **kw):
            seen.update(host=host, port=port, dir_id=dir_id, id_len=len(local.id))

        with mock.patch.object(sys, "argv", ["x", "127.0.0.1", "9", "ab" * 32]):
            run_main(fake_run)
        self.assertEqual(seen["host"], "127.0.0.1")
        self.assertEqual(seen["port"], 9)
        self.assertEqual(seen["dir_id"], bytes.fromhex("ab" * 32))
        self.assertEqual(seen["id_len"], 32)

    def test_run_main_usage_error_on_too_few_args(self):
        from thicket.fiber import run_main

        with mock.patch.object(sys, "argv", ["x", "only-one"]):
            with self.assertRaises(SystemExit):
                run_main(lambda *a, **k: None)


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class EndToEnd(unittest.TestCase):
    def test_demo_runs_end_to_end(self):
        import run_demo

        out = asyncio.run(asyncio.wait_for(run_demo.demo(2, 3), 40))
        self.assertEqual(out["sum"], 5)
        self.assertIn("The sum is 5", out["description"])

    def test_delegation_demo_blocks_overreach(self):
        import delegation_demo

        lines = asyncio.run(asyncio.wait_for(delegation_demo.demo(), 40))
        self.assertTrue(any("DENIED" in ln for ln in lines), lines)
        self.assertFalse(any("ALLOWED" in ln for ln in lines), lines)
        self.assertTrue(any("launch codes" in ln for ln in lines), lines)  # read-only read worked


if __name__ == "__main__":
    unittest.main()
