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

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
for _p in ("apps/py/demo", "fibers/py/llm", "fibers/py/tool_calc", "fibers/py/memory",
           "fibers/py/collector", "fibers/py/trigger", "fibers/py/router",
           "weaves/py/sum_describer"):
    sys.path.insert(0, os.path.join(REPO, *_p.split("/")))

FIBER_MODULES = ["llm", "calc", "memory", "collector", "trigger", "router", "weave"]


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


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class EndToEnd(unittest.TestCase):
    def test_demo_runs_end_to_end(self):
        import run_demo

        out = asyncio.run(asyncio.wait_for(run_demo.demo(2, 3), 40))
        self.assertEqual(out["sum"], 5)
        self.assertIn("The sum is 5", out["description"])


if __name__ == "__main__":
    unittest.main()
