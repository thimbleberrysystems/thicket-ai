"""Wave 1 integration: a Rust directory + a Python LLM fiber (in-process) + the
CLI consumer. Discover → connect → stream, and grant-gating.

Skipped if the Rust directory_server example isn't built.
"""

import asyncio
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
sys.path.insert(0, os.path.join(REPO, "fibers", "py", "llm"))
sys.path.insert(0, os.path.join(REPO, "apps", "py", "cli"))

from thicket import LocalIdentity, RootKey, grant, unix_now  # noqa: E402

import cli  # noqa: E402
import llm  # noqa: E402


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class Wave1(unittest.TestCase):
    def _directory(self):
        proc = subprocess.Popen(
            [DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        id_hex, addr = proc.stdout.readline().strip().split()
        host, port = addr.split(":")
        return proc, bytes.fromhex(id_hex), host, int(port)

    @staticmethod
    async def _serve_fiber(host, port, dir_id, **kw):
        fiber_local = LocalIdentity.from_root(RootKey.generate())
        ready = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(llm.run(fiber_local, host, port, dir_id, ready=ready, **kw))
        await asyncio.wait_for(ready, 10)
        return fiber_local, task

    @staticmethod
    async def _stop(task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    def test_discover_invoke_stream(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                _, task = await self._serve_fiber(host, port, dir_id)
                consumer = LocalIdentity.from_root(RootKey.generate())
                text = await cli.generate(host, port, dir_id, consumer, "hello world")
                await self._stop(task)
                return text

            text = asyncio.run(asyncio.wait_for(scenario(), 25))
            self.assertIn("echo:", text)
            self.assertIn("hello world", text)
            self.assertIn("[done]", text)
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_grant_gated_invocation(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                fiber_local, task = await self._serve_fiber(host, port, dir_id, require_grant=True)
                consumer = LocalIdentity.from_root(RootKey.generate())

                denied = False
                try:
                    await cli.generate(host, port, dir_id, consumer, "x")
                except Exception:
                    denied = True

                g = grant.issue(
                    fiber_local.id,
                    fiber_local.working,
                    consumer.working.public(),
                    grant.caveats(["generate"], unix_now() + 100_000),
                )
                text = await cli.generate(host, port, dir_id, consumer, "y", auth=g)
                await self._stop(task)
                return denied, text

            denied, text = asyncio.run(asyncio.wait_for(scenario(), 25))
            self.assertTrue(denied, "call without a grant should be rejected")
            self.assertIn("echo:", text)
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
