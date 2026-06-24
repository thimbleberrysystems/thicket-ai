"""Wave 3 integration: a Weave composes a tool fiber + an LLM fiber, propagating
context; plus grant attenuation enforced end to end."""

import asyncio
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
for p in ("fibers/py/llm", "fibers/py/tool_calc", "weaves/py/sum_describer"):
    sys.path.insert(0, os.path.join(REPO, *p.split("/")))

from thicket import Conn, DirectoryClient, LocalIdentity, RootKey, WorkingKey, cbor, grant, unix_now  # noqa: E402

import calc  # noqa: E402
import llm  # noqa: E402
import weave as weave_mod  # noqa: E402


async def _serve(coro, dir_id, host, port, **kw):
    local = LocalIdentity.from_root(RootKey.generate())
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
    await asyncio.wait_for(ready, 10)
    return local, task


async def _stop(*tasks):
    for t in tasks:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class Wave3(unittest.TestCase):
    def _directory(self):
        proc = subprocess.Popen(
            [DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        id_hex, addr = proc.stdout.readline().strip().split()
        host, port = addr.split(":")
        return proc, bytes.fromhex(id_hex), host, int(port)

    def test_weave_composes_and_propagates_context(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                _, ttask = await _serve(calc.run, dir_id, host, port)
                _, ltask = await _serve(llm.run, dir_id, host, port)
                _, wtask = await _serve(weave_mod.run, dir_id, host, port)
                consumer = LocalIdentity.from_root(RootKey.generate())

                dc = await DirectoryClient.connect(host, port, consumer, dir_id)
                hits = await dc.search("describe sum", kind="weave", top_k=5)
                await dc.close()
                rec = hits[0]["payload"]
                wh, wp = rec["locators"][0]["endpoint"].split(":")

                trace = b"TRACE-abcdef012345"
                conn = await Conn.connect(wh, int(wp), consumer, expected_id=rec["id"])
                resp = await conn.call(
                    "describe_sum",
                    cbor.encode({"a": 2, "b": 3}),
                    context={"trace_id": trace, "span_id": b"rootspan"},
                    timeout=20,
                )
                await conn.close()
                await _stop(ttask, ltask, wtask)
                return cbor.decode(resp["payload"]["body"])

            out = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(out["sum"], 5)
            self.assertIn("The sum is 5", out["description"])
            self.assertIn("echo:", out["description"])
            # the weave propagated the trace down to the tool fiber
            self.assertEqual(out["tool_trace"], b"TRACE-abcdef012345")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_grant_attenuation_is_enforced(self):
        target = LocalIdentity.from_root(RootKey.generate())
        alice = WorkingKey.generate()
        bob = WorkingKey.generate()
        now = unix_now()

        g = grant.issue(
            target.id, target.working, alice.public(), grant.caveats(["calc.add", "calc.sub"], now + 100_000)
        )
        # Alice delegates a strictly narrower grant to Bob.
        sub = grant.attenuate(g, alice, bob.public(), grant.caveats(["calc.add"], now + 50_000))

        self.assertTrue(
            grant.verify(sub, target.root_public_key, target.endorsements, bob.public(), "calc.add", now)
        )
        # the dropped capability is not authorized
        self.assertFalse(
            grant.verify(sub, target.root_public_key, target.endorsements, bob.public(), "calc.sub", now)
        )
        # widening during attenuation is rejected
        with self.assertRaises(ValueError):
            grant.attenuate(g, alice, bob.public(), grant.caveats(["calc.add", "calc.mul"], now + 50_000))


if __name__ == "__main__":
    unittest.main()
