"""Gap 1 — capability-scoped delegation.

An agent is granted read+write on a resource; it delegates **read-only** to a
sub-agent. The sub-agent then physically cannot write or delete — the resource
verifies the grant chain back to its own key and rejects any over-reach. This is
the property no in-process framework can offer: authority enforced by the
protocol, not the prompt.
"""

import asyncio
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
sys.path.insert(0, os.path.join(REPO, "fibers", "py", "tool_fs"))

from thicket import Client, Context, LocalIdentity, RootKey, ThicketError, grant, unix_now  # noqa: E402

import fs as fs_mod  # noqa: E402


async def _stop(*tasks):
    for t in tasks:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class Delegation(unittest.TestCase):
    def _directory(self):
        proc = subprocess.Popen([DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        id_hex, addr = proc.stdout.readline().strip().split()
        host, port = addr.split(":")
        return proc, bytes.fromhex(id_hex), host, int(port)

    async def _serve_fs(self, owner, dir_id, host, port):
        ready = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(fs_mod.run(owner, host, port, dir_id, ready=ready))
        info = await asyncio.wait_for(ready, 10)
        return task, info

    def test_readonly_subagent_cannot_write_or_delete(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                owner = LocalIdentity.from_root(RootKey.generate())  # the resource's identity
                ftask, _ = await self._serve_fs(owner, dir_id, host, port)
                far = unix_now() + 3600

                # owner grants the AGENT read + write (not delete)
                agent = LocalIdentity.from_root(RootKey.generate())
                g_agent = grant.issue(
                    owner.id, owner.working, agent.working.public(),
                    grant.caveats(["fs.read", "fs.write"], far),
                )

                # the AGENT delegates READ-ONLY to a fresh sub-agent
                subagent = LocalIdentity.from_root(RootKey.generate())
                actx = Context(agent, (host, port, dir_id), {"trace_id": b"t"}, tool_grant=g_agent)
                g_sub = actx.delegate(subagent.working.public(), ["fs.read"])

                results = {}
                # the agent (read+write) seeds a file, can't delete
                async with Client(host, port, dir_id, local=agent) as ac:
                    results["agent_write"] = await ac.call("tool", "fs.write", {"path": "notes", "content": "hi"}, auth=g_agent)
                    try:
                        await ac.call("tool", "fs.delete", {"path": "notes"}, auth=g_agent)
                    except ThicketError as e:
                        results["agent_delete"] = e.code

                # the read-only sub-agent: read works, write/delete are denied
                async with Client(host, port, dir_id, local=subagent) as sc:
                    results["sub_read"] = await sc.call("tool", "fs.read", {"path": "notes"}, auth=g_sub)
                    try:
                        await sc.call("tool", "fs.write", {"path": "notes", "content": "pwned"}, auth=g_sub)
                    except ThicketError as e:
                        results["sub_write"] = e.code
                    try:
                        await sc.call("tool", "fs.delete", {"path": "notes"}, auth=g_sub)
                    except ThicketError as e:
                        results["sub_delete"] = e.code
                    # read back: the denied write must have left the file untouched
                    results["sub_reread"] = await sc.call("tool", "fs.read", {"path": "notes"}, auth=g_sub)

                await _stop(ftask)
                return results

            r = asyncio.run(asyncio.wait_for(scenario(), 30))
            # the delegated chain verifies: read-only sub-agent CAN read
            self.assertEqual(r["sub_read"]["content"], "hi")
            # ...but is cryptographically incapable of writing or deleting
            self.assertEqual(r["sub_write"], "Unauthorized")
            self.assertEqual(r["sub_delete"], "Unauthorized")
            # the agent has write (it was granted it) but never had delete
            self.assertEqual(r["agent_write"]["ok"], True)
            self.assertEqual(r["agent_delete"], "Unauthorized")
            # the denied write left the file untouched — not merely an error code
            self.assertEqual(r["sub_reread"]["content"], "hi")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_path_constrained_delegation_is_enforced(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                owner = LocalIdentity.from_root(RootKey.generate())
                ftask, _ = await self._serve_fs(owner, dir_id, host, port)
                far = unix_now() + 3600

                agent = LocalIdentity.from_root(RootKey.generate())
                g_agent = grant.issue(owner.id, owner.working, agent.working.public(),
                                      grant.caveats(["fs.read", "fs.write"], far))
                async with Client(host, port, dir_id, local=agent) as ac:
                    await ac.call("tool", "fs.write", {"path": "allowed", "content": "ok"}, auth=g_agent)
                    await ac.call("tool", "fs.write", {"path": "other", "content": "nope"}, auth=g_agent)

                # delegate read-only AND scoped to a single path
                subagent = LocalIdentity.from_root(RootKey.generate())
                actx = Context(agent, (host, port, dir_id), {}, tool_grant=g_agent)
                g_sub = actx.delegate(subagent.working.public(), ["fs.read"], constraints={"path": "allowed"})

                res = {}
                async with Client(host, port, dir_id, local=subagent) as sc:
                    res["allowed"] = await sc.call("tool", "fs.read", {"path": "allowed"}, auth=g_sub)
                    try:
                        await sc.call("tool", "fs.read", {"path": "other"}, auth=g_sub)
                    except ThicketError as e:
                        res["other"] = e.code
                await _stop(ftask)
                return res

            res = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(res["allowed"]["content"], "ok")   # permitted path reads
            self.assertEqual(res["other"], "Unauthorized")       # other path blocked by the constraint
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_cannot_delegate_authority_you_lack(self):
        owner = LocalIdentity.from_root(RootKey.generate())
        agent = LocalIdentity.from_root(RootKey.generate())
        sub = LocalIdentity.from_root(RootKey.generate())
        g_agent = grant.issue(
            owner.id, owner.working, agent.working.public(),
            grant.caveats(["fs.read", "fs.write"], unix_now() + 3600),
        )
        ctx = Context(agent, ("h", 1, b"d"), {}, tool_grant=g_agent)

        # delegating a subset is fine
        self.assertIsNotNone(ctx.delegate(sub.working.public(), ["fs.read"]))
        # delegating something not held is refused — you can't grant what you lack
        with self.assertRaises(ThicketError):
            ctx.delegate(sub.working.public(), ["fs.delete"])

    def test_satisfies_constraints_semantics(self):
        self.assertTrue(grant.satisfies(None, {"path": "x"}))  # no grant -> vacuously true
        self.assertTrue(grant.satisfies({"links": [{"caveats": {"constraints": {}}}]}, {"path": "x"}))
        g = {"links": [{"caveats": {"constraints": {"path": "notes"}}}]}
        self.assertTrue(grant.satisfies(g, {"path": "notes"}))
        self.assertFalse(grant.satisfies(g, {"path": "other"}))
        self.assertFalse(grant.satisfies(g, {}))  # missing attribute -> not satisfied

    def test_delegate_without_a_grant_raises(self):
        agent = LocalIdentity.from_root(RootKey.generate())
        sub = LocalIdentity.from_root(RootKey.generate())
        ctx = Context(agent, ("h", 1, b"d"), {}, tool_grant=None)
        with self.assertRaises(ThicketError):
            ctx.delegate(sub.working.public(), ["fs.read"])


if __name__ == "__main__":
    unittest.main()
