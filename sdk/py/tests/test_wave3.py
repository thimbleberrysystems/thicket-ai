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
for p in ("fibers/py/llm", "fibers/py/tool_calc", "fibers/py/collector", "weaves/py/sum_describer"):
    sys.path.insert(0, os.path.join(REPO, *p.split("/")))

from thicket import Conn, DirectoryClient, LocalIdentity, RootKey, WorkingKey, cbor, grant, unix_now  # noqa: E402

import calc  # noqa: E402
import collector as collector_mod  # noqa: E402
import llm  # noqa: E402
import weave as weave_mod  # noqa: E402


async def _serve(coro, dir_id, host, port, **kw):
    local = LocalIdentity.from_root(RootKey.generate())
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
    await asyncio.wait_for(ready, 10)
    return local, task


async def _start(local, coro, dir_id, host, port, **kw):
    """Start a fiber with a *pre-built* identity (so grants can name it)."""
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
    info = await asyncio.wait_for(ready, 10)
    return task, info


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
            # (trace propagation down to the tool is verified end-to-end in
            # test_spans_assemble_into_weave_tree via the collector.)
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


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class Wave3Contract(unittest.TestCase):
    """The cross-cutting guarantees a weave must honor: grant attenuation,
    self-reported tracing, and deadline/budget enforcement."""

    def _directory(self):
        proc = subprocess.Popen(
            [DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        id_hex, addr = proc.stdout.readline().strip().split()
        host, port = addr.split(":")
        return proc, bytes.fromhex(id_hex), host, int(port)

    def test_tool_enforces_grant_boundary(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                tool = LocalIdentity.from_root(RootKey.generate())
                ttask, info = await _start(tool, calc.run, dir_id, host, port, require_grant=True)
                caller = LocalIdentity.from_root(RootKey.generate())
                th, tp = info["endpoint"].split(":")

                far = unix_now() + 3600
                g_add = grant.issue(tool.id, tool.working, caller.working.public(), grant.caveats(["calc.add"], far))
                g_sub = grant.issue(tool.id, tool.working, caller.working.public(), grant.caveats(["calc.sub"], far))

                conn = await Conn.connect(th, int(tp), caller, expected_id=info["id"])
                body = cbor.encode({"a": 2, "b": 3})
                ok = (await conn.call("calc.add", body, auth=g_add))["payload"]
                overreach = (await conn.call("calc.add", body, auth=g_sub))["payload"]
                missing = (await conn.call("calc.add", body))["payload"]
                await conn.close()
                await _stop(ttask)
                return ok, overreach, missing

            ok, overreach, missing = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(ok.get("typ"), "Response")
            self.assertEqual(cbor.decode(ok["body"])["result"], 5)
            self.assertEqual(overreach.get("typ"), "Error")  # grant doesn't cover calc.add
            self.assertEqual(overreach["error"]["code"], "Unauthorized")
            self.assertEqual(missing.get("typ"), "Error")  # no grant at all
            self.assertEqual(missing["error"]["code"], "Unauthorized")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_weave_attenuates_grant_to_tool(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                tool = LocalIdentity.from_root(RootKey.generate())
                weaver = LocalIdentity.from_root(RootKey.generate())
                # the tool grants the weave a *broad* capability; the weave must
                # narrow it to exactly the call it makes.
                broad = grant.issue(
                    tool.id, tool.working, weaver.working.public(),
                    grant.caveats(["calc.add", "calc.sub"], unix_now() + 3600),
                )
                ttask, _ = await _start(tool, calc.run, dir_id, host, port, require_grant=True)
                ltask, _ = await _serve_existing(llm.run, dir_id, host, port)
                wtask, winfo = await _start(weaver, weave_mod.run, dir_id, host, port, tool_grant=broad)

                consumer = LocalIdentity.from_root(RootKey.generate())
                wh, wp = winfo["endpoint"].split(":")
                conn = await Conn.connect(wh, int(wp), consumer, expected_id=winfo["id"])
                resp = await conn.call("describe_sum", cbor.encode({"a": 4, "b": 5}), timeout=20)
                await conn.close()
                await _stop(ttask, ltask, wtask)
                return resp["payload"]

            p = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(p.get("typ"), "Response", p)
            self.assertEqual(cbor.decode(p["body"])["sum"], 9)
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_spans_assemble_into_weave_tree(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                _, ctask, cinfo = await _serve3(collector_mod.run, dir_id, host, port)
                sink = {"id": cinfo["id"], "endpoint": cinfo["endpoint"]}
                _, ttask = await _serve(calc.run, dir_id, host, port)
                _, ltask = await _serve(llm.run, dir_id, host, port)
                # the weave routes its trace to this sink; tool/llm inherit it via
                # the propagated context (they were told nothing about a sink).
                _, wtask = await _serve(weave_mod.run, dir_id, host, port, sink=sink)
                consumer = LocalIdentity.from_root(RootKey.generate())

                dc = await DirectoryClient.connect(host, port, consumer, dir_id)
                hits = await dc.search("describe sum", kind="weave", top_k=5)
                await dc.close()
                rec = hits[0]["payload"]
                wh, wp = rec["locators"][0]["endpoint"].split(":")

                trace = b"trace-tree-00001"
                conn = await Conn.connect(wh, int(wp), consumer, expected_id=rec["id"])
                await conn.call(
                    "describe_sum", cbor.encode({"a": 2, "b": 3}),
                    context={"trace_id": trace, "span_id": b"rootspan"}, timeout=20,
                )
                await conn.close()

                # the weave self-reports its span just after responding; poll until
                # all three spans (weave + tool + llm) have landed.
                cc = await collector_mod.CollectorClient.connect(
                    cinfo["endpoint"].split(":")[0], int(cinfo["endpoint"].split(":")[1]), consumer, cinfo["id"]
                )
                tr = {"spans": []}
                for _ in range(100):
                    tr = await cc.trace(trace)
                    if len(tr["spans"]) >= 3:
                        break
                    await asyncio.sleep(0.1)
                await cc.close()
                await _stop(ctask, ttask, ltask, wtask)
                return tr

            tr = asyncio.run(asyncio.wait_for(scenario(), 90))
            names = {s["name"] for s in tr["spans"]}
            self.assertEqual(names, {"weave:describe_sum", "tool:calc.add", "model:generate"})
            self.assertEqual(len(tr["roots"]), 1)
            root = tr["roots"][0]
            self.assertEqual(root["span"]["name"], "weave:describe_sum")
            self.assertEqual(
                {c["span"]["name"] for c in root["children"]},
                {"tool:calc.add", "model:generate"},
            )
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_weave_routes_trace_to_its_chosen_sink(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                # two trace sinks; the weave is configured to route to B only.
                _, c1, a_info = await _serve3(collector_mod.run, dir_id, host, port)
                _, c2, b_info = await _serve3(collector_mod.run, dir_id, host, port)
                sink_b = {"id": b_info["id"], "endpoint": b_info["endpoint"]}
                _, ttask = await _serve(calc.run, dir_id, host, port)
                _, ltask = await _serve(llm.run, dir_id, host, port)
                _, wtask, winfo = await _serve3(weave_mod.run, dir_id, host, port, sink=sink_b)
                consumer = LocalIdentity.from_root(RootKey.generate())

                wh, wp = winfo["endpoint"].split(":")
                trace = b"trace-routed-0001"
                conn = await Conn.connect(wh, int(wp), consumer, expected_id=winfo["id"])
                await conn.call(
                    "describe_sum", cbor.encode({"a": 1, "b": 1}),
                    context={"trace_id": trace, "span_id": b"rootspan"}, timeout=20,
                )
                await conn.close()

                async def trace_at(info):
                    cc = await collector_mod.CollectorClient.connect(
                        info["endpoint"].split(":")[0], int(info["endpoint"].split(":")[1]),
                        consumer, info["id"],
                    )
                    out = {"spans": []}
                    for _ in range(100):
                        out = await cc.trace(trace)
                        if len(out["spans"]) >= 3:
                            break
                        await asyncio.sleep(0.1)
                    await cc.close()
                    return out

                in_b = await trace_at(b_info)
                in_a = await trace_at(a_info)
                await _stop(c1, c2, ttask, ltask, wtask)
                return in_a, in_b

            in_a, in_b = asyncio.run(asyncio.wait_for(scenario(), 90))
            self.assertEqual(len(in_b["spans"]), 3, "the chosen sink B receives the whole trace")
            self.assertEqual(len(in_a["spans"]), 0, "sink A, not chosen, receives nothing")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_weave_errors_cleanly_on_missing_dependency(self):
        # weave is up but no tool/llm are registered — it must return a clean
        # error envelope, not crash the handler / drop the connection.
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                _, wtask, winfo = await _serve3(weave_mod.run, dir_id, host, port)
                consumer = LocalIdentity.from_root(RootKey.generate())
                wh, wp = winfo["endpoint"].split(":")
                conn = await Conn.connect(wh, int(wp), consumer, expected_id=winfo["id"])
                resp = await conn.call("describe_sum", cbor.encode({"a": 2, "b": 3}), timeout=10)
                await conn.close()
                await _stop(wtask)
                return resp["payload"]

            p = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(p.get("typ"), "Error")
            self.assertEqual(p["error"]["code"], "Unavailable")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_weave_enforces_budget(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                _, wtask, winfo = await _serve3(weave_mod.run, dir_id, host, port)
                consumer = LocalIdentity.from_root(RootKey.generate())
                wh, wp = winfo["endpoint"].split(":")
                conn = await Conn.connect(wh, int(wp), consumer, expected_id=winfo["id"])
                resp = await conn.call(
                    "describe_sum", cbor.encode({"a": 2, "b": 3}),
                    context={"trace_id": b"b", "span_id": b"s", "budget": 0}, timeout=10,
                )
                await conn.close()
                await _stop(wtask)
                return resp["payload"]

            p = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(p.get("typ"), "Error")
            self.assertEqual(p["error"]["code"], "BudgetExhausted")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_deadline_is_enforced_across_the_tree(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                _, ttask = await _serve(calc.run, dir_id, host, port)
                _, ltask = await _serve(llm.run, dir_id, host, port)
                _, wtask, winfo = await _serve3(weave_mod.run, dir_id, host, port)
                consumer = LocalIdentity.from_root(RootKey.generate())
                tinfo = None  # discover tool for the direct call
                dc = await DirectoryClient.connect(host, port, consumer, dir_id)
                thit = (await dc.search("addition", kind="tool", top_k=1))[0]["payload"]
                await dc.close()

                past = unix_now() - 5
                # (a) a leaf fiber enforces the deadline directly
                th, tp = thit["locators"][0]["endpoint"].split(":")
                tconn = await Conn.connect(th, int(tp), consumer, expected_id=thit["id"])
                leaf = (await tconn.call(
                    "calc.add", cbor.encode({"a": 1, "b": 1}),
                    context={"trace_id": b"d", "span_id": b"s", "deadline": past},
                ))["payload"]
                await tconn.close()

                # (b) the weave enforces / propagates the deadline across the tree
                wh, wp = winfo["endpoint"].split(":")
                wconn = await Conn.connect(wh, int(wp), consumer, expected_id=winfo["id"])
                tree = (await wconn.call(
                    "describe_sum", cbor.encode({"a": 2, "b": 3}),
                    context={"trace_id": b"d2", "span_id": b"s2", "deadline": past}, timeout=20,
                ))["payload"]
                await wconn.close()
                await _stop(ttask, ltask, wtask)
                return leaf, tree

            leaf, tree = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(leaf.get("typ"), "Error")
            self.assertEqual(leaf["error"]["code"], "DeadlineExceeded")
            self.assertEqual(tree.get("typ"), "Error")
            self.assertEqual(tree["error"]["code"], "DeadlineExceeded")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


async def _serve_existing(coro, dir_id, host, port, **kw):
    """Like _serve but returns (task, info) with a fresh identity."""
    local = LocalIdentity.from_root(RootKey.generate())
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
    await asyncio.wait_for(ready, 10)
    return task, local


async def _serve3(coro, dir_id, host, port, **kw):
    """Like _serve but also returns the fiber's registration info (id/endpoint)."""
    local = LocalIdentity.from_root(RootKey.generate())
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
    info = await asyncio.wait_for(ready, 10)
    return local, task, info


if __name__ == "__main__":
    unittest.main()
