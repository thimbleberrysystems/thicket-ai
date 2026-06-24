"""Wave 4: collector + profiler (observability), trigger (pub/sub), router."""

import asyncio
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
for p in ("fibers/py/collector", "fibers/py/trigger", "fibers/py/router", "apps/py/profiler"):
    sys.path.insert(0, os.path.join(REPO, *p.split("/")))

from thicket import (  # noqa: E402
    Conn,
    DirectoryClient,
    LocalIdentity,
    RootKey,
    cbor,
    record,
)

import collector as collector_mod  # noqa: E402
import profiler as profiler_mod  # noqa: E402
import router as router_mod  # noqa: E402
import trigger as trigger_mod  # noqa: E402


async def _serve(coro, dir_id, host, port, **kw):
    local = LocalIdentity.from_root(RootKey.generate())
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(coro(local, host, port, dir_id, ready=ready, **kw))
    info = await asyncio.wait_for(ready, 10)
    return local, task, info


async def _stop(*tasks):
    for t in tasks:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass


# ---- spans used by the collector + profiler tests ----
T = b"trace-wave4-0001"
W, TL, LM = b"span-weave", b"span-tool0", b"span-llm00"
SPANS = [
    {"trace_id": T, "span_id": W, "parent_span_id": b"", "name": "weave:describe_sum",
     "fiber_id": b"f-weave", "kind": "weave", "start_ms": 0, "end_ms": 100, "attrs": {}},
    {"trace_id": T, "span_id": TL, "parent_span_id": W, "name": "tool:calc.add",
     "fiber_id": b"f-tool0", "kind": "tool", "start_ms": 10, "end_ms": 20,
     "attrs": {"tokens": 0, "cost_micros": 0}},
    {"trace_id": T, "span_id": LM, "parent_span_id": W, "name": "model:generate",
     "fiber_id": b"f-llm00", "kind": "model", "start_ms": 30, "end_ms": 90,
     "attrs": {"tokens": 12, "cost_micros": 1500}},
]


class ProfilerPure(unittest.TestCase):
    def test_summarize_per_fiber_latency_and_cost(self):
        s = profiler_mod.summarize(SPANS)
        self.assertEqual(s["per_fiber"]["tool:calc.add"]["latency_ms"], 10)
        self.assertEqual(s["per_fiber"]["model:generate"]["latency_ms"], 60)
        self.assertEqual(s["per_fiber"]["weave:describe_sum"]["latency_ms"], 100)
        self.assertEqual(s["per_fiber"]["model:generate"]["tokens"], 12)
        self.assertEqual(s["total_cost_micros"], 1500)
        self.assertEqual(s["total_tokens"], 12)

    def test_render_tree_contains_each_fiber(self):
        tree = profiler_mod.render(collector_mod.build_tree(SPANS))
        for name in ("weave:describe_sum", "tool:calc.add", "model:generate"):
            self.assertIn(name, tree)


class RouterPure(unittest.TestCase):
    CANDS = [
        {"id": b"cheap", "endpoint": "", "cost_micros": 5, "latency_ms": 800, "context_window": 4000, "reputation": 60},
        {"id": b"fast", "endpoint": "", "cost_micros": 50, "latency_ms": 100, "context_window": 4000, "reputation": 70},
        {"id": b"big", "endpoint": "", "cost_micros": 30, "latency_ms": 300, "context_window": 32000, "reputation": 90},
    ]

    def test_optimize_cost(self):
        self.assertEqual(router_mod.select({"optimize": "cost"}, self.CANDS)["id"], b"cheap")

    def test_optimize_latency(self):
        self.assertEqual(router_mod.select({"optimize": "latency"}, self.CANDS)["id"], b"fast")

    def test_min_context_constraint(self):
        chosen = router_mod.select({"min_context": 16000, "optimize": "cost"}, self.CANDS)
        self.assertEqual(chosen["id"], b"big")

    def test_no_candidate_satisfies(self):
        self.assertIsNone(router_mod.select({"max_cost_micros": 1}, self.CANDS))


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class Wave4Net(unittest.TestCase):
    def _directory(self):
        proc = subprocess.Popen(
            [DIR_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        id_hex, addr = proc.stdout.readline().strip().split()
        host, port = addr.split(":")
        return proc, bytes.fromhex(id_hex), host, int(port)

    def test_collector_assembles_independently_reported_spans(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                _, ctask, info = await _serve(collector_mod.run, dir_id, host, port)
                ch, cp = info["endpoint"].split(":")

                # each span is reported by a *separate* identity/connection
                for span in SPANS:
                    reporter = LocalIdentity.from_root(RootKey.generate())
                    cc = await collector_mod.CollectorClient.connect(ch, int(cp), reporter, info["id"])
                    await cc.report(span)
                    await cc.close()

                viewer = LocalIdentity.from_root(RootKey.generate())
                cc = await collector_mod.CollectorClient.connect(ch, int(cp), viewer, info["id"])
                tr = await cc.trace(T)
                await cc.close()
                await _stop(ctask)
                return tr

            tr = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(len(tr["roots"]), 1)
            root = tr["roots"][0]
            self.assertEqual(root["span"]["name"], "weave:describe_sum")
            self.assertEqual(len(root["children"]), 2)
            self.assertEqual(
                {c["span"]["name"] for c in root["children"]},
                {"tool:calc.add", "model:generate"},
            )
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_trigger_delivers_events_in_order(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                _, ttask, info = await _serve(trigger_mod.run, dir_id, host, port)
                th, tp = info["endpoint"].split(":")

                sub_id = LocalIdentity.from_root(RootKey.generate())
                sub = await Conn.connect(th, int(tp), sub_id, expected_id=info["id"])
                stream = sub.call_stream("trigger.subscribe", timeout=10)
                ready = await stream.__anext__()  # ready marker (empty body)
                assert ready.get("body", b"") == b""

                pub_id = LocalIdentity.from_root(RootKey.generate())
                pub = await Conn.connect(th, int(tp), pub_id, expected_id=info["id"])
                topics = ["build.started", "build.step", "build.finished"]
                for i, topic in enumerate(topics):
                    await pub.call("trigger.emit", cbor.encode({"topic": topic, "data": {"n": i}}))
                await pub.close()

                got = []
                for _ in topics:
                    chunk = await stream.__anext__()
                    got.append(cbor.decode(chunk["body"]))
                await sub.close()
                await _stop(ttask)
                return got

            got = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual([e["topic"] for e in got], ["build.started", "build.step", "build.finished"])
            self.assertEqual([e["data"]["n"] for e in got], [0, 1, 2])
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_router_selects_expected_fiber(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def _register_model(prof):
                ident = LocalIdentity.from_root(RootKey.generate())
                rec = record.self_record(
                    ident,
                    kind="model",
                    capabilities=[record.capability("model", "text generation", tags=["llm"])],
                    locators=[record.locator("tcp", "127.0.0.1:9")],
                    profile=prof,
                )
                dc = await DirectoryClient.connect(host, port, ident, dir_id)
                await dc.register(rec)
                await dc.close()
                return ident.id

            async def scenario():
                _, rtask, info = await _serve(router_mod.run, dir_id, host, port)
                rh, rp = info["endpoint"].split(":")

                cheap = await _register_model({"cost_micros": "5", "latency_ms": "800", "context_window": "4000", "reputation": "60"})
                await _register_model({"cost_micros": "50", "latency_ms": "100", "context_window": "4000", "reputation": "70"})
                big = await _register_model({"cost_micros": "30", "latency_ms": "300", "context_window": "32000", "reputation": "90"})

                client = LocalIdentity.from_root(RootKey.generate())
                conn = await Conn.connect(rh, int(rp), client, expected_id=info["id"])
                by_cost = cbor.decode(
                    (await conn.call("route", cbor.encode({"optimize": "cost"})))["payload"]["body"]
                )
                by_ctx = cbor.decode(
                    (await conn.call("route", cbor.encode({"min_context": 16000, "optimize": "cost"})))["payload"]["body"]
                )
                await conn.close()
                await _stop(rtask)
                return cheap, big, by_cost, by_ctx

            cheap, big, by_cost, by_ctx = asyncio.run(asyncio.wait_for(scenario(), 30))
            self.assertEqual(by_cost["chosen_id"], cheap)
            self.assertEqual(by_ctx["chosen_id"], big)
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
