"""Edge-case coverage for the example fibers/apps: router filtering + error
paths, the LLM fiber's HTTP/Ollama path (mocked — no server), CLI no-result, and
profiler edges. These are the branches the happy-path integration tests skip."""

import asyncio
import os
import subprocess
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(__file__)
REPO = os.path.join(HERE, "..", "..", "..")
DIR_BIN = os.path.join(REPO, "target", "debug", "examples", "directory_server")
for _p in ("fibers/py/llm", "fibers/py/router", "apps/py/cli", "apps/py/profiler"):
    sys.path.insert(0, os.path.join(REPO, *_p.split("/")))

from thicket import Conn, LocalIdentity, RootKey, cbor  # noqa: E402

import cli  # noqa: E402
import llm  # noqa: E402
import profiler as profiler_mod  # noqa: E402
import router as router_mod  # noqa: E402

CANDS = [
    {"id": b"cheap", "endpoint": "", "cost_micros": 5, "latency_ms": 800, "context_window": 4000, "reputation": 60},
    {"id": b"fast", "endpoint": "", "cost_micros": 50, "latency_ms": 100, "context_window": 4000, "reputation": 70},
    {"id": b"big", "endpoint": "", "cost_micros": 30, "latency_ms": 300, "context_window": 32000, "reputation": 90},
]


class RouterPureEdges(unittest.TestCase):
    def test_max_latency_filters_candidates(self):
        chosen = router_mod.select({"max_latency_ms": 200, "optimize": "cost"}, CANDS)
        self.assertEqual(chosen["id"], b"fast")  # only fast (100ms) survives

    def test_max_cost_filters_candidates(self):
        chosen = router_mod.select({"max_cost_micros": 10, "optimize": "latency"}, CANDS)
        self.assertEqual(chosen["id"], b"cheap")  # only cheap (5µ) survives

    def test_reputation_optimization(self):
        self.assertEqual(router_mod.select({"optimize": "reputation"}, CANDS)["id"], b"big")

    def test_int_parse_falls_back_on_bad_value(self):
        self.assertEqual(router_mod._int({"k": "not-a-number"}, "k", 7), 7)
        self.assertEqual(router_mod._int({}, "k", 9), 9)

    def test_candidates_handle_missing_locators_and_profile(self):
        hits = [{"payload": {"id": b"x", "profile": {"cost_micros": "5"}}}]  # no locators
        cands = router_mod._candidates_from_hits(hits)
        self.assertEqual(cands[0]["endpoint"], "")
        self.assertEqual(cands[0]["cost_micros"], 5)


class LlmHttpPath(unittest.TestCase):
    def test_ollama_model_parses_completion(self):
        urlopen = mock.MagicMock()
        urlopen.return_value.__enter__.return_value.read.return_value = b'{"response": "hello world"}'
        with mock.patch("urllib.request.urlopen", urlopen):
            out = llm.ollama_model("hi", model="x", host="http://h")
        self.assertEqual(out, ["hello world"])


class ProfilerEdges(unittest.TestCase):
    def test_summarize_empty_trace(self):
        s = profiler_mod.summarize([])
        self.assertEqual(s["per_fiber"], {})
        self.assertEqual(s["total_cost_micros"], 0)
        self.assertEqual(s["wall_ms"], 0)

    def test_render_empty(self):
        self.assertEqual(profiler_mod.render([]), "")


@unittest.skipUnless(os.path.exists(DIR_BIN), "rust directory_server example not built")
class FiberErrorPaths(unittest.TestCase):
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

    def test_cli_errors_when_no_model_fiber(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                consumer = LocalIdentity.from_root(RootKey.generate())
                with self.assertRaises(RuntimeError):
                    await cli.generate(host, port, dir_id, consumer, "anything")

            asyncio.run(asyncio.wait_for(scenario(), 20))
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_router_errors_on_unknown_capability_and_no_match(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                rtask, rinfo = await self._serve(router_mod.run, dir_id, host, port)
                consumer = LocalIdentity.from_root(RootKey.generate())
                rh, rp = rinfo["endpoint"].split(":")
                conn = await Conn.connect(rh, int(rp), consumer, expected_id=rinfo["id"])
                unknown = (await conn.call("nope", b""))["payload"]
                # no model fibers registered at all -> no candidate satisfies
                nomatch = (await conn.call("route", cbor.encode({"optimize": "cost"})))["payload"]
                await conn.close()
                rtask.cancel()
                try:
                    await rtask
                except asyncio.CancelledError:
                    pass
                return unknown, nomatch

            unknown, nomatch = asyncio.run(asyncio.wait_for(scenario(), 25))
            self.assertEqual(unknown["error"]["code"], "NotFound")
            self.assertEqual(nomatch["error"]["code"], "NotFound")
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_llm_enforces_deadline(self):
        proc, dir_id, host, port = self._directory()
        try:

            async def scenario():
                ltask, linfo = await self._serve(llm.run, dir_id, host, port)
                consumer = LocalIdentity.from_root(RootKey.generate())
                lh, lp = linfo["endpoint"].split(":")
                conn = await Conn.connect(lh, int(lp), consumer, expected_id=linfo["id"])
                err = None
                try:
                    async for _ in conn.call_stream(
                        "generate", b"hi",
                        context={"trace_id": b"d", "span_id": b"s", "deadline": 1},
                    ):
                        pass
                except ConnectionError as e:
                    err = str(e)
                await conn.close()
                ltask.cancel()
                try:
                    await ltask
                except asyncio.CancelledError:
                    pass
                return err

            err = asyncio.run(asyncio.wait_for(scenario(), 25))
            self.assertIsNotNone(err)
            self.assertIn("deadline", err.lower())
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
