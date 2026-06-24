"""Per-module SDK unit tests (Phase 2): id derivation, envelope tamper
detection, framing round-trip, and the tracing context helpers (the Python
mirror of the Rust core's Context::child test)."""

import asyncio
import unittest

from thicket import LocalIdentity, RootKey, crypto, envelope, sha256, tracing
from thicket.framing import read_frame, write_frame


class Identity(unittest.TestCase):
    def test_id_is_hash_of_root_public_key(self):
        ident = LocalIdentity.from_root(RootKey.generate())
        self.assertEqual(ident.id, sha256(ident.root_public_key))
        self.assertEqual(len(ident.id), 32)

    def test_distinct_roots_give_distinct_ids(self):
        a = LocalIdentity.from_root(RootKey.generate())
        b = LocalIdentity.from_root(RootKey.generate())
        self.assertNotEqual(a.id, b.id)


class Envelope(unittest.TestCase):
    def _signed(self):
        ident = LocalIdentity.from_root(RootKey.generate())
        payload = envelope.build_envelope_payload(
            from_id=ident.id, to_id=ident.id, typ="Request",
            correlation=b"\x01" * 16, capability="ping", body=b"hello",
        )
        return ident, envelope.sign_envelope(payload, ident.working)

    def test_valid_envelope_verifies(self):
        ident, signed = self._signed()
        self.assertTrue(envelope.verify_envelope_with_key(signed, ident.working.public()))

    def test_tampered_body_fails(self):
        ident, signed = self._signed()
        signed["payload"]["body"] = b"goodbye"
        self.assertFalse(envelope.verify_envelope_with_key(signed, ident.working.public()))

    def test_wrong_key_fails(self):
        _, signed = self._signed()
        other = crypto.WorkingKey.generate()
        self.assertFalse(envelope.verify_envelope_with_key(signed, other.public()))


class Framing(unittest.TestCase):
    def test_roundtrip_and_eof(self):
        async def scenario():
            srv_reader = {}

            async def handle(reader, writer):
                srv_reader["frame"] = await read_frame(reader)
                writer.close()

            server = await asyncio.start_server(handle, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await write_frame(writer, b"a frame of bytes")
            await asyncio.sleep(0.05)
            # the client side hits EOF (server closed) -> read_frame returns None
            self.assertIsNone(await read_frame(reader))
            writer.close()
            server.close()
            await server.wait_closed()
            return srv_reader["frame"]

        self.assertEqual(asyncio.run(scenario()), b"a frame of bytes")


class Tracing(unittest.TestCase):
    def test_child_context_tightens_deadline_and_budget(self):
        parent = {"trace_id": b"T", "span_id": b"P", "deadline": 100, "budget": 50}
        child = tracing.child_context(parent, span_id=b"C", local_deadline=80, spent=20)
        self.assertEqual(child["trace_id"], b"T")
        self.assertEqual(child["parent_span_id"], b"P")
        self.assertEqual(child["span_id"], b"C")
        self.assertEqual(child["deadline"], 80)  # min(100, 80)
        self.assertLessEqual(child["deadline"], parent["deadline"])
        self.assertEqual(child["budget"], 30)  # 50 - 20
        self.assertLessEqual(child["budget"], parent["budget"])

    def test_child_starts_a_trace_when_none(self):
        child = tracing.child_context(None)
        self.assertEqual(len(child["trace_id"]), 16)
        self.assertEqual(child["parent_span_id"], b"")

    def test_sink_propagates_and_can_be_overridden(self):
        sink_a = {"id": b"A" * 32, "endpoint": "127.0.0.1:1"}
        sink_b = {"id": b"B" * 32, "endpoint": "127.0.0.1:2"}
        parent = {"trace_id": b"T", "span_id": b"P", "sink": sink_a}
        # inherits the parent's sink by default
        self.assertEqual(tracing.child_context(parent)["sink"], sink_a)
        # a weave reroutes its subtree
        self.assertEqual(tracing.child_context(parent, sink=sink_b)["sink"], sink_b)
        # ...or stops reporting below here
        self.assertNotIn("sink", tracing.child_context(parent, sink=None))
        # no sink anywhere => none introduced
        self.assertNotIn("sink", tracing.child_context({"trace_id": b"T"}))

    def test_deadline_and_budget_predicates(self):
        self.assertTrue(tracing.deadline_exceeded({"deadline": 100}, now=101))
        self.assertFalse(tracing.deadline_exceeded({"deadline": 100}, now=100))
        self.assertFalse(tracing.deadline_exceeded({}, now=999))
        self.assertTrue(tracing.budget_exhausted({"budget": 0}))
        self.assertFalse(tracing.budget_exhausted({"budget": 1}))
        self.assertFalse(tracing.budget_exhausted({}))


if __name__ == "__main__":
    unittest.main()
