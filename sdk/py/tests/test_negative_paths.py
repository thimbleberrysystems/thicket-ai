"""Negative-path tests: the Python SDK must independently *reject* bad input, not
just match Rust on good input. Covers grant + record verification rejections,
malformed CBOR, the framing size guard, and connecting to the wrong peer."""

import asyncio
import copy
import unittest

from thicket import (
    Conn,
    LocalIdentity,
    RootKey,
    WorkingKey,
    cbor,
    grant,
    record,
    serve,
    unix_now,
)
from thicket.framing import MAX_FRAME, read_frame


class GrantVerifyRejections(unittest.TestCase):
    def setUp(self):
        self.target = LocalIdentity.from_root(RootKey.generate())
        self.alice = WorkingKey.generate()
        self.now = unix_now()
        self.g = grant.issue(
            self.target.id, self.target.working, self.alice.public(),
            grant.caveats(["x"], self.now + 1000),
        )

    def _verify(self, g, caller=None, cap="x", now=None, root=None, endo=None, revocations=None):
        return grant.verify(
            g,
            root if root is not None else self.target.root_public_key,
            endo if endo is not None else self.target.endorsements,
            caller if caller is not None else self.alice.public(),
            cap,
            now if now is not None else self.now,
            revocations=revocations,
        )

    def test_valid_grant_verifies(self):
        self.assertTrue(self._verify(self.g))

    def test_revoked_chain_key_rejected(self):
        self.assertTrue(self._verify(self.g))  # valid with no revocations
        # revoking the issuing (head) key kills the grant
        self.assertFalse(self._verify(self.g, revocations={self.target.working.public()}))
        # revoking the audience kills a delegated grant
        self.assertFalse(self._verify(self.g, revocations={self.alice.public()}))
        # an unrelated revoked key doesn't affect it
        self.assertTrue(self._verify(self.g, revocations={WorkingKey.generate().public()}))

    def test_wrong_caller_rejected(self):
        self.assertFalse(self._verify(self.g, caller=WorkingKey.generate().public()))

    def test_ungranted_capability_rejected(self):
        self.assertFalse(self._verify(self.g, cap="y"))

    def test_expired_grant_rejected(self):
        expired = grant.issue(
            self.target.id, self.target.working, self.alice.public(),
            grant.caveats(["x"], self.now - 1),
        )
        self.assertFalse(self._verify(expired))

    def test_wrong_target_root_rejected(self):
        other = LocalIdentity.from_root(RootKey.generate())
        self.assertFalse(self._verify(self.g, root=other.root_public_key, endo=other.endorsements))

    def test_empty_chain_rejected(self):
        self.assertFalse(self._verify({"target": self.target.id, "links": []}))

    def test_tampered_signature_rejected(self):
        forged = copy.deepcopy(self.g)
        forged["links"][-1]["sig"] = b"\x00" * 64
        self.assertFalse(self._verify(forged))

    def test_non_holder_cannot_attenuate(self):
        with self.assertRaises(ValueError):
            grant.attenuate(
                self.g, WorkingKey.generate(), WorkingKey.generate().public(),
                grant.caveats(["x"], self.now + 500),
            )

    def test_attenuation_cannot_widen(self):
        with self.assertRaises(ValueError):
            grant.attenuate(
                self.g, self.alice, WorkingKey.generate().public(),
                grant.caveats(["x", "y"], self.now + 500),  # adds "y" — widening
            )

    def test_attenuation_cannot_drop_a_constraint(self):
        constrained = grant.issue(
            self.target.id, self.target.working, self.alice.public(),
            grant.caveats(["x"], self.now + 1000, {"region": "eu"}),
        )
        with self.assertRaises(ValueError):  # dropping the region caveat widens authority
            grant.attenuate(
                constrained, self.alice, WorkingKey.generate().public(),
                grant.caveats(["x"], self.now + 500),
            )


class RecordVerifyRejections(unittest.TestCase):
    def _record(self, ident):
        return record.self_record(
            ident, kind="tool",
            capabilities=[record.capability("tool", "x")],
            locators=[record.locator("tcp", "127.0.0.1:1")],
        )

    def test_valid_record_verifies(self):
        rec = self._record(LocalIdentity.from_root(RootKey.generate()))
        self.assertTrue(record.verify_record(rec, unix_now()))

    def test_id_mismatch_rejected(self):
        rec = self._record(LocalIdentity.from_root(RootKey.generate()))
        bad = copy.deepcopy(rec)
        bad["payload"]["id"] = b"\x00" * 32
        self.assertFalse(record.verify_record(bad, unix_now()))

    def test_tampered_signature_rejected(self):
        rec = self._record(LocalIdentity.from_root(RootKey.generate()))
        bad = copy.deepcopy(rec)
        bad["signature"] = b"\x00" * 64
        self.assertFalse(record.verify_record(bad, unix_now()))

    def test_expired_endorsement_rejected(self):
        root, working = RootKey.generate(), WorkingKey.generate()
        endo = root.endorse(working.public(), 0, 100)  # not_after = epoch 100
        ident = LocalIdentity(root, working, [endo])
        rec = self._record(ident)
        self.assertTrue(record.verify_record(rec, 50))    # inside the window
        self.assertFalse(record.verify_record(rec, 200))  # past not_after


class MalformedCbor(unittest.TestCase):
    def test_encode_negative_int_rejected(self):
        with self.assertRaises(ValueError):
            cbor.encode(-1)

    def test_encode_unsupported_type_rejected(self):
        with self.assertRaises(TypeError):
            cbor.encode(1.5)  # no floats in the wire subset

    def test_decode_trailing_bytes_rejected(self):
        with self.assertRaises(ValueError):
            cbor.decode(b"\x00\x00")  # int 0, then a stray byte

    def test_decode_unsupported_simple_value_rejected(self):
        with self.assertRaises(ValueError):
            cbor.decode(b"\xe0")  # major 7, simple value 0


class FramingGuard(unittest.TestCase):
    def test_oversize_frame_rejected(self):
        async def scenario():
            reader = asyncio.StreamReader()
            reader.feed_data((MAX_FRAME + 1).to_bytes(4, "big"))
            reader.feed_eof()
            with self.assertRaises(ValueError):
                await read_frame(reader)

        asyncio.run(scenario())


class WrongPeerRejected(unittest.TestCase):
    def test_connect_to_unexpected_identity_is_rejected(self):
        async def scenario():
            host_id = LocalIdentity.from_root(RootKey.generate())

            async def handler(conn, req):
                await conn.respond(req, b"")

            server = await serve("127.0.0.1", 0, host_id, handler)
            port = server.sockets[0].getsockname()[1]
            client = LocalIdentity.from_root(RootKey.generate())
            try:
                with self.assertRaises(ValueError):
                    # pin the wrong id — the handshake authenticates, the pin fails
                    await Conn.connect("127.0.0.1", port, client, expected_id=b"\x00" * 32)
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(scenario())


class ServerResilience(unittest.TestCase):
    """A serving fiber must survive bad connections and handler crashes."""

    def test_bad_connection_does_not_crash_server(self):
        async def scenario():
            host = LocalIdentity.from_root(RootKey.generate())

            async def handler(conn, req):
                await conn.respond(req, b"ok")

            server = await serve("127.0.0.1", 0, host, handler)
            port = server.sockets[0].getsockname()[1]
            # a peer that connects then vanishes mid-handshake
            _, w = await asyncio.open_connection("127.0.0.1", port)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            # the server is unharmed — a real client still works
            client = LocalIdentity.from_root(RootKey.generate())
            conn = await Conn.connect("127.0.0.1", port, client, expected_id=host.id)
            resp = await conn.call("ping", b"")
            await conn.close()
            server.close()
            await server.wait_closed()
            return resp["payload"]["body"]

        self.assertEqual(asyncio.run(scenario()), b"ok")

    def test_handler_exception_is_isolated(self):
        async def scenario():
            host = LocalIdentity.from_root(RootKey.generate())

            async def handler(conn, req):
                if req.get("capability") == "boom":
                    raise RuntimeError("handler blew up")
                await conn.respond(req, b"ok")

            server = await serve("127.0.0.1", 0, host, handler)
            port = server.sockets[0].getsockname()[1]
            client = LocalIdentity.from_root(RootKey.generate())

            conn = await Conn.connect("127.0.0.1", port, client, expected_id=host.id)
            with self.assertRaises(Exception):  # the crashing call drops its connection
                await conn.call("boom", b"", timeout=5)
            await conn.close()

            # ...but the server kept serving — a fresh call succeeds
            conn2 = await Conn.connect("127.0.0.1", port, client, expected_id=host.id)
            resp = await conn2.call("ping", b"")
            await conn2.close()
            server.close()
            await server.wait_closed()
            return resp["payload"]["body"]

        self.assertEqual(asyncio.run(scenario()), b"ok")


if __name__ == "__main__":
    unittest.main()
