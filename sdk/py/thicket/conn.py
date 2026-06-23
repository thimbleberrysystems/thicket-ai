"""An authenticated, encrypted connection to a peer (async)."""

from __future__ import annotations

import asyncio
import os

from . import cbor, envelope, secure
from .framing import read_frame, write_frame
from .identity import LocalIdentity, unix_now


class Conn:
    def __init__(self, reader, writer, noise, peer, local):
        self.reader = reader
        self.writer = writer
        self.noise = noise
        self.peer = peer  # {"id": bytes, "working_pub": bytes}
        self.local = local

    @classmethod
    async def connect(cls, host: str, port: int, local: LocalIdentity, expected_id=None) -> "Conn":
        reader, writer = await asyncio.open_connection(host, port)
        noise, peer = await secure.handshake(reader, writer, local, initiator=True, now=unix_now())
        if expected_id is not None and peer["id"] != expected_id:
            writer.close()
            raise ValueError("peer identity is not the expected one")
        return cls(reader, writer, noise, peer, local)

    async def call(self, capability: str, body: bytes = b"", *, auth=None, timeout: float = 10.0) -> dict:
        """Send a request and return the (decoded, signed) response envelope."""
        payload = envelope.build_envelope_payload(
            from_id=self.local.id,
            to_id=self.peer["id"],
            typ="Request",
            correlation=os.urandom(16),
            capability=capability,
            auth=auth,
            body=body,
        )
        signed = envelope.sign_envelope(payload, self.local.working)
        await write_frame(self.writer, secure.encrypt_frame(self.noise, cbor.encode(signed)))

        blob = await asyncio.wait_for(read_frame(self.reader), timeout)
        if blob is None:
            raise ConnectionError("connection closed")
        return cbor.decode(secure.decrypt_frame(self.noise, blob))

    def verify_response(self, signed: dict) -> bool:
        """Verify a response is from the handshake-authenticated peer."""
        return envelope.verify_envelope_with_key(signed, self.peer["working_pub"])

    async def close(self) -> None:
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass
