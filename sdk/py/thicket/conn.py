"""An authenticated, encrypted connection to a peer (async): connect/accept,
call, call_stream, and the serving primitives recv/send."""

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

    # ---- establishment ----

    @classmethod
    async def connect(cls, host: str, port: int, local: LocalIdentity, expected_id=None) -> "Conn":
        reader, writer = await asyncio.open_connection(host, port)
        noise, peer = await secure.handshake(reader, writer, local, initiator=True, now=unix_now())
        if expected_id is not None and peer["id"] != expected_id:
            writer.close()
            raise ValueError("peer identity is not the expected one")
        return cls(reader, writer, noise, peer, local)

    @classmethod
    async def accept(cls, reader, writer, local: LocalIdentity, expected_id=None) -> "Conn":
        noise, peer = await secure.handshake(reader, writer, local, initiator=False, now=unix_now())
        if expected_id is not None and peer["id"] != expected_id:
            writer.close()
            raise ValueError("peer identity is not the expected one")
        return cls(reader, writer, noise, peer, local)

    # ---- raw frame I/O ----

    async def _send_signed(self, payload: dict) -> None:
        signed = envelope.sign_envelope(payload, self.local.working)
        await write_frame(self.writer, secure.encrypt_frame(self.noise, cbor.encode(signed)))

    async def _recv_signed(self, timeout=None):
        blob = await (asyncio.wait_for(read_frame(self.reader), timeout) if timeout else read_frame(self.reader))
        if blob is None:
            return None
        return cbor.decode(secure.decrypt_frame(self.noise, blob))

    # ---- client side ----

    async def call(self, capability: str, body: bytes = b"", *, auth=None, timeout: float = 10.0) -> dict:
        """Send a request and return the single (decoded, signed) response."""
        payload = self._request(capability, body, auth)
        await self._send_signed(payload)
        resp = await self._recv_signed(timeout)
        if resp is None:
            raise ConnectionError("connection closed")
        return resp

    async def call_stream(self, capability: str, body: bytes = b"", *, auth=None, timeout: float = 30.0):
        """Async-iterate response payloads until a single Response or an end-of-
        stream chunk."""
        await self._send_signed(self._request(capability, body, auth))
        while True:
            resp = await self._recv_signed(timeout)
            if resp is None:
                return
            p = resp["payload"]
            if p.get("typ") == "Error":
                raise ConnectionError((p.get("error") or {}).get("message", "remote error"))
            yield p
            if p.get("typ") == "Response" or (p.get("typ") == "StreamChunk" and p.get("stream_end")):
                return

    def _request(self, capability, body, auth) -> dict:
        return envelope.build_envelope_payload(
            from_id=self.local.id,
            to_id=self.peer["id"],
            typ="Request",
            correlation=os.urandom(16),
            capability=capability,
            auth=auth,
            body=body,
        )

    def verify_response(self, signed: dict) -> bool:
        return envelope.verify_envelope_with_key(signed, self.peer["working_pub"])

    # ---- server side ----

    async def recv(self):
        """Receive the next authenticated inbound envelope, or None on close."""
        while True:
            signed = await self._recv_signed()
            if signed is None:
                return None
            if signed["payload"].get("from") != self.peer["id"]:
                continue
            if not envelope.verify_envelope_with_key(signed, self.peer["working_pub"]):
                continue
            return signed

    async def respond(self, request_payload: dict, body: bytes) -> None:
        await self._send_signed(
            envelope.build_envelope_payload(
                from_id=self.local.id,
                to_id=request_payload["from"],
                typ="Response",
                correlation=request_payload["correlation"],
                body=body,
            )
        )

    async def respond_error(self, request_payload: dict, code: str, message: str) -> None:
        await self._send_signed(
            envelope.build_envelope_payload(
                from_id=self.local.id,
                to_id=request_payload["from"],
                typ="Error",
                correlation=request_payload["correlation"],
                error={"code": code, "message": message},
            )
        )

    async def stream_chunk(self, request_payload: dict, seq: int, end: bool, body: bytes) -> None:
        await self._send_signed(
            envelope.build_envelope_payload(
                from_id=self.local.id,
                to_id=request_payload["from"],
                typ="StreamChunk",
                correlation=request_payload["correlation"],
                stream_seq=seq,
                stream_end=end,
                body=body,
            )
        )

    async def close(self) -> None:
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass
