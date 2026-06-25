"""An authenticated, encrypted connection to a peer (async).

A single **reader task** demultiplexes inbound frames by correlation: responses
and stream chunks are routed to the waiting `call` / `call_stream`; requests go to
a queue for the server side. This makes **concurrent in-flight calls on one
channel** safe — matching the Rust `Conn`. Sends are serialized because the Noise
transport assigns a sequential nonce per message.
"""

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
        self.closed_event = asyncio.Event()
        self._write_lock = asyncio.Lock()
        self._pending: dict[bytes, asyncio.Future] = {}  # correlation -> unary future
        self._streams: dict[bytes, asyncio.Queue] = {}  # correlation -> stream queue
        self._inbound: asyncio.Queue = asyncio.Queue()  # inbound requests (server side)
        self._reader_task = asyncio.ensure_future(self._reader_loop())

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

    # ---- reader / demux ----

    async def _reader_loop(self):
        try:
            while True:
                blob = await read_frame(self.reader)
                if blob is None:
                    break  # EOF
                try:
                    signed = cbor.decode(secure.decrypt_frame(self.noise, blob))
                except Exception:
                    break  # AEAD failure: corrupt or hostile, close
                payload = signed["payload"]
                # authenticate every message against the handshake-proven key
                if payload.get("from") != self.peer["id"]:
                    continue
                if not envelope.verify_envelope_with_key(signed, self.peer["working_pub"]):
                    continue
                self._route(signed, payload)
        finally:
            self._teardown()

    def _route(self, signed, payload):
        typ = payload.get("typ")
        corr = payload.get("correlation")
        if typ == "Request":
            self._inbound.put_nowait(signed)
        elif typ == "StreamChunk":
            q = self._streams.get(corr)
            if q is not None:
                q.put_nowait(signed)
        else:  # Response or Error — a unary reply, or a stream's terminal frame
            fut = self._pending.pop(corr, None)
            if fut is not None and not fut.done():
                fut.set_result(signed)
            else:
                q = self._streams.get(corr)
                if q is not None:
                    q.put_nowait(signed)

    def _teardown(self):
        if self.closed_event.is_set():
            return
        self.closed_event.set()
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("connection closed"))
        self._pending.clear()
        for q in self._streams.values():
            q.put_nowait(None)
        self._inbound.put_nowait(None)

    # ---- send (serialized: Noise assigns a sequential nonce) ----

    async def _send_signed(self, payload: dict) -> None:
        blob = cbor.encode(envelope.sign_envelope(payload, self.local.working))
        async with self._write_lock:
            await write_frame(self.writer, secure.encrypt_frame(self.noise, blob))

    def _request(self, capability, body, auth, context=None) -> dict:
        return envelope.build_envelope_payload(
            from_id=self.local.id,
            to_id=self.peer["id"],
            typ="Request",
            correlation=os.urandom(16),
            capability=capability,
            auth=auth,
            context=context,
            body=body,
        )

    # ---- client side ----

    async def call(self, capability: str, body: bytes = b"", *, auth=None, context=None, timeout: float = 10.0) -> dict:
        """Send a request and return the single (decoded, signed) response.
        Safe to run concurrently with other calls on the same connection."""
        if self.closed_event.is_set():
            raise ConnectionError("connection closed")
        payload = self._request(capability, body, auth, context)
        corr = payload["correlation"]
        fut = asyncio.get_running_loop().create_future()
        self._pending[corr] = fut
        try:
            await self._send_signed(payload)
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(corr, None)

    async def call_stream(self, capability: str, body: bytes = b"", *, auth=None, context=None, timeout: float = 30.0):
        """Async-iterate response payloads until a single Response or an end-of-
        stream chunk. Safe to run concurrently with other calls."""
        if self.closed_event.is_set():
            raise ConnectionError("connection closed")
        payload = self._request(capability, body, auth, context)
        corr = payload["correlation"]
        q: asyncio.Queue = asyncio.Queue()
        self._streams[corr] = q
        try:
            await self._send_signed(payload)
            while True:
                signed = await asyncio.wait_for(q.get(), timeout)
                if signed is None:
                    return  # connection closed
                p = signed["payload"]
                if p.get("typ") == "Error":
                    raise ConnectionError((p.get("error") or {}).get("message", "remote error"))
                yield p
                if p.get("typ") == "Response" or (p.get("typ") == "StreamChunk" and p.get("stream_end")):
                    return
        finally:
            self._streams.pop(corr, None)

    def verify_response(self, signed: dict) -> bool:
        return envelope.verify_envelope_with_key(signed, self.peer["working_pub"])

    # ---- server side ----

    async def recv(self):
        """The next authenticated inbound request, or None on close. (Auth +
        from-binding are checked in the reader loop.)"""
        return await self._inbound.get()

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
        self._teardown()
        self._reader_task.cancel()
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass
