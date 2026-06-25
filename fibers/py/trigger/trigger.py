"""Trigger fiber (Wave 4): `kind: trigger` — a minimal pub/sub event source.

`trigger.subscribe` is a long-lived streaming call: the subscriber gets a ready
chunk (empty body) once registered, then one StreamChunk per event in emit order.
`trigger.emit` publishes an event {topic, data} to every current subscriber.

Events are fanned out through per-subscriber FIFO queues, so a subscriber sees
emits in the order they were published.
"""

from __future__ import annotations

import asyncio

from thicket import cbor, record
from thicket.fiber import run_fiber

SUBSCRIBE = "trigger.subscribe"
EMIT = "trigger.emit"


class _Hub:
    def __init__(self) -> None:
        self.subs: set[asyncio.Queue] = set()

    def emit(self, event: dict) -> None:
        for q in list(self.subs):
            q.put_nowait(event)


def make_handler(hub: _Hub):
    async def handler(conn, payload: dict) -> None:
        cap = payload.get("capability")
        if cap == EMIT:
            hub.emit(cbor.decode(payload["body"]) if payload.get("body") else {})
            await conn.respond(payload, cbor.encode({"ok": True}))
        elif cap == SUBSCRIBE:
            q: asyncio.Queue = asyncio.Queue()
            hub.subs.add(q)
            # End the subscription when the subscriber disconnects: race each event
            # against the connection's closed signal.
            closed = asyncio.ensure_future(conn.closed_event.wait())
            try:
                seq = 0
                await conn.stream_chunk(payload, seq, False, b"")  # ready marker
                seq += 1
                while True:
                    getter = asyncio.ensure_future(q.get())
                    done, _ = await asyncio.wait({getter, closed}, return_when=asyncio.FIRST_COMPLETED)
                    if closed in done:
                        getter.cancel()
                        break
                    await conn.stream_chunk(payload, seq, False, cbor.encode(getter.result()))
                    seq += 1
            finally:
                closed.cancel()
                hub.subs.discard(q)
        else:
            await conn.respond_error(payload, "NotFound", "unknown capability")

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", ready=None):
    await run_fiber(
        local,
        dir_host,
        dir_port,
        dir_id,
        kind="trigger",
        capabilities=[record.capability("trigger", "publish/subscribe to events", tags=["events"])],
        handler=make_handler(_Hub()),
        host=host,
        ready=ready,
    )


if __name__ == "__main__":
    from thicket.fiber import run_main

    run_main(run)
