"""Trigger fiber: minimal pub/sub, on the ergonomic API.

`trigger.subscribe` streams events as they're emitted — a ready marker first
(empty body, so a subscriber knows it's registered), then one chunk per event,
ending automatically when the subscriber disconnects. `trigger.emit` fans an
event out to every current subscriber. Subscribers are kept in per-instance state
(`ctx.config`), so events arrive in publish order.
"""

import asyncio

from thicket import Fiber

trigger = Fiber(kind="trigger")


@trigger.handles("trigger.subscribe", "subscribe to events", tags=["events"])
async def subscribe(req, ctx):
    q: asyncio.Queue = asyncio.Queue()
    subs = ctx.config.setdefault("subs", set())
    subs.add(q)
    try:
        yield None  # ready marker (empty body): the subscription is registered
        while True:
            yield await q.get()
    finally:
        subs.discard(q)  # on disconnect the SDK cancels this generator


@trigger.handles("trigger.emit", "publish an event", tags=["events"])
async def emit(event, ctx):
    for q in list(ctx.config.setdefault("subs", set())):
        q.put_nowait(event)
    return {"ok": True}


run = trigger.run

if __name__ == "__main__":
    trigger.main()
