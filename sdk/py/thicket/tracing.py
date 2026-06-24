"""Self-reported tracing (Phase 2 SDK module): context propagation/attenuation,
deadline/budget checks, and span emission to an opt-in collector.

The context block (trace_id / span_id / parent_span_id / deadline / budget) rides
in the envelope. ``child_context`` derives a downstream context the way the Rust
core's ``Context::child`` does — same trace, a fresh span, this span becomes the
parent, deadline only tightens (min), budget only debits (child ≤ parent). Spans
are **self**-reported: a fiber emits its own span to a collector it discovers from
the directory (opt-in — a silent no-op when no collector is registered), so
nothing proxies or sniffs the encrypted path.
"""

from __future__ import annotations

import contextlib
import os
import time

from . import cbor
from .conn import Conn
from .directory import DirectoryClient

REPORT = "collector.report"


def now_s() -> int:
    return int(time.time())


def now_ms() -> int:
    return int(time.time() * 1000)


def child_context(parent, *, span_id=None, local_deadline=None, spent=0) -> dict:
    """Derive a downstream context: same trace, fresh span, parent linkage;
    deadline only tightens (min), budget only debits. Mirrors Context::child."""
    parent = parent or {}
    ctx = {
        "trace_id": parent.get("trace_id") or os.urandom(16),
        "span_id": span_id or os.urandom(8),
        "parent_span_id": parent.get("span_id", b""),
    }
    deadlines = [d for d in (parent.get("deadline"), local_deadline) if d is not None]
    if deadlines:
        ctx["deadline"] = min(deadlines)
    if parent.get("budget") is not None:
        ctx["budget"] = max(0, parent["budget"] - spent)
    return ctx


def deadline_exceeded(ctx, now=None) -> bool:
    ctx = ctx or {}
    d = ctx.get("deadline")
    return d is not None and (now if now is not None else now_s()) > d


def budget_exhausted(ctx) -> bool:
    ctx = ctx or {}
    b = ctx.get("budget")
    return b is not None and b <= 0


class SpanEmitter:
    """Self-reports spans to a collector discovered from the directory. Opt-in: if
    no collector is registered the first lookup caches a no-op. One emitter per
    fiber; reuse it across requests, ``close()`` on shutdown."""

    def __init__(self, local, dir_host, dir_port, dir_id):
        self.local = local
        self._dir = (dir_host, dir_port, dir_id)
        self._conn = None
        self._looked_up = False

    async def _collector(self):
        if self._looked_up:
            return self._conn
        self._looked_up = True
        try:
            host, port, dir_id = self._dir
            dc = await DirectoryClient.connect(host, port, self.local, dir_id)
            hits = await dc.search("trace collector", kind="collector", top_k=1)
            await dc.close()
            if hits:
                rec = hits[0]["payload"]
                h, p = rec["locators"][0]["endpoint"].split(":")
                self._conn = await Conn.connect(h, int(p), self.local, expected_id=rec["id"])
        except Exception:
            self._conn = None
        return self._conn

    @contextlib.asynccontextmanager
    async def span(self, ctx, *, name, kind, attrs=None):
        """Time the wrapped work and report a self-span (span_id/parent from
        ``ctx``). No-op if the trace has no id or no collector is reachable."""
        start = now_ms()
        try:
            yield
        finally:
            ctx = ctx or {}
            conn = await self._collector()
            if conn is not None and ctx.get("trace_id"):
                span = {
                    "trace_id": ctx["trace_id"],
                    "span_id": ctx.get("span_id") or os.urandom(8),
                    "parent_span_id": ctx.get("parent_span_id", b""),
                    "name": name,
                    "fiber_id": self.local.id,
                    "kind": kind,
                    "start_ms": start,
                    "end_ms": now_ms(),
                    "attrs": attrs or {},
                }
                try:
                    await conn.call(REPORT, cbor.encode(span))
                except Exception:
                    pass

    async def close(self):
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
