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

REPORT = "collector.report"

_UNSET = object()


def now_s() -> int:
    return int(time.time())


def now_ms() -> int:
    return int(time.time() * 1000)


def child_context(parent, *, span_id=None, local_deadline=None, spent=0, sink=_UNSET) -> dict:
    """Derive a downstream context: same trace, fresh span, parent linkage;
    deadline only tightens (min), budget only debits. Mirrors Context::child.

    The trace **sink** (where spans are reported) propagates from the parent
    unchanged unless ``sink`` is given — passing ``sink={...}`` reroutes this
    subtree (a weave overriding the sink for its children), ``sink=None`` stops
    reporting below here."""
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
    effective_sink = parent.get("sink") if sink is _UNSET else sink
    if effective_sink is not None:
        ctx["sink"] = effective_sink
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
    """Self-reports each span to **the sink named in the context** — not a
    directory-discovered one — so every fiber in a trace reports to the place the
    initiator (a weave) chose, and the tree assembles coherently. Opt-in: no
    ``sink`` in the context ⇒ a silent no-op. Connections are cached per sink id;
    one emitter per fiber, ``close()`` on shutdown."""

    def __init__(self, local):
        self.local = local
        self._conns: dict[bytes, Conn] = {}

    async def _sink_conn(self, sink):
        sid = sink["id"]
        conn = self._conns.get(sid)
        if conn is None:
            host, port = sink["endpoint"].split(":")
            conn = await Conn.connect(host, int(port), self.local, expected_id=sid)
            self._conns[sid] = conn
        return conn

    @contextlib.asynccontextmanager
    async def span(self, ctx, *, name, kind, attrs=None):
        """Time the wrapped work and report a self-span (span_id/parent/sink all
        from ``ctx``). No-op when the context carries no trace id or no sink."""
        start = now_ms()
        try:
            yield
        finally:
            ctx = ctx or {}
            sink = ctx.get("sink")
            if sink and ctx.get("trace_id"):
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
                    conn = await self._sink_conn(sink)
                    await conn.call(REPORT, cbor.encode(span))
                except Exception:
                    pass

    async def close(self):
        for conn in self._conns.values():
            try:
                await conn.close()
            except Exception:
                pass
        self._conns.clear()
