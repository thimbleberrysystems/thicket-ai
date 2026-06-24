"""Collector fiber (Wave 4): `kind: collector`.

Fibers self-report spans (no proxy/MITM — see the wire spec's tracing model); the
collector groups them by `trace_id` and assembles a trace tree on request. A span
is reported independently by whichever fiber produced it; the collector stitches
them together purely by `trace_id` / `parent_span_id`.

Span shape (CBOR map):
    trace_id, span_id, parent_span_id (b"" for a root), name, fiber_id, kind,
    start_ms, end_ms, attrs: {tokens, cost_micros}
"""

from __future__ import annotations

from thicket import Conn, cbor, record
from thicket.fiber import run_fiber

REPORT = "collector.report"
TRACE = "collector.trace"


def build_tree(spans: list) -> list:
    """Assemble flat spans into root nodes; each node is {span, children}. Spans
    are ordered by start_ms; an unknown/empty parent makes a root."""
    nodes = {s["span_id"]: {"span": s, "children": []} for s in spans}
    roots = []
    for s in sorted(spans, key=lambda s: s.get("start_ms", 0)):
        node = nodes[s["span_id"]]
        parent = nodes.get(s.get("parent_span_id", b""))
        if parent is None or s.get("parent_span_id", b"") == b"":
            roots.append(node)
        else:
            parent["children"].append(node)
    return roots


class _Store:
    def __init__(self) -> None:
        self.by_trace: dict[bytes, list] = {}

    def report(self, span: dict) -> None:
        self.by_trace.setdefault(span["trace_id"], []).append(span)

    def spans(self, trace_id: bytes) -> list:
        return sorted(self.by_trace.get(trace_id, []), key=lambda s: s.get("start_ms", 0))


def make_handler(store: _Store):
    async def handler(conn, payload: dict) -> None:
        cap = payload.get("capability")
        body = cbor.decode(payload["body"]) if payload.get("body") else {}
        if cap == REPORT:
            store.report(body)
            await conn.respond(payload, cbor.encode({"ok": True}))
        elif cap == TRACE:
            spans = store.spans(body["trace_id"])
            await conn.respond(payload, cbor.encode({"spans": spans, "roots": build_tree(spans)}))
        else:
            await conn.respond_error(payload, "NotFound", "unknown capability")

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", ready=None):
    await run_fiber(
        local,
        dir_host,
        dir_port,
        dir_id,
        kind="collector",
        capabilities=[record.capability("collector", "assemble trace trees from self-reported spans", tags=["trace"])],
        handler=make_handler(_Store()),
        host=host,
        ready=ready,
    )


class CollectorClient:
    """Small client fibers/apps use to report spans and fetch assembled traces."""

    def __init__(self, conn: Conn) -> None:
        self.conn = conn

    @classmethod
    async def connect(cls, host, port, local, collector_id):
        return cls(await Conn.connect(host, port, local, expected_id=collector_id))

    async def report(self, span: dict) -> None:
        await self.conn.call(REPORT, cbor.encode(span))

    async def trace(self, trace_id: bytes) -> dict:
        resp = await self.conn.call(TRACE, cbor.encode({"trace_id": trace_id}))
        return cbor.decode(resp["payload"]["body"])

    async def close(self) -> None:
        await self.conn.close()
