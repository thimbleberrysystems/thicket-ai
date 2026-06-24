"""Collector fiber: fibers self-report spans (no proxy/MITM); the collector
groups them by ``trace_id`` and assembles a trace tree on request."""

from thicket import Conn, Fiber, cbor

collector = Fiber(kind="collector")


def build_tree(spans: list) -> list:
    """Assemble flat spans into root nodes ({span, children}), ordered by
    start_ms; an empty/unknown parent makes a root."""
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


@collector.handles("collector.report", "store a self-reported span", tags=["trace"])
async def report(span, ctx):
    ctx.config.setdefault("by_trace", {}).setdefault(span["trace_id"], []).append(span)
    return {"ok": True}


@collector.handles("collector.trace", "assemble a trace tree by trace_id")
async def trace(req, ctx):
    spans = sorted(
        ctx.config.setdefault("by_trace", {}).get(req["trace_id"], []),
        key=lambda s: s.get("start_ms", 0),
    )
    return {"spans": spans, "roots": build_tree(spans)}


run = collector.run


class CollectorClient:
    """Small client fibers/apps use to report spans and fetch assembled traces."""

    def __init__(self, conn: Conn) -> None:
        self.conn = conn

    @classmethod
    async def connect(cls, host, port, local, collector_id):
        return cls(await Conn.connect(host, port, local, expected_id=collector_id))

    async def report(self, span: dict) -> None:
        await self.conn.call("collector.report", cbor.encode(span))

    async def trace(self, trace_id: bytes) -> dict:
        resp = await self.conn.call("collector.trace", cbor.encode({"trace_id": trace_id}))
        return cbor.decode(resp["payload"]["body"])

    async def close(self) -> None:
        await self.conn.close()


if __name__ == "__main__":
    collector.main()
