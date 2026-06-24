"""Profiler app (Wave 4): turn a collected trace into per-fiber latency and
token/$ cost, and render the trace tree.

This is a *consumer app*, not a fiber: it asks a collector for a trace and
computes a summary. Pure functions (`summarize`, `render`) operate on the span
data so they are trivially testable.
"""

from __future__ import annotations


def summarize(spans: list) -> dict:
    """Per-fiber latency + cost and trace-wide totals from flat spans."""
    per_fiber: dict[str, dict] = {}
    total_cost = 0
    total_tokens = 0
    for s in spans:
        name = s.get("name", "?")
        attrs = s.get("attrs") or {}
        latency = max(0, s.get("end_ms", 0) - s.get("start_ms", 0))
        cost = attrs.get("cost_micros", 0)
        tokens = attrs.get("tokens", 0)
        agg = per_fiber.setdefault(name, {"latency_ms": 0, "tokens": 0, "cost_micros": 0, "calls": 0})
        agg["latency_ms"] += latency
        agg["tokens"] += tokens
        agg["cost_micros"] += cost
        agg["calls"] += 1
        total_cost += cost
        total_tokens += tokens
    span_extent = 0
    if spans:
        span_extent = max(s.get("end_ms", 0) for s in spans) - min(s.get("start_ms", 0) for s in spans)
    return {
        "per_fiber": per_fiber,
        "total_cost_micros": total_cost,
        "total_tokens": total_tokens,
        "wall_ms": max(0, span_extent),
    }


def render(roots: list, _depth: int = 0) -> str:
    """ASCII trace tree: indented `name  latency_ms  tokens/cost`."""
    lines = []
    for node in roots:
        s = node["span"]
        attrs = s.get("attrs") or {}
        latency = max(0, s.get("end_ms", 0) - s.get("start_ms", 0))
        lines.append(
            f"{'  ' * _depth}{s.get('name', '?')}  {latency}ms"
            f"  {attrs.get('tokens', 0)}tok  {attrs.get('cost_micros', 0)}µ$"
        )
        lines.append(render(node["children"], _depth + 1))
    return "\n".join(x for x in lines if x)


async def profile(collector_client, trace_id: bytes) -> dict:
    """Fetch a trace from a collector and return its summary + rendering."""
    tr = await collector_client.trace(trace_id)
    summary = summarize(tr["spans"])
    summary["tree"] = render(tr["roots"])
    return summary
