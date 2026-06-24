"""Router fiber: picks the best model fiber for a need (cost / latency / context
window + reputation). It discovers candidate `model` fibers, reads their
advertised `profile`, filters by the hard constraints, optimizes, and returns the
chosen fiber's id + endpoint — the caller then connects directly (the router is
never in the data path)."""

from thicket import Fiber, ThicketError

router = Fiber(kind="weave")


def _int(profile: dict, key: str, default: int) -> int:
    try:
        return int(profile.get(key, default))
    except (TypeError, ValueError):
        return default


def select(need: dict, candidates: list):
    """Hard-filter by constraints, then optimize. Returns the chosen candidate or
    None if none qualify."""
    max_cost, max_latency = need.get("max_cost_micros"), need.get("max_latency_ms")
    min_context, optimize = need.get("min_context"), need.get("optimize", "cost")
    eligible = []
    for c in candidates:
        if max_cost is not None and c["cost_micros"] > max_cost:
            continue
        if max_latency is not None and c["latency_ms"] > max_latency:
            continue
        if min_context is not None and c["context_window"] < min_context:
            continue
        eligible.append(c)
    if not eligible:
        return None
    keyers = {
        "cost": lambda c: (c["cost_micros"], -c["reputation"]),
        "latency": lambda c: (c["latency_ms"], -c["reputation"]),
        "reputation": lambda c: (-c["reputation"], c["cost_micros"]),
    }
    return min(eligible, key=keyers.get(optimize, keyers["cost"]))


def _candidates_from_hits(hits: list) -> list:
    out = []
    for h in hits:
        rec = h["payload"]
        prof = rec.get("profile") or {}
        out.append(
            {
                "id": rec["id"],
                "endpoint": (rec["locators"][0]["endpoint"] if rec.get("locators") else ""),
                "cost_micros": _int(prof, "cost_micros", 1 << 30),
                "latency_ms": _int(prof, "latency_ms", 1 << 30),
                "context_window": _int(prof, "context_window", 0),
                "reputation": _int(prof, "reputation", 0),
            }
        )
    return out


@router.handles("route", "pick the best model fiber for a need", tags=["route"])
async def route(need, ctx):
    need = need or {}
    hits = await ctx.search("model", need.get("intent_text", "text generation"), top_k=20)
    chosen = select(need, _candidates_from_hits(hits))
    if chosen is None:
        raise ThicketError("NotFound", "no model satisfies the constraints")
    return {"chosen_id": chosen["id"], "endpoint": chosen["endpoint"]}


run = router.run

if __name__ == "__main__":
    router.main()
