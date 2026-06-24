"""Router fiber (Wave 4): selects among model fibers by envelope constraints
(cost / latency / context window) + reputation.

Serves `route`: given a `need`, the router discovers candidate `model` fibers from
the directory, reads each one's advertised `profile` (cost_micros, latency_ms,
context_window, reputation), filters to those that satisfy the hard constraints,
and picks the best by the requested optimization. It returns the chosen fiber's
id + endpoint; the caller then connects directly (the router is not in the data
path).
"""

from __future__ import annotations

from thicket import DirectoryClient, cbor, record
from thicket.fiber import run_fiber

ROUTE = "route"


def _int(profile: dict, key: str, default: int) -> int:
    try:
        return int(profile.get(key, default))
    except (TypeError, ValueError):
        return default


def select(need: dict, candidates: list):
    """Pure selection: hard-filter by constraints, then optimize. Returns the
    chosen candidate dict, or None if none qualify."""
    max_cost = need.get("max_cost_micros")
    max_latency = need.get("max_latency_ms")
    min_context = need.get("min_context")
    optimize = need.get("optimize", "cost")

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


def make_handler(local, dir_host, dir_port, dir_id):
    async def handler(conn, payload: dict) -> None:
        if payload.get("capability") != ROUTE:
            await conn.respond_error(payload, "NotFound", "unknown capability")
            return
        need = cbor.decode(payload["body"]) if payload.get("body") else {}

        dc = await DirectoryClient.connect(dir_host, dir_port, local, dir_id)
        hits = await dc.search(need.get("intent_text", "text generation"), kind="model", top_k=20)
        await dc.close()

        chosen = select(need, _candidates_from_hits(hits))
        if chosen is None:
            await conn.respond_error(payload, "NotFound", "no model satisfies the constraints")
            return
        await conn.respond(payload, cbor.encode({"chosen_id": chosen["id"], "endpoint": chosen["endpoint"]}))

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", ready=None):
    await run_fiber(
        local,
        dir_host,
        dir_port,
        dir_id,
        kind="weave",
        capabilities=[record.capability("weave", "route a request to the best model fiber", tags=["route"])],
        handler=make_handler(local, dir_host, dir_port, dir_id),
        host=host,
        ready=ready,
    )


if __name__ == "__main__":
    from thicket.fiber import run_main

    run_main(run)
