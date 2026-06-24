"""A Weave (Wave 3): composes a tool fiber + an LLM fiber to accomplish a goal.

Serves `describe_sum`: discover a `tool` and a `model` fiber, add two numbers via
the tool, then describe the sum via the LLM. The weave is the **span parent** —
it propagates a child context (trace/deadline/budget) to each sub-call.

A weave is itself a fiber (`kind: weave`) and nests like any other.
"""

from __future__ import annotations

import os

from thicket import Conn, DirectoryClient, cbor, record
from thicket.fiber import run_fiber


async def _discover(dc, kind, query):
    results = await dc.search(query, kind=kind, top_k=5)
    if not results:
        raise RuntimeError(f"no {kind} fiber for {query!r}")
    rec = results[0]["payload"]
    host, port = rec["locators"][0]["endpoint"].split(":")
    return rec["id"], host, int(port)


def make_handler(local, dir_host, dir_port, dir_id):
    async def handler(conn, payload: dict) -> None:
        if payload.get("capability") != "describe_sum":
            await conn.respond_error(payload, "NotFound", "unknown capability")
            return
        args = cbor.decode(payload["body"]) if payload.get("body") else {}

        # The weave is the span parent: propagate a child context downstream.
        ctx = payload.get("context") or {}
        child = {
            "trace_id": ctx.get("trace_id") or os.urandom(16),
            "span_id": os.urandom(8),
            "parent_span_id": ctx.get("span_id", b""),
        }
        if ctx.get("deadline") is not None:
            child["deadline"] = ctx["deadline"]
        if ctx.get("budget") is not None:
            child["budget"] = ctx["budget"]

        dc = await DirectoryClient.connect(dir_host, dir_port, local, dir_id)
        tool_id, th, tp = await _discover(dc, "tool", "addition")
        llm_id, lh, lp = await _discover(dc, "model", "text generation")
        await dc.close()

        # 1. tool: add
        tconn = await Conn.connect(th, tp, local, expected_id=tool_id)
        tresp = await tconn.call(
            "calc.add", cbor.encode({"a": args.get("a", 0), "b": args.get("b", 0)}), context=child
        )
        await tconn.close()
        tres = cbor.decode(tresp["payload"]["body"])
        total = tres["result"]

        # 2. llm: describe
        lconn = await Conn.connect(lh, lp, local, expected_id=llm_id)
        tokens = []
        async for c in lconn.call_stream("generate", f"The sum is {total}".encode(), context=child):
            tokens.append(c.get("body", b"").decode("utf-8", "replace"))
        await lconn.close()

        await conn.respond(
            payload,
            cbor.encode(
                {"sum": total, "description": "".join(tokens), "tool_trace": tres.get("trace_id", b"")}
            ),
        )

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", ready=None):
    await run_fiber(
        local,
        dir_host,
        dir_port,
        dir_id,
        kind="weave",
        capabilities=[record.capability("weave", "describe the sum of two numbers", tags=["compose"])],
        handler=make_handler(local, dir_host, dir_port, dir_id),
        host=host,
        ready=ready,
    )
