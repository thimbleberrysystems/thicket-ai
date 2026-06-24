"""A Weave (Wave 3): composes a tool fiber + an LLM fiber to accomplish a goal.

Serves `describe_sum`: discover a `tool` and a `model` fiber, add two numbers via
the tool, then describe the sum via the LLM. The weave is the **span parent** —
it honors the cross-cutting contract: it derives a child context per sub-call
(trace propagated, deadline tightened, budget debited), **attenuates** its held
grant down to exactly the capability it invokes, self-reports its own span, and
surfaces any downstream error.

A weave is itself a fiber (`kind: weave`) and nests like any other.
"""

from __future__ import annotations

import os

from thicket import Conn, DirectoryClient, cbor, grant, record, tracing
from thicket.fiber import run_fiber

# Rough per-sub-call spend, debited from the inherited budget (units are the
# caller's — tokens, micro-dollars, …; the weave only enforces monotonic debit).
TOOL_COST = 1
LLM_COST = 1


async def _discover(dc, kind, query):
    results = await dc.search(query, kind=kind, top_k=5)
    if not results:
        raise RuntimeError(f"no {kind} fiber for {query!r}")
    rec = results[0]["payload"]
    host, port = rec["locators"][0]["endpoint"].split(":")
    return rec["id"], host, int(port)


def _narrow(tool_grant, holder_key, capability):
    """Attenuate a held grant down to a single capability (audience = self), so
    the tool sees a grant that authorizes exactly this call and no more."""
    last = tool_grant["links"][-1]["caveats"]
    return grant.attenuate(
        tool_grant,
        holder_key,
        holder_key.public(),
        grant.caveats([capability], last["not_after"], last.get("constraints")),
    )


def make_handler(local, dir_host, dir_port, dir_id, *, tool_grant=None, sink=None, emitter=None):
    async def handler(conn, payload: dict) -> None:
        if payload.get("capability") != "describe_sum":
            await conn.respond_error(payload, "NotFound", "unknown capability")
            return
        args = cbor.decode(payload["body"]) if payload.get("body") else {}

        # The weave's own span: this becomes the parent of every sub-call's span.
        # The weave routes the trace to its chosen sink (override) when configured,
        # else it inherits whatever sink the caller named — and either way the sink
        # propagates to all descendants, so the whole subtree reports to one place.
        ctx = payload.get("context") or {}
        weave_ctx = (
            tracing.child_context(ctx, span_id=os.urandom(8), sink=sink)
            if sink is not None
            else tracing.child_context(ctx, span_id=os.urandom(8))
        )
        span = emitter.span(weave_ctx, name="weave:describe_sum", kind="weave") if emitter else None

        async def body():
            if tracing.deadline_exceeded(weave_ctx):
                await conn.respond_error(payload, "DeadlineExceeded", "deadline passed before weave ran")
                return
            if tracing.budget_exhausted(weave_ctx):
                await conn.respond_error(payload, "BudgetExhausted", "no budget for the weave")
                return

            dc = await DirectoryClient.connect(dir_host, dir_port, local, dir_id)
            tool_id, th, tp = await _discover(dc, "tool", "addition")
            llm_id, lh, lp = await _discover(dc, "model", "text generation")
            await dc.close()

            # 1. tool: add — child context (debit budget) + attenuated grant
            tool_ctx = tracing.child_context(weave_ctx, span_id=os.urandom(8), spent=TOOL_COST)
            auth = _narrow(tool_grant, local.working, "calc.add") if tool_grant is not None else None
            tconn = await Conn.connect(th, tp, local, expected_id=tool_id)
            tresp = await tconn.call(
                "calc.add", cbor.encode({"a": args.get("a", 0), "b": args.get("b", 0)}), auth=auth, context=tool_ctx
            )
            await tconn.close()
            tpay = tresp["payload"]
            if tpay.get("typ") == "Error":  # surface downstream failures
                err = tpay.get("error") or {}
                await conn.respond_error(payload, err.get("code", "Error"), err.get("message", "tool failed"))
                return
            tres = cbor.decode(tpay["body"])
            total = tres["result"]

            # 2. llm: describe — child context (further debit)
            llm_ctx = tracing.child_context(weave_ctx, span_id=os.urandom(8), spent=TOOL_COST + LLM_COST)
            lconn = await Conn.connect(lh, lp, local, expected_id=llm_id)
            tokens = []
            try:
                async for c in lconn.call_stream("generate", f"The sum is {total}".encode(), context=llm_ctx):
                    tokens.append(c.get("body", b"").decode("utf-8", "replace"))
            except ConnectionError as e:
                await lconn.close()
                await conn.respond_error(payload, "Error", str(e))
                return
            await lconn.close()

            await conn.respond(
                payload,
                cbor.encode(
                    {"sum": total, "description": "".join(tokens), "tool_trace": tres.get("trace_id", b"")}
                ),
            )

        if span is not None:
            async with span:
                await body()
        else:
            await body()

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", tool_grant=None, sink=None, ready=None):
    emitter = tracing.SpanEmitter(local)
    try:
        await run_fiber(
            local,
            dir_host,
            dir_port,
            dir_id,
            kind="weave",
            capabilities=[record.capability("weave", "describe the sum of two numbers", tags=["compose"])],
            handler=make_handler(
                local, dir_host, dir_port, dir_id, tool_grant=tool_grant, sink=sink, emitter=emitter
            ),
            host=host,
            ready=ready,
        )
    finally:
        await emitter.close()
