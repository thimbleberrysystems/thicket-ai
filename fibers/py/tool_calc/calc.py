"""Tool fiber (Wave 3): integer addition, grant-gateable.

Echoes the received context `trace_id` in its result so propagation through a
weave is observable in tests. Self-reports a span to a collector (if one is
registered) and enforces the context deadline/budget — proof that a leaf fiber
honors the cross-cutting contract on its own.
"""

from __future__ import annotations

import contextlib

from thicket import cbor, grant, record, tracing, unix_now
from thicket.fiber import run_fiber


def make_handler(local, *, require_grant: bool = False, emitter=None):
    async def handler(conn, payload: dict) -> None:
        if payload.get("capability") != "calc.add":
            await conn.respond_error(payload, "NotFound", "unknown capability")
            return
        ctx = payload.get("context") or {}
        # cross-cutting contract: enforce the inherited deadline/budget
        if tracing.deadline_exceeded(ctx):
            await conn.respond_error(payload, "DeadlineExceeded", "deadline passed before tool ran")
            return
        if tracing.budget_exhausted(ctx):
            await conn.respond_error(payload, "BudgetExhausted", "no budget remaining for tool")
            return
        if require_grant:
            auth = payload.get("auth")
            ok = auth is not None and grant.verify(
                auth,
                local.root_public_key,
                local.endorsements,
                conn.peer["working_pub"],
                "calc.add",
                unix_now(),
            )
            if not ok:
                await conn.respond_error(payload, "Unauthorized", "valid grant required")
                return
        span = emitter.span(ctx, name="tool:calc.add", kind="tool") if emitter else contextlib.nullcontext()
        async with span:
            args = cbor.decode(payload["body"]) if payload.get("body") else {}
            await conn.respond(
                payload,
                cbor.encode(
                    {"result": args.get("a", 0) + args.get("b", 0), "trace_id": ctx.get("trace_id", b"")}
                ),
            )

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", require_grant=False, ready=None):
    emitter = tracing.SpanEmitter(local)
    try:
        await run_fiber(
            local,
            dir_host,
            dir_port,
            dir_id,
            kind="tool",
            capabilities=[record.capability("tool", "integer addition", tags=["calc"])],
            handler=make_handler(local, require_grant=require_grant, emitter=emitter),
            host=host,
            ready=ready,
        )
    finally:
        await emitter.close()


if __name__ == "__main__":
    from thicket.fiber import run_main

    run_main(run)
