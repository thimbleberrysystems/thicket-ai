"""Tool fiber (Wave 3): integer addition, grant-gateable.

Echoes the received context `trace_id` in its result so propagation through a
weave is observable in tests.
"""

from __future__ import annotations

from thicket import cbor, grant, record, unix_now
from thicket.fiber import run_fiber


def make_handler(local, *, require_grant: bool = False):
    async def handler(conn, payload: dict) -> None:
        if payload.get("capability") != "calc.add":
            await conn.respond_error(payload, "NotFound", "unknown capability")
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
        args = cbor.decode(payload["body"]) if payload.get("body") else {}
        ctx = payload.get("context") or {}
        await conn.respond(
            payload,
            cbor.encode({"result": args.get("a", 0) + args.get("b", 0), "trace_id": ctx.get("trace_id", b"")}),
        )

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", require_grant=False, ready=None):
    await run_fiber(
        local,
        dir_host,
        dir_port,
        dir_id,
        kind="tool",
        capabilities=[record.capability("tool", "integer addition", tags=["calc"])],
        handler=make_handler(local, require_grant=require_grant),
        host=host,
        ready=ready,
    )
