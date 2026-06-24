"""Memory fiber (Wave 2).

Serves conversation memory keyed by a **session reference** (pass-by-reference
context): callers pass a session id, not the whole history.

Capabilities: `memory.append`, `memory.materialize`, `memory.retrieve`.
"""

from __future__ import annotations

from thicket import Conn, cbor, record
from thicket.fiber import run_fiber


def make_handler(store: dict):
    async def handler(conn, payload: dict) -> None:
        cap = payload.get("capability")
        args = cbor.decode(payload["body"]) if payload.get("body") else {}
        if cap == "memory.append":
            store.setdefault(args["session"], []).append(args["message"])
            await conn.respond(payload, cbor.encode({"ok": True}))
        elif cap == "memory.materialize":
            await conn.respond(payload, cbor.encode({"messages": store.get(args["session"], [])}))
        elif cap == "memory.retrieve":
            q = (args.get("query") or "").lower()
            msgs = store.get(args["session"], [])
            hits = [m for m in msgs if q in str(m.get("content", "")).lower()] if q else list(msgs)
            await conn.respond(payload, cbor.encode({"messages": hits}))
        else:
            await conn.respond_error(payload, "NotFound", "unknown capability")

    return handler


async def run(local, dir_host, dir_port, dir_id, *, host="127.0.0.1", ready=None, store=None):
    await run_fiber(
        local,
        dir_host,
        dir_port,
        dir_id,
        kind="memory",
        capabilities=[record.capability("memory", "conversation memory store", tags=["memory"])],
        handler=make_handler({} if store is None else store),
        host=host,
        ready=ready,
    )


class MemoryClient:
    """Typed client for a memory fiber."""

    def __init__(self, conn: Conn) -> None:
        self.conn = conn

    @classmethod
    async def connect(cls, host, port, local, expected_id) -> "MemoryClient":
        return cls(await Conn.connect(host, int(port), local, expected_id=expected_id))

    async def _call(self, cap: str, args: dict) -> dict:
        resp = await self.conn.call(cap, cbor.encode(args))
        p = resp["payload"]
        if p.get("typ") == "Error":
            raise RuntimeError((p.get("error") or {}).get("message", "memory error"))
        return cbor.decode(p["body"]) if p.get("body") else {}

    async def append(self, session: str, message: dict) -> None:
        await self._call("memory.append", {"session": session, "message": message})

    async def materialize(self, session: str) -> list:
        return (await self._call("memory.materialize", {"session": session})).get("messages", [])

    async def retrieve(self, session: str, query: str) -> list:
        return (await self._call("memory.retrieve", {"session": session, "query": query})).get("messages", [])

    async def close(self) -> None:
        await self.conn.close()


if __name__ == "__main__":
    from thicket.fiber import run_main

    run_main(run)
