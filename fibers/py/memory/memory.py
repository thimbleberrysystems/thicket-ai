"""Memory fiber: conversation memory keyed by a **session reference** — callers
pass a session id, not the whole history. State lives in ``ctx.config`` so each
running instance is isolated."""

from thicket import Conn, Fiber, cbor

memory = Fiber(kind="memory")


@memory.handles("memory.append", "append a message to a session", tags=["memory"])
async def append(req, ctx):
    ctx.config.setdefault("store", {}).setdefault(req["session"], []).append(req["message"])
    return {"ok": True}


@memory.handles("memory.materialize", "all messages in a session")
async def materialize(req, ctx):
    return {"messages": ctx.config.setdefault("store", {}).get(req["session"], [])}


@memory.handles("memory.retrieve", "messages in a session matching a query")
async def retrieve(req, ctx):
    msgs = ctx.config.setdefault("store", {}).get(req["session"], [])
    q = (req.get("query") or "").lower()
    return {"messages": [m for m in msgs if q in str(m.get("content", "")).lower()] if q else list(msgs)}


run = memory.run


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
    memory.main()
