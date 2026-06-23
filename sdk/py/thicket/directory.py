"""Typed client for the networked directory (register/resolve/search/…)."""

from __future__ import annotations

from . import cbor
from .conn import Conn

REGISTER = "directory.register"
RESOLVE = "directory.resolve"
SEARCH = "directory.search"
RENEW = "directory.renew"
DEREGISTER = "directory.deregister"


class DirectoryError(Exception):
    pass


class DirectoryClient:
    def __init__(self, conn: Conn) -> None:
        self.conn = conn

    @classmethod
    async def connect(cls, host: str, port: int, local, directory_id: bytes) -> "DirectoryClient":
        return cls(await Conn.connect(host, port, local, expected_id=directory_id))

    async def _call(self, capability: str, body: bytes) -> bytes:
        resp = await self.conn.call(capability, body)
        p = resp["payload"]
        if p.get("typ") == "Error":
            raise DirectoryError((p.get("error") or {}).get("message", "remote error"))
        return p.get("body", b"")

    async def register(self, signed_record: dict) -> None:
        await self._call(REGISTER, cbor.encode(signed_record))

    async def resolve(self, fiber_id: bytes):
        try:
            return cbor.decode(await self._call(RESOLVE, cbor.encode(fiber_id)))
        except DirectoryError:
            return None

    async def search(self, intent_text: str, *, kind=None, tags=None, top_k: int = 5) -> list:
        need = {
            "intent_text": intent_text,
            "kind": kind,
            "tags": list(tags or []),
            "top_k": top_k,
        }
        return cbor.decode(await self._call(SEARCH, cbor.encode(need)))

    async def renew(self, ttl: int) -> int:
        args = {"id": self.conn.local.id, "ttl": ttl}
        return cbor.decode(await self._call(RENEW, cbor.encode(args)))

    async def deregister(self) -> None:
        await self._call(DEREGISTER, cbor.encode(self.conn.local.id))

    async def close(self) -> None:
        await self.conn.close()
