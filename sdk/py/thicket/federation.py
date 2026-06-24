"""Federated discovery (Phase 7): scatter-gather search/resolve across several
**independent** directories — no central hub, no authoritative index.

A ``FederatedDirectory`` fans a query out to every peer directory in parallel,
then merges their (individually-ranked) results round-robin and dedupes by fiber
id. Each record is **verified** before it is trusted — a federated peer is just
another participant, not an authority, so its self-certifying records stand on
their own signatures. This mirrors the Rust ``thicket-federation`` crate's
scatter-gather/dedupe semantics, but over the wire and across processes.
"""

from __future__ import annotations

import asyncio
from itertools import zip_longest

from . import record
from .directory import DirectoryClient
from .identity import unix_now


class FederatedDirectory:
    def __init__(self, clients: list[DirectoryClient]) -> None:
        self.clients = clients

    @classmethod
    async def connect(cls, peers, local) -> "FederatedDirectory":
        """``peers``: list of ``(host, port, directory_id)``. The peer order is the
        resolve priority and the round-robin order for search."""
        clients = [await DirectoryClient.connect(h, p, local, d) for (h, p, d) in peers]
        return cls(clients)

    async def search(self, intent_text: str, *, kind=None, tags=None, top_k: int = 5) -> list:
        lists = await asyncio.gather(
            *(c.search(intent_text, kind=kind, tags=tags, top_k=top_k) for c in self.clients),
            return_exceptions=True,
        )
        now = unix_now()
        seen: set[bytes] = set()
        merged: list = []
        # round-robin across peers (fairness), dedupe by fiber id, verify each record
        per_peer = [r for r in lists if not isinstance(r, Exception)]
        for tier in zip_longest(*per_peer):
            for rec in tier:
                if rec is None:
                    continue
                rid = rec["payload"]["id"]
                if rid in seen or not record.verify_record(rec, now):
                    continue
                seen.add(rid)
                merged.append(rec)
        return merged[:top_k]

    async def resolve(self, fiber_id: bytes):
        """First peer (in priority order) with a verifiable record for ``id`` wins."""
        now = unix_now()
        for c in self.clients:
            rec = await c.resolve(fiber_id)
            if rec is not None and record.verify_record(rec, now):
                return rec
        return None

    async def close(self) -> None:
        for c in self.clients:
            await c.close()
