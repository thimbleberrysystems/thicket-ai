"""Optional persistence for stateful fibers.

`FileStore(None)` is purely in-memory (the default — no behaviour change).
`FileStore(path)` loads its dict on construction and rewrites the file atomically
on `save()`, so a fiber's state (memory sessions, collected spans, …) survives a
restart. CBOR (not JSON) so byte-valued state — trace ids, keys — round-trips.
"""

from __future__ import annotations

import os

from . import cbor


class FileStore:
    def __init__(self, path: str | None = None):
        self.path = path
        self.data: dict = {}
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                blob = f.read()
            if blob:
                self.data = cbor.decode(blob)

    def save(self) -> None:
        if not self.path:
            return  # in-memory only
        tmp = f"{self.path}.tmp"
        with open(tmp, "wb") as f:
            f.write(cbor.encode(self.data))
        os.replace(tmp, self.path)  # atomic swap — never a half-written file
