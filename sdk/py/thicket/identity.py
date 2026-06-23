"""Local identity bundle for connecting/serving."""

from __future__ import annotations

import time

from . import crypto


def unix_now() -> int:
    return int(time.time())


class LocalIdentity:
    def __init__(self, root: crypto.RootKey, working: crypto.WorkingKey, endorsements):
        self.root = root
        self.working = working
        self.endorsements = endorsements
        self.id = root.id()
        self.root_public_key = root.public()

    @classmethod
    def from_root(cls, root: crypto.RootKey, valid_secs: int = 1_000_000_000) -> "LocalIdentity":
        working = crypto.WorkingKey.generate()
        endorsement = root.endorse(working.public(), 0, unix_now() + valid_secs)
        return cls(root, working, [endorsement])

    @classmethod
    def generate(cls) -> "LocalIdentity":
        return cls.from_root(crypto.RootKey.generate())
