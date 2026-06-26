"""Durable execution, built from the smallest element up.

The **checkpoint** itself is a core primitive (see ``thicket-core``'s
``Checkpoint`` + ``spec/thicket-wire.md``): a run's recorded steps, encoded
canonically as ``{run_id, steps:[{key, value}]}`` with opaque ``value`` bytes — so
a run checkpointed by one implementation is resumable by another. This module is
the Python side of that contract, plus the **step** runner built on it.

The atom is a step: an async operation that runs at most once per run. Its result
(CBOR-encoded — the SDK's convention for ``value``) is recorded; on resume (same
``run_id``) a recorded step returns its value instead of re-executing. Everything
larger — ``ctx.call``, a weave, an agent loop — is just a sequence of steps over
this one primitive, so durability **composes**.

Contract: a durable workflow must be **deterministic** in its step *sequence*;
recording is **at-least-once** (a crash between completing and persisting a step
re-runs it on resume); a persisted step value must be serializable (CBOR).
"""

from __future__ import annotations

from . import cbor


def encode_checkpoint(run_id: bytes, steps: dict) -> bytes:
    """Canonical encoding of a checkpoint — byte-identical to the Rust core's
    ``Checkpoint::to_cbor``. ``steps`` is an ordered ``{key: value_bytes}``."""
    return cbor.encode(
        {"run_id": run_id, "steps": [{"key": k, "value": v} for k, v in steps.items()]}
    )


def decode_checkpoint(blob: bytes):
    """Inverse of :func:`encode_checkpoint` → ``(run_id, {key: value_bytes})``."""
    d = cbor.decode(blob)
    return d["run_id"], {s["key"]: s["value"] for s in d["steps"]}


class Checkpoint:
    """A run's recorded steps. ``open`` to start/resume, ``step`` to run-or-replay."""

    def __init__(self, store, run_id, steps):
        self._store = store
        self._run_id = run_id
        self._steps = steps  # ordered {key: value_bytes}
        self._seq = 0

    @classmethod
    async def open(cls, store, run_id) -> "Checkpoint":
        blob = await store.load(run_id)
        steps = decode_checkpoint(blob)[1] if blob else {}
        return cls(store, run_id, steps)

    async def step(self, fn, *, key=None):
        """Run ``fn()`` once for this run and record its (CBOR-encoded) result; on
        resume, return the recorded value without re-running. ``key`` defaults to
        the step's position (the ``#0``/``#1`` sequence convention)."""
        if key is None:
            key, self._seq = f"#{self._seq}", self._seq + 1
        if key in self._steps:
            return cbor.decode(self._steps[key]) if self._steps[key] else None
        value = await fn()
        self._steps[key] = cbor.encode(value) if value is not None else b""
        await self._store.save(self._run_id, encode_checkpoint(self._run_id, self._steps))
        return value

    @property
    def steps_done(self) -> int:
        return len(self._steps)


class DictStore:
    """In-memory checkpoint store — single process / tests. Stores canonical
    checkpoint bytes, so it behaves identically to a persistent backend."""

    def __init__(self):
        self._runs: dict = {}

    async def load(self, run_id):
        return self._runs.get(run_id)

    async def save(self, run_id, blob):
        self._runs[run_id] = blob


class FileCheckpointStore:
    """A durable checkpoint store backed by a CBOR file (survives restart)."""

    def __init__(self, path):
        from .store import FileStore

        self._fs = FileStore(path)

    async def load(self, run_id):
        return self._fs.data.get(run_id)

    async def save(self, run_id, blob):
        self._fs.data[run_id] = blob
        self._fs.save()
