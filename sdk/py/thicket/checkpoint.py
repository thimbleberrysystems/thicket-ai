"""Durable execution, built from the smallest element up.

The atom is a **step**: an async operation that runs at most once per run. Its
result is recorded in a pluggable store; on resume (same ``run_id``) a recorded
step returns its value instead of re-executing. Everything larger — a weave, an
agent loop — is just a sequence of steps over this one primitive, so durability
**composes**: a sub-weave call is a single step at the level above.

Contract (standard for durable execution):
- A durable workflow must be **deterministic** in its step *sequence* — the Nth
  step each run must be the same logical operation. Randomness, time, and I/O
  belong *inside* steps (so their results are recorded), not in the control flow
  that decides which steps run.
- Recording is **at-least-once**: a crash between a step completing and its record
  being persisted re-runs that step on resume, so step bodies should be idempotent
  or tolerate replay.
- For a persistent store, a step's result must be serializable (CBOR).
"""

from __future__ import annotations


class Checkpoint:
    """A run's recorded steps. ``open`` to start/resume, ``step`` to run-or-replay."""

    def __init__(self, store, run_id, recorded):
        self._store = store
        self._run_id = run_id
        self._recorded = recorded
        self._seq = 0

    @classmethod
    async def open(cls, store, run_id) -> "Checkpoint":
        return cls(store, run_id, dict(await store.load(run_id) or {}))

    async def step(self, fn, *, key=None):
        """Run ``fn()`` once for this run and record its result; on resume, return
        the recorded value without re-running. ``key`` defaults to the step's
        position in the run (so a deterministic workflow replays in order)."""
        if key is None:
            key, self._seq = f"#{self._seq}", self._seq + 1
        if key in self._recorded:
            return self._recorded[key]
        value = await fn()
        self._recorded[key] = value
        await self._store.save(self._run_id, self._recorded)
        return value

    @property
    def steps_done(self) -> int:
        return len(self._recorded)


class DictStore:
    """In-memory checkpoint store — single process / tests."""

    def __init__(self):
        self._runs: dict = {}

    async def load(self, run_id):
        return dict(self._runs.get(run_id, {}))

    async def save(self, run_id, recorded):
        self._runs[run_id] = dict(recorded)


class FileCheckpointStore:
    """A durable checkpoint store backed by a CBOR file (survives restart)."""

    def __init__(self, path):
        from .store import FileStore

        self._fs = FileStore(path)

    async def load(self, run_id):
        return dict(self._fs.data.get(run_id, {}))

    async def save(self, run_id, recorded):
        self._fs.data[run_id] = dict(recorded)
        self._fs.save()
