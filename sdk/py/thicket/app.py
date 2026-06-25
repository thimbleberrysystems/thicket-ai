"""Ergonomic authoring layer — write a fiber or weave in a few lines.

Everything hard lives here: capability dispatch, request/response (de)coding,
deadline + budget enforcement, grant gating, span emission, discovery, the
connection, grant attenuation, and turning any exception into a clean error
envelope. A fiber author writes only the logic:

    from thicket import Fiber

    calc = Fiber(kind="tool")

    @calc.handles("calc.add", "integer addition")
    async def add(req):
        return {"result": req["a"] + req["b"]}

A handler takes the decoded request (and, optionally, a ``Context``) and returns
a value — auto-encoded. **Yield** instead of return to stream. A weave reaches
other fibers through ``ctx.call(...)`` / ``ctx.gather(...)``, which discover,
connect, propagate context, attenuate grants, and decode for you:

    weave = Fiber(kind="weave")

    @weave.handles("describe_sum", "describe the sum of two numbers")
    async def describe_sum(req, ctx):
        total = await ctx.call("tool", "calc.add", {"a": req["a"], "b": req["b"]})
        text = await ctx.gather("model", "generate", f"The sum is {total['result']}")
        return {"sum": total["result"], "description": text}
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect

from . import cbor, grant, record, tracing
from .conn import Conn
from .directory import DirectoryClient
from .fiber import run_fiber, run_main
from .identity import LocalIdentity, unix_now


def _encode(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return cbor.encode(value)


def _decode(body):
    if not body:
        return None
    try:
        return cbor.decode(body)
    except Exception:
        return body


class ThicketError(RuntimeError):
    """Raise from a handler (or it surfaces from ``ctx.call`` / ``Client.call``) to
    return a coded error envelope. Subclasses ``RuntimeError`` so a broad
    ``except RuntimeError`` still catches it, while ``except ThicketError`` and the
    ``.code`` / ``.message`` fields give callers the detail."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Client:
    """Consumer-side handle: discover and invoke fibers in one line, from an app
    or another fiber. Reuses one directory connection and one Noise channel per
    fiber (and caches discovery), so repeated calls don't re-handshake. ``close()``
    when done, or use ``async with Client(...) as c:``.

        async with Client(host, port, dir_id) as c:
            out = await c.call("tool", "calc.add", {"a": 2, "b": 3})
    """

    def __init__(self, dir_host, dir_port, dir_id, *, local=None):
        self._local = local or LocalIdentity.generate()
        self._dir_cfg = (dir_host, dir_port, dir_id)
        self._dc = None  # cached DirectoryClient
        self._conns: dict[bytes, Conn] = {}  # fiber id -> reused channel
        self._disc: dict[tuple, tuple] = {}  # (kind, capability) -> (id, host, port)

    async def _directory(self):
        if self._dc is None:
            self._dc = await DirectoryClient.connect(self._dir_cfg[0], self._dir_cfg[1], self._local, self._dir_cfg[2])
        return self._dc

    async def search(self, kind, intent, *, top_k=10) -> list:
        """Discover fibers by kind + semantic intent — the raw signed records."""
        return await (await self._directory()).search(intent, kind=kind, top_k=top_k)

    async def _discover(self, kind, capability):
        key = (kind, capability)
        if key not in self._disc:
            hits = await self.search(kind, capability, top_k=5)
            if not hits:
                raise ThicketError("Unavailable", f"no {kind!r} fiber serves {capability!r}")
            rec = hits[0]["payload"]
            host, port = rec["locators"][0]["endpoint"].split(":")
            self._disc[key] = (rec["id"], host, int(port))
        return self._disc[key]

    async def _channel(self, fiber_id, host, port):
        conn = self._conns.get(fiber_id)
        if conn is None:
            conn = await Conn.connect(host, port, self._local, expected_id=fiber_id)
            self._conns[fiber_id] = conn
        return conn

    def _evict(self, kind, capability, fiber_id):
        self._disc.pop((kind, capability), None)
        self._conns.pop(fiber_id, None)

    async def call(self, kind, capability, args=None, *, context=None, auth=None, timeout=10.0):
        """Discover a ``kind`` fiber serving ``capability``, invoke it, return the
        decoded result. Raises ``ThicketError`` on a remote error."""
        fiber_id, host, port = await self._discover(kind, capability)
        try:
            conn = await self._channel(fiber_id, host, port)
            resp = await conn.call(capability, _encode(args), auth=auth, context=context, timeout=timeout)
        except (ConnectionError, OSError):
            self._evict(kind, capability, fiber_id)  # stale channel — next call reconnects
            raise
        p = resp["payload"]
        if p.get("typ") == "Error":
            err = p.get("error") or {}
            raise ThicketError(err.get("code", "Error"), err.get("message", "remote error"))
        return _decode(p.get("body"))

    async def gather(self, kind, capability, args=None, *, context=None, auth=None, timeout=30.0):
        """Like ``call`` but for a streamed capability — collects the chunks,
        joining text into one string."""
        fiber_id, host, port = await self._discover(kind, capability)
        conn = await self._channel(fiber_id, host, port)
        chunks = []
        try:
            async for c in conn.call_stream(capability, _encode(args), auth=auth, context=context, timeout=timeout):
                body = c.get("body", b"")
                if body:
                    chunks.append(_decode(body))
        except (ConnectionError, OSError):
            self._evict(kind, capability, fiber_id)
            raise
        if chunks and all(isinstance(c, str) for c in chunks):
            return "".join(chunks)
        return chunks

    async def close(self):
        for conn in self._conns.values():
            with contextlib.suppress(Exception):
                await conn.close()
        self._conns.clear()
        self._disc.clear()
        if self._dc is not None:
            with contextlib.suppress(Exception):
                await self._dc.close()
            self._dc = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()


class Context:
    """A handler's optional second argument: the live trace/deadline/budget, the
    per-call ``config`` passed to ``run``, and one-line access to other fibers
    (``call`` / ``gather`` / ``search``) with the trace context propagated and any
    held grant attenuated automatically."""

    def __init__(self, local, directory, self_ctx, *, tool_grant=None, grant=None, config=None):
        self._local = local
        self._client = Client(directory[0], directory[1], directory[2], local=local)
        self._ctx = self_ctx  # this fiber's span context — the parent of sub-calls
        self._tool_grant = tool_grant
        # NB: `config or {}` would replace a shared (but empty) dict with a fresh
        # one each call, breaking stateful fibers — identity-check None instead.
        self.config = {} if config is None else config
        self.grant = grant  # the grant the caller presented (for constraint checks)
        self.trace_id = self_ctx.get("trace_id")
        self.deadline = self_ctx.get("deadline")
        self.budget = self_ctx.get("budget")

    async def search(self, kind, intent, *, top_k=10) -> list:
        return await self._client.search(kind, intent, top_k=top_k)

    def _auth_for(self, capability):
        if self._tool_grant is None:
            return None
        last = self._tool_grant["links"][-1]["caveats"]
        caps = last["capabilities"]
        if "*" not in caps and capability not in caps:
            return None  # the held grant doesn't cover this call — send no auth
        return grant.attenuate(
            self._tool_grant, self._local.working, self._local.working.public(),
            grant.caveats([capability], last["not_after"], last.get("constraints")),
        )

    def delegate(self, audience_pub, capabilities, *, not_after=None, constraints=None):
        """Mint a **strictly narrower** grant for another fiber (a sub-agent) to
        act on this fiber's behalf — fewer capabilities, never a later expiry, and
        optionally tighter ``constraints`` (e.g. ``{"path": "notes"}``) that the
        resource enforces. The sub-agent is then cryptographically incapable of
        exceeding it; the resource verifies the chain back to its own key on every
        call.

        Raises ``ThicketError`` if this fiber holds no grant, or if ``capabilities``
        isn't a subset of what it holds — you cannot delegate authority you lack.
        """
        if self._tool_grant is None:
            raise ThicketError("Unauthorized", "this fiber holds no grant to delegate")
        last = self._tool_grant["links"][-1]["caveats"]
        expiry = last["not_after"] if not_after is None else min(not_after, last["not_after"])
        merged = dict(last.get("constraints") or {})  # keep parent constraints…
        if constraints:
            merged.update(constraints)  # …and tighten with new ones
        try:
            return grant.attenuate(
                self._tool_grant, self._local.working, audience_pub,
                grant.caveats(capabilities, expiry, merged),
            )
        except ValueError as e:
            raise ThicketError("Unauthorized", f"cannot delegate authority you don't hold ({e})")

    async def call(self, kind, capability, args=None, *, spent=1):
        """Discover and invoke a ``kind`` fiber, with this call parented to the
        fiber's span and any held grant attenuated to ``capability``."""
        return await self._client.call(
            kind, capability, args,
            context=tracing.child_context(self._ctx, spent=spent), auth=self._auth_for(capability),
        )

    async def gather(self, kind, capability, args=None, *, spent=1):
        """Streamed counterpart of ``call`` — collects the chunks."""
        return await self._client.gather(
            kind, capability, args,
            context=tracing.child_context(self._ctx, spent=spent), auth=self._auth_for(capability),
        )

    async def aclose(self):
        await self._client.close()


class _Cap:
    __slots__ = ("fn", "description", "tags", "require_grant", "takes_ctx", "is_stream")

    def __init__(self, fn, description, tags, require_grant):
        self.fn = fn
        self.description = description
        self.tags = tags
        self.require_grant = require_grant
        self.takes_ctx = len(inspect.signature(fn).parameters) >= 2
        self.is_stream = inspect.isasyncgenfunction(fn)


class Fiber:
    """A fiber (or weave). Declare capabilities with ``@f.handles(...)``, then
    ``await f.run(...)`` to serve, or ``f.main()`` for a standalone process."""

    def __init__(self, *, kind: str) -> None:
        self.kind = kind
        self._caps: dict[str, _Cap] = {}

    def handles(self, capability, description="", *, tags=None, require_grant=False):
        def deco(fn):
            self._caps[capability] = _Cap(fn, description, list(tags or []), require_grant)
            return fn

        return deco

    def _capabilities(self):
        return [
            record.capability(self.kind, c.description or cap, tags=c.tags)
            for cap, c in self._caps.items()
        ]

    def _handler(self, local, directory, emitter, *, sink, tool_grant, require_grant, revocations, config):
        async def handler(conn, payload):
            cap = payload.get("capability")
            entry = self._caps.get(cap)
            if entry is None:
                await conn.respond_error(payload, "NotFound", f"unknown capability {cap!r}")
                return
            env = payload.get("context") or {}
            if tracing.deadline_exceeded(env):
                await conn.respond_error(payload, "DeadlineExceeded", "deadline passed")
                return
            if tracing.budget_exhausted(env):
                await conn.respond_error(payload, "BudgetExhausted", "no budget remaining")
                return
            if entry.require_grant or require_grant:
                auth = payload.get("auth")
                ok = auth is not None and grant.verify(
                    auth, local.root_public_key, local.endorsements,
                    conn.peer["working_pub"], cap, unix_now(), revocations=revocations,
                )
                if not ok:
                    await conn.respond_error(payload, "Unauthorized", "valid grant required")
                    return
            # This fiber's own span IS the one the caller allocated for it (the
            # context's span_id) — don't mint a new one, or sub-spans orphan. A
            # configured sink overrides where this subtree reports.
            self_ctx = dict(env)
            if sink is not None:
                self_ctx["sink"] = sink
            ctx = Context(local, directory, self_ctx, tool_grant=tool_grant, grant=payload.get("auth"), config=config)
            call_args = (_decode(payload.get("body")), ctx) if entry.takes_ctx else (_decode(payload.get("body")),)
            span = emitter.span(self_ctx, name=f"{self.kind}:{cap}", kind=self.kind) if emitter else contextlib.nullcontext()
            try:
                async with span:
                    if entry.is_stream:
                        await self._stream(conn, payload, entry.fn(*call_args))
                    else:
                        await conn.respond(payload, _encode(await entry.fn(*call_args)))
            except ThicketError as e:
                await conn.respond_error(payload, e.code, e.message)
            except Exception as e:  # never crash the connection — return a clean error
                await conn.respond_error(payload, "Error", str(e))
            finally:
                await ctx.aclose()  # release any channels the handler opened downstream

        return handler

    @staticmethod
    async def _stream(conn, payload, agen):
        seq, prev, have = 0, None, False
        async for chunk in agen:
            if have:
                await conn.stream_chunk(payload, seq, False, _encode(prev))
                seq += 1
            prev, have = chunk, True
        if have:
            await conn.stream_chunk(payload, seq, True, _encode(prev))
        else:
            await conn.respond(payload, b"")

    async def run(self, local, dir_host, dir_port, dir_id, *, host="127.0.0.1",
                  sink=None, tool_grant=None, require_grant=False, revocations=None, ready=None, **config):
        """Serve every declared capability, register with the directory, and run
        until cancelled. ``revocations`` is this resource's set of revoked working
        keys (grants involving any of them are rejected). ``**config`` is passed
        through to handlers as ``ctx.config`` (e.g. an LLM fiber's model backend)."""
        directory = (dir_host, dir_port, dir_id)
        emitter = tracing.SpanEmitter(local)
        try:
            await run_fiber(
                local, dir_host, dir_port, dir_id,
                kind=self.kind,
                capabilities=self._capabilities(),
                handler=self._handler(
                    local, directory, emitter,
                    sink=sink, tool_grant=tool_grant, require_grant=require_grant,
                    revocations=revocations, config=config,
                ),
                host=host, ready=ready,
            )
        finally:
            await emitter.close()

    def main(self):
        """CLI entry: ``python <fiber>.py <dir_host> <dir_port> <dir_id_hex>``."""
        run_main(self.run)
