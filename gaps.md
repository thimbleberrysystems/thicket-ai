# Gaps — the road to "better than LangGraph"

> Working backlog. **Ordered by impact** (highest first). We visit them one by
> one and re-sequence by ROI as we go. Each gap has a `Status:` we update.

## The thesis (why these gaps, in this order)

We do **not** win by out-featuring LangGraph on orchestration — we'd lose on
maturity for years. We win on what LangGraph *structurally cannot do* because it
is in-process, single-language, single-trust-domain: secure delegation,
cross-language/cross-org composition, distributed durable execution, and a
discoverable network of capabilities. We close the DX gap just enough that a
developer never *needs* to leave, and we **embrace** LangGraph (wrap its agents
as fibers) rather than fight it.

One-line positioning: **LangGraph builds an agent; Thicket lets that agent
safely use — and be used by — every other agent on Earth.**

What's already real and tested (the foundation these build on): self-certifying
identity, attenuable capability grants, Noise-encrypted interconnect, directory +
federation, self-reported tracing with woven sinks, the ergonomic `Fiber` /
`Context` / `Client` SDK. Everything below is additive.

Effort key: **S** ≈ days · **M** ≈ 1–2 weeks · **L** ≈ a month+.

---

## 1. Capability-scoped agent delegation + the safety demo  ⭐ do first
**Status:** ✅ Done + hardened. `ctx.delegate(audience_pub, capabilities,
constraints=...)` mints a strictly-narrower grant; the grant-gated `tool_fs`
fiber is the resource; `apps/py/demo/delegation_demo.py` shows owner → agent →
read-only sub-agent with the write cryptographically DENIED.

Review found and fixed real security gaps (all tested):
- **Revocation parity** — Python `grant.verify` ignored revocation entirely while
  Rust checked it. Both now reject a grant if **any** key in the chain (issuer or
  audience) is revoked, so a resource can kill its own key *or* a delegated
  sub-grant. (`revocations=` threads through `Fiber.run`.)
- **Cross-language verification** (not just encoding): forward —
  `grant_gated_server` (Rust) verifies a **Python-minted** grant
  (`test_grant_interop`); reverse — Python verifies the **Rust-minted** grant
  vector (`test_conformance`).
- **Constraint enforcement** — caveat constraints (e.g. `{"path": ...}`) are now
  enforceable: `grant.satisfies(grant, attributes)` + `ctx.grant`; `tool_fs`
  enforces path scoping; a path-constrained delegation test proves it.
- **Stronger test** — reads back to prove a denied write left state untouched.

A second re-audit found (and closed) the remaining cross-language asymmetries:
- **Signed revocation primitive in Python** — added `RootKey.revoke` +
  `verify_revocation` (matching the Rust `thicket-revocation-v1` view), a
  `revocation.cbor` conformance vector (Python reproduces byte-exact + verifies),
  and an end-to-end test: a root-signed revocation → deny-list → the grant dies.
- **Constraint satisfaction conformance** — added Rust `Grant::satisfies` (parity
  with Python), a `grant_constrained.cbor` vector both languages run `satisfies`
  on, and spec'd the exact-match semantics.
- **`ctx.grant` is now verified-only** — set only after the grant passes
  verification, so `satisfies` can't be fooled by a forged grant (closing the
  require_grant-pairing footgun).
- spec/thicket-wire.md documents the Revocation object + constraint semantics.

*Remaining (later, logged below): richer constraint matching (prefix/glob), and
the spawn-an-ephemeral-sub-agent-fiber flow (model b). Pairs with gap 2
(LangGraph adapter).*

**Impact (highest).** This is the differentiating, *fundable* thesis and the
industry's scariest unsolved problem: letting agents act and delegate without
giving them unbounded authority. No framework has a security model for delegation
because they're all in-process. We already have the cryptographic primitive
(attenuable grants), tested.

**State today.** Grants are implemented + tested in core/SDK; `ctx.call`
auto-attenuates a held grant to the called capability. But there's no ergonomic
"spawn a sub-agent with strictly narrower authority" API and no end-to-end demo.

**What's needed.**
- A `ctx.delegate(...)` / weave-level helper that issues a *narrowed* grant to a
  sub-agent (fewer capabilities, sooner expiry, tighter caveats) and hands it
  off.
- The killer demo: an agent given **read-only** access that is *cryptographically
  incapable* of writing — enforced by the protocol, not a prompt. Show the
  over-reach attempt returning `Unauthorized`.
- Docs/narrative: "the safe way to let agents act and delegate."

**Depends on:** nothing (grants done). Pair with #2 for the headline demo.

---

## 2. LangGraph / MCP adapters — embrace adoption
**Status:** Not started

**Impact (very high, low effort).** Don't compete for their users — *consume*
them. Every existing LangGraph agent / MCP tool server becomes a Thicket fiber in
one line, instantly composable + securely reachable. Rides their adoption.

**State today.** None.

**What's needed.**
- `Fiber.from_langgraph(graph)` — wrap a compiled LangGraph graph as a fiber.
- `Fiber.from_mcp(server)` — expose an MCP tool server as a fiber (and/or a fiber
  that *speaks* MCP to clients).
- Demo: "drop your existing LangGraph agent on Thicket; now it can safely
  delegate to agents you don't control."

**Depends on:** nothing.

---

## 3. Durable execution (network-native checkpointing)
**Status:** Not started

**Impact (high).** LangGraph's headline feature is durable, resumable agents.
Matching it removes the #1 reason to stay. The network-native version is a
*differentiator*: state lives on a state fiber, not in one process — so agents
are resumable *and* portable across machines, with no database the developer runs.

**State today.** The `memory` fiber exists; weaves are stateless per call; no
checkpoint/resume pattern.

**What's needed.**
- A checkpoint helper: a weave persists per-step state to a state/memory fiber
  after each step; resume by replaying from the last checkpoint.
- Possibly a `@durable` decorator that makes a weave automatically checkpointed.

**Depends on:** memory fiber (done); benefits from #6 (loops).

---

## 4. Python SDK: express the network's native concurrency  *(reframed)*
**Status:** Not started — and smaller than first labelled.

**Reframe (important).** Distributed parallelism is **native**, not a missing
feature: fibers are independent network participants, the wire carries concurrent
in-flight calls, and the Rust `Conn` already multiplexes them (test:
`many_concurrent_calls_are_multiplexed`). Fan-out to *different* fibers (with warm
discovery) already runs truly in parallel today. This entry is just a **Python-SDK
plumbing fix** so the client can fully express the concurrency the network already
provides.

**Impact (medium — corrected down from "high").**

**State today.** The Python `Conn` reads "the next frame" without correlation
demux, and `Context`/`Client` share one directory connection + one channel per
fiber. So the *only* thing that races is **one shared channel** under concurrency:
(a) cold discovery over the shared directory connection, (b) two concurrent calls
to the *same* fiber over its one cached channel.

**What's needed (client-side only).**
- Port the Rust correlation-demux into the Python `Conn` (a reader task +
  `pending`/`streams` maps keyed by correlation), so one channel multiplexes.
- Lock the `Client` lazy init (directory conn + discovery/channel caches).
- Ship a `gather_all([...])` convenience.

**Depends on:** nothing. (Subsumes the "Python `Conn` is sequential" tech-debt
item.)

---

## 5. The capability marketplace / discoverable secure network
**Status:** Not started

**Impact (highest long-term — the moat).** A library can't have a network effect;
a network can. A public, hosted directory where anyone publishes a fiber and
anyone discovers + calls it — with reputation and payment — is npm/Docker Hub for
agent capabilities, and the real defensibility.

**State today.** Directory + federation + trust (reputation/Sybil) crates exist
and are tested; everything is in-memory; no hosted network, public catalog, or
payment/reputation surfacing.

**What's needed.**
- A hosted directory (persistent storage — see tech debt) + a public fiber
  catalog/browser.
- Reputation surfaced from the trust crate; a payment/metering hook.
- Onboarding: publish a fiber in one command.

**Depends on:** federation (done), trust (done), persistence (tech debt), hosting.

---

## 6. Agent loops / cycles in weaves
**Status:** Not started

**Impact (medium-high).** True agentic behavior (reason → act → observe → repeat).
Table stakes vs LangGraph's cyclic graphs.

**State today.** Weaves are linear recipes.

**What's needed.** Ergonomic loop helpers (bounded reason-act loops, tool-calling
loops) + examples. It's just async control flow — the value is the ergonomics.

**Depends on:** nothing; pairs with #3 (durable) and #9 (observability) to debug.

---

## 7. Human-in-the-loop as a fiber
**Status:** Not started

**Impact (medium-high).** LangGraph HITL parity, but network-native: the approver
can be anyone, anywhere. "A human is just an approval fiber."

**State today.** The `trigger` fiber (pub/sub) exists.

**What's needed.** An approval/await pattern: a weave pauses awaiting an approval
fiber's response; resume on approve/deny.

**Depends on:** trigger (done), durable execution (#3) for long pauses.

---

## 8. End-to-end streaming out of a weave
**Status:** Not started

**Impact (medium).** UX parity — stream partial results to the consumer as
sub-fibers produce them.

**State today.** Fiber streaming works; a weave currently *aggregates*
(`ctx.gather` collects all chunks before returning).

**What's needed.** Stream-through: forward sub-fiber chunks to the weave's
consumer as they arrive.

**Depends on:** benefits from #4 (parallelism).

---

## 9. OTLP export from the collector (observability)
**Status:** Not started

**Impact (medium).** Matches LangSmith table stakes — Thicket traces in
Jaeger/Grafana/etc. Design already mapped: a sink fiber, no core change.

**State today.** Native `collector` + `profiler` exist; format is Thicket-native.

**What's needed.** An exporter fiber that ingests `collector.report` and re-emits
spans as OTLP (HTTP/protobuf to start). Span format stays the fiber's business.

**Depends on:** collector (done).

---

## 10. Cross-language / cross-org showcase weave
**Status:** Not started

**Impact (medium — proof).** A recorded demo of the impossible-in-LangGraph
claim: a Python agent → a Rust tool → an external/hosted model, all discovered,
encrypted, and capability-gated.

**State today.** Python↔Rust interop is tested both directions; no headline
multi-language/org weave demo.

**What's needed.** Build + record the demo; turn it into the README's hero asset.

**Depends on:** existing interop; richer once #1 (delegation) lands.

---

## Known technical debt

1. ✅ **Python `Conn` concurrency** — reader-task correlation-demux + `Client`
   double-checked cache-lock + `gather_all`. Concurrent fan-out is now safe and at
   parity with Rust (test: 12 calls multiplexed over one channel).
2. ✅ **`Client` auto-recovery** — `_channel` is liveness-aware: a dead cached
   channel is replaced *before* sending (safe, no double-execution); tested.
3. ✅ **`trigger` → ergonomic API** — now a normal `Fiber` (async-generator
   subscribe + emit); the SDK's `_stream` was reworked to deliver each chunk
   immediately, send a terminal marker on exhaustion, and cancel on disconnect.
4. ✅ **Negative-path coverage** — all Noise handshake-proof rejection branches
   are unit-tested (id/endorsement/signature/static-binding/expiry). *(Remaining:
   the Rust `directory/server` + `federation/peer` ~70% is mostly Debug/glue, not
   logic — left as-is.)*
5. ✅ **Persistence** — `thicket.FileStore` (CBOR-backed, atomic save); the memory
   fiber persists with `run(persist="<path>")` and survives restart (tested). The
   Rust directory/registry persistence is a separate, larger task → **#5 gap**.
6. ✅ **Metering / quota** — a capability declares `@handles(..., cost=N)`; the SDK
   rejects calls whose context budget is below the cost with `QuotaExceeded`.
   (Payment rails for the marketplace remain a #5-gap feature.)

*(Plus, from gap 1: richer constraint matching — prefix/glob; and the
spawn-ephemeral-sub-agent-fiber flow.)*
