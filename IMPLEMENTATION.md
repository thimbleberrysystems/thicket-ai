# Thicket — Implementation Plan (Spec, SDK, Fibers, Weaves)

> Companion to [`plan.md`](plan.md) (the protocol design). This document is the
> **build plan for everything above the Rust core**: the wire spec, the
> language SDKs, and the fibers/weaves built on them — with the tests that gate
> each phase.

---

## 1. Vocabulary (locked)

| Term | Meaning |
|---|---|
| **Thicket** | the network — the federated substrate as a whole |
| **Fiber** | *any* participant on the Thicket: it has a self-certifying identity, a signed record, and serves and/or calls capabilities. Single-responsibility by default. |
| **Weave** | a Fiber whose job is to **bind other Fibers** into a goal. `kind: weave`. It **nests** — to a higher weave, a lower weave is just another fiber. *Weaves weave weaves.* |
| **Capability** | one thing a fiber can do (described in its record). |
| **kind** | what a fiber does: `model`, `memory`, `tool`, `trigger`, `embed`, `collector`, `router`, `weave`, … |

Everything that lives on the Thicket is a **Fiber**. "Resource" and "client" (as
participant words) are retired. `Conn`/`DirectoryClient`/`Server` remain — they
are the *connection machinery a fiber uses*, not participants.

---

## 2. Principles (locked)

1. **Decentralized, no central hub.** Hub-shaped things (directory, collector,
   router) are optional fibers, never mandatory core.
2. **Core shares no code with fibers.** The only cross-implementation contract is
   the **wire spec + conformance vectors**. An SDK is an independent
   re-implementation, never a dependency on the Rust core.
3. **Observability is self-reported.** A small context block (trace / deadline /
   budget) rides in the envelope; fibers emit their own spans to an opt-in
   collector. No proxy, no sniffing — preserves end-to-end encryption.
4. **One responsibility per fiber; weaves compose.**
5. **Mock before real**, and **same capability schema** for mock and real so they
   are drop-in interchangeable.

---

## 3. Directory layout (locked)

```
crates/        # core (Rust): directory, registry, net, interconnect, trust, federation
spec/          # the ONLY cross-impl contract
  thicket-wire.md      # canonical formats, handshake, signing rules
  vectors/             # conformance vectors (byte-exact ground truth)
sdk/
  py/                  # the Python SDK (independent wire-protocol impl)
fibers/
  py/                  # leaf fibers — single responsibility
    llm/                 # one fiber, pluggable backends: fake / ollama / claude
    memory/  tool_http/  collector/  trigger/  router/
weaves/
  py/                  # weaves — compositions (each is also a fiber on the wire)
    inbox_summarizer/
apps/
  py/                  # pure consumers / human-facing
    cli/  profiler/
```

The three buckets map to the three roles: **`fibers/`** serves one capability ·
**`weaves/`** serves by composing others · **`apps/`** consumes only.

---

## 4. Testing strategy (applies to every phase)

- **Conformance vectors are ground truth.** `spec/vectors/` is generated from the
  Rust core and is the byte-exact reference. *Every* implementation — including
  the Rust core itself — must pass them.
- **Cross-impl interop is the headline test.** A Python fiber registering with and
  invoking through the Rust core over real TCP+Noise is the proof of
  language-agnosticism. CI runs it.
- **No paid API keys in tests.** The LLM fiber has a **pluggable backend**
  (`FakeBackend` / `OllamaBackend` / `ClaudeBackend`). Two tiers:
  - *fast/deterministic* — `FakeBackend`, the bulk of tests, exact assertions;
  - *integration/smoke* — `OllamaBackend` (real local inference, **no key**),
    a few tests asserting **structure, not content** (non-empty completion, ≥1
    streamed token, schema-conformant, errors handled).
  A session-scoped fixture ensures Ollama + a tiny model (e.g. `qwen2.5:0.5b`),
  starts the server, and **skips gracefully** if Ollama is absent. CI installs
  Ollama in a **dedicated integration job** and caches `~/.ollama/models`; the
  fast `fmt · clippy · unit` gate stays separate.
- **Subprocess integration harness.** Integration tests boot a Rust core
  directory + Python fibers as subprocesses and drive them end to end.
- **CI gate** (extends the existing `fmt · clippy · test`): add `pytest`, the
  conformance suite, and the Rust↔Python interop test.

Definition of done for a phase = its deliverables exist **and** its listed tests
pass in CI.

---

## 5. Phases

### Phase 0 — Core touch-ups (Rust)
The only changes to the existing core.

**Deliverables**
- Add the **context block** to the envelope: `trace_id`, `span_id`,
  `parent_span_id`, `deadline` (exists), `budget`; define propagation +
  attenuation rules (child gets a tightened deadline / debited budget).
- **Rename** `resource`/`client` → `fiber` and `kind: agent` → `kind: weave`
  across `plan.md`, `README.md`, and core doc comments.

**Tests**
- All existing 58 tests still pass (rename is non-functional).
- New: envelope round-trips carrying a context block; context survives
  sign/verify; deadline/budget propagation helper unit-tested (child ≤ parent).

---

### Phase 1 — Wire spec + conformance vectors
The contract every implementation builds against.

**Deliverables**
- `spec/thicket-wire.md`: canonical CBOR rules pinned byte-for-byte; record,
  envelope, grant, framing, the context block, and the Noise
  `XX_25519_ChaChaPoly_SHA256` handshake + Ed25519 static-key binding.
- `spec/vectors/`: emitted from the Rust core — sample signed fiber records
  (CBOR + JSON), the **exact canonical signing-input bytes**, a grant chain, an
  envelope set, and a handshake transcript / test inputs.
- A Rust binary/test that **emits** the vectors; a Rust test that **verifies the
  core passes** them.

**Tests**
- Rust golden test: regenerated vectors are byte-stable.
- Rust: round-trip + verify every vector.
- Negative vectors (tampered record/grant/envelope) must fail verification.

---

### Phase 2 — Python SDK (`sdk/py/thicket`)
Independent re-implementation of the wire protocol; tracing built in.

**Deliverables (modules)**
- `identity` (Ed25519 keys, `id = sha256(pub)`, endorsements/rotation)
- `cbor` (canonical encoding matching the spec) · `signing` (canonical input +
  sign/verify)
- `record` (build/sign/verify) · `grant` (issue/attenuate/verify)
- `envelope` (build/sign/verify + context block) · `framing`
- `secure` (Noise XX + identity binding) · `conn` (async: connect/accept, call,
  call_stream, emit, subscribe)
- `directory` (register/resolve/search/renew/deregister) · `server`
  (accept + dispatch)
- `tracing` (context propagation + span emission + collector push) — automatic
  around `call`/handlers.

**Tests**
- **Conformance:** Python verifies every Rust-generated vector; Python *produces*
  a signed record whose bytes/signature match the vector exactly.
- **Cross-impl interop:** Python SDK registers with, resolves from, and searches
  the **Rust core directory** over real TCP+Noise; a Python fiber is invoked by a
  Rust caller and vice-versa.
- Unit tests per module (id derivation, grant attenuation monotonicity, envelope
  tamper detection, framing).
- Async tests: Python↔Python and Python↔Rust request/response + streaming.

---

### Phase 3 — Wave 1: CLI app + LLM fiber (`FakeBackend`)
First end-to-end across languages and processes.

**Deliverables**
- `fibers/py/llm/` — `kind: model`; registers, serves `generate` (streamed
  tokens), renews its lease. Pluggable backend; Wave 1 ships the deterministic
  **`FakeBackend`** (the "mock" — same capability schema the real backends use).
- `apps/py/cli/` — consumer: search → resolve → connect → call/stream.

**Tests**
- Integration (subprocess): Rust directory + Python LLM fiber (FakeBackend) + CLI
  → discover, invoke, stream; assert streamed tokens (deterministic).
- Grant-gated invocation: call without a grant → `Unauthorized`; with a valid
  grant → response.
- LLM fiber unit tests over `FakeBackend` (deterministic output + schema).

---

### Phase 4 — Wave 2: real LLM backends + Memory fiber
Real inference + state.

**Deliverables**
- `fibers/py/llm/` — add **`OllamaBackend`** (default for dev/test, real local
  inference, **no key**) and **`ClaudeBackend`** (optional production). Same fiber
  and capability schema as Wave 1 — only the backend differs.
- `fibers/py/memory/` — `kind: memory`; `append` / `materialize` / `retrieve`
  keyed by a session reference (pass-by-reference context).

**Tests**
- LLM integration (Ollama, **no key**): a tiny model answers through the fiber;
  assert **structure not content** — non-empty completion, ≥1 streamed token,
  schema-conformant, errors handled. Fixture bootstraps Ollama + model, skips if
  absent.
- `ClaudeBackend`: client mocked — assert request shaping + response mapping; no
  live API call.
- Memory fiber: append→retrieve→materialize correctness; pass-by-reference
  (caller passes a session ref, not history).
- Integration: a consumer drives a stateful multi-turn exchange using memory +
  LLM wired by hand (precursor to a weave).

---

### Phase 5 — Wave 3: Tool fiber + first Weave
The headline composition demo.

**Deliverables**
- `fibers/py/tool_http/` (or `tool_calc/`) — `kind: tool`, grant-gated.
- `weaves/py/inbox_summarizer/` — `kind: weave`; discovers an LLM + memory +
  tool, runs the loop, **attenuates grants** to each fiber, **propagates context**
  (trace/deadline/budget).

**Tests**
- Weave integration: accomplishes a goal using ≥2 fibers; assert correct
  composition + final result.
- **Grant attenuation:** weave hands a fiber a narrowed grant; the fiber cannot
  exceed it (assert `Unauthorized` on over-reach).
- **Tracing:** the collector receives self-reported spans that assemble into the
  weave-shaped tree (parent = weave, children = fibers).
- **Deadline/budget:** an overall deadline/budget is enforced across the tree;
  exceeding it cancels/errors.

---

### Phase 6 — Wave 4: Collector + profiler, Trigger, Router
Observability and breadth.

**Deliverables**
- `fibers/py/collector/` — `kind: collector`; receives spans, assembles trace
  trees (and/or OTLP export).
- `apps/py/profiler/` — renders the trace tree + per-fiber latency + token/$ cost.
- `fibers/py/trigger/` — `kind: trigger`; emits `build.started/finished` events
  (pub/sub).
- `fibers/py/router/` — `kind: model`/`weave`; selects among model fibers by
  envelope (cost/latency/context) + reputation.

**Tests**
- Collector assembles a multi-fiber trace from independently-reported spans.
- Profiler computes per-fiber latency and cost from spans.
- Trigger: subscriber receives emitted events in order.
- Router: selects the expected fiber for a given need/constraints.

---

## 6. Sequencing

```
Phase 0  core touch-ups (context block + rename)
   │
Phase 1  spec + conformance vectors  ──┐
   │                                   │ (vectors are the contract)
Phase 2  Python SDK  ◀─────────────────┘   (validated against vectors + interop)
   │
Phase 3  Wave 1  CLI + Mock LLM
Phase 4  Wave 2  Claude LLM + Memory
Phase 5  Wave 3  Tool + first Weave
Phase 6  Wave 4  Collector + profiler, Trigger, Router
```

Phases 0–2 are the critical path; nothing real runs cross-language until the SDK
passes the vectors and the interop test.

---

## 7. Deliberately *not* framework decisions

These are per-fiber / per-weave implementation freedoms, **not** things the
framework or this plan must settle up front. Listed so we don't mistake them for
blockers.

- **Weave internals are free.** How a weave orchestrates — hardcoded loop,
  declarative recipe, LLM-driven via tool-calls, or a mix — is each weave's own
  choice and may differ per weave. The framework requires only that a weave honor
  the cross-cutting contract: **attenuate grants** to the fibers it calls and
  **propagate the context block**. The SDK provides those primitives; the rest is
  the weave's business. We pick a style *per example weave* when we build it; it
  constrains nothing else.
- **LLM capability schema** is a *convention among model fibers* (so mock and real
  are drop-in), chosen when we build the first model fiber (Phase 3) and
  refinable. Not a framework mandate.

## 8. Choices made at their phase (not blockers now)

- **Collector flavor** — OTLP export vs. Thicket-native (Phase 6).
- **Wave 1 scope** — minimal (CLI + Mock LLM) vs. pull Memory in (Phase 3).
- **Python crypto/CBOR/Noise libraries** — chosen in Phase 2 (must match the
  vectors exactly).

Phases 0–2 (core touch-ups → spec+vectors → SDK) are unblocked and can start now.
