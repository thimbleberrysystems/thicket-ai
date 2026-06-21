# Thicket — Design Plan

> **Status:** Draft for review
> **Scope:** the *framework*, not the things that plug into it.

## TL;DR

Thicket is a **federated, language-agnostic substrate for machine-to-machine
collaboration** — a DNS-plus-dial-tone for a machine-only network. Heterogeneous
resources (LLMs, memories, CI/CD, tools, agents — *any* machine) publish
**self-certifying, signed records of what they can do**, discover each other by
**identity** or by **semantic need**, and then **talk peer-to-peer** over a
universal envelope. The framework standardizes *how to find and how to connect* —
never *what is said*. It is built to be **evolvable** (tiny permanent kernel,
everything else versioned and negotiated) and to survive an **adversarial, open**
network (Sybil resistance, authorization, key revocation are first-class, not
afterthoughts).

---

## 0. What we are building (and what we are not)

Thicket rests on **two pillars**:

1. **Directory (find each other).** Resources publish what they can do; any
   resource finds others by direct identity or semantic need.
2. **Interconnect (talk to each other).** Once found, any resource opens an
   authenticated channel to any other and invokes its advertised capabilities —
   regardless of who built either side or what language they speak.

The two are joined by the **Resource Record**, which hands a caller everything
needed to talk: `id` (who), `locator` (where), `io` schema (how), `public_key`
(secure the channel). Like the internet, **the registry is the phone book, not
the switchboard**: you look a resource up, then the conversation goes *directly*
peer-to-peer. Registries are never in the data path.

**Any machine is a first-class participant.** LLM, memory, CI/CD trigger, tool,
or **agent** — all register and talk through the *same* record shape and *same*
interconnect. `kind: agent` is one value in an open set, neither privileged nor
excluded.

**Explicitly NOT part of the framework** — Thicket defines the directory, the
identity model, the message envelope, the interaction patterns, and the security
primitives. It does **not** implement resources or interpret their payloads.
Out of scope here:

- LLMs / memories / CI-CD / tools / agents (independent *clients*).
- The *business-logic payload* of a conversation (carried, never interpreted).
- Orchestration / control loops / agent-spawning *logic* (may be built on top).

### Design principles

1. **Machine-only.** No human-readable names, no naming authority. Identity is
   self-certifying.
2. **Federated, like DNS.** No single central database or controller. Cooperating
   registries, referral, caching, eventual consistency.
3. **Self-certifying and signed.** Every record is signed; any registry — even an
   untrusted one — can serve a cached copy and the requester verifies it
   independently.
4. **Capability-first discovery.** No names, so *search by need* is the front
   door; resolve-by-id is the fast path once you hold an id.
5. **Heterogeneous but uniform.** Every kind registers and talks through the same
   record shape and interconnect, differing only in `kind` and descriptor.
6. **Directory off the data path.** Registries answer who/where/how; conversations
   go peer-to-peer.
7. **Secure by identity.** Identity *is* a public key, so any two resources
   mutually authenticate and encrypt a channel directly — no CA.
8. **Evolvable by explicit versioning (the governing constraint).** AI moves fast;
   anything frozen today is a liability tomorrow. So: a *tiny permanent kernel*,
   and everything else **versioned, self-describing, and negotiated**. We
   standardize *how to agree*, not *what to agree on*. **But flexibility comes
   from explicit negotiation, not lax parsing** — implementations parse
   **strictly** and **MUST reject** malformed or ambiguous messages; tolerance is
   confined to *designated* extension points (the `ext` map and version
   negotiation), never blanket "ignore anything unknown." (Postel's robustness
   principle is now considered a security/interop anti-pattern — it breeds
   ambiguity and dialect drift; we avoid it.)
9. **Language-agnostic by wire contract.** Thicket is a *protocol, not a library*.
   Everything is defined as **bytes on the wire + state machines** — never as
   types in one language. Nodes in Python/Go/Rust/TS interoperate because they
   share a wire spec, not code. SDKs are thin conveniences; **the conformance
   test suite is the spec.**

### Stable kernel vs. evolvable surface

Keep the **permanent kernel tiny**; everything outside it must be replaceable
without coordination.

| Stable kernel (change rarely, carefully) | Evolvable surface (expected to change often) |
|---|---|
| Identity = a key; records are signed; **root-key→working-key** chain (§7) | Which hash / signature scheme (advertised, swappable) |
| A minimal, strictly-parsed **negotiation handshake** | Transports, codecs, channel crypto, interaction patterns |
| A record maps **id → locators + capabilities** | Record fields, capability descriptor shape |
| Discovery yields a verifiable, self-describing record | Embedding model, search/ranking, federation routing, reputation |

If a kernel item needs frequent change, that's a signal it belongs in the surface.

### Defined at the wire, not the API

So any language can implement a conformant node, the spec is expressed as:

- **Message formats** in a language-neutral, self-describing serialization
  (CBOR / JSON / protobuf), with **one mandatory baseline codec** so two nodes
  always bootstrap.
- **State machines** for the handshake and each pattern.
- **A canonical signing input** — an exact, deterministic byte layout so a
  signature made in one language verifies in another.
- **Ubiquitous baseline algorithms** for the *mandatory* crypto/codec/transport
  (e.g. Ed25519 + SHA-256, CBOR/JSON, HTTP/2 or QUIC). Richer options negotiate
  on top, never required.
- **A conformance test suite** (wire-level vectors) as the real definition of
  "compatible."

---

## 1. Core concepts

| Concept | Definition |
|---|---|
| **Resource** | Any capability-bearing network endpoint. The unit of the network. |
| **Identity** | `id = hash(root_public_key)` — self-certifying, permanent. The "address." |
| **Working key** | A short-lived key the root authorizes for day-to-day signing (§7). |
| **Locator** | A current endpoint (`protocol + address`). Mutable. |
| **Resource Record** | The signed document a resource publishes (§2). |
| **Capability** | One thing a resource can do, described to be matchable across kinds (§3). |
| **Registry** | Stores authoritative records for its registrants; participates in federation. |
| **Resolver** | Client/edge component that caches and walks the federation to answer queries. |
| **Channel** | Direct, mutually authenticated, encrypted connection between two resources. |
| **Envelope** | The universal message wrapper (§6). |
| **Grant** | A signed, attenuable token authorizing a holder to invoke a capability (§8). |

### Identity / locator split

Identity (a key) is decoupled from location (an endpoint). A resource can move,
redeploy, or change transport without changing identity. The registry's core
mapping is **stable id → {current locators, capabilities}**.

---

## 2. The Resource Record

Uniform across all kinds. Only `id`, `public_key`, `signature` are hard-required;
everything else is conventional and may evolve. Unknown keys at the *designated*
`ext` point are preserved; malformed *known* fields are rejected (§8 principle).

```
ResourceRecord {
  schema:      record version + crypto scheme (multicodec-style, swappable)
  id:          hash(root_public_key)     // self-certifying identity = the address
  keys:        [{ working_pubkey, not_before, not_after, root_signature }]  // §7
  kind:        model | memory | tool | trigger | composite | agent | …  (OPEN set)
  locators:    [{ protocol, endpoint }]  // mutable; advertises transports
  capabilities:[ Capability ]            // §3
  envelope:    { cost, latency, throughput, limits, region, … }  // perf/economic profile
  supports:    { patterns, codecs, embedding_scheme, … }         // for negotiation
  visibility:  public | unlisted | private                       // §10
  authz:       { policy_hint }           // how to obtain a grant, if required (§8)
  trust:       { attestations, reputation }                      // §9
  lease:       { ttl, issued_at, expires_at, last_heartbeat }    // §12
  version:     monotonic counter         // cache freshness; highest wins on conflict
  ext:         { … }                     // designated extension point; unknown keys preserved
  signature:   sign(record, working_key) // verifiable via the root-signed key chain
}
```

Self-certifying + signed = **safe federated caching**: a poisoned cache entry
fails verification. (DNS needed DNSSEC bolted on; we get it by construction.)

---

## 3. The capability descriptor (the matchable unit)

Three layers, each feeding a different matching stage:

```
Capability {
  kind:        model                                       // → HARD FILTER
  description: "long-context reasoning over source code"    // → SEMANTIC (embedded)
  io:          { input: <schema>, output: <schema> }        // → STRUCTURAL compatibility
  tags:        [code, reasoning, refactor]                  // → FILTER
  modalities:  [text]
  envelope:    { context_window, cost_per_unit, p50_latency_ms, max_rps }  // → FILTER + RANK
}
```

- **Semantic** (NL → embedding): fuzzy "what I need" recall.
- **Structural** (typed I/O): can the requester actually call and wire it in?
- **Filter** (tags/envelope/trust): precision.

> **Lean loose (§15):** NL description always works; `io`/tags/envelope are
> *optional, advertised* refinements. Avoids UDDI's "speak my schema or be
> invisible" failure. Structure is opt-in, not a gateway.

---

## 4. Discovery — two query modes

### `Resolve(id)` — directed, exact
You hold an id (from a referral or prior search). Returns the signed record. Fast
path; usually cached. Flat-key — federated via referral/DHT (§5).

### `Search(need)` — undirected, semantic
The front door of the network.

```
need = { intent_text, kind?, io_requirements?, filters? }  →  ranked signed records
```

### Local search pipeline (one registry)
```
1. FILTER    candidates = catalog.where(kind, filters, trust ≥ t, lease alive, visible-to-caller)
2. RECALL    q = embed(intent_text); hits = ANN(candidates, q, top_N)
3. COMPAT    drop hits whose io can't satisfy need.io_requirements
4. RERANK    score = w1·cos(q,h) + w2·envelope_fit + w3·reputation + w4·freshness + w5·exploration   // §9 cold-start
5. RETURN    top_k signed records
```

Two local indexes: a **vector index** (recall) and an **attribute index**
(filtering).

---

## 5. Federation architecture (the DNS-analog)

DNS federates a hierarchical *namespace*; we can't (flat ids, semantic queries).
We borrow DNS's **mechanisms** — referral, caching, TTL, eventual consistency —
but partition per query mode.

- **Home registries (authoritative tier).** Each resource registers with a home
  registry holding the authoritative signed record + lease. Everyone else holds
  **cached, verifiable copies**.
- **`Resolve(id)` — flat key.** Registries form a Kademlia-style DHT keyed by
  registry id; a record is findable near the resource id (O(log N) hops). Usually
  direct, because search results carry `{id, home_registry, record}`. *Start with
  referral+replication; add the DHT when scale demands (§15).*
- **`Search(need)` — semantic referral.** (1) **Catalog profiles**: each registry
  gossips a compact summary (embedding centroids + tag/kind histogram). (2)
  **Collection selection → scatter-gather**: a query scores which peers are worth
  asking, fans out to the top-M, merges + re-ranks. (3) **TTL caching** of records
  and hot query buckets.

Signed records make scatter-gathered results from untrusted registries
independently verifiable.

---

## 6. Interconnect — talking to each other

The framework provides a *lingua franca* and interaction patterns — it does not
interpret what is said.

### The record is the bridge
A resolved record carries `id` (who), `public_key` (secure channel), `locators`
(where + transports), `capabilities[].io` (how to call), and `authz` (how to get
permission). Discovery *hands you the call instructions*.

### Channels — authenticated and encrypted by identity
Because identity is a public key, two resources establish a mutually
authenticated, encrypted channel directly (Noise / libp2p-secure-channel style),
each proving control of the working key in its root-signed chain (§7). No CA, no
pre-shared secret. **Registries are not on this path** (relay/NAT help is an
optional resource kind, not the default).

### The universal envelope (the lingua franca)
```
Envelope {
  v:            envelope version             // self-describing
  from:         sender id
  to:           recipient id
  capability:   which advertised capability
  correlation:  links request ↔ response(s) / a multi-turn exchange
  type:         REQUEST | RESPONSE | EVENT | ERROR | STREAM_CHUNK | CANCEL   // open set
  content_type: how to decode the body (e.g. io schema id)
  deadline:     hard time budget (for timeouts/cancellation)                // §13
  auth:         capability grant authorizing this invocation                // §8
  body:         opaque payload (domain-specific — never interpreted)
  ext:          { … }                        // designated extension point
  signature:    signed by `from`'s working key
}
```
Required: `from`, `to`, `signature`. Unknown values at `ext`/open enums are
*preserved*; malformed known fields are **rejected** (strict parse, §8). The
framework standardizes the *frame and patterns*, never the *payload* — like HTTP
carrying anything and adding headers without breaking old clients.

### Interaction patterns
1. **Request/response** — the only near-universal baseline.
2. **Streaming** — ordered `STREAM_CHUNK`s.
3. **Async/callback** — fire-and-forget + later response by correlation.
4. **Pub/sub events** — emit/subscribe `EVENT`s.

Patterns 2–4 are **advertised capabilities, not mandates**. A request/response-
only resource is a full citizen.

### Invocation
Pick a `locator` whose transport you speak → open secure channel → send a
`REQUEST` naming the `capability`, with a `body` conforming to `io.input` and an
`auth` grant if required. Reply conforms to `io.output`. The `io` schema from
discovery is the contract; the envelope is the carrier.

### Conversations & composition (a deliberate scope line)
`correlation` tracks multi-turn exchanges. The framework provides **delegation
primitives** — attenuable grants (§8), correlation, and reference-passing — that
*enable* composition (A→B→C, agents wiring agents). It deliberately does **not**
provide an orchestrator, pipeline engine, or shared conversational state; those
belong to resources (or a `kind: memory`/`kind: composite` resource).

---

## 7. Identity, keys & revocation

The hard problem self-certifying ids usually ignore: **what happens when a key
leaks?** If `id = hash(key)`, rotating the key changes the identity. We fix this
with a **two-level key chain**:

- **Root key** → `id = hash(root_public_key)`. Held in cold storage, used rarely.
  Identity is permanent.
- **Working keys** → the root signs short-lived working keys (`not_before/after`).
  All day-to-day signing (records, envelopes, channels) uses working keys.
- **Rotation** — the root signs a new working key; **identity is unchanged**.
- **Revocation** — a root-signed revocation statement for a compromised working
  key, published as an attestation and propagated/cached alongside the record;
  resolvers and peers check it before trusting a signature.
- **Residual risk** — root-key compromise is catastrophic (identity lost).
  Mitigate with cold storage and an **optional threshold/multi-sig root** for
  high-value resources, plus social-recovery successor designation. Tracked in
  §17.

---

## 8. Authorization & delegation

Authentication (who) ≠ authorization (allowed to?). In an open network, "anyone
who finds me may call me" is an abuse/DoS vector. So invocation carries an
**authorization grant**:

- **Grant** — a signed, **attenuable** token (macaroon-style) issued by (or on
  behalf of) the target resource, authorizing a holder to invoke specific
  capabilities, with **caveats**: scope, expiry, rate, budget, audience.
- **Attenuation** — a holder can mint a *weaker* sub-grant for a delegate; never
  stronger. Authority decreases monotonically down a delegation chain. **This is
  the safety primitive for agents spawning agents**: a parent hands a child a
  narrowed grant; the child cannot escalate.
- **Enforcement** — the callee verifies the grant chain and caveats and decides.
  The framework supplies the *token mechanism*; **policy is the resource's**
  (open, allowlist, grant-required — advertised via `record.authz`).
- **Default posture** — a resource chooses. Public utilities may need no grant;
  sensitive ones require one. Rate/budget caveats are the built-in DoS valve.

---

## 9. Trust, reputation & Sybil resistance

Identity is free to mint, so an open registry is a Sybil/spam magnet. Reputation
is the precision mechanism that keeps semantic search honest — and it must itself
be Sybil-resistant.

- **Cost to register.** A home registry MAY require proof-of-work, stake, or an
  attestation from an already-trusted resource before accepting a record. Raises
  the price of mass-minting identities. (Registry policy — negotiable, §15.)
- **Capabilities are self-asserted → discount unverified claims** via:
  - **Reputation** — track record (did it deliver?), folded into ranking.
  - **Attestations** — signed vouches forming a trust graph.
  - **Verification/probing** — a verifier issues a known challenge against a
    claimed capability; signed results become attestations.
- **Sybil-resistant aggregation.** Weight attestations by *attester* reputation
  (EigenTrust/PageRank-style), so a cluster of fake identities vouching for each
  other carries little weight.
- **Cold-start (the paradox).** New honest resources have no reputation, so
  ranking reserves an **exploration budget** (ε-greedy `w5` term in §4), supports
  **probation tiers**, and lets established resources **vouch** to bootstrap
  newcomers. Without this the network ossifies around incumbents.
- **Verification is adversarial** — a resource can behave on probes and cheat
  otherwise (the "defeat-device" problem). Probing reduces, never eliminates,
  this. Tracked in §17.

---

## 10. Privacy & visibility

A public capability catalog is a reconnaissance goldmine and a non-starter for
many (enterprise) deployments. Records therefore carry a `visibility`:

- **public** — discoverable in search, resolvable by id.
- **unlisted** — resolvable by id (if you were told it) but excluded from search.
- **private** — disclosed only to authorized queriers / within a private
  federation.
- **Private federations** — a closed set of registries that don't gossip outside;
  membership-gated. A first-class deployment mode, not an afterthought.
- **Query privacy** — registries learn *who searches for what*. Mitigations
  (oblivious lookup, client-side filtering, trusted resolvers) exist but are
  costly; treated as an open problem (§17), not solved in v1.

---

## 11. Threat model

| Threat | Mechanism that addresses it |
|---|---|
| Impersonation | self-certifying id + signatures + root→working key chain (§7) |
| Cache/record poisoning | every record signed; verify independently (§2) |
| Eavesdropping / MITM on a conversation | authenticated, encrypted channels (§6) |
| Sybil / mass-minted identities | cost-to-register + Sybil-resistant reputation (§9) |
| Index poisoning / capability lying | verification/probing + reputation discount (§9) |
| Unauthorized invocation / abuse | capability grants + caveats (§8) |
| Invocation-flood DoS | rate/budget caveats (§8); registry off data path |
| Stolen working key | revocation + short validity + rotation (§7) |
| Malicious/lying registry | signed records make lies verifiable; multi-registry cross-check (§5) |
| Censorship by a registry | federation + multiple home registries / re-registration (§5) |
| Replay | nonce + `deadline` + correlation in signed envelope (§6, §13) |
| Reconnaissance via public catalog | visibility tiers + private federations (§10) |

Out-of-scope-but-named residuals: root-key compromise, probe-gaming, query
privacy, incentive bootstrapping (§17).

---

## 12. Liveness & consistency

- **Leases + heartbeat** — `expires_at` must be renewed; registered ≠ alive.
- **Bounded staleness** — cached copies expire at TTL; eventually consistent,
  like DNS.
- **Authoritative source = home registry**; everyone else caches; signed records
  make invalidation safe.
- **Conflict resolution** — on disagreement, **highest `version` with a valid
  signature wins**, bounded by lease freshness.

---

## 13. Failure & error semantics

Distributed systems live or die here, so it is explicit, not happy-path:

- **Error envelopes** — `type: ERROR` with a coded reason (NOT_FOUND, UNAUTH,
  TIMEOUT, UNAVAILABLE, BAD_REQUEST, CONFLICT, …).
- **Deadlines** — every `REQUEST` carries a `deadline`; expiry → `CANCEL`/TIMEOUT.
- **Idempotency** — `Invoke` carries an idempotency key (the `correlation`); a
  retried call must not double-execute. Resources declare which capabilities are
  idempotent.
- **Streams** — partial failure surfaces as a terminal `ERROR` chunk; consumers
  must handle truncation.
- **Partitions / stale locators** — a resolve may return a dead locator; the
  caller retries other locators, then refreshes from the home registry.
- **Registry partition** — answer from cache within TTL; reconcile by `version`
  on heal.

---

## 14. Protocol verbs

**Directory plane** (resource/client ↔ registry — small payloads):

| Verb | Direction | Purpose |
|---|---|---|
| `Register(record)` | resource → home registry | publish authoritative signed record |
| `Renew`/`Heartbeat` | resource → home registry | extend lease, prove liveness |
| `Deregister(id)` | resource → home registry | withdraw |
| `Resolve(id)` | client → resolver | id → signed record |
| `Search(need)` | client → resolver | need → ranked signed records |
| `Advertise(profile)` | registry → registry | gossip catalog summaries |
| `Attest(id, claim)` | resource → registry | publish a trust/verification edge |
| `Revoke(key_or_id)` | resource → registry | publish a root-signed revocation (§7) |

**Interconnect plane** (resource ↔ resource, peer-to-peer):

| Verb | Direction | Purpose |
|---|---|---|
| `Connect(id)` | resource → resource | open authenticated, encrypted channel |
| `Invoke(capability, body, auth)` | resource → resource | call a capability (with grant) |
| `Stream` | resource → resource | ordered `STREAM_CHUNK`s |
| `Subscribe`/`Emit` | resource ↔ resource | pub/sub `EVENT`s |
| `Grant`/`Attenuate` | resource → resource | issue / narrow an authorization (§8) |
| `Cancel(correlation)` | resource → resource | abort an in-flight invocation |

Directory payloads stay small; bulk data flows peer-to-peer, never through a
registry.

---

## 15. Open parameters (choose a *default*, keep it swappable)

Not permanent commitments — each is versioned and negotiable.

1. **Embedding space(s).** Advertised `embedding_scheme`; multiple may coexist;
   compare within a shared space. Start with one good default; the registry
   embeds, not the resource.
2. **Descriptor shape.** Loose by default (NL always works; structure opt-in).
3. **Federation membership.** Permissionless-but-reputation-weighted to start;
   tighten later. Cost-to-register policy is per-registry.
4. **Resolve substrate.** Referral+replication first; Kademlia DHT later; same
   `Resolve(id)` interface either way.
5. **Reputation model.** Signals, aggregation, gaming-resistance — pure surface,
   expected to be rewritten.
6. **Envelope + channel baseline.** Smallest possible mandatory set: a strict
   handshake + request/response + one baseline codec/transport/signature scheme.
   Resist adding required fields.
7. **Crypto suite.** Ed25519 + SHA-256 as the boring, ubiquitous baseline;
   swappable via the `schema`/key-scheme tags.

---

## 16. Non-goals / out of scope

- Implementing any specific resource (LLM, memory, CI/CD, tool, agent).
- Interpreting message `body` / defining domain payload semantics.
- Orchestration, pipeline engines, agent-spawning *logic* (delegation primitives
  only, §6/§8).
- Conversational/business state (lives with participants or a `memory` resource).
- Human UI, naming, accounts.
- **Payment/settlement** — `cost` is advertised metadata; the economic layer is a
  named future pillar (§17), not built here.
- Mandating an implementation language or single reference library — the spec is
  wire + conformance tests.

---

## 17. Known hard problems / open risks

Named honestly; none fully solved in v1.

- **Sybil & spam at scale.** Cost-to-register + Sybil-resistant reputation raise
  the bar but don't end the arms race.
- **Capability verification / probe-gaming.** Can't fully prove a self-asserted
  capability; probing is partial and adversarial.
- **Root-key compromise.** Catastrophic; mitigated, not eliminated (threshold
  root, recovery).
- **Incentives / who runs registries.** No economic layer yet; the federation may
  not self-sustain or may centralize around subsidizers. Likely a future pillar
  (ties to conserved-budget delegation, §8).
- **Dialect fragmentation.** Flexibility + no central authority risks incompatible
  dialects; conformance suite + strict parsing are the defense, governance is TBD.
- **Query privacy.** Registries learn who wants what.
- **Semantic search quality.** Adversarial descriptions, embedding drift,
  cross-registry rank fusion, long-tail cost of unique queries.
- **Protocol governance.** Who evolves the kernel / defines conformance across an
  open federation (IETF-like process TBD).

---

## 18. Proposed build order

Implemented in Rust as a Cargo workspace (`crates/`), 47 passing tests. Status
below; ✅ = implemented with tests, ◑ = partial.

1. ✅ **Record + capability schema + signing + key chain** — `thicket-core`
   (`record`, `capability`, `identity`, `crypto`). Canonical signing
   (`domain ‖ 0x00 ‖ CBOR`); CBOR+JSON round-trip verified.
2. ✅ **Identity, signature verification & revocation** — `thicket-core`
   root→working key chain, rotation, revocation; tests cover tamper/expiry/revoke.
3. ✅ **Single registry** — `thicket-registry`: register / resolve / search
   (filter→recall→rerank) with a pluggable `Embedder` (`MockEmbedder` in tests),
   `visibility` + lease enforced.
4. ✅ **Interconnect v1** — `thicket-interconnect`: auth handshake, signed
   envelope, request/response, and attenuable **grants** (authz from day one,
   monotonic-narrowing enforced).
5. ✅ **Streaming + events + error/deadline semantics + networking** —
   `thicket-net`: length-delimited framing, mutually-authenticated async
   handshake (with timeout), and a request/response + streaming session with
   correlation, deadlines, and grant-gated invocation, over in-memory duplex and
   real TCP. (Encrypting transport adapter still pending — see below.)
6. ✅ **Trust v1** — `thicket-trust`: signed attestations, Sybil-resistant
   reputation, cold-start exploration ranking. (Probing/cost-to-register are
   modeled as outcome/weight inputs; enforcement policy is per-registry.)
7. ✅ **Federation v1** — `thicket-federation`: catalog profiles, collection
   selection, scatter-gather with per-record verification, global rerank, TTL
   resolve cache; closed peer membership = private federation.
8. ◑ **Resolve federation** — referral + replication implemented; Kademlia DHT
   still deferred (the `Resolve` interface is unchanged, so it swaps underneath).

**Not yet built (the network edge):** the encrypting transport adapter
(Noise/QUIC) beneath the authentication layer, the Kademlia DHT (referral +
replication is in place), and cross-language conformance vectors.

---

## Open questions for reviewer

- Is the **stable kernel** still small enough now that key-chain identity and
  grants are in it? Anything here that will churn and should move to the surface?
- **Identity model**: agree with **root-key → working-key** (permanent id +
  rotatable/revocable working keys), or prefer a different scheme (e.g. DID-style)?
- **Authorization**: is the **attenuable-grant** primitive the right minimal authz
  layer, or do you want authz fully out of framework scope (resource-defined only)?
- **Sybil/cost-to-register**: comfortable leaving the *mechanism* (PoW/stake/
  vouch) as per-registry policy, or should the framework prescribe a default?
- **Negotiation over Postel** (principle #8): agree we parse strictly and
  MUST-reject, with tolerance only at `ext`/version points?
- **Build order**: authz at step 4 (with first invoke) — right, or too early?
- **Baseline** crypto/codec/transport: Ed25519 + SHA-256 + CBOR/JSON + HTTP-2/QUIC
  acceptable as the mandatory floor?
