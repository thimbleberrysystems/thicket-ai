# Thicket

**A federated, language-agnostic substrate for machine-to-machine collaboration.**

Thicket is a DNS-plus-dial-tone for a machine-only network. Heterogeneous
resources — LLMs, memories, CI/CD triggers, tools, agents, *any* machine —
publish **self-certifying, signed records of what they can do**, discover each
other by **identity** or by **semantic need**, and then **talk peer-to-peer**
over a universal, authenticated channel.

The framework standardizes *how to find and how to connect* — never *what is
said*. It is built to be **evolvable** (a tiny permanent kernel; everything else
versioned and negotiated) and to survive an **adversarial, open** network
(Sybil resistance, capability-scoped authorization, and key revocation are
first-class, not afterthoughts).

> Design rationale, threat model, and the full protocol specification live in
> [`plan.md`](plan.md). This README is the implementation guide.

---

## Two pillars

1. **Directory — find each other.** Resources publish capability records; anyone
   resolves them by id or searches them by natural-language need.
2. **Interconnect — talk to each other.** Once found, any resource opens a
   mutually-authenticated channel to any other and invokes its advertised
   capabilities, gated by capability grants.

The **Resource Record** joins the two: it hands a caller everything needed to
talk — `id` (who), `locator` (where), `io` schema (how), and `public_key`
(to secure the channel). Like the internet, **the registry is the phone book,
not the switchboard**: you look a resource up, then the conversation goes
directly peer-to-peer.

`kind: agent` is just one value in an open set — agents are neither privileged
nor excluded. An "agent" is an emergent composition of discovered resources, not
a special node type.

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
                 │                 DIRECTORY                     │
   register ───▶ │  thicket-registry  ──gossip──  federation     │
   resolve  ───▶ │   (filter→recall→rerank)     (selection +     │
   search   ───▶ │                               scatter-gather) │
                 └───────────────────┬──────────────────────────┘
                       signed records │ (id, locators, capabilities)
                 ┌───────────────────▼──────────────────────────┐
                 │                INTERCONNECT                    │
   connect  ───▶ │  thicket-net (framing, handshake, sessions)   │
   invoke   ───▶ │  thicket-interconnect (envelope, grants)      │
                 └───────────────────┬──────────────────────────┘
                                     │ verifies against
                 ┌───────────────────▼──────────────────────────┐
                 │         KERNEL — thicket-core                  │
                 │  self-certifying identity (root→working keys, │
                 │  rotation, revocation), signed records,        │
                 │  capability descriptors, canonical signing     │
                 └────────────────────────────────────────────────┘
                          thicket-trust — reputation & Sybil resistance
```

### Crates

| Crate | Plan | Responsibility |
|---|---|---|
| [`thicket-core`](crates/thicket-core) | §2, §3, §7 | Self-certifying identity (`id = sha256(root_key)`), the root→working key chain with rotation & revocation, signed `ResourceRecord`s, capability descriptors, and the canonical signing rule. The permanent kernel. |
| [`thicket-registry`](crates/thicket-registry) | §4, §10, §12 | A single registry: `register` / `resolve` / semantic `search` (filter → recall → rerank) over a pluggable `Embedder`, with `visibility` and lease enforcement. |
| [`thicket-interconnect`](crates/thicket-interconnect) | §6, §8 | The universal signed `Envelope`, attenuable capability `Grant`s (authorization), and the authentication handshake primitives. |
| [`thicket-trust`](crates/thicket-trust) | §9 | Signed attestations, Sybil-resistant reputation aggregation, and cold-start-aware ranking. |
| [`thicket-federation`](crates/thicket-federation) | §5 | Federated discovery: catalog profiles, collection selection, scatter-gather with per-record verification, global rerank, and a TTL resolve cache. Closed membership doubles as a private federation. |
| [`thicket-net`](crates/thicket-net) | §6 | The networking spine: an **encrypted** channel (Noise `XX_25519_ChaChaPoly_SHA256`, identity-bound via Ed25519), framing, request/response + streaming sessions, pub/sub events, per-message key freshness, and a reusable `Server` accept/dispatch abstraction — over any `AsyncRead + AsyncWrite` (in-memory or TCP). |
| [`thicket-directory`](crates/thicket-directory) | §14 | The directory plane over the wire: a registry served as a Thicket resource (`register` / `resolve` / `search` / `renew` / `deregister`) with a typed client. Mutations are gated by the channel identity. |

Dependency direction: everything depends on `thicket-core`; `net` builds on
`interconnect`; `federation` builds on `registry`. Nothing depends on a specific
resource implementation — those are clients.

---

## Core concepts

- **Identity is a key.** `id = sha256(root_public_key)` — permanent and
  machine-native, no naming authority. The cold-stored **root key** endorses
  short-lived **working keys** that do day-to-day signing, so keys can rotate and
  be revoked without the identity ever changing.
- **Records are signed and self-verifying.** Any registry — even an untrusted
  one — can serve a cached copy; a poisoned copy fails signature verification.
- **Discovery is capability-first.** With no human-readable names, *search by
  need* (semantic) is the front door; *resolve by id* is the fast path.
- **Authorization is an attenuable grant.** A grant authorizes a holder to invoke
  specific capabilities, with caveats; a holder can delegate a strictly
  **narrower** sub-grant but never a wider one. This monotonic-narrowing
  invariant is the safety primitive for agents spawning agents.
- **Evolvable by explicit versioning.** A tiny permanent kernel; everything else
  is versioned, self-describing, and negotiated — flexibility via explicit
  negotiation, not lax parsing.

---

## Build & test

Requires a recent stable Rust toolchain.

```bash
cargo build --workspace          # build everything
cargo test  --workspace          # run all tests
cargo test -p thicket-core       # test a single crate
```

The framework has **no external service dependencies** for its tests: a
deterministic `MockEmbedder` stands in for a real embedding model, and the
network layer is exercised over both an in-memory duplex and a real loopback TCP
socket.

---

## A guided tour of the flow

A request like *"find something that can summarize code and call it"* maps onto
the crates as:

1. **Search** — `registry.search(Need)` (or `federation.search`) embeds the
   intent, filters by kind/tags/visibility/lease, and returns ranked signed
   records.
2. **Resolve** — pick a candidate; you now hold its `id`, `locators`,
   capability `io`, and `public_key`.
3. **Connect** — `Conn::connect(stream, local_identity, Some(expected_id))`
   performs the mutually-authenticated handshake over TCP (or any transport),
   verifying the peer is exactly who discovery said.
4. **Authorize** — obtain/attenuate a `Grant` and attach it to the request
   envelope.
5. **Invoke** — `conn.call(request, deadline)` sends a signed `Envelope` and
   awaits the correlated response; the server verifies the grant before acting.

Streaming (`conn.call_stream`), events, errors, deadlines, and cancellation are
all carried by the same `Envelope` frame.

---

## Status

Implemented as a Rust workspace with a comprehensive test suite (58 tests). The
**behavioral protocol surface and the encrypted transport are complete**:
identity/records, registry, interconnect (envelope + grants), trust, federation,
the networking spine (Noise-encrypted channels, request/response, streaming,
events, the `Server` abstraction), and the **networked directory** all work
end-to-end over real TCP — confidential, integrity-protected, forward-secret,
and mutually authenticated.

**Swappable substrate still to build (below the protocol surface):** a Kademlia
DHT for resolve (referral + replication is in place) and cross-language
conformance vectors. See [`plan.md`](plan.md) §18. These sit beneath the
protocol surface a client sees, so they can be added without a client reshaping
the core.

Clients (LLM / memory / CI-CD / agent resources) are intentionally **out of
scope** for the framework — they register and talk *over* Thicket. Example
clients will follow once the core network layer is locked down.

---

## License

Apache-2.0. See [`LICENSE`](LICENSE).
