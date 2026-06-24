<div align="center">

# 🌿 Thicket

### The open network layer for AI agents

**A protocol, not a framework.** Any agent, in any language, on any machine —
discovers, authenticates, and securely calls any other. No central hub. No shared SDK.

[![CI](https://github.com/thimbleberrysystems/thicket-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/thimbleberrysystems/thicket-ai/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-111%20passing-brightgreen)](#proof-not-promises)
[![Rust](https://img.shields.io/badge/core-Rust-orange)](crates/)
[![Python SDK](https://img.shields.io/badge/SDK-Python-blue)](sdk/py/)
[![License](https://img.shields.io/badge/license-MIT-black)](LICENSE)

</div>

---

## Agents shouldn't be islands

Every agent framework today — LangChain, CrewAI, AutoGen — makes you rebuild your
agents inside *their* abstractions, in *one* language, in *one* process, brokered
by *one* central app. The result is a million agents that can't find, trust, or
call each other.

The web had the same problem in 1991. It was solved not by a framework, but by
**protocols** — DNS to find, TLS to trust, HTTP to talk — that nobody owns and
anyone can implement.

**Thicket is that layer for AI agents.** A federated, language-agnostic,
end-to-end-encrypted substrate where heterogeneous participants publish
**self-certifying records of what they can do**, find each other by **identity or
semantic need**, and talk **peer-to-peer** — gated by attenuable capability
grants, observable by design, owned by no one.

> Like the internet, **the registry is the phone book, not the switchboard.** You
> look someone up, then the conversation goes directly, encrypted, peer-to-peer.

---

## The 30-second proof

Thicket's core is **Rust**. Its first SDK is **Python**. They share **zero code** —
the only contract between them is a wire spec and a set of byte-exact conformance
vectors. That's not a slogan; it's a test:

```text
$ python -m unittest tests.test_conformance
  ✓ the Python SDK reproduces the Rust core's signed bytes EXACTLY
    (record, envelope, grant — byte-for-byte, signature-for-signature)
```

So a fiber written in Python is indistinguishable on the wire from one written in
Rust. Here's one being **invoked across languages**, mutually authenticated over
Noise + Ed25519, with no gateway in between:

```bash
# A capability, written in Python, serving on the network…
$ python weather_fiber.py
listening as 9f2c… on 127.0.0.1:51820

# …invoked from a Rust process. Different language. Same wire. Direct + encrypted.
$ cargo run --example rust_caller -- 9f2c… 127.0.0.1:51820 weather "Lisbon"
OK
Lisbon: 22°C, clear
```

This is the whole thesis in one command: **a protocol, not a framework.**

---

## Write a fiber in ~15 lines

A **Fiber** is any participant on the Thicket: one identity, one job, one signed
record of what it can do. Here's a complete one.

```python
import asyncio
from thicket import LocalIdentity, RootKey, record
from thicket.fiber import run_fiber

async def handle(conn, req):
    city = req["body"].decode()
    await conn.respond(req, f"{city}: 22°C, clear".encode())

async def main():
    me = LocalIdentity.from_root(RootKey.generate())   # self-certifying: id = hash(pubkey)
    await run_fiber(
        me, DIR_HOST, DIR_PORT, DIR_ID,                # register with a directory
        kind="tool",
        capabilities=[record.capability("tool", "current weather", tags=["weather"])],
        handler=handle,                                # serve, peer-to-peer, encrypted
    )

asyncio.run(main())
```

Discovering and calling it from anywhere:

```python
dc = await DirectoryClient.connect(DIR_HOST, DIR_PORT, me, DIR_ID)
hit = (await dc.search("what's the weather?", kind="tool"))[0]["payload"]   # semantic discovery
host, port = hit["locators"][0]["endpoint"].split(":")

conn = await Conn.connect(host, int(port), me, expected_id=hit["id"])       # pins identity
print((await conn.call("weather", b"Lisbon"))["payload"]["body"].decode())
```

No framework to adopt. No base class to inherit. Just an identity and a wire.

---

## How is this different?

|                       | Agent frameworks<br/>(LangChain, CrewAI) | MCP | A2A | **Thicket** |
|-----------------------|:---:|:---:|:---:|:---:|
| **Primary unit**      | a Python app | a tool server | an agent endpoint | **any networked participant** |
| **Languages**         | one (Python) | SDK-bound | HTTP | **any — wire spec + vectors** |
| **Topology**          | in-process | client→server | mostly hub / enterprise | **decentralized, federated** |
| **Identity & trust**  | none | host trust | enterprise auth | **self-certifying keys** |
| **Authorization**     | — | — | coarse | **attenuable capability grants** |
| **Composition**       | hardcoded | per client | per agent | **weaves (compose & nest)** |
| **Observability**     | bolt-on | — | — | **self-reported, encryption-safe** |

Thicket isn't here to replace your framework or your MCP servers — **wrap them in a
fiber.** Frameworks are how you build *one* agent. Thicket is how a million agents,
built by different teams in different languages, find and trust each other.

---

## The vocabulary

- **Thicket** — the network: the federated substrate as a whole.
- **Fiber** — any participant. A self-certifying identity + a signed record + the
  capabilities it serves and calls. Single-responsibility by default
  (`kind: model | memory | tool | trigger | collector | router | …`).
- **Weave** — a Fiber whose job is to **bind other Fibers** into a goal
  (`kind: weave`). It **nests** — to a higher weave, a lower weave is just another
  fiber. *Fibers weave into a thicket.*

---

## The hard parts, done right

The distributed-systems problems that frameworks ignore are the ones Thicket
treats as first-class:

- **🔐 Self-certifying identity.** An id *is* the hash of a root public key
  (`id = sha256(root_pubkey)`, Ed25519). No CA, no registrar, no central trust —
  identity is math. Working keys rotate; revocation and endorsement are built in.
- **🎟️ Capability security.** Authorization is an **attenuable grant**: a holder
  can delegate only a *narrower* slice of authority (fewer capabilities, sooner
  expiry), never wider. A weave hands each fiber exactly the grant it needs and not
  one bit more — enforced cryptographically, end to end.
- **🔒 Encrypted by construction.** Every connection is a Noise `XX` handshake
  (`25519 / ChaChaPoly / SHA256`) with each peer's static key bound to its Ed25519
  identity. Mutual auth and end-to-end encryption are not optional.
- **🧬 One contract, many implementations.** The cross-language boundary is a
  canonical CBOR wire spec plus byte-exact conformance vectors — *not* a shared
  library. Any language that passes the vectors is a first-class citizen. (Proven:
  the Python SDK matches the Rust core byte-for-byte.)
- **🔭 Observability that respects encryption.** No proxy, no sniffing. Fibers
  **self-report** their own spans, and *which* sink a trace flows to is **woven** —
  carried in-band and chosen by the orchestrating weave. Coherent distributed
  traces, zero man-in-the-middle.
- **🕸️ No central hub.** Directory, collector, router — every hub-shaped thing is
  just an *optional* fiber. Directories **federate**: discovery scatter-gathers
  across independent directories and merges, so nothing is authoritative.

---

## Proof, not promises

This is early, research-grade software — and unusually well-tested for its age.
Everything below is covered by the CI gate, today:

- ✅ **111 tests green** — 66 Rust + 45 Python, on every commit.
- ✅ **Cross-language interop, both directions** — a Python client invokes a Rust
  fiber, and a Rust client invokes a Python fiber, over real TCP + Noise.
- ✅ **Byte-exact conformance** — the Python SDK reproduces the Rust core's signed
  records, envelopes, and grants bit-for-bit.
- ✅ **Decentralized discovery** — fibers registered in *different* directories are
  both reachable through one federated lookup. No central hub.
- ✅ **Real composition** — a weave discovers a tool + an LLM fiber, composes them,
  attenuates a grant to each, propagates a deadline, and assembles a distributed
  trace.
- ✅ **Real inference, no keys** — the example model fiber answers through a local
  model via Ollama; swapping in OpenAI / vLLM / anything is a one-line change the
  framework never sees.

---

## Quickstart

```bash
git clone https://github.com/thimbleberrysystems/thicket-ai
cd thicket-ai

# 1. Build the core + run the conformance suite (the contract)
cargo test --workspace

# 2. Start a directory — the phone book. It prints "<id_hex> <addr>".
cargo run -p thicket-directory --example directory_server

# 3. Run the Python SDK's interop + integration tests against it
cd sdk/py && pip install cryptography noiseprotocol
PYTHONPATH=. python -m unittest discover -s tests
```

Architecture, threat model, and the full protocol spec live in
[`plan.md`](plan.md); the build plan and phase-by-phase test gates live in
[`IMPLEMENTATION.md`](IMPLEMENTATION.md); the cross-language contract is
[`spec/thicket-wire.md`](spec/thicket-wire.md).

---

## Why now

Three things just became true at once: agents are suddenly *useful*, they're
multiplying faster than any one vendor can corral, and we're handing them real
authority over our systems and our money. That combination has exactly one safe
shape — **decentralized, identity-first, capability-scoped, language-agnostic** —
and no one has built the substrate for it. The framework wars are a race to own
the application layer. Thicket is the layer underneath: the one nobody owns, that
lets all of them interoperate.

The internet didn't scale because someone built the best website. It scaled
because of the protocols beneath every website. **Agents need theirs.**

---

## Status & roadmap

Working today: identity, signing, grants, the Noise interconnect, directory +
federation, the Python SDK, and example fibers/weaves (model, memory, tool,
collector, trigger, router) — all cross-language tested.

Next: a hosted playground, SDKs in more languages (the wire spec makes this
additive, not a rewrite), production directory federation, and a public catalog
of fibers.

**Contributing & design partners:** issues and PRs welcome. If you're building
agents that need to talk to agents you don't control, we want to hear from you —
open an issue or reach out.

## License

MIT — see [`LICENSE`](LICENSE). Built by [Thimbleberry Systems](https://github.com/thimbleberrysystems).
