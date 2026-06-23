# Thicket Python SDK

An **independent** implementation of the Thicket wire protocol — it shares no
code with the Rust core. Conformance is proven against the byte-exact vectors in
[`spec/vectors/`](../../spec/vectors).

Implemented so far:

- `thicket.cbor` — a minimal canonical CBOR codec matching the spec (byte
  strings, field-order maps, shortest-form ints).
- `thicket.crypto` — Ed25519 identity (`id = sha256(pub)`), endorsements, the
  canonical signing-input rule.
- `thicket.record` — build / sign / verify fiber records.
- `thicket.envelope` — build / sign / verify envelopes.
- `thicket.grant` — issue / attenuate (narrowing-enforced) / verify grants.
- `thicket.secure` / `conn` / `framing` — Noise `XX` channel with Ed25519
  identity binding, async connection, and length framing.
- `thicket.directory` — `DirectoryClient` (register / resolve / search / …).

Dependencies: `cryptography` (Ed25519/SHA-256) and `noiseprotocol` (Noise, as
Rust uses `snow`). CBOR is hand-rolled for byte-exact control.

## Test

```bash
cd sdk/py
PYTHONPATH=. python3 -m unittest discover -s tests
```

The suite (a) builds records/envelopes/grants from the same fixed seeds as the
Rust vectors and asserts the bytes match exactly; and (b) **interoperates live**
with the Rust core over TCP+Noise — a Python client invokes a Rust echo server,
and a Python fiber registers with / resolves from / searches a Rust directory.

Add the dep and build the Rust example servers for the interop tests:

```bash
pip install noiseprotocol
cargo build --workspace --examples
```
