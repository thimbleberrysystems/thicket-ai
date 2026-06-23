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

Only dependency: `cryptography` (Ed25519/SHA-256). CBOR is hand-rolled for
byte-exact control.

## Test

```bash
cd sdk/py
PYTHONPATH=. python3 -m unittest discover -s tests
```

The conformance suite builds records/envelopes/grants from the same fixed seeds
as the Rust vectors and asserts the bytes match exactly, and that Rust-produced
records verify in Python.

## Not yet implemented

The networking layer — Noise `XX` handshake, async connection, directory client,
and live interop with a Rust core node over TCP — is the next milestone.
