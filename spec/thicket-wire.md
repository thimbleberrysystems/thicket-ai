# Thicket Wire Specification (v1)

The byte-level contract every implementation must follow. The Rust core is *one*
implementation of this spec; it is held to it by the golden vectors in
[`vectors/`](vectors/). Any other implementation (e.g. the Python SDK) is
conformant iff it reproduces those vectors byte-for-byte and interoperates.

> **`vectors/` is authoritative.** Where prose and the vectors disagree, the
> vectors win. Regenerate them with
> `THICKET_REGEN=1 cargo test -p thicket-interconnect vectors`.

---

## 1. Canonical encoding

All signed and transmitted objects are encoded as **CBOR** (RFC 8949) with these
**fixed rules** (this is the cross-language linchpin):

1. **Structs → CBOR maps** with **text-string keys = field names**, emitted in
   **field-declaration order** (the order given in §3). Not sorted.
2. **Byte fields → CBOR byte strings** (major type 2) — *never* arrays of
   integers. Applies to ids, public keys, signatures, nonces, correlation ids,
   and the envelope `body`.
3. **Integers → unsigned, shortest-form** (CBOR canonical integer encoding).
4. **No floating point in signed data.** Numeric advisory metadata (cost,
   latency) is carried as **text strings** (e.g. `"0.5"`).
5. **Enums (unit variants) → the variant name as a text string** — e.g.
   `Visibility::Public` → `"Public"`, `EnvelopeType::Request` → `"Request"`,
   `ErrorCode::Unauthorized` → `"Unauthorized"`.
6. **Optional / defaulted fields are omitted when absent** (no `null`, no empty
   placeholder) — `lease` when none, `Capability.io` when none, the envelope
   `capability/content_type/auth/stream_seq/error/context` when unset, and the
   `Context` sub-fields when empty.
7. **`String→String` / `String→Number` maps** use CBOR maps with keys **sorted**
   (the implementation uses ordered maps; emit keys in ascending byte order).

JSON encoding is available for readability/debugging only; it is **not** the
signed form and byte fields degrade to integer arrays there.

---

## 2. Signing

Every signature is an **Ed25519** signature over:

```
signing_input = domain_utf8  ‖  0x00  ‖  CBOR(payload)
```

where `payload` is the unsigned object (§3) encoded per §1, and `domain` is:

| Object | Domain tag |
|---|---|
| Resource record | `thicket-record-v1` |
| Working-key endorsement | `thicket-endorsement-v1` |
| Working-key revocation | `thicket-revocation-v1` |
| Envelope | `thicket-envelope-v1` |
| Grant link | `thicket-grant-v1` |
| Noise static binding | `thicket-noise-static-v1` |

The exact `signing_input` bytes for the sample record and envelope are committed
as `vectors/record.signin` and `vectors/envelope.signin`.

**Identity:** `id = SHA-256(root_public_key)` (32-byte byte string). The root key
endorses short-lived working keys; working keys sign records/envelopes/grants.
Verification: `id == sha256(root_public_key)` → signer is an endorsed,
unexpired, unrevoked working key → signature valid over the canonical bytes.

---

## 3. Objects (field order is the encoding order)

### KeyEndorsement
`working_pub` (bytes), `not_before` (uint), `not_after` (uint), `root_sig` (bytes).
Signed view (domain `thicket-endorsement-v1`): `{working_pub, not_before, not_after}`.

### RecordPayload
`schema` (text), `id` (bytes), `root_public_key` (bytes), `keys` (array of
KeyEndorsement), `kind` (text), `locators` (array of `{protocol, endpoint}`),
`capabilities` (array of Capability), `profile` (map text→text), `supports`
(map text→text), `visibility` (enum text), `lease?` (`{ttl, issued_at,
expires_at}`), `version` (uint), `ext` (map text→text).

### Capability
`kind` (text), `description` (text), `io?` (`{input, output}`), `tags` (array of
text), `modalities` (array of text), `envelope` (map text→text).

### SignedRecord
`payload` (RecordPayload), `signer_pub` (bytes), `signature` (bytes).

### Context
`trace_id?` (bytes), `span_id?` (bytes), `parent_span_id?` (bytes), `deadline?`
(uint), `budget?` (uint), `sink?` (SinkRef). A downstream call's Context
**tightens**: same `trace_id`, fresh `span_id`, `parent_span_id` = caller's span,
`deadline = min(parent, local)`, `budget = parent − spent`. `sink` propagates
unchanged unless the caller overrides it (a weave rerouting its subtree's spans)
or clears it (stop reporting below this point).

### SinkRef
`id` (Id bytes), `endpoint` (text). Where fibers in a trace **self-report** their
spans — chosen by the initiator (typically a weave), carried in the Context so
every hop reports to the same place. Absent ⇒ no reporting. The span *format* and
what the sink does with spans are the sink fiber's business, not the wire's.

### EnvelopePayload
`v` (uint), `from` (Id bytes), `to` (Id bytes), `typ` (enum text:
Request|Response|Event|Error|StreamChunk|Cancel), `capability?` (text),
`correlation` (bytes), `content_type?` (text), `context?` (Context), `auth?`
(Grant), `stream_seq?` (uint), `stream_end` (bool), `error?` (`{code, message}`),
`body` (bytes), `ext` (map text→text).

### SignedEnvelope
`payload` (EnvelopePayload), `signer_pub` (bytes), `signature` (bytes).

### Caveats / GrantLink / Grant
- **Caveats**: `capabilities` (sorted set of text; `"*"` = wildcard),
  `not_after` (uint), `constraints` (map text→text).
- **GrantLink**: `issuer_pub` (bytes), `audience_pub` (bytes), `caveats`
  (Caveats), `sig` (bytes). Signed view (domain `thicket-grant-v1`):
  `{target, issuer_pub, audience_pub, caveats, prev}` where `prev` is the
  previous link's `sig` (empty bytes for the head).
- **Grant**: `target` (Id bytes), `links` (array of GrantLink). Attenuation only
  narrows (subset of capabilities, `not_after ≤` parent, constraints preserved).

---

## 4. Framing

Each message on a channel is length-delimited: a **4-byte big-endian unsigned
length** followed by that many bytes. Max frame = 16 MiB. On an encrypted channel
(§5) the framed bytes are the Noise-wrapped record (a `u32` chunk count, then per
chunk a `u16` ciphertext length + ciphertext).

---

## 5. Secure channel

Channels run **Noise `XX_25519_ChaChaPoly_SHA256`** (the `snow` parameters
string `Noise_XX_25519_ChaChaPoly_SHA256`). Identity is bound the libp2p way:

- Each side generates a **per-connection X25519 static** for Noise.
- It signs that static's public key with its **Ed25519 working key**:
  `sign(working, "thicket-noise-static-v1" ‖ 0x00 ‖ CBOR(byte_string(static_pub)))`.
- It sends, inside the encrypted XX handshake, an `IdentityProof`:
  `{id, root_public_key, endorsements, working_pub, static_sig}`.
- The peer verifies the signature binds the negotiated remote static **and** runs
  the §2 key-chain verification. The dialing side is the Noise **initiator**, the
  accepting side the **responder**.

No Ed25519↔X25519 key conversion — the link is a signature.

---

## 6. Conformance

An implementation is conformant iff:

1. It reproduces every file in `vectors/` byte-for-byte (record/envelope/grant
   CBOR, and the `*.signin` signing inputs).
2. It verifies the Rust-produced vectors, and the Rust core verifies its output.
3. It interoperates over a real channel: registers with / resolves from / invokes
   through a Rust core node, and is invoked by one.
