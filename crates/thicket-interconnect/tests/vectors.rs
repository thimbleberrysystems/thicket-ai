//! Conformance vectors — the byte-exact cross-language ground truth (plan §1).
//!
//! Built deterministically from fixed seeds and written to `spec/vectors/`. The
//! Rust core must reproduce them byte-for-byte (golden test), and every other
//! implementation (the Python SDK) validates against the same files.
//!
//! Regenerate with: `THICKET_REGEN=1 cargo test -p thicket-interconnect vectors`

use std::collections::BTreeMap;

use thicket_core::{
    Capability, Lease, Locator, RecordPayload, RevocationSet, RootKey, SignedRecord, Visibility,
    WorkingKey,
};
use thicket_interconnect::{Caveats, EnvelopePayload, Grant};

const VEC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors");
const NOW: u64 = 1_000_000;

/// Deterministic identity from a single seed byte.
fn ident(seed: u8) -> (RootKey, WorkingKey) {
    (
        RootKey::from_seed(&[seed; 32]),
        WorkingKey::from_seed(&[seed.wrapping_add(100); 32]),
    )
}

fn record() -> (SignedRecord, WorkingKey) {
    let (root, working) = ident(1);
    let endorsement = root.endorse(&working.public(), 0, 2_000_000).unwrap();
    let payload = RecordPayload {
        schema: "thicket/record/1".into(),
        id: root.id(),
        root_public_key: root.public(),
        keys: vec![endorsement],
        kind: "model".into(),
        locators: vec![Locator {
            protocol: "tcp".into(),
            endpoint: "10.0.0.1:7000".into(),
        }],
        capabilities: vec![Capability::new("model", "text generation").with_tags(["chat"])],
        profile: BTreeMap::from([("cost_per_1k".into(), "0.5".into())]),
        supports: BTreeMap::new(),
        visibility: Visibility::Public,
        lease: Some(Lease {
            ttl: 3600,
            issued_at: NOW,
            expires_at: NOW + 3600,
        }),
        version: 1,
        ext: BTreeMap::new(),
    };
    (payload.sign(&working).unwrap(), working)
}

fn envelope() -> thicket_interconnect::SignedEnvelope {
    let (root, working) = ident(1);
    let (to_root, _) = ident(3);
    let mut payload = EnvelopePayload::request(root.id(), to_root.id(), "generate");
    payload.correlation = vec![0xAB; 16];
    payload.body = b"hello".to_vec();
    payload.sign(&working).unwrap()
}

fn grant() -> Grant {
    let (root, working) = ident(1);
    let (_, audience) = ident(4);
    Grant::issue(
        root.id(),
        &working,
        &audience.public(),
        Caveats::new(["generate"], 2_000_000),
    )
    .unwrap()
}

fn grant_constrained() -> Grant {
    let (root, working) = ident(1);
    let (_, audience) = ident(4);
    let mut cav = Caveats::new(["read"], 2_000_000);
    cav.constraints.insert("region".into(), "eu".into());
    Grant::issue(root.id(), &working, &audience.public(), cav).unwrap()
}

fn revocation() -> thicket_core::Revocation {
    let (root, _) = ident(1);
    let (_, revoked) = ident(5);
    root.revoke(&revoked.public(), 1_500_000).unwrap()
}

fn checkpoint() -> thicket_core::Checkpoint {
    let mut cp = thicket_core::Checkpoint::new(b"run-7".to_vec());
    cp.record("#0", b"first".to_vec());
    cp.record("#1", b"second".to_vec());
    cp
}

/// The full named vector set as raw bytes.
fn build_vectors() -> Vec<(&'static str, Vec<u8>)> {
    let (rec, _) = record();
    let env = envelope();
    let grant = grant();
    vec![
        ("record.cbor", rec.to_cbor().unwrap()),
        ("record.json", rec.to_json().unwrap().into_bytes()),
        ("record.signin", rec.payload.signing_input().unwrap()),
        ("envelope.cbor", to_cbor(&env)),
        ("envelope.signin", env.payload.signing_input().unwrap()),
        ("grant.cbor", to_cbor(&grant)),
        ("grant_constrained.cbor", to_cbor(&grant_constrained())),
        ("revocation.cbor", to_cbor(&revocation())),
        ("checkpoint.cbor", checkpoint().to_cbor().unwrap()),
    ]
}

fn to_cbor<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let mut b = Vec::new();
    ciborium::into_writer(v, &mut b).unwrap();
    b
}

#[test]
fn vectors_are_byte_stable() {
    let regen = std::env::var("THICKET_REGEN").is_ok();
    for (name, bytes) in build_vectors() {
        let path = format!("{VEC_DIR}/{name}");
        if regen {
            std::fs::create_dir_all(VEC_DIR).unwrap();
            std::fs::write(&path, &bytes).unwrap();
        } else {
            let committed = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("missing vector {name}: {e} (run THICKET_REGEN=1)"));
            assert_eq!(
                committed, bytes,
                "vector {name} drifted from committed bytes"
            );
        }
    }
}

#[test]
fn record_vector_verifies() {
    let (rec, _) = record();
    rec.verify(NOW, &RevocationSet::new()).unwrap();
    // and the same bytes decoded from the committed CBOR
    let decoded = SignedRecord::from_cbor(&rec.to_cbor().unwrap()).unwrap();
    decoded.verify(NOW, &RevocationSet::new()).unwrap();
}

#[test]
fn negative_vector_fails_verification() {
    let (mut rec, _) = record();
    // Flip a bit in the signature — a valid-CBOR but unverifiable record.
    rec.signature[0] ^= 0xFF;
    assert!(rec.verify(NOW, &RevocationSet::new()).is_err());
}
