//! End-to-end kernel tests: identity binding, the key chain, signing,
//! tamper-detection, expiry, revocation, and cross-serialization stability.

use std::collections::BTreeMap;

use thicket_core::{
    Capability, Lease, Locator, RecordPayload, Result, RevocationSet, RootKey, SignedRecord,
    Visibility, WorkingKey,
};

const NOW: u64 = 1_000_000;

/// Build a fully valid signed record for a fresh identity, plus the keys so
/// tests can re-sign / revoke. The working key is endorsed around `now`.
fn fixture(now: u64) -> (RootKey, WorkingKey, SignedRecord) {
    let root = RootKey::generate();
    let working = WorkingKey::generate();
    let endorsement = root
        .endorse(&working.public(), now - 100, now + 10_000)
        .unwrap();

    let payload = RecordPayload {
        schema: "thicket/record/1".into(),
        id: root.id(),
        root_public_key: root.public(),
        keys: vec![endorsement],
        kind: "model".into(),
        locators: vec![Locator {
            protocol: "grpc".into(),
            endpoint: "10.0.0.1:7000".into(),
        }],
        capabilities: vec![
            Capability::new("model", "long-context reasoning over source code")
                .with_tags(["code", "reasoning"]),
        ],
        profile: BTreeMap::from([("cost_per_1k".into(), "0.5".into())]),
        supports: BTreeMap::new(),
        visibility: Visibility::Public,
        lease: Some(Lease {
            ttl: 3600,
            issued_at: now,
            expires_at: now + 3600,
        }),
        version: 1,
        ext: BTreeMap::new(),
    };

    let record = payload.sign(&working).unwrap();
    (root, working, record)
}

#[test]
fn valid_record_verifies() -> Result<()> {
    let (_root, _wk, record) = fixture(NOW);
    record.verify(NOW, &RevocationSet::new())
}

#[test]
fn id_is_bound_to_root_key() {
    let (_root, _wk, mut record) = fixture(NOW);
    // Point the id at a different key while leaving the signature intact.
    let other = RootKey::generate();
    record.payload.id = other.id();
    let err = record.verify(NOW, &RevocationSet::new()).unwrap_err();
    assert!(matches!(err, thicket_core::Error::IdMismatch));
}

#[test]
fn tampering_with_payload_is_detected() {
    let (_root, _wk, mut record) = fixture(NOW);
    record.payload.kind = "memory".into(); // mutate signed content
    let err = record.verify(NOW, &RevocationSet::new()).unwrap_err();
    assert!(matches!(err, thicket_core::Error::VerifyFailed));
}

#[test]
fn unendorsed_signer_is_rejected() {
    let (_root, _wk, mut record) = fixture(NOW);
    // Re-sign with a working key that the root never endorsed.
    let rogue = WorkingKey::generate();
    let resigned = record.payload.clone().sign(&rogue).unwrap();
    record.signer_pub = resigned.signer_pub;
    record.signature = resigned.signature;
    let err = record.verify(NOW, &RevocationSet::new()).unwrap_err();
    assert!(matches!(err, thicket_core::Error::NoValidEndorsement));
}

#[test]
fn expired_working_key_is_rejected() {
    let root = RootKey::generate();
    let working = WorkingKey::generate();
    let endorsement = root.endorse(&working.public(), NOW - 100, NOW - 1).unwrap();
    let payload = RecordPayload {
        schema: "thicket/record/1".into(),
        id: root.id(),
        root_public_key: root.public(),
        keys: vec![endorsement],
        kind: "tool".into(),
        locators: vec![],
        capabilities: vec![],
        profile: BTreeMap::new(),
        supports: BTreeMap::new(),
        visibility: Visibility::Public,
        lease: None,
        version: 1,
        ext: BTreeMap::new(),
    };
    let record = payload.sign(&working).unwrap();
    let err = record.verify(NOW, &RevocationSet::new()).unwrap_err();
    assert!(matches!(err, thicket_core::Error::EndorsementExpired));
}

#[test]
fn key_rotation_keeps_identity() {
    // The same identity rotates to a new working key; id is unchanged and the
    // record signed by the new key still verifies.
    let (root, _old, _record) = fixture(NOW);
    let new_wk = WorkingKey::generate();
    let endorsement = root.endorse(&new_wk.public(), NOW, NOW + 5000).unwrap();
    let payload = RecordPayload {
        schema: "thicket/record/1".into(),
        id: root.id(),
        root_public_key: root.public(),
        keys: vec![endorsement],
        kind: "model".into(),
        locators: vec![],
        capabilities: vec![],
        profile: BTreeMap::new(),
        supports: BTreeMap::new(),
        visibility: Visibility::Public,
        lease: None,
        version: 2,
        ext: BTreeMap::new(),
    };
    let rotated = payload.sign(&new_wk).unwrap();
    rotated.verify(NOW, &RevocationSet::new()).unwrap();
    assert_eq!(rotated.id(), &root.id());
}

#[test]
fn revoked_working_key_is_rejected() {
    let (root, working, record) = fixture(NOW);
    record.verify(NOW, &RevocationSet::new()).unwrap();

    let revocation = root.revoke(&working.public(), NOW).unwrap();
    // The revocation itself is verifiable under the root key.
    thicket_core::verify_revocation(&root.public(), &revocation).unwrap();

    let mut revoked = RevocationSet::new();
    revoked.revoke_key(revocation.working_pub());
    let err = record.verify(NOW, &revoked).unwrap_err();
    assert!(matches!(err, thicket_core::Error::Revoked));
}

#[test]
fn revocation_does_not_verify_under_wrong_root() {
    let (root, working, _record) = fixture(NOW);
    let revocation = root.revoke(&working.public(), NOW).unwrap();
    let stranger = RootKey::generate();
    assert!(thicket_core::verify_revocation(&stranger.public(), &revocation).is_err());
}

#[test]
fn cbor_roundtrip_preserves_verifiability() {
    let (_root, _wk, record) = fixture(NOW);
    let bytes = record.to_cbor().unwrap();
    let decoded = SignedRecord::from_cbor(&bytes).unwrap();
    decoded.verify(NOW, &RevocationSet::new()).unwrap();
}

#[test]
fn json_roundtrip_preserves_verifiability() {
    // Proves the signature is over the canonical payload bytes, not the
    // transport encoding: sign once, ship as JSON, still verifies.
    let (_root, _wk, record) = fixture(NOW);
    let json = record.to_json().unwrap();
    let decoded = SignedRecord::from_json(&json).unwrap();
    decoded.verify(NOW, &RevocationSet::new()).unwrap();
}

#[test]
fn ids_encode_as_cbor_byte_strings() {
    // Byte fields must serialize as CBOR byte strings (major type 2), not arrays
    // of integers — this is the cross-language canonical-encoding guarantee.
    let id = RootKey::generate().id();
    let mut buf = Vec::new();
    ciborium::into_writer(&id, &mut buf).unwrap();
    // 32-byte byte string => header 0x58 (major type 2, 1-byte length) + 0x20 (32)
    assert_eq!(
        buf[0], 0x58,
        "expected CBOR byte-string header (major type 2)"
    );
    assert_eq!(buf[1], 32);
    assert_eq!(buf.len(), 2 + 32);
}

#[test]
fn signature_encodes_as_cbor_byte_string() {
    // The 64-byte signature must appear in the record's CBOR as a byte string —
    // header 0x58 0x40 (major type 2, 1-byte length = 64) — not an int array.
    let (_root, _wk, record) = fixture(NOW);
    let cbor = record.to_cbor().unwrap();
    assert!(
        cbor.windows(2).any(|w| w == [0x58, 0x40]),
        "expected a 64-byte CBOR byte string (the signature) in the record",
    );
}

#[test]
fn id_from_hex_roundtrips_and_rejects_bad_input() {
    use thicket_core::Id;
    let id = RootKey::generate().id();
    assert_eq!(Id::from_hex(&id.hex()).unwrap(), id, "hex round-trips");
    assert!(Id::from_hex("nothex!!").is_err(), "non-hex rejected");
    assert!(Id::from_hex("abcd").is_err(), "wrong length rejected");
}
