//! Tests for grants (issue/attenuate/verify + the narrowing invariant), the
//! envelope (sign/verify/deadline/patterns), and the auth handshake.

use thicket_core::{Id, KeyEndorsement, RevocationSet, RootKey, WorkingKey};
use thicket_interconnect::{
    envelope::EnvelopePayload, prove, verify_proof, Caveats, Challenge, EnvelopeType, Error,
    ErrorCode, Grant,
};

const NOW: u64 = 1_000_000;

/// A complete identity with a root-endorsed working key.
struct Identity {
    root: RootKey,
    working: WorkingKey,
    endorsements: Vec<KeyEndorsement>,
    id: Id,
}

fn identity() -> Identity {
    let root = RootKey::generate();
    let working = WorkingKey::generate();
    let endorsements = vec![root
        .endorse(&working.public(), NOW - 100, NOW + 100_000)
        .unwrap()];
    let id = root.id();
    Identity {
        root,
        working,
        endorsements,
        id,
    }
}

// ---------- grants ----------

#[test]
fn grant_authorizes_only_listed_capabilities() {
    let target = identity();
    let alice = identity();
    let grant = Grant::issue(
        target.id.clone(),
        &target.working,
        &alice.working.public(),
        Caveats::new(["summarize", "translate"], NOW + 1000),
    )
    .unwrap();

    let revs = RevocationSet::new();
    // Permitted capability for the right caller.
    grant
        .verify(
            &target.root.public(),
            &target.endorsements,
            &alice.working.public(),
            "summarize",
            NOW,
            &revs,
        )
        .unwrap();
    // Capability outside the grant.
    assert!(matches!(
        grant
            .verify(
                &target.root.public(),
                &target.endorsements,
                &alice.working.public(),
                "delete",
                NOW,
                &revs,
            )
            .unwrap_err(),
        Error::CapabilityNotAllowed
    ));
}

#[test]
fn attenuation_narrows_and_is_enforced() {
    let target = identity();
    let alice = identity();
    let bob = identity();

    let root_grant = Grant::issue(
        target.id.clone(),
        &target.working,
        &alice.working.public(),
        Caveats::new(["summarize", "translate"], NOW + 1000),
    )
    .unwrap();

    // Alice delegates a strictly narrower grant to Bob.
    let sub = root_grant
        .attenuate(
            &alice.working,
            &bob.working.public(),
            Caveats::new(["summarize"], NOW + 500),
        )
        .unwrap();

    let revs = RevocationSet::new();
    // Bob may summarize...
    sub.verify(
        &target.root.public(),
        &target.endorsements,
        &bob.working.public(),
        "summarize",
        NOW,
        &revs,
    )
    .unwrap();
    // ...but not translate (dropped during attenuation).
    assert!(matches!(
        sub.verify(
            &target.root.public(),
            &target.endorsements,
            &bob.working.public(),
            "translate",
            NOW,
            &revs,
        )
        .unwrap_err(),
        Error::CapabilityNotAllowed
    ));
}

#[test]
fn attenuation_cannot_widen_authority() {
    let target = identity();
    let alice = identity();
    let bob = identity();
    let root_grant = Grant::issue(
        target.id.clone(),
        &target.working,
        &alice.working.public(),
        Caveats::new(["summarize"], NOW + 1000),
    )
    .unwrap();

    // Try to add a capability the parent never had.
    let widened = root_grant.attenuate(
        &alice.working,
        &bob.working.public(),
        Caveats::new(["summarize", "delete"], NOW + 1000),
    );
    assert!(matches!(widened.unwrap_err(), Error::BadAttenuation));

    // Try to extend the expiry beyond the parent.
    let longer = root_grant.attenuate(
        &alice.working,
        &bob.working.public(),
        Caveats::new(["summarize"], NOW + 5000),
    );
    assert!(matches!(longer.unwrap_err(), Error::BadAttenuation));
}

#[test]
fn non_holder_cannot_attenuate() {
    let target = identity();
    let alice = identity();
    let mallory = identity();
    let bob = identity();
    let grant = Grant::issue(
        target.id.clone(),
        &target.working,
        &alice.working.public(),
        Caveats::new(["summarize"], NOW + 1000),
    )
    .unwrap();
    // Mallory is not the audience and cannot delegate.
    assert!(matches!(
        grant
            .attenuate(
                &mallory.working,
                &bob.working.public(),
                Caveats::new(["summarize"], NOW + 500),
            )
            .unwrap_err(),
        Error::NotHolder
    ));
}

#[test]
fn grant_rejects_wrong_caller_target_and_tampering() {
    let target = identity();
    let alice = identity();
    let charlie = identity();
    let grant = Grant::issue(
        target.id.clone(),
        &target.working,
        &alice.working.public(),
        Caveats::new(["summarize"], NOW + 1000),
    )
    .unwrap();
    let revs = RevocationSet::new();

    // Wrong caller.
    assert!(matches!(
        grant
            .verify(
                &target.root.public(),
                &target.endorsements,
                &charlie.working.public(),
                "summarize",
                NOW,
                &revs,
            )
            .unwrap_err(),
        Error::AudienceMismatch
    ));

    // Wrong target root key.
    let stranger = identity();
    assert!(matches!(
        grant
            .verify(
                &stranger.root.public(),
                &stranger.endorsements,
                &alice.working.public(),
                "summarize",
                NOW,
                &revs,
            )
            .unwrap_err(),
        Error::TargetMismatch
    ));

    // Tamper with a link's caveats after signing.
    let mut tampered = grant.clone();
    tampered.links[0]
        .caveats
        .capabilities
        .insert("delete".into());
    assert!(matches!(
        tampered
            .verify(
                &target.root.public(),
                &target.endorsements,
                &alice.working.public(),
                "delete",
                NOW,
                &revs,
            )
            .unwrap_err(),
        Error::BadSignature
    ));
}

#[test]
fn expired_grant_is_rejected() {
    let target = identity();
    let alice = identity();
    let grant = Grant::issue(
        target.id.clone(),
        &target.working,
        &alice.working.public(),
        Caveats::new(["summarize"], NOW - 1),
    )
    .unwrap();
    assert!(matches!(
        grant
            .verify(
                &target.root.public(),
                &target.endorsements,
                &alice.working.public(),
                "summarize",
                NOW,
                &RevocationSet::new(),
            )
            .unwrap_err(),
        Error::Expired
    ));
}

// ---------- envelope ----------

#[test]
fn envelope_signs_and_verifies() {
    let a = identity();
    let b = identity();
    let env = EnvelopePayload::request(a.id.clone(), b.id.clone(), "summarize")
        .with_body(b"hello".to_vec())
        .sign(&a.working)
        .unwrap();

    env.verify(
        &a.root.public(),
        &a.endorsements,
        NOW,
        &RevocationSet::new(),
    )
    .unwrap();
    assert_eq!(env.payload.typ, EnvelopeType::Request);
    assert!(!env.payload.correlation.is_empty());
}

#[test]
fn envelope_tampering_is_detected() {
    let a = identity();
    let b = identity();
    let mut env = EnvelopePayload::request(a.id.clone(), b.id.clone(), "summarize")
        .sign(&a.working)
        .unwrap();
    env.payload.body = b"tampered".to_vec();
    assert!(matches!(
        env.verify(
            &a.root.public(),
            &a.endorsements,
            NOW,
            &RevocationSet::new()
        )
        .unwrap_err(),
        Error::BadEnvelope
    ));
}

#[test]
fn envelope_deadline_and_correlation() {
    let a = identity();
    let b = identity();
    let req = EnvelopePayload::request(a.id.clone(), b.id.clone(), "summarize")
        .with_deadline(NOW + 10)
        .sign(&a.working)
        .unwrap();
    assert!(!req.is_expired(NOW));
    assert!(req.is_expired(NOW + 11));

    // A response carries the request's correlation id.
    let resp =
        EnvelopePayload::response(b.id.clone(), a.id.clone(), req.payload.correlation.clone())
            .sign(&b.working)
            .unwrap();
    assert_eq!(resp.payload.correlation, req.payload.correlation);
    assert_eq!(resp.payload.typ, EnvelopeType::Response);
}

#[test]
fn error_envelope_carries_code() {
    let a = identity();
    let b = identity();
    let corr = vec![1, 2, 3];
    let err = EnvelopePayload::error(
        b.id.clone(),
        a.id.clone(),
        corr.clone(),
        ErrorCode::Unauthorized,
        "no grant",
    )
    .sign(&b.working)
    .unwrap();
    assert_eq!(err.payload.typ, EnvelopeType::Error);
    assert_eq!(
        err.payload.error.as_ref().unwrap().code,
        ErrorCode::Unauthorized
    );
}

// ---------- handshake ----------

#[test]
fn handshake_proof_authenticates_peer() {
    let peer = identity();
    let challenge = Challenge::new();
    let proof = prove(&challenge, &peer.id, &peer.working).unwrap();
    verify_proof(
        &challenge,
        &proof,
        &peer.root.public(),
        &peer.endorsements,
        NOW,
        &RevocationSet::new(),
    )
    .unwrap();
}

#[test]
fn handshake_rejects_replayed_or_wrong_challenge() {
    let peer = identity();
    let challenge = Challenge::new();
    let proof = prove(&challenge, &peer.id, &peer.working).unwrap();
    // A different challenge must not accept the old proof.
    let other = Challenge::new();
    assert!(matches!(
        verify_proof(
            &other,
            &proof,
            &peer.root.public(),
            &peer.endorsements,
            NOW,
            &RevocationSet::new(),
        )
        .unwrap_err(),
        Error::BadProof
    ));
}

#[test]
fn handshake_rejects_unendorsed_key() {
    let peer = identity();
    let rogue = WorkingKey::generate();
    let challenge = Challenge::new();
    // Prove with a key the peer's root never endorsed.
    let proof = prove(&challenge, &peer.id, &rogue).unwrap();
    assert!(verify_proof(
        &challenge,
        &proof,
        &peer.root.public(),
        &peer.endorsements,
        NOW,
        &RevocationSet::new(),
    )
    .is_err());
}
