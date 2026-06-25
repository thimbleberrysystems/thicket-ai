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
fn grant_rejects_revoked_chain_key() {
    let target = identity();
    let alice = identity();
    let bob = identity();
    let g = Grant::issue(
        target.id.clone(),
        &target.working,
        &alice.working.public(),
        Caveats::new(["read", "write"], NOW + 1000),
    )
    .unwrap();
    // Alice delegates read-only to Bob.
    let sub = g
        .attenuate(&alice.working, &bob.working.public(), Caveats::new(["read"], NOW + 500))
        .unwrap();

    let ok = |revs: &RevocationSet| {
        sub.verify(&target.root.public(), &target.endorsements, &bob.working.public(), "read", NOW, revs)
    };

    ok(&RevocationSet::new()).expect("valid with no revocations");

    // Revoking the issuing (head) key kills the whole chain.
    let mut r_head = RevocationSet::new();
    r_head.revoke_key(&target.working.public());
    assert!(ok(&r_head).is_err(), "revoked head key must reject");

    // Revoking the delegated audience kills the sub-grant.
    let mut r_sub = RevocationSet::new();
    r_sub.revoke_key(&bob.working.public());
    assert!(ok(&r_sub).is_err(), "revoked sub-agent key must reject");
}

#[test]
fn grant_satisfies_constraints() {
    use std::collections::BTreeMap;
    let target = identity();
    let alice = identity();
    let mut cav = Caveats::new(["read"], NOW + 1000);
    cav.constraints.insert("region".into(), "eu".into());
    let g = Grant::issue(target.id.clone(), &target.working, &alice.working.public(), cav).unwrap();

    let eu: BTreeMap<String, String> = [("region".to_string(), "eu".to_string())].into();
    let us: BTreeMap<String, String> = [("region".to_string(), "us".to_string())].into();
    assert!(g.satisfies(&eu), "matching constraint is satisfied");
    assert!(!g.satisfies(&us), "wrong value is not satisfied");
    assert!(!g.satisfies(&BTreeMap::new()), "missing attribute is not satisfied");
}

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

// ---------- context block ----------

#[test]
fn context_child_tightens_deadline_and_budget() {
    use thicket_interconnect::Context;
    let parent = Context {
        trace_id: vec![1, 2, 3],
        span_id: vec![9],
        parent_span_id: vec![],
        deadline: Some(100),
        budget: Some(50),
        sink: None,
    };
    let child = parent.child(vec![10], Some(80), 20);

    assert_eq!(child.trace_id, parent.trace_id, "same trace");
    assert_eq!(child.parent_span_id, vec![9], "parent linkage");
    assert_eq!(child.span_id, vec![10]);
    // child ≤ parent for both deadline and budget
    assert!(child.deadline.unwrap() <= parent.deadline.unwrap());
    assert_eq!(child.deadline, Some(80)); // min(100, 80)
    assert!(child.budget.unwrap() <= parent.budget.unwrap());
    assert_eq!(child.budget, Some(30)); // 50 - 20

    assert!(parent.deadline_passed(101));
    assert!(!parent.deadline_passed(100));
}

#[test]
fn context_propagates_sink_and_stays_empty_without_one() {
    use thicket_interconnect::{Context, SinkRef};
    // No sink: the context is still "empty" (so the envelope omits it) — the
    // sink field can't bloat the wire when unused.
    assert!(Context::default().is_empty());

    let sink = SinkRef {
        id: Id::from_root_public(&[9u8; 32]).unwrap(),
        endpoint: "127.0.0.1:9000".into(),
    };
    let parent = Context {
        trace_id: vec![1],
        span_id: vec![2],
        sink: Some(sink.clone()),
        ..Default::default()
    };
    assert!(!parent.is_empty());
    // the sink rides along to every child of the trace
    let child = parent.child(vec![3], None, 0);
    assert_eq!(child.sink, Some(sink));
    assert_eq!(child.parent_span_id, vec![2]);
}

#[test]
fn envelope_carries_context_through_sign_and_verify() {
    use thicket_interconnect::Context;
    let a = identity();
    let b = identity();
    let ctx = Context {
        trace_id: vec![7; 16],
        span_id: vec![1],
        parent_span_id: vec![],
        deadline: Some(NOW + 5),
        budget: Some(1000),
        sink: None,
    };
    let env = EnvelopePayload::request(a.id.clone(), b.id.clone(), "x")
        .with_context(ctx)
        .sign(&a.working)
        .unwrap();

    env.verify(
        &a.root.public(),
        &a.endorsements,
        NOW,
        &RevocationSet::new(),
    )
    .unwrap();
    assert_eq!(env.payload.context.trace_id, vec![7; 16]);
    assert_eq!(env.payload.context.budget, Some(1000));
    assert!(!env.is_expired(NOW));
    assert!(env.is_expired(NOW + 6));
}
