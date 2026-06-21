//! Tests for attestations, Sybil-resistant reputation, and cold-start ranking.

use thicket_core::{Id, KeyEndorsement, RevocationSet, RootKey, WorkingKey};
use thicket_trust::{score, Attestation, ReputationLedger, ScoreWeights};

const NOW: u64 = 1_000_000;

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

#[test]
fn attestation_verifies_and_detects_forgery() {
    let attester = identity();
    let subject = identity();
    let mut att = Attestation::issue(
        &attester.id,
        &attester.working,
        subject.id.clone(),
        "good-at-summarization",
        0.9,
        NOW,
    )
    .unwrap();

    att.verify(
        &attester.root.public(),
        &attester.endorsements,
        NOW,
        &RevocationSet::new(),
    )
    .unwrap();

    // Tamper with the score after signing.
    att.score = 0.1;
    assert!(att
        .verify(
            &attester.root.public(),
            &attester.endorsements,
            NOW,
            &RevocationSet::new()
        )
        .is_err());
}

#[test]
fn outcomes_drive_direct_reputation() {
    let r = identity();
    let mut ledger = ReputationLedger::new();
    for _ in 0..9 {
        ledger.record_outcome(&r.id, true);
    }
    ledger.record_outcome(&r.id, false);
    assert!((ledger.outcome_score(&r.id) - 0.9).abs() < 1e-6);
    assert_eq!(ledger.observations(&r.id), 10);
}

#[test]
fn sybil_attestations_carry_little_weight() {
    // Subject A is vouched for by an attester with a real track record.
    // Subject B is vouched for by a fresh "sybil" with no outcomes.
    let reputable = identity();
    let sybil = identity();
    let subject_a = identity();
    let subject_b = identity();

    let mut ledger = ReputationLedger::new();
    // Give the reputable attester a track record; the sybil has none.
    for _ in 0..10 {
        ledger.record_outcome(&reputable.id, true);
    }

    ledger.add_attestation(
        Attestation::issue(&reputable.id, &reputable.working, subject_a.id.clone(), "x", 1.0, NOW)
            .unwrap(),
    );
    ledger.add_attestation(
        Attestation::issue(&sybil.id, &sybil.working, subject_b.id.clone(), "x", 1.0, NOW).unwrap(),
    );

    let rep_a = ledger.reputation(&subject_a.id);
    let rep_b = ledger.reputation(&subject_b.id);
    assert!(rep_a > rep_b, "rep_a={rep_a} rep_b={rep_b}");
    assert!(rep_b < 1e-6, "sybil-vouched reputation should be ~0");
}

#[test]
fn higher_reputation_breaks_ties_at_equal_relevance() {
    let w = ScoreWeights::default();
    let high = score(0.7, 0.9, 50, &w);
    let low = score(0.7, 0.2, 50, &w);
    assert!(high > low);
}

#[test]
fn exploration_gives_newcomers_a_chance() {
    // Equal relevance; an established high-reputation resource vs a brand-new
    // one with no reputation. Without exploration the incumbent wins; with
    // exploration the newcomer is at least competitive.
    let established_rel = 0.8;
    let newcomer_rel = 0.8;

    let no_explore = ScoreWeights {
        relevance: 1.0,
        reputation: 0.5,
        exploration: 0.0,
    };
    let with_explore = ScoreWeights {
        relevance: 1.0,
        reputation: 0.5,
        exploration: 0.5,
    };

    let est_no = score(established_rel, 0.9, 100, &no_explore);
    let new_no = score(newcomer_rel, 0.0, 0, &no_explore);
    assert!(est_no > new_no, "without exploration the incumbent should win");

    let est_yes = score(established_rel, 0.9, 100, &with_explore);
    let new_yes = score(newcomer_rel, 0.0, 0, &with_explore);
    assert!(
        new_yes >= est_yes,
        "with exploration the newcomer should be competitive: new={new_yes} est={est_yes}"
    );
}
