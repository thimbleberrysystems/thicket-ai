//! Sybil-resistant reputation aggregation (plan §9).
//!
//! Reputation blends two signals: direct **outcomes** (did this resource deliver
//! when invoked/probed?) and **attestations** weighted by the *attester's own*
//! outcome reputation. Weighting vouches by attester standing is what defangs
//! Sybil clusters: a swarm of fresh identities vouching for each other carries
//! near-zero weight because none of them has a track record.

use std::collections::HashMap;

use thicket_core::Id;

use crate::attestation::Attestation;

/// Tracks outcomes and verified attestations, and derives reputation.
#[derive(Debug, Default)]
pub struct ReputationLedger {
    /// id → (successes, failures)
    outcomes: HashMap<Id, (u64, u64)>,
    /// Attestations assumed verified before insertion.
    attestations: Vec<Attestation>,
}

impl ReputationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the result of an invocation or probe of `id`.
    pub fn record_outcome(&mut self, id: &Id, success: bool) {
        let e = self.outcomes.entry(id.clone()).or_insert((0, 0));
        if success {
            e.0 += 1;
        } else {
            e.1 += 1;
        }
    }

    /// Add a (verified) attestation to the trust graph.
    pub fn add_attestation(&mut self, attestation: Attestation) {
        self.attestations.push(attestation);
    }

    /// Number of recorded outcomes for `id` (for cold-start exploration).
    pub fn observations(&self, id: &Id) -> u64 {
        self.outcomes.get(id).map_or(0, |(s, f)| s + f)
    }

    /// Direct success rate in `[0, 1]`, or 0 with no track record.
    pub fn outcome_score(&self, id: &Id) -> f32 {
        match self.outcomes.get(id) {
            Some((s, f)) if s + f > 0 => *s as f32 / (s + f) as f32,
            _ => 0.0,
        }
    }

    /// Aggregate reputation in `[0, 1]`: a blend of direct outcomes and
    /// attester-weighted vouches.
    pub fn reputation(&self, id: &Id) -> f32 {
        let direct = self.outcome_score(id);

        let mut num = 0.0f32;
        let mut den = 0.0f32;
        for att in self.attestations.iter().filter(|a| &a.subject == id) {
            let weight = self.outcome_score(&att.attester); // Sybil resistance
            num += weight * att.score;
            den += weight;
        }
        let vouched = if den > 0.0 { num / den } else { 0.0 };

        match (self.observations(id) > 0, den > 0.0) {
            (true, true) => 0.5 * direct + 0.5 * vouched,
            (true, false) => direct,
            (false, true) => vouched,
            (false, false) => 0.0,
        }
    }
}
