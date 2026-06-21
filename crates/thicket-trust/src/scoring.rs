//! Ranking that combines relevance, reputation, and a cold-start exploration
//! term (plan §4 step 4, §9). The exploration term reserves rank for resources
//! with little track record, so the network does not ossify around incumbents.

/// Weights for the ranking terms.
#[derive(Clone, Debug)]
pub struct ScoreWeights {
    pub relevance: f32,
    pub reputation: f32,
    pub exploration: f32,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            relevance: 1.0,
            reputation: 0.5,
            exploration: 0.5,
        }
    }
}

/// Exploration bonus that decays as a resource accrues observations.
/// `observations = 0` → 1.0 (maximum benefit of the doubt).
pub fn exploration_bonus(observations: u64) -> f32 {
    1.0 / (1.0 + observations as f32)
}

/// Final ranking score for a candidate.
pub fn score(relevance: f32, reputation: f32, observations: u64, w: &ScoreWeights) -> f32 {
    w.relevance * relevance
        + w.reputation * reputation
        + w.exploration * exploration_bonus(observations)
}
