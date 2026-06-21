//! # thicket-trust
//!
//! The trust layer (plan §9): signed attestations, Sybil-resistant reputation
//! aggregation, and cold-start-aware ranking. Keeps semantic search honest
//! without a central authority.

pub mod attestation;
pub mod error;
pub mod reputation;
pub mod scoring;

pub use attestation::Attestation;
pub use error::{Error, Result};
pub use reputation::ReputationLedger;
pub use scoring::{exploration_bonus, score, ScoreWeights};
