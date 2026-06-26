//! The checkpoint/state primitive: a run's recorded steps, so durable execution
//! can resume without re-running completed work.
//!
//! Like a record or a grant, this is a **data primitive** — the core defines its
//! shape and canonical encoding and nothing more. It is *stateless* (it stores
//! nothing) and *fiber-independent* (it knows nothing about the SDK, weaves, or
//! the network). Where a checkpoint lives — a file, a state fiber, memory — is the
//! consumer's choice; the core only owns the contract so a checkpoint written by
//! one implementation can be resumed by another.

use serde::{Deserialize, Serialize};

/// One recorded step: a stable key and the opaque result bytes. The value is
/// domain-specific and never interpreted by the core.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    pub key: String,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

/// A run's checkpoint: its recorded steps, in execution order, keyed by a run id.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    #[serde(with = "serde_bytes")]
    pub run_id: Vec<u8>,
    pub steps: Vec<Step>,
}

impl Checkpoint {
    pub fn new(run_id: impl Into<Vec<u8>>) -> Self {
        Self {
            run_id: run_id.into(),
            steps: Vec::new(),
        }
    }

    /// The recorded value for `key`, if that step already ran.
    pub fn replay(&self, key: &str) -> Option<&[u8]> {
        self.steps
            .iter()
            .find(|s| s.key == key)
            .map(|s| s.value.as_slice())
    }

    /// Record a completed step. Idempotent on the key — the first write wins, so a
    /// replay never overwrites a recorded result.
    pub fn record(&mut self, key: impl Into<String>, value: impl Into<Vec<u8>>) {
        let key = key.into();
        if self.replay(&key).is_none() {
            self.steps.push(Step {
                key,
                value: value.into(),
            });
        }
    }

    /// The positional key for the next step — the canonical sequence convention
    /// (`#0`, `#1`, …) both implementations use so a deterministic run replays.
    pub fn next_key(&self) -> String {
        format!("#{}", self.steps.len())
    }

    pub fn to_cbor(&self) -> crate::Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| crate::Error::Serialization(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> crate::Result<Self> {
        ciborium::from_reader(bytes).map_err(|e| crate::Error::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_replay_and_roundtrip() {
        let mut cp = Checkpoint::new(b"run".to_vec());
        assert_eq!(cp.next_key(), "#0");
        cp.record("#0", b"a".to_vec());
        assert_eq!(cp.next_key(), "#1");
        cp.record("#0", b"b".to_vec()); // idempotent: first write wins, replay never overwrites
        assert_eq!(cp.replay("#0"), Some(&b"a"[..]));
        assert_eq!(cp.replay("#9"), None);
        let bytes = cp.to_cbor().unwrap();
        assert_eq!(Checkpoint::from_cbor(&bytes).unwrap(), cp);
    }
}
