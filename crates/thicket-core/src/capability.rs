//! Capability descriptors and the supporting record value types (plan §3).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Who may discover a record (plan §10).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    #[default]
    Public,
    Unlisted,
    Private,
}

/// The structural I/O contract layer of a capability.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Io {
    pub input: String,
    pub output: String,
}

/// One thing a resource can do, described to be matchable across kinds.
///
/// `description` (semantic), `io` (structural), and `tags`/`envelope` (filter)
/// are the three matching layers from plan §3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    pub kind: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io: Option<Io>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub modalities: Vec<String>,
    #[serde(default)]
    pub envelope: BTreeMap<String, f64>,
}

impl Capability {
    /// Minimal constructor for the common case (semantic layer only).
    pub fn new(kind: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
            io: None,
            tags: Vec::new(),
            modalities: Vec::new(),
            envelope: BTreeMap::new(),
        }
    }

    pub fn with_tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }
}

/// A current network endpoint for a resource. Mutable; identity is separate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Locator {
    pub protocol: String,
    pub endpoint: String,
}

/// Lease/liveness metadata (plan §12). `expires_at` bounds staleness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lease {
    pub ttl: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}
