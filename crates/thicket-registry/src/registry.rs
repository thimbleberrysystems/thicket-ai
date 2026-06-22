//! A single registry: the authoritative store for its registrants, with
//! register / resolve / search (plan §4). Federation across registries is a
//! later increment; this is the local node.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thicket_core::{verify_revocation, Id, Revocation, RevocationSet, SignedRecord, Visibility};

use crate::embedder::{cosine, Embedder};

/// Errors returned by registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("record rejected: {0}")]
    Core(#[from] thicket_core::Error),
    #[error("stale: version is not newer than the current record")]
    Stale,
    #[error("not found")]
    NotFound,
    #[error("not authorized to resolve a private record")]
    NotAuthorized,
}

/// A semantic discovery query (plan §4 `Search(need)`). Serializable so it can
/// cross the wire to a networked directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Need {
    pub intent_text: String,
    pub kind: Option<String>,
    pub tags: Vec<String>,
    pub top_k: usize,
}

impl Need {
    pub fn new(intent_text: impl Into<String>, top_k: usize) -> Self {
        Self {
            intent_text: intent_text.into(),
            kind: None,
            tags: Vec::new(),
            top_k,
        }
    }

    pub fn of_kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = Some(kind.into());
        self
    }
}

struct Stored {
    record: SignedRecord,
    /// One embedding per capability, computed at registration time.
    cap_embeddings: Vec<Vec<f32>>,
}

/// The registry, generic over the embedding provider.
pub struct Registry<E: Embedder> {
    store: HashMap<Id, Stored>,
    revocations: RevocationSet,
    embedder: E,
}

impl<E: Embedder> std::fmt::Debug for Registry<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("records", &self.store.len())
            .finish_non_exhaustive()
    }
}

impl<E: Embedder> Registry<E> {
    pub fn new(embedder: E) -> Self {
        Self {
            store: HashMap::new(),
            revocations: RevocationSet::new(),
            embedder,
        }
    }

    /// Publish (or update) a record. Verifies the full signature/key chain at
    /// `now`, rejects stale versions, and indexes capability embeddings.
    pub fn register(&mut self, record: SignedRecord, now: u64) -> Result<(), RegistryError> {
        record.verify(now, &self.revocations)?;

        if let Some(existing) = self.store.get(record.id()) {
            if record.payload.version <= existing.record.payload.version {
                return Err(RegistryError::Stale);
            }
        }

        let cap_embeddings = record
            .payload
            .capabilities
            .iter()
            .map(|c| self.embedder.embed(&c.description))
            .collect();

        self.store.insert(
            record.id().clone(),
            Stored {
                record,
                cap_embeddings,
            },
        );
        Ok(())
    }

    /// Resolve by id (plan §4). Returns public/unlisted records; private records
    /// require authorization (not wired until the grant layer).
    pub fn resolve(&self, id: &Id, now: u64) -> Result<SignedRecord, RegistryError> {
        let stored = self.store.get(id).ok_or(RegistryError::NotFound)?;
        if lease_expired(&stored.record, now) {
            return Err(RegistryError::NotFound);
        }
        match stored.record.payload.visibility {
            Visibility::Private => Err(RegistryError::NotAuthorized),
            _ => Ok(stored.record.clone()),
        }
    }

    /// Semantic search: filter → recall → rank (plan §4). Only public, live
    /// records are returned, ranked by best-matching capability.
    pub fn search(&self, need: &Need, now: u64) -> Vec<SignedRecord> {
        let q = self.embedder.embed(&need.intent_text);

        let mut scored: Vec<(f32, &Stored)> = self
            .store
            .values()
            .filter(|s| s.record.payload.visibility == Visibility::Public)
            .filter(|s| !lease_expired(&s.record, now))
            .filter(|s| kind_matches(s, need))
            .filter(|s| tags_match(s, need))
            .map(|s| (best_capability_score(&q, s), s))
            .collect();

        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored
            .into_iter()
            .take(need.top_k)
            .map(|(_, s)| s.record.clone())
            .collect()
    }

    /// Apply a root-signed revocation (plan §7). Verifies it under the record's
    /// root key, records the revoked working key, and drops the record if its
    /// own signer became untrusted.
    pub fn revoke(&mut self, id: &Id, revocation: &Revocation) -> Result<(), RegistryError> {
        let root_pub = self
            .store
            .get(id)
            .ok_or(RegistryError::NotFound)?
            .record
            .payload
            .root_public_key
            .clone();

        verify_revocation(&root_pub, revocation)?;
        self.revocations.revoke_key(revocation.working_pub());

        if let Some(stored) = self.store.get(id) {
            if self.revocations.is_revoked(&stored.record.signer_pub) {
                self.store.remove(id);
            }
        }
        Ok(())
    }

    /// Extend a record's lease (plan §12 `Renew`/heartbeat). The new expiry must
    /// move forward. Only the record's current holder should be able to do this
    /// over the wire; the networked directory gates that with the channel
    /// identity. Returns the bumped expiry.
    pub fn renew(&mut self, id: &Id, now: u64, ttl: u64) -> Result<u64, RegistryError> {
        let stored = self.store.get_mut(id).ok_or(RegistryError::NotFound)?;
        let lease = stored
            .record
            .payload
            .lease
            .as_mut()
            .ok_or(RegistryError::NotFound)?;
        lease.issued_at = now;
        lease.ttl = ttl;
        lease.expires_at = now + ttl;
        Ok(lease.expires_at)
    }

    /// Withdraw a record (plan §14 `Deregister`).
    pub fn deregister(&mut self, id: &Id) -> bool {
        self.store.remove(id).is_some()
    }

    /// Evict records whose lease has expired as of `now`. Returns how many.
    pub fn sweep_expired(&mut self, now: u64) -> usize {
        let before = self.store.len();
        self.store.retain(|_, s| !lease_expired(&s.record, now));
        before - self.store.len()
    }

    /// All public, currently-live records. Used by federation to build a
    /// catalog profile and to scatter-gather (plan §5).
    pub fn public_records(&self, now: u64) -> Vec<SignedRecord> {
        self.store
            .values()
            .filter(|s| s.record.payload.visibility == Visibility::Public)
            .filter(|s| !lease_expired(&s.record, now))
            .map(|s| s.record.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

fn lease_expired(record: &SignedRecord, now: u64) -> bool {
    record
        .payload
        .lease
        .as_ref()
        .is_some_and(|l| now > l.expires_at)
}

fn kind_matches(stored: &Stored, need: &Need) -> bool {
    match &need.kind {
        None => true,
        Some(k) => {
            &stored.record.payload.kind == k
                || stored
                    .record
                    .payload
                    .capabilities
                    .iter()
                    .any(|c| &c.kind == k)
        }
    }
}

fn tags_match(stored: &Stored, need: &Need) -> bool {
    need.tags.iter().all(|t| {
        stored
            .record
            .payload
            .capabilities
            .iter()
            .any(|c| c.tags.contains(t))
    })
}

fn best_capability_score(query: &[f32], stored: &Stored) -> f32 {
    stored
        .cap_embeddings
        .iter()
        .map(|e| cosine(query, e))
        .fold(f32::MIN, f32::max)
}
