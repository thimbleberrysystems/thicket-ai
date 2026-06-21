//! The federation: collection selection → scatter-gather → merge/rerank, plus a
//! TTL resolve cache (plan §5). Membership is a closed set of explicitly-added
//! peers, which is also the simplest form of a private federation (§10): a
//! record in a registry that is not a peer is simply not discoverable here.

use std::cell::RefCell;
use std::collections::HashMap;

use thicket_core::{Id, RevocationSet, SignedRecord};
use thicket_registry::{cosine, Embedder, Need};

use crate::peer::Peer;
use crate::profile::CatalogProfile;

/// A federation of registries reachable from this node.
pub struct Federation<E: Embedder> {
    peers: Vec<Box<dyn Peer>>,
    profiles: Vec<CatalogProfile>,
    embedder: E,
    cache: RefCell<HashMap<Id, (SignedRecord, u64)>>,
    default_ttl: u64,
    /// Max peers to fan a query out to (collection selection cut-off).
    max_peers: usize,
}

impl<E: Embedder> Federation<E> {
    pub fn new(embedder: E) -> Self {
        Self {
            peers: Vec::new(),
            profiles: Vec::new(),
            embedder,
            cache: RefCell::new(HashMap::new()),
            default_ttl: 300,
            max_peers: usize::MAX,
        }
    }

    /// Limit how many peers a query fans out to.
    pub fn with_max_peers(mut self, max_peers: usize) -> Self {
        self.max_peers = max_peers;
        self
    }

    /// Add a peer and capture its catalog profile (as of `now`).
    pub fn add_peer(&mut self, peer: Box<dyn Peer>, now: u64) {
        let profile = CatalogProfile::build(&peer.public_records(now), &self.embedder);
        self.peers.push(peer);
        self.profiles.push(profile);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Collection selection: peer indices ranked by how well their catalog
    /// centroid matches `intent`, capped at `max_peers`.
    pub fn select_peers(&self, intent: &str) -> Vec<usize> {
        let q = self.embedder.embed(intent);
        let mut scored: Vec<(f32, usize)> = self
            .profiles
            .iter()
            .enumerate()
            .map(|(i, p)| (cosine(&q, &p.centroid), i))
            .collect();
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored
            .into_iter()
            .take(self.max_peers)
            .map(|(_, i)| i)
            .collect()
    }

    /// Federated search: select peers, scatter-gather, verify, dedupe by id
    /// (highest version wins), rerank globally, take top-k.
    pub fn search(&self, need: &Need, now: u64) -> Vec<SignedRecord> {
        let q = self.embedder.embed(&need.intent_text);
        let revs = RevocationSet::new();

        let mut best: HashMap<Id, SignedRecord> = HashMap::new();
        for i in self.select_peers(&need.intent_text) {
            for rec in self.peers[i].search(need, now) {
                if rec.verify(now, &revs).is_err() {
                    continue; // never trust an unverifiable cross-peer record
                }
                match best.get(rec.id()) {
                    Some(existing) if existing.payload.version >= rec.payload.version => {}
                    _ => {
                        best.insert(rec.id().clone(), rec);
                    }
                }
            }
        }

        let mut results: Vec<SignedRecord> = best.into_values().collect();
        results.sort_by(|a, b| {
            self.record_score(&q, b)
                .partial_cmp(&self.record_score(&q, a))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(need.top_k);
        results
    }

    /// Resolve by id with a TTL cache (plan §5). Cache hits skip the peers;
    /// misses ask peers (referral), verify, and cache with the record's lease
    /// TTL (or a default).
    pub fn resolve(&self, id: &Id, now: u64) -> Option<SignedRecord> {
        if let Some((rec, expires)) = self.cache.borrow().get(id) {
            if *expires > now {
                return Some(rec.clone());
            }
        }

        let revs = RevocationSet::new();
        for peer in &self.peers {
            if let Some(rec) = peer.resolve(id, now) {
                if rec.verify(now, &revs).is_ok() {
                    let ttl = rec
                        .payload
                        .lease
                        .as_ref()
                        .map_or(self.default_ttl, |l| l.ttl);
                    self.cache
                        .borrow_mut()
                        .insert(id.clone(), (rec.clone(), now + ttl));
                    return Some(rec);
                }
            }
        }
        None
    }

    /// Whether `id` is in the cache and still fresh at `now`.
    pub fn is_cached(&self, id: &Id, now: u64) -> bool {
        self.cache
            .borrow()
            .get(id)
            .is_some_and(|(_, expires)| *expires > now)
    }

    fn record_score(&self, q: &[f32], rec: &SignedRecord) -> f32 {
        rec.payload
            .capabilities
            .iter()
            .map(|c| cosine(q, &self.embedder.embed(&c.description)))
            .fold(f32::MIN, f32::max)
    }
}
