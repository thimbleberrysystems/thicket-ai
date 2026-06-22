//! The peer abstraction: a federated registry the local node can query. A
//! concrete [`RegistryPeer`] wraps an in-process [`Registry`]; a real
//! deployment would have a network-backed implementation behind the same trait.

use thicket_core::{Id, SignedRecord};
use thicket_registry::{Embedder, Need, Registry};

/// A queryable registry in the federation.
pub trait Peer {
    fn search(&self, need: &Need, now: u64) -> Vec<SignedRecord>;
    fn resolve(&self, id: &Id, now: u64) -> Option<SignedRecord>;
    fn public_records(&self, now: u64) -> Vec<SignedRecord>;
}

/// A peer backed by a local in-process registry.
pub struct RegistryPeer<E: Embedder> {
    registry: Registry<E>,
}

impl<E: Embedder> std::fmt::Debug for RegistryPeer<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryPeer")
            .field("registry", &self.registry)
            .finish()
    }
}

impl<E: Embedder> RegistryPeer<E> {
    pub fn new(registry: Registry<E>) -> Self {
        Self { registry }
    }

    pub fn registry_mut(&mut self) -> &mut Registry<E> {
        &mut self.registry
    }
}

impl<E: Embedder> Peer for RegistryPeer<E> {
    fn search(&self, need: &Need, now: u64) -> Vec<SignedRecord> {
        self.registry.search(need, now)
    }

    fn resolve(&self, id: &Id, now: u64) -> Option<SignedRecord> {
        self.registry.resolve(id, now).ok()
    }

    fn public_records(&self, now: u64) -> Vec<SignedRecord> {
        self.registry.public_records(now)
    }
}
