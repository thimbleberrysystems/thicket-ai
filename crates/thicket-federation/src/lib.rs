//! # thicket-federation
//!
//! Federated discovery across registries (plan §5): catalog profiles, collection
//! selection, scatter-gather with per-record verification, global rerank, and a
//! TTL resolve cache. Closed peer membership doubles as a private federation.

pub mod federation;
pub mod peer;
pub mod profile;

pub use federation::Federation;
pub use peer::{Peer, RegistryPeer};
pub use profile::CatalogProfile;
