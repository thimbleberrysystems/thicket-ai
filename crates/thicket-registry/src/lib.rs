//! # thicket-registry
//!
//! A single Thicket registry node: the authoritative store for the resources
//! that register with it, with id resolution and semantic capability search
//! (plan §4). Federation across registries (§5) is a later increment.

pub mod embedder;
pub mod registry;

pub use embedder::{cosine, Embedder, MockEmbedder};
pub use registry::{Need, Registry, RegistryError};
