//! Catalog profiles: the compact summary a registry gossips so queries can be
//! routed to promising peers without broadcasting (plan §5, the referral
//! substitute).

use std::collections::BTreeSet;

use thicket_core::SignedRecord;
use thicket_registry::Embedder;

/// A compact summary of a registry's catalog: a capability-embedding centroid
/// plus the kinds/tags it holds and a size.
pub struct CatalogProfile {
    pub centroid: Vec<f32>,
    pub kinds: BTreeSet<String>,
    pub tags: BTreeSet<String>,
    pub count: usize,
}

impl CatalogProfile {
    /// Build a profile from a set of records using `embedder`.
    pub fn build(records: &[SignedRecord], embedder: &dyn Embedder) -> Self {
        let dim = embedder.dim();
        let mut centroid = vec![0f32; dim];
        let mut n = 0usize;
        let mut kinds = BTreeSet::new();
        let mut tags = BTreeSet::new();

        for rec in records {
            kinds.insert(rec.payload.kind.clone());
            for cap in &rec.payload.capabilities {
                for t in &cap.tags {
                    tags.insert(t.clone());
                }
                for (i, x) in embedder.embed(&cap.description).iter().enumerate() {
                    centroid[i] += x;
                }
                n += 1;
            }
        }

        if n > 0 {
            for x in centroid.iter_mut() {
                *x /= n as f32;
            }
        }
        let norm: f32 = centroid.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in centroid.iter_mut() {
                *x /= norm;
            }
        }

        Self {
            centroid,
            kinds,
            tags,
            count: records.len(),
        }
    }
}
