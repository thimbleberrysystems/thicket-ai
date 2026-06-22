//! Pluggable embedding provider.
//!
//! The registry embeds capability descriptions for semantic recall (plan §4).
//! In production this would call out to a real embedding model resource; the
//! framework only depends on the [`Embedder`] trait. [`MockEmbedder`] is a
//! deterministic stand-in (a "mock LLM") so tests are fast and reproducible.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Turns text into a fixed-dimension vector for similarity search.
pub trait Embedder: Send + Sync {
    fn dim(&self) -> usize;
    fn embed(&self, text: &str) -> Vec<f32>;
}

/// Deterministic hashing embedder: a normalized bag-of-hashed-words. Shares
/// direction with text that shares vocabulary, which is enough to exercise the
/// ranking pipeline without a real model.
#[derive(Debug, Clone)]
pub struct MockEmbedder {
    dim: usize,
}

impl MockEmbedder {
    pub fn new(dim: usize) -> Self {
        Self { dim: dim.max(1) }
    }
}

impl Default for MockEmbedder {
    fn default() -> Self {
        Self::new(64)
    }
}

impl Embedder for MockEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0f32; self.dim];
        for token in text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
        {
            let mut hasher = DefaultHasher::new();
            token.to_lowercase().hash(&mut hasher);
            let idx = (hasher.finish() as usize) % self.dim;
            v[idx] += 1.0;
        }
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in v.iter_mut() {
                *x /= norm;
            }
        }
        v
    }
}

/// Cosine similarity. Inputs from [`MockEmbedder`] are already L2-normalized, so
/// this is their dot product, but we normalize defensively for other embedders.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}
