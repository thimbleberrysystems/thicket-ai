//! Small shared helpers.

use rand::RngCore;

/// A fresh random byte string (correlation ids, nonces).
pub fn fresh_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}
