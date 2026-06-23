//! Low-level cryptographic primitives and the canonical signing-input rule.
//!
//! Everything signed in Thicket is signed over `signing_bytes(domain, payload)`:
//! a domain-separation tag, a NUL separator, then the deterministic CBOR
//! encoding of the payload. Pinning this byte layout is what lets a signature
//! produced in one language verify in another (see plan §0 "Defined at the
//! wire"). The cross-language canonicalization rule is intentionally simple here
//! (deterministic field-order CBOR) and is a tracked open item.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Produce the canonical bytes to be signed for `payload` under `domain`.
///
/// Layout: `domain_utf8 || 0x00 || cbor(payload)`.
pub fn signing_bytes<T: ?Sized + Serialize>(domain: &str, payload: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(domain.as_bytes());
    buf.push(0u8);
    ciborium::into_writer(payload, &mut buf).map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(buf)
}

pub(crate) fn vk_from_bytes(bytes: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::BadKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| Error::BadKey)
}

pub(crate) fn sig_from_bytes(bytes: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = bytes.try_into().map_err(|_| Error::BadSig)?;
    Ok(Signature::from_bytes(&arr))
}

/// Verify a raw Ed25519 signature over `msg` for the given public key bytes.
pub(crate) fn verify_raw(pub_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let vk = vk_from_bytes(pub_bytes)?;
    let sig = sig_from_bytes(sig_bytes)?;
    vk.verify(msg, &sig).map_err(|_| Error::VerifyFailed)
}

/// Public wrapper over [`verify_raw`] for other crates that build their own
/// signed objects (envelopes, grants, attestations) over [`signing_bytes`].
pub fn verify_signature(pub_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    verify_raw(pub_bytes, msg, sig_bytes)
}
