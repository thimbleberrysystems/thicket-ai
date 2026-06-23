//! The authentication core of channel establishment (plan §6).
//!
//! Two resources prove control of a root-endorsed working key by signing a
//! peer-supplied challenge nonce. This is the identity-verification half of the
//! "secure by identity" channel; the encrypting transport (Noise/QUIC) is an
//! adapter layered on top and out of scope for the protocol logic.

use serde::{Deserialize, Serialize};
use thicket_core::{
    signing_bytes, verify_signature, verify_working_key, Id, KeyEndorsement, RevocationSet,
    WorkingKey,
};

use crate::error::{Error, Result};
use crate::util::fresh_bytes;

const HANDSHAKE_DOMAIN: &str = "thicket-handshake-v1";

/// A random nonce a verifier issues for the peer to sign.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

impl Challenge {
    pub fn new() -> Self {
        Self {
            nonce: fresh_bytes(32),
        }
    }
}

impl Default for Challenge {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
struct ProofView<'a> {
    #[serde(with = "serde_bytes")]
    nonce: &'a [u8],
    id: &'a Id,
}

/// A signed response proving the prover controls a working key for `id`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub id: Id,
    #[serde(with = "serde_bytes")]
    pub working_pub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// Answer a challenge by signing `(nonce, id)` with a working key.
pub fn prove(challenge: &Challenge, id: &Id, working: &WorkingKey) -> Result<Proof> {
    let view = ProofView {
        nonce: &challenge.nonce,
        id,
    };
    let sig = working.sign(&signing_bytes(HANDSHAKE_DOMAIN, &view)?);
    Ok(Proof {
        id: id.clone(),
        working_pub: working.public(),
        sig,
    })
}

/// Verify a peer's proof against the challenge and the peer's (discovered) key
/// material: the proving key must be a valid working key for the claimed id, and
/// the signature must cover this exact challenge.
pub fn verify_proof(
    challenge: &Challenge,
    proof: &Proof,
    peer_root_pub: &[u8],
    peer_endorsements: &[KeyEndorsement],
    now: u64,
    revocations: &RevocationSet,
) -> Result<()> {
    verify_working_key(
        peer_root_pub,
        &proof.id,
        peer_endorsements,
        &proof.working_pub,
        now,
        revocations,
    )?;
    let view = ProofView {
        nonce: &challenge.nonce,
        id: &proof.id,
    };
    verify_signature(
        &proof.working_pub,
        &signing_bytes(HANDSHAKE_DOMAIN, &view)?,
        &proof.sig,
    )
    .map_err(|_| Error::BadProof)
}
