//! The mutually-authenticated channel handshake (plan §6).
//!
//! Symmetric and deadlock-free: both sides write `Hello` (carrying their
//! self-certifying key material and a challenge nonce), then read the peer's
//! `Hello`, then write a `Proof` signing the peer's nonce, then verify the
//! peer's proof against their own nonce. The encrypting transport is layered
//! underneath; this establishes *who* the peer is.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use thicket_core::{Id, KeyEndorsement, RevocationSet};
use thicket_interconnect::{prove, verify_proof, Challenge, Proof};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::framing::{read_msg, write_msg};
use crate::identity::{LocalIdentity, VerifiedPeer};

#[derive(Serialize, Deserialize)]
struct Hello {
    id: Id,
    root_public_key: Vec<u8>,
    endorsements: Vec<KeyEndorsement>,
    working_pub: Vec<u8>,
    nonce: Vec<u8>,
}

fn nonce() -> Vec<u8> {
    let mut b = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// Perform the handshake over a split stream. Returns the authenticated peer.
pub async fn handshake<R, W>(
    r: &mut R,
    w: &mut W,
    local: &LocalIdentity,
    now: u64,
) -> Result<VerifiedPeer>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let my_nonce = nonce();
    let hello = Hello {
        id: local.id.clone(),
        root_public_key: local.root_public_key.clone(),
        endorsements: local.endorsements.clone(),
        working_pub: local.working.public(),
        nonce: my_nonce.clone(),
    };

    write_msg(w, &hello).await?;
    let peer_hello: Hello = read_msg(r).await?.ok_or(Error::Handshake)?;

    // Sign the peer's challenge with our working key.
    let my_proof = prove(
        &Challenge {
            nonce: peer_hello.nonce.clone(),
        },
        &local.id,
        &local.working,
    )?;
    write_msg(w, &my_proof).await?;

    // Verify the peer's proof against the nonce we issued.
    let peer_proof: Proof = read_msg(r).await?.ok_or(Error::Handshake)?;
    verify_proof(
        &Challenge { nonce: my_nonce },
        &peer_proof,
        &peer_hello.root_public_key,
        &peer_hello.endorsements,
        now,
        &RevocationSet::new(),
    )
    .map_err(|_| Error::Handshake)?;

    // The proving identity must match the announced identity.
    if peer_proof.id != peer_hello.id || peer_proof.working_pub != peer_hello.working_pub {
        return Err(Error::Handshake);
    }

    // Capture the validated working key's expiry for per-message freshness.
    let key_not_after = peer_hello
        .endorsements
        .iter()
        .find(|e| e.working_pub() == peer_hello.working_pub.as_slice())
        .map(|e| e.not_after())
        .ok_or(Error::Handshake)?;

    Ok(VerifiedPeer {
        id: peer_hello.id,
        working_pub: peer_hello.working_pub,
        key_not_after,
    })
}
