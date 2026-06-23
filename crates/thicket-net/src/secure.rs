//! Encrypted, mutually-authenticated channels via the Noise Protocol Framework
//! (`Noise_XX_25519_ChaChaPoly_SHA256`), bound to Thicket's Ed25519 identities.
//!
//! Noise gives confidentiality, integrity, and forward secrecy between two
//! per-connection X25519 static keys. We authenticate those statics to a
//! self-certifying identity the libp2p way: each side signs its Noise static
//! public key with its Ed25519 working key and sends that signature (plus its
//! key-chain) inside the encrypted handshake. The peer then checks the signature
//! binds the Noise static to the working key, and that the working key is
//! root-endorsed (`verify_working_key`). No Ed25519↔X25519 key conversion.

use serde::{Deserialize, Serialize};
use snow::{HandshakeState, TransportState};
use thicket_core::{
    signing_bytes, verify_signature, verify_working_key, Id, KeyEndorsement, RevocationSet,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::framing::{from_cbor, read_frame, to_cbor, write_frame};
use crate::identity::{LocalIdentity, VerifiedPeer};

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const STATIC_BINDING_DOMAIN: &str = "thicket-noise-static-v1";
/// Noise messages are bounded at 65535 bytes; 16 of those are the AEAD tag.
const NOISE_MAX_PAYLOAD: usize = 65535 - 16;

fn crypto<E: std::fmt::Display>(e: E) -> Error {
    Error::Crypto(e.to_string())
}

/// Carried inside the encrypted handshake: binds the Noise static key to a
/// Thicket identity.
#[derive(Serialize, Deserialize)]
struct IdentityProof {
    id: Id,
    #[serde(with = "serde_bytes")]
    root_public_key: Vec<u8>,
    endorsements: Vec<KeyEndorsement>,
    #[serde(with = "serde_bytes")]
    working_pub: Vec<u8>,
    /// `sign(working, domain ‖ noise_static_pub)`.
    #[serde(with = "serde_bytes")]
    static_sig: Vec<u8>,
}

fn binding_message(noise_static_pub: &[u8]) -> Result<Vec<u8>> {
    Ok(signing_bytes(
        STATIC_BINDING_DOMAIN,
        serde_bytes::Bytes::new(noise_static_pub),
    )?)
}

fn make_proof(local: &LocalIdentity, noise_static_pub: &[u8]) -> Result<IdentityProof> {
    let static_sig = local.working.sign(&binding_message(noise_static_pub)?);
    Ok(IdentityProof {
        id: local.id.clone(),
        root_public_key: local.root_public_key.clone(),
        endorsements: local.endorsements.clone(),
        working_pub: local.working.public(),
        static_sig,
    })
}

fn verify_proof(proof: &IdentityProof, remote_static: &[u8], now: u64) -> Result<VerifiedPeer> {
    // The working key must be a valid, root-endorsed key for this identity.
    verify_working_key(
        &proof.root_public_key,
        &proof.id,
        &proof.endorsements,
        &proof.working_pub,
        now,
        &RevocationSet::new(),
    )?;
    // The signature must bind the Noise static we actually negotiated.
    verify_signature(
        &proof.working_pub,
        &binding_message(remote_static)?,
        &proof.static_sig,
    )
    .map_err(|_| Error::Handshake)?;
    let key_not_after = proof
        .endorsements
        .iter()
        .find(|e| e.working_pub() == proof.working_pub.as_slice())
        .map(|e| e.not_after())
        .ok_or(Error::Handshake)?;
    Ok(VerifiedPeer {
        id: proof.id.clone(),
        working_pub: proof.working_pub.clone(),
        key_not_after,
    })
}

/// Run the Noise XX handshake over `stream`, authenticating both identities.
/// The dialing side is the initiator; the accepting side is the responder.
pub async fn establish<S>(
    stream: &mut S,
    local: &LocalIdentity,
    initiator: bool,
    now: u64,
) -> Result<(TransportState, VerifiedPeer)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().map_err(crypto)?;
    let builder = snow::Builder::new(params);
    let keypair = builder.generate_keypair().map_err(crypto)?;
    let proof_bytes = to_cbor(&make_proof(local, &keypair.public)?)?;
    let builder = builder
        .local_private_key(&keypair.private)
        .map_err(crypto)?;

    let mut hs: HandshakeState = if initiator {
        builder.build_initiator().map_err(crypto)?
    } else {
        builder.build_responder().map_err(crypto)?
    };

    let mut msg = vec![0u8; NOISE_MAX_PAYLOAD + 1024];
    let peer_proof: IdentityProof = if initiator {
        // -> e
        let n = hs.write_message(&[], &mut msg).map_err(crypto)?;
        write_frame(stream, &msg[..n]).await?;
        // <- e, ee, s, es  (responder's proof)
        let ct = read_frame(stream).await?.ok_or(Error::Handshake)?;
        let mut payload = vec![0u8; ct.len()];
        let plen = hs.read_message(&ct, &mut payload).map_err(crypto)?;
        let proof = from_cbor(&payload[..plen])?;
        // -> s, se  (our proof)
        let n = hs.write_message(&proof_bytes, &mut msg).map_err(crypto)?;
        write_frame(stream, &msg[..n]).await?;
        proof
    } else {
        // <- e
        let ct = read_frame(stream).await?.ok_or(Error::Handshake)?;
        let mut payload = vec![0u8; ct.len().max(1)];
        hs.read_message(&ct, &mut payload).map_err(crypto)?;
        // -> e, ee, s, es  (our proof)
        let n = hs.write_message(&proof_bytes, &mut msg).map_err(crypto)?;
        write_frame(stream, &msg[..n]).await?;
        // <- s, se  (initiator's proof)
        let ct = read_frame(stream).await?.ok_or(Error::Handshake)?;
        let mut payload = vec![0u8; ct.len()];
        let plen = hs.read_message(&ct, &mut payload).map_err(crypto)?;
        from_cbor(&payload[..plen])?
    };

    let remote_static = hs.get_remote_static().ok_or(Error::Handshake)?.to_vec();
    let peer = verify_proof(&peer_proof, &remote_static, now)?;
    let transport = hs.into_transport_mode().map_err(crypto)?;
    Ok((transport, peer))
}

/// Encrypt one logical frame, chunked to Noise's message limit. Wire layout:
/// `u32 chunk_count` then, per chunk, `u16 ciphertext_len` + ciphertext.
pub(crate) fn encrypt_frame(transport: &mut TransportState, plaintext: &[u8]) -> Result<Vec<u8>> {
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        Vec::new()
    } else {
        plaintext.chunks(NOISE_MAX_PAYLOAD).collect()
    };
    let mut out = Vec::with_capacity(plaintext.len() + 16 * chunks.len() + 4);
    out.extend_from_slice(&(chunks.len() as u32).to_be_bytes());
    let mut buf = vec![0u8; NOISE_MAX_PAYLOAD + 16];
    for chunk in chunks {
        let n = transport.write_message(chunk, &mut buf).map_err(crypto)?;
        out.extend_from_slice(&(n as u16).to_be_bytes());
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Decrypt one logical frame produced by [`encrypt_frame`].
pub(crate) fn decrypt_frame(transport: &mut TransportState, frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() < 4 {
        return Err(Error::Crypto("short frame".into()));
    }
    let count = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
    let mut pos = 4;
    let mut out = Vec::with_capacity(frame.len());
    let mut buf = vec![0u8; NOISE_MAX_PAYLOAD + 16];
    for _ in 0..count {
        if pos + 2 > frame.len() {
            return Err(Error::Crypto("truncated chunk header".into()));
        }
        let len = u16::from_be_bytes(frame[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if pos + len > frame.len() {
            return Err(Error::Crypto("truncated chunk".into()));
        }
        let n = transport
            .read_message(&frame[pos..pos + len], &mut buf)
            .map_err(crypto)?;
        out.extend_from_slice(&buf[..n]);
        pos += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;
    use thicket_core::RootKey;
    use tokio::io::duplex;

    #[tokio::test]
    async fn noise_channel_authenticates_and_encrypts() {
        let (mut a, mut b) = duplex(65536);
        let a_local = LocalIdentity::from_root(&RootKey::generate(), 1_000_000);
        let b_local = LocalIdentity::from_root(&RootKey::generate(), 1_000_000);
        let a_id = a_local.id.clone();
        let b_id = b_local.id.clone();
        let now = crate::unix_now();

        // Run both sides of the handshake concurrently.
        let b_task = tokio::spawn(async move {
            establish(&mut b, &b_local, false, now)
                .await
                .map(|(t, p)| (t, p, b))
        });
        let (mut ta, peer_a) = establish(&mut a, &a_local, true, now).await.unwrap();
        let (mut tb, peer_b, _b) = b_task.await.unwrap().unwrap();

        // Each side authenticated the other's self-certifying identity.
        assert_eq!(peer_a.id, b_id);
        assert_eq!(peer_b.id, a_id);

        // A frame on the wire is ciphertext: the plaintext marker must not appear.
        let plaintext = b"TOP-SECRET-MARKER-0xDEADBEEF".to_vec();
        let ciphertext = encrypt_frame(&mut ta, &plaintext).unwrap();
        let leaked = ciphertext
            .windows(b"TOP-SECRET".len())
            .any(|w| w == b"TOP-SECRET");
        assert!(!leaked, "plaintext leaked into the ciphertext frame");

        // The peer decrypts it back.
        let decrypted = decrypt_frame(&mut tb, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // A tampered ciphertext fails the AEAD.
        let mut tampered = ciphertext.clone();
        *tampered.last_mut().unwrap() ^= 0xFF;
        assert!(decrypt_frame(&mut tb, &tampered).is_err());
    }
}
