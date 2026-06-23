//! Self-certifying identity with a two-level key chain (plan §7).
//!
//! `id = sha256(root_public_key)` — permanent. The cold-stored **root key**
//! endorses short-lived **working keys** that do day-to-day signing. Rotation =
//! the root endorses a new working key (identity unchanged). Revocation = the
//! root signs a revocation for a compromised working key.

use std::collections::HashSet;
use std::fmt;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::{sha256, signing_bytes, verify_raw};
use crate::error::{Error, Result};

const ENDORSE_DOMAIN: &str = "thicket-endorsement-v1";
const REVOKE_DOMAIN: &str = "thicket-revocation-v1";

/// A self-certifying identity: `sha256(root_public_key)`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id(#[serde(with = "serde_bytes")] Vec<u8>);

impl Id {
    /// Derive the id from a 32-byte root public key.
    pub fn from_root_public(root_pub: &[u8]) -> Result<Id> {
        if root_pub.len() != 32 {
            return Err(Error::BadKey);
        }
        Ok(Id(sha256(root_pub).to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({}…)", &self.hex()[..self.hex().len().min(12)])
    }
}

/// The long-lived root key. Holds secret material; never serialized.
pub struct RootKey {
    signing: SigningKey,
}

impl fmt::Debug for RootKey {
    // Redacted: never expose secret key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootKey").field("id", &self.id()).finish()
    }
}

impl RootKey {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
        }
    }

    pub fn public(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec()
    }

    pub fn id(&self) -> Id {
        Id::from_root_public(&self.public()).expect("root public key is 32 bytes")
    }

    /// Endorse a working key for the validity window `[not_before, not_after]`.
    pub fn endorse(
        &self,
        working_pub: &[u8],
        not_before: u64,
        not_after: u64,
    ) -> Result<KeyEndorsement> {
        let view = EndorsementView {
            working_pub,
            not_before,
            not_after,
        };
        let msg = signing_bytes(ENDORSE_DOMAIN, &view)?;
        let sig = self.signing.sign(&msg);
        Ok(KeyEndorsement {
            working_pub: working_pub.to_vec(),
            not_before,
            not_after,
            root_sig: sig.to_bytes().to_vec(),
        })
    }

    /// Revoke a working key as of `issued_at`.
    pub fn revoke(&self, working_pub: &[u8], issued_at: u64) -> Result<Revocation> {
        let view = RevocationView {
            working_pub,
            issued_at,
        };
        let msg = signing_bytes(REVOKE_DOMAIN, &view)?;
        let sig = self.signing.sign(&msg);
        Ok(Revocation {
            working_pub: working_pub.to_vec(),
            issued_at,
            root_sig: sig.to_bytes().to_vec(),
        })
    }
}

/// A short-lived working key used for record/envelope signing. Secret material.
///
/// `Clone` so one identity can sign on many concurrent connections (e.g. a
/// server accepting many channels). Cloning copies secret key bytes.
#[derive(Clone)]
pub struct WorkingKey {
    signing: SigningKey,
}

impl fmt::Debug for WorkingKey {
    // Redacted: print only the (public) verifying key, never the secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkingKey")
            .field("public", &hex::encode(self.public()))
            .finish()
    }
}

impl WorkingKey {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
        }
    }

    pub fn public(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec()
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing.sign(msg).to_bytes().to_vec()
    }
}

#[derive(Serialize)]
struct EndorsementView<'a> {
    #[serde(with = "serde_bytes")]
    working_pub: &'a [u8],
    not_before: u64,
    not_after: u64,
}

#[derive(Serialize)]
struct RevocationView<'a> {
    #[serde(with = "serde_bytes")]
    working_pub: &'a [u8],
    issued_at: u64,
}

/// A root-signed endorsement of a working key, carried inside a record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEndorsement {
    #[serde(with = "serde_bytes")]
    pub(crate) working_pub: Vec<u8>,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) root_sig: Vec<u8>,
}

impl KeyEndorsement {
    pub fn working_pub(&self) -> &[u8] {
        &self.working_pub
    }
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// A root-signed statement that a working key is revoked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revocation {
    #[serde(with = "serde_bytes")]
    pub(crate) working_pub: Vec<u8>,
    pub(crate) issued_at: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) root_sig: Vec<u8>,
}

impl Revocation {
    pub fn working_pub(&self) -> &[u8] {
        &self.working_pub
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
}

/// Verify that `endorsement` was actually signed by `root_pub`.
pub(crate) fn verify_endorsement(root_pub: &[u8], e: &KeyEndorsement) -> Result<()> {
    let view = EndorsementView {
        working_pub: &e.working_pub,
        not_before: e.not_before,
        not_after: e.not_after,
    };
    let msg = signing_bytes(ENDORSE_DOMAIN, &view)?;
    verify_raw(root_pub, &msg, &e.root_sig).map_err(|_| Error::BadEndorsement)
}

/// Verify that `revocation` was actually signed by `root_pub`.
pub fn verify_revocation(root_pub: &[u8], r: &Revocation) -> Result<()> {
    let view = RevocationView {
        working_pub: &r.working_pub,
        issued_at: r.issued_at,
    };
    let msg = signing_bytes(REVOKE_DOMAIN, &view)?;
    verify_raw(root_pub, &msg, &r.root_sig).map_err(|_| Error::BadEndorsement)
}

/// Verify that `signer_pub` is a currently-valid working key for the identity
/// rooted at `root_pub` (plan §7): id binding, a matching root endorsement valid
/// at `now`, and not revoked. Shared by records, envelopes, grants, and proofs.
pub fn verify_working_key(
    root_pub: &[u8],
    id: &Id,
    endorsements: &[KeyEndorsement],
    signer_pub: &[u8],
    now: u64,
    revocations: &RevocationSet,
) -> Result<()> {
    let expected = Id::from_root_public(root_pub)?;
    if &expected != id {
        return Err(Error::IdMismatch);
    }
    let e = endorsements
        .iter()
        .find(|e| e.working_pub() == signer_pub)
        .ok_or(Error::NoValidEndorsement)?;
    verify_endorsement(root_pub, e)?;
    if now < e.not_before() || now > e.not_after() {
        return Err(Error::EndorsementExpired);
    }
    if revocations.is_revoked(signer_pub) {
        return Err(Error::Revoked);
    }
    Ok(())
}

/// A set of revoked working keys, consulted during record verification.
#[derive(Debug, Default, Clone)]
pub struct RevocationSet {
    revoked: HashSet<Vec<u8>>,
}

impl RevocationSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke_key(&mut self, working_pub: &[u8]) {
        self.revoked.insert(working_pub.to_vec());
    }

    pub fn is_revoked(&self, working_pub: &[u8]) -> bool {
        self.revoked.contains(working_pub)
    }
}
