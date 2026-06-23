//! The Resource Record: the signed document a resource publishes (plan §2).
//!
//! A record is split into a [`RecordPayload`] (everything that is signed) and
//! the surrounding [`SignedRecord`] (the signer's working key + the signature).
//! This avoids a struct that signs over its own signature, and makes the
//! canonical signing input unambiguous.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::capability::{Capability, Lease, Locator, Visibility};
use crate::crypto::{signing_bytes, verify_raw};
use crate::error::{Error, Result};
use crate::identity::{verify_working_key, Id, KeyEndorsement, RevocationSet, WorkingKey};

const RECORD_DOMAIN: &str = "thicket-record-v1";

/// The signed body of a resource record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordPayload {
    /// Record schema + crypto scheme tag (multicodec-style, swappable).
    pub schema: String,
    /// Self-certifying identity = `sha256(root_public_key)`.
    pub id: Id,
    /// The root public key, so a verifier can check `id == sha256(this)`.
    #[serde(with = "serde_bytes")]
    pub root_public_key: Vec<u8>,
    /// Root-signed endorsements of the working keys this resource uses.
    pub keys: Vec<KeyEndorsement>,
    /// Open-set resource kind: model | memory | tool | trigger | agent | …
    pub kind: String,
    #[serde(default)]
    pub locators: Vec<Locator>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    /// Perf/economic profile (cost, latency, …). Advisory, string-encoded so it
    /// stays out of the float-canonicalization hazard in the signed form.
    #[serde(default)]
    pub profile: BTreeMap<String, String>,
    /// What the resource speaks, for negotiation (patterns, codecs, …).
    #[serde(default)]
    pub supports: BTreeMap<String, String>,
    #[serde(default)]
    pub visibility: Visibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
    /// Monotonic version; highest signed version wins on conflict.
    pub version: u64,
    /// Designated extension point; unknown keys are preserved, not rejected.
    #[serde(default)]
    pub ext: BTreeMap<String, String>,
}

impl RecordPayload {
    /// The exact canonical bytes that get signed for this payload — the
    /// cross-language ground truth (`domain ‖ 0x00 ‖ CBOR`).
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        signing_bytes(RECORD_DOMAIN, self)
    }

    /// Sign this payload with a working key, producing a [`SignedRecord`].
    pub fn sign(self, working: &WorkingKey) -> Result<SignedRecord> {
        let msg = signing_bytes(RECORD_DOMAIN, &self)?;
        let signature = working.sign(&msg);
        Ok(SignedRecord {
            payload: self,
            signer_pub: working.public(),
            signature,
        })
    }
}

/// A record plus the working-key signature over its payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRecord {
    pub payload: RecordPayload,
    /// The working public key that produced `signature`.
    #[serde(with = "serde_bytes")]
    pub signer_pub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SignedRecord {
    pub fn id(&self) -> &Id {
        &self.payload.id
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| Error::Serialization(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(|e| Error::Serialization(e.to_string()))
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| Error::Serialization(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Full verification (plan §7): id binding, root-endorsed and unexpired
    /// working key, not revoked, and a valid signature over the payload.
    pub fn verify(&self, now: u64, revocations: &RevocationSet) -> Result<()> {
        // 1–3. The signer must be a valid working key for this identity.
        verify_working_key(
            &self.payload.root_public_key,
            &self.payload.id,
            &self.payload.keys,
            &self.signer_pub,
            now,
            revocations,
        )?;

        // 4. The signature must verify over the canonical payload bytes.
        let msg = signing_bytes(RECORD_DOMAIN, &self.payload)?;
        verify_raw(&self.signer_pub, &msg, &self.signature)
    }
}
