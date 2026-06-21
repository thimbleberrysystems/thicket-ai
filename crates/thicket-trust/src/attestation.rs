//! Signed attestations: one resource vouching for another (plan §9).

use serde::{Deserialize, Serialize};
use thicket_core::{
    signing_bytes, verify_signature, verify_working_key, Id, KeyEndorsement, RevocationSet,
    WorkingKey,
};

use crate::error::{Error, Result};

const ATTEST_DOMAIN: &str = "thicket-attestation-v1";

#[derive(Serialize)]
struct AttestView<'a> {
    subject: &'a Id,
    claim: &'a str,
    score_bits: u32,
    issued_at: u64,
    attester: &'a Id,
}

/// A signed statement by `attester` about `subject` for `claim`, with a quality
/// `score` in `[0, 1]`. Trust edges form the graph reputation aggregates over.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub subject: Id,
    pub claim: String,
    pub score: f32,
    pub issued_at: u64,
    pub attester: Id,
    pub attester_pub: Vec<u8>,
    pub sig: Vec<u8>,
}

impl Attestation {
    pub fn issue(
        attester: &Id,
        attester_working: &WorkingKey,
        subject: Id,
        claim: impl Into<String>,
        score: f32,
        now: u64,
    ) -> Result<Attestation> {
        let claim = claim.into();
        let view = AttestView {
            subject: &subject,
            claim: &claim,
            score_bits: score.to_bits(),
            issued_at: now,
            attester,
        };
        let sig = attester_working.sign(&signing_bytes(ATTEST_DOMAIN, &view)?);
        Ok(Attestation {
            subject,
            claim,
            score,
            issued_at: now,
            attester: attester.clone(),
            attester_pub: attester_working.public(),
            sig,
        })
    }

    /// Verify the attester actually signed this with a valid working key.
    pub fn verify(
        &self,
        attester_root_pub: &[u8],
        attester_endorsements: &[KeyEndorsement],
        now: u64,
        revocations: &RevocationSet,
    ) -> Result<()> {
        verify_working_key(
            attester_root_pub,
            &self.attester,
            attester_endorsements,
            &self.attester_pub,
            now,
            revocations,
        )?;
        let view = AttestView {
            subject: &self.subject,
            claim: &self.claim,
            score_bits: self.score.to_bits(),
            issued_at: self.issued_at,
            attester: &self.attester,
        };
        verify_signature(
            &self.attester_pub,
            &signing_bytes(ATTEST_DOMAIN, &view)?,
            &self.sig,
        )
        .map_err(|_| Error::BadAttestation)
    }
}
