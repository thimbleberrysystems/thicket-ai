//! Errors for the interconnect layer.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] thicket_core::Error),
    #[error("grant has no links")]
    EmptyGrant,
    #[error("grant target does not match the resource")]
    TargetMismatch,
    #[error("grant delegation chain is broken")]
    BrokenChain,
    #[error("grant link signature is invalid")]
    BadSignature,
    #[error("attenuation widened authority (must only narrow)")]
    BadAttenuation,
    #[error("capability not permitted by grant")]
    CapabilityNotAllowed,
    #[error("grant has expired")]
    Expired,
    #[error("grant audience is not the caller")]
    AudienceMismatch,
    #[error("signer is not the current grant holder")]
    NotHolder,
    #[error("envelope signature is invalid")]
    BadEnvelope,
    #[error("handshake proof is invalid")]
    BadProof,
    #[error("deadline exceeded")]
    DeadlineExceeded,
}

pub type Result<T> = std::result::Result<T, Error>;
