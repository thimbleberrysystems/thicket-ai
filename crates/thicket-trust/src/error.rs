//! Errors for the trust layer.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] thicket_core::Error),
    #[error("attestation signature is invalid")]
    BadAttestation,
}

pub type Result<T> = std::result::Result<T, Error>;
