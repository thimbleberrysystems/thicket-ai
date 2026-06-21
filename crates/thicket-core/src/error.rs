//! Error type for the Thicket kernel.

/// Errors produced while constructing, serializing, or verifying kernel objects.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("invalid key material (expected 32 bytes)")]
    BadKey,
    #[error("invalid signature material (expected 64 bytes)")]
    BadSig,
    #[error("signature verification failed")]
    VerifyFailed,
    #[error("id does not match root public key")]
    IdMismatch,
    #[error("no working-key endorsement matches the signer")]
    NoValidEndorsement,
    #[error("working-key endorsement is expired or not yet valid")]
    EndorsementExpired,
    #[error("working key has been revoked")]
    Revoked,
    #[error("endorsement/revocation signature is not valid under the root key")]
    BadEndorsement,
}

/// Convenience result alias for the kernel.
pub type Result<T> = std::result::Result<T, Error>;
