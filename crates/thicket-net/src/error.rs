//! Errors for the networking layer.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(String),
    #[error("codec: {0}")]
    Codec(String),
    #[error("handshake failed")]
    Handshake,
    #[error("peer identity is not the expected one")]
    PeerMismatch,
    #[error("request timed out")]
    Timeout,
    #[error("connection closed")]
    Closed,
    #[error("frame exceeds the maximum size")]
    FrameTooLarge,
    #[error(transparent)]
    Core(#[from] thicket_core::Error),
    #[error(transparent)]
    Interconnect(#[from] thicket_interconnect::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
