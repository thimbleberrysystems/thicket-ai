//! Errors for the networked directory.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Net(#[from] thicket_net::Error),
    #[error(transparent)]
    Core(#[from] thicket_core::Error),
    #[error("codec: {0}")]
    Codec(String),
    #[error("directory rejected the request: {0}")]
    Remote(String),
}

pub type Result<T> = std::result::Result<T, Error>;
