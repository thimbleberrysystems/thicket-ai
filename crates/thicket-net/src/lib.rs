//! # thicket-net
//!
//! The networking spine (plan §6): length-delimited framing, a mutually
//! authenticated handshake, and an authenticated [`Conn`] supporting
//! request/response with deadlines, streaming, and an inbound queue for serving.
//! Generic over any `AsyncRead + AsyncWrite`, so the same logic runs over an
//! in-memory duplex (tests) or a real TCP socket.

pub mod conn;
pub mod error;
pub mod framing;
pub mod handshake;
pub mod identity;
pub mod server;

pub use conn::{peer_key_fresh, Conn};
pub use error::{Error, Result};
pub use framing::{read_frame, write_frame, MAX_FRAME};
pub use handshake::handshake;
pub use identity::{LocalIdentity, VerifiedPeer};
pub use server::{Reply, Request, Server};

/// Current unix time in seconds (validity windows, lease checks).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
