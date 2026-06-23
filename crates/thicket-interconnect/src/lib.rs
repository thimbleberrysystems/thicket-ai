//! # thicket-interconnect
//!
//! The talking half of Thicket (plan §6, §8): the universal message envelope,
//! attenuable capability grants, and the authentication handshake. Defined as
//! signed wire objects + verification logic; the encrypting transport is a
//! separate adapter.

pub mod envelope;
pub mod error;
pub mod grant;
pub mod handshake;
mod util;

pub use envelope::{
    Context, EnvelopePayload, EnvelopeType, ErrorCode, ErrorInfo, SignedEnvelope,
};
pub use error::{Error, Result};
pub use grant::{Caveats, Grant, GrantLink};
pub use handshake::{prove, verify_proof, Challenge, Proof};
