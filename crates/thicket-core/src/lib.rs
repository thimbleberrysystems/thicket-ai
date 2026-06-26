//! # thicket-core
//!
//! The Thicket kernel (plan §0 "stable kernel"): self-certifying identity, a
//! root→working key chain with rotation/revocation, signed resource records, and
//! capability descriptors. Everything here is defined as wire objects + a
//! canonical signing rule so any language can interoperate.

pub mod capability;
pub mod checkpoint;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod record;

pub use capability::{Capability, Io, Lease, Locator, Visibility};
pub use checkpoint::{Checkpoint, Step};
pub use crypto::{sha256, signing_bytes, verify_signature};
pub use error::{Error, Result};
pub use identity::{
    verify_revocation, verify_working_key, Id, KeyEndorsement, Revocation, RevocationSet, RootKey,
    WorkingKey,
};
pub use record::{RecordPayload, SignedRecord};
