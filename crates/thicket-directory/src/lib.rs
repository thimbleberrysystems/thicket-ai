//! # thicket-directory
//!
//! The directory plane (plan §14) exposed over the wire: a [`Registry`] served
//! as an ordinary Thicket resource over `thicket-net`, with a typed client.
//!
//! This is "registry as a resource" — the same handshake, envelope, and identity
//! machinery that secures resource invocation also secures directory access.
//! Mutating operations (register / renew / deregister) are gated by the channel
//! identity: a caller may only manage records whose id equals its own.
//!
//! [`Registry`]: thicket_registry::Registry

pub mod client;
pub mod error;
pub mod server;
pub mod wire;

pub use client::DirectoryClient;
pub use error::{Error, Result};
pub use server::DirectoryServer;

/// Capability names for the directory plane.
pub mod capability {
    pub const REGISTER: &str = "directory.register";
    pub const RESOLVE: &str = "directory.resolve";
    pub const SEARCH: &str = "directory.search";
    pub const RENEW: &str = "directory.renew";
    pub const DEREGISTER: &str = "directory.deregister";
}
