//! Local identity bundle and verified-peer handle for a channel.

use thicket_core::{Id, KeyEndorsement, RootKey, WorkingKey};

/// Everything a node presents to authenticate itself on a channel: its id, the
/// root public key (so the peer can check `id == hash(root)`), the working-key
/// endorsements, and the working key it signs with.
pub struct LocalIdentity {
    pub id: Id,
    pub root_public_key: Vec<u8>,
    pub endorsements: Vec<KeyEndorsement>,
    pub working: WorkingKey,
}

impl LocalIdentity {
    /// Build a local identity from a root key, generating and endorsing a fresh
    /// working key valid for `valid_secs` from now.
    pub fn from_root(root: &RootKey, valid_secs: u64) -> Self {
        let working = WorkingKey::generate();
        let now = crate::unix_now();
        let endorsement = root
            .endorse(&working.public(), 0, now + valid_secs)
            .expect("endorse working key");
        LocalIdentity {
            id: root.id(),
            root_public_key: root.public(),
            endorsements: vec![endorsement],
            working,
        }
    }
}

/// A peer whose identity was authenticated during the handshake.
#[derive(Clone, Debug)]
pub struct VerifiedPeer {
    pub id: Id,
    pub working_pub: Vec<u8>,
}
