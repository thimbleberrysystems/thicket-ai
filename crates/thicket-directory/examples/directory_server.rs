//! A Thicket directory server for cross-language interop testing.
//!
//! Deterministic identity; binds a TCP port; prints `<id_hex> <addr>`; serves the
//! directory plane (register/resolve/search/…) over a `MockEmbedder` registry.

use thicket_core::{RootKey, WorkingKey};
use thicket_directory::DirectoryServer;
use thicket_net::{unix_now, LocalIdentity};
use thicket_registry::{MockEmbedder, Registry};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let root = RootKey::from_seed(&[8u8; 32]);
    let working = WorkingKey::from_seed(&[108u8; 32]);
    let endorsement = root
        .endorse(&working.public(), 0, unix_now() + 1_000_000_000)
        .unwrap();
    let identity = LocalIdentity {
        id: root.id(),
        root_public_key: root.public(),
        endorsements: vec![endorsement],
        working,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("{} {}", root.id().hex(), addr);
    use std::io::Write;
    std::io::stdout().flush().unwrap();

    DirectoryServer::new(identity, Registry::new(MockEmbedder::default()))
        .serve(listener)
        .await
        .unwrap();
}
