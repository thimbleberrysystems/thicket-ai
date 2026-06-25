//! A grant-gated Thicket server for cross-language authorization testing.
//!
//! Serves the `secret` capability **only** to callers presenting a valid grant,
//! verified with the core's `Grant::verify`. Deterministic identity (root seed
//! 12) so a client in another language can mint grants against it from the same
//! seeds. Prints `<id_hex> <addr>`; killed by the test harness.

use thicket_core::{RevocationSet, RootKey, WorkingKey};
use thicket_interconnect::ErrorCode;
use thicket_net::{unix_now, LocalIdentity, Reply, Request, Server};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let root = RootKey::from_seed(&[12u8; 32]);
    let working = WorkingKey::from_seed(&[112u8; 32]);
    let now = unix_now();
    let endorsement = root
        .endorse(&working.public(), 0, now + 1_000_000_000)
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

    let root_pub = identity.root_public_key.clone();
    let endorsements = identity.endorsements.clone();
    let server = Server::new(identity, move |req: Request| {
        let root_pub = root_pub.clone();
        let endorsements = endorsements.clone();
        async move {
            // The grant must verify against this server's identity, bind to the
            // handshake-authenticated caller, and cover the requested capability.
            let authorized = req
                .auth
                .as_ref()
                .map(|g| {
                    g.verify(
                        &root_pub,
                        &endorsements,
                        &req.peer.working_pub,
                        &req.capability,
                        unix_now(),
                        &RevocationSet::new(),
                    )
                    .is_ok()
                })
                .unwrap_or(false);
            if authorized {
                Reply::Ok(req.body)
            } else {
                Reply::Error(ErrorCode::Unauthorized, "valid grant required".into())
            }
        }
    });
    server.serve(listener).await.unwrap();
}
