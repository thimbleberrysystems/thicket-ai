//! A minimal Thicket echo server for cross-language interop testing.
//!
//! Uses a deterministic identity (so a client can pin the expected id), binds a
//! TCP port, prints `<id_hex> <addr>` on the first stdout line, and replies to
//! every request by echoing its body. Killed by the test harness when done.

use thicket_core::{RootKey, WorkingKey};
use thicket_net::{unix_now, LocalIdentity, Reply, Request, Server};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let root = RootKey::from_seed(&[7u8; 32]);
    let working = WorkingKey::from_seed(&[107u8; 32]);
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
    // First line: the id + address the client connects to.
    println!("{} {}", root.id().hex(), addr);
    use std::io::Write;
    std::io::stdout().flush().unwrap();

    let server = Server::new(identity, |req: Request| async move { Reply::Ok(req.body) });
    server.serve(listener).await.unwrap();
}
