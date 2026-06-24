//! A minimal Thicket *caller* for cross-language interop testing — the mirror of
//! `echo_server`. It dials a fiber (e.g. a Python one) over TCP+Noise, invokes a
//! capability, and prints the outcome:
//!   line 1: `OK` | `ERROR` | `OTHER`
//!   line 2: the response body as UTF-8 (lossy)
//!
//! Usage: `rust_caller <fiber_id_hex> <host:port> <capability> [body]`

use std::time::Duration;

use thicket_core::{Id, RootKey, WorkingKey};
use thicket_interconnect::{EnvelopePayload, EnvelopeType};
use thicket_net::{unix_now, Conn, LocalIdentity};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fiber_id = Id::from_hex(&args[1]).expect("valid fiber id hex");
    let addr = args[2].clone();
    let capability = args[3].clone();
    let body = args.get(4).cloned().unwrap_or_default();

    // Deterministic ephemeral caller identity (it self-certifies; the Python
    // fiber authenticates it during the Noise handshake like any other peer).
    let root = RootKey::from_seed(&[9u8; 32]);
    let working = WorkingKey::from_seed(&[109u8; 32]);
    let now = unix_now();
    let endorsement = root
        .endorse(&working.public(), 0, now + 1_000_000_000)
        .unwrap();
    let local = LocalIdentity {
        id: root.id(),
        root_public_key: root.public(),
        endorsements: vec![endorsement],
        working,
    };

    let stream = TcpStream::connect(&addr).await.expect("tcp connect");
    let conn = Conn::connect(stream, local, Some(fiber_id.clone()))
        .await
        .expect("handshake");

    let payload = EnvelopePayload::request(conn.local_id().clone(), fiber_id, capability)
        .with_body(body.into_bytes());
    let resp = conn
        .call(payload, Duration::from_secs(10))
        .await
        .expect("call");

    match resp.payload.typ {
        EnvelopeType::Response => {
            println!("OK");
            print!("{}", String::from_utf8_lossy(&resp.payload.body));
        }
        EnvelopeType::Error => println!("ERROR"),
        _ => println!("OTHER"),
    }
}
