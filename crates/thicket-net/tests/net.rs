//! Networking tests over both an in-memory duplex and a real TCP socket:
//! framing, authenticated handshake, request/response, timeouts, peer-identity
//! checks, grant-gated invocation, and streaming.

use std::sync::Arc;
use std::time::Duration;

use thicket_core::{Id, KeyEndorsement, RevocationSet, RootKey, WorkingKey};
use thicket_interconnect::{Caveats, EnvelopePayload, EnvelopeType, ErrorCode, Grant};
use thicket_net::framing::{read_frame, write_frame};
use thicket_net::{unix_now, Conn, LocalIdentity};
use tokio::io::duplex;
use tokio::net::{TcpListener, TcpStream};

fn node(valid: u64) -> (LocalIdentity, Id) {
    let root = RootKey::generate();
    let local = LocalIdentity::from_root(&root, valid);
    let id = local.id.clone();
    (local, id)
}

/// Echo every request body back as a response.
async fn serve_echo(conn: Arc<Conn>) {
    while let Some(req) = conn.recv_request().await {
        let resp = EnvelopePayload::response(
            conn.local_id().clone(),
            req.payload.from.clone(),
            req.payload.correlation.clone(),
        )
        .with_body(req.payload.body.clone());
        let _ = conn.send(resp).await;
    }
}

#[tokio::test]
async fn framing_roundtrips() {
    let (mut a, mut b) = duplex(1024);
    let writer = tokio::spawn(async move {
        write_frame(&mut a, b"hello frame").await.unwrap();
        write_frame(&mut a, b"second").await.unwrap();
    });
    assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"hello frame");
    assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"second");
    writer.await.unwrap();
}

#[tokio::test]
async fn request_response_over_duplex() {
    let (cs, ss) = duplex(65536);
    let (server_local, server_id) = node(1_000_000);
    let (client_local, client_id) = node(1_000_000);

    let server = tokio::spawn(async move {
        let conn = Conn::accept(ss, server_local, None).await.unwrap();
        serve_echo(conn).await;
    });

    let client = Conn::connect(cs, client_local, Some(server_id.clone()))
        .await
        .unwrap();
    let resp = client
        .call(
            EnvelopePayload::request(client_id, server_id, "echo").with_body(b"ping".to_vec()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(resp.payload.typ, EnvelopeType::Response);
    assert_eq!(resp.payload.body, b"ping".to_vec());

    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn request_times_out_when_unanswered() {
    let (cs, ss) = duplex(65536);
    let (server_local, server_id) = node(1_000_000);
    let (client_local, client_id) = node(1_000_000);

    let server = tokio::spawn(async move {
        let conn = Conn::accept(ss, server_local, None).await.unwrap();
        // Receive the request but never answer; keep the conn alive.
        let _req = conn.recv_request().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    let client = Conn::connect(cs, client_local, Some(server_id.clone()))
        .await
        .unwrap();
    let err = client
        .call(
            EnvelopePayload::request(client_id, server_id, "echo"),
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, thicket_net::Error::Timeout));
    server.abort();
}

#[tokio::test]
async fn connecting_to_unexpected_peer_is_rejected() {
    let (cs, ss) = duplex(65536);
    let (server_local, _server_id) = node(1_000_000);
    let (client_local, _client_id) = node(1_000_000);
    let (_other_local, wrong_id) = node(1_000_000);

    let server = tokio::spawn(async move {
        // Server still completes its side of the handshake.
        let _ = Conn::accept(ss, server_local, None).await;
    });

    let result = Conn::connect(cs, client_local, Some(wrong_id)).await;
    assert!(matches!(result, Err(thicket_net::Error::PeerMismatch)));
    let _ = server.await;
}

#[tokio::test]
async fn invocation_is_gated_by_grants() {
    // Build the server identity by hand so we keep its working key to issue a
    // grant and its key material to verify one.
    let server_root = RootKey::generate();
    let server_working = WorkingKey::generate();
    let now = unix_now();
    let endorsement: KeyEndorsement = server_root
        .endorse(&server_working.public(), 0, now + 1_000_000)
        .unwrap();
    let server_id = server_root.id();
    let server_root_pub = server_root.public();
    let server_endorsements = vec![endorsement.clone()];

    let (client_local, client_id) = node(1_000_000);
    let client_working_pub = client_local.working.public();

    // The server authorizes the client to call "echo".
    let grant = Grant::issue(
        server_id.clone(),
        &server_working,
        &client_working_pub,
        Caveats::new(["echo"], now + 1_000_000),
    )
    .unwrap();

    let server_local = LocalIdentity {
        id: server_id.clone(),
        root_public_key: server_root_pub.clone(),
        endorsements: server_endorsements.clone(),
        working: server_working,
    };

    let (cs, ss) = duplex(65536);
    let server_id_task = server_id.clone();
    let server = tokio::spawn(async move {
        let conn = Conn::accept(ss, server_local, None).await.unwrap();
        while let Some(req) = conn.recv_request().await {
            let cap = req.payload.capability.clone().unwrap_or_default();
            let ok = req.payload.auth.as_ref().is_some_and(|g| {
                g.verify(
                    &server_root_pub,
                    &server_endorsements,
                    &conn.peer().working_pub,
                    &cap,
                    unix_now(),
                    &RevocationSet::new(),
                )
                .is_ok()
            });
            let resp = if ok {
                EnvelopePayload::response(
                    server_id_task.clone(),
                    req.payload.from.clone(),
                    req.payload.correlation.clone(),
                )
                .with_body(b"authorized".to_vec())
            } else {
                EnvelopePayload::error(
                    server_id_task.clone(),
                    req.payload.from.clone(),
                    req.payload.correlation.clone(),
                    ErrorCode::Unauthorized,
                    "missing or invalid grant",
                )
            };
            conn.send(resp).await.unwrap();
        }
    });

    let client = Conn::connect(cs, client_local, Some(server_id.clone()))
        .await
        .unwrap();

    // With a valid grant: authorized.
    let ok = client
        .call(
            EnvelopePayload::request(client_id.clone(), server_id.clone(), "echo")
                .with_auth(grant.clone()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(ok.payload.typ, EnvelopeType::Response);
    assert_eq!(ok.payload.body, b"authorized".to_vec());

    // Without a grant: rejected.
    let denied = client
        .call(
            EnvelopePayload::request(client_id, server_id, "echo"),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(denied.payload.typ, EnvelopeType::Error);
    assert_eq!(denied.payload.error.unwrap().code, ErrorCode::Unauthorized);

    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn streaming_delivers_ordered_chunks() {
    let (cs, ss) = duplex(65536);
    let (server_local, server_id) = node(1_000_000);
    let (client_local, client_id) = node(1_000_000);

    let server_id_task = server_id.clone();
    let server = tokio::spawn(async move {
        let conn = Conn::accept(ss, server_local, None).await.unwrap();
        while let Some(req) = conn.recv_request().await {
            if req.payload.capability.as_deref() == Some("count") {
                for seq in 0..3u64 {
                    let chunk = EnvelopePayload::stream_chunk(
                        server_id_task.clone(),
                        req.payload.from.clone(),
                        req.payload.correlation.clone(),
                        seq,
                        seq == 2,
                    )
                    .with_body(vec![seq as u8]);
                    conn.send(chunk).await.unwrap();
                }
            }
        }
    });

    let client = Conn::connect(cs, client_local, Some(server_id.clone()))
        .await
        .unwrap();
    let mut rx = client
        .call_stream(EnvelopePayload::request(client_id, server_id, "count"))
        .await
        .unwrap();

    let mut got = Vec::new();
    while let Some(chunk) = rx.recv().await {
        got.push(chunk.payload.body[0]);
    }
    assert_eq!(got, vec![0, 1, 2]);

    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn request_response_over_real_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (server_local, server_id) = node(1_000_000);
    let (client_local, client_id) = node(1_000_000);

    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let conn = Conn::accept(sock, server_local, None).await.unwrap();
        serve_echo(conn).await;
    });

    let sock = TcpStream::connect(addr).await.unwrap();
    let client = Conn::connect(sock, client_local, Some(server_id.clone()))
        .await
        .unwrap();
    let resp = client
        .call(
            EnvelopePayload::request(client_id, server_id, "echo").with_body(b"over-tcp".to_vec()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(resp.payload.body, b"over-tcp".to_vec());

    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn many_concurrent_calls_are_multiplexed() {
    let (cs, ss) = duplex(65536);
    let (server_local, server_id) = node(1_000_000);
    let (client_local, client_id) = node(1_000_000);

    let server = tokio::spawn(async move {
        let conn = Conn::accept(ss, server_local, None).await.unwrap();
        serve_echo(conn).await;
    });

    let client = Conn::connect(cs, client_local, Some(server_id.clone()))
        .await
        .unwrap();

    // Fire many calls concurrently on one connection; each must get its own
    // correlated reply back (no cross-talk, no head-of-line stall).
    let mut handles = Vec::new();
    for i in 0..50u8 {
        let c = client.clone();
        let (cid, sid) = (client_id.clone(), server_id.clone());
        handles.push(tokio::spawn(async move {
            let resp = c
                .call(
                    EnvelopePayload::request(cid, sid, "echo").with_body(vec![i]),
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            assert_eq!(resp.payload.body, vec![i]);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn bidirectional_nodes_serve_and_call() {
    // Both ends serve echo AND call each other: the non-blocking reader must not
    // deadlock when a node is simultaneously a server and a client.
    let (a_stream, b_stream) = duplex(65536);
    let (a_local, a_id) = node(1_000_000);
    let (b_local, b_id) = node(1_000_000);

    let a_task = tokio::spawn(Conn::accept(a_stream, a_local, None));
    let b = Conn::connect(b_stream, b_local, None).await.unwrap();
    let a = a_task.await.unwrap().unwrap();

    let a_srv = tokio::spawn(serve_echo(a.clone()));
    let b_srv = tokio::spawn(serve_echo(b.clone()));

    let from_a = a
        .call(
            EnvelopePayload::request(a_id.clone(), b_id.clone(), "echo")
                .with_body(b"a->b".to_vec()),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let from_b = b
        .call(
            EnvelopePayload::request(b_id.clone(), a_id.clone(), "echo")
                .with_body(b"b->a".to_vec()),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    assert_eq!(from_a.payload.body, b"a->b".to_vec());
    assert_eq!(from_b.payload.body, b"b->a".to_vec());

    a_srv.abort();
    b_srv.abort();
}

#[tokio::test]
async fn pubsub_delivers_events_to_subscriber() {
    let (cs, ss) = duplex(65536);
    let (server_local, server_id) = node(1_000_000);
    let (client_local, client_id) = node(1_000_000);

    let sid = server_id.clone();
    let server = tokio::spawn(async move {
        let conn = Conn::accept(ss, server_local, None).await.unwrap();
        while let Some(req) = conn.recv_request().await {
            if req.payload.capability.as_deref() == Some("start") {
                for i in 0..3u8 {
                    conn.emit("updates", vec![i]).await.unwrap();
                }
            }
        }
    });

    let client = Conn::connect(cs, client_local, Some(server_id.clone()))
        .await
        .unwrap();
    let mut rx = client.subscribe("updates");
    // Trigger the server to start emitting after we are subscribed.
    client
        .send(EnvelopePayload::request(client_id, sid, "start"))
        .await
        .unwrap();

    let mut got = Vec::new();
    for _ in 0..3 {
        got.push(rx.recv().await.unwrap().payload.body[0]);
    }
    assert_eq!(got, vec![0, 1, 2]);

    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn server_abstraction_dispatches_by_capability() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (server_local, server_id) = node(1_000_000);
    let (client_local, client_id) = node(1_000_000);

    let server = thicket_net::Server::new(server_local, |req: thicket_net::Request| async move {
        match req.capability.as_str() {
            "echo" => thicket_net::Reply::Ok(req.body),
            _ => thicket_net::Reply::Error(ErrorCode::NotFound, "unknown capability".into()),
        }
    });
    let server_task = tokio::spawn(server.serve(listener));

    let client = Conn::connect(
        TcpStream::connect(addr).await.unwrap(),
        client_local,
        Some(server_id.clone()),
    )
    .await
    .unwrap();

    let ok = client
        .call(
            EnvelopePayload::request(client_id.clone(), server_id.clone(), "echo")
                .with_body(b"hey".to_vec()),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(ok.payload.body, b"hey".to_vec());

    let miss = client
        .call(
            EnvelopePayload::request(client_id, server_id, "nope"),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(miss.payload.typ, EnvelopeType::Error);

    drop(client);
    server_task.abort();
}

#[test]
fn peer_key_freshness_boundary() {
    assert!(thicket_net::peer_key_fresh(100, 50));
    assert!(thicket_net::peer_key_fresh(100, 100));
    assert!(!thicket_net::peer_key_fresh(100, 101));
}
