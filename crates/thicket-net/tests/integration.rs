//! End-to-end integration across the whole core stack — the exact path a client
//! will follow:
//!
//!   register → search → resolve → connect (identity verified) → authorize → invoke
//!
//! The server's channel identity is the *same* identity it published in its
//! record, so discovery and connection are bound together: connecting with the
//! resolved id guarantees you reached the resource you found.

use std::collections::BTreeMap;
use std::time::Duration;

use thicket_core::{
    Capability, KeyEndorsement, Lease, Locator, RecordPayload, RevocationSet, RootKey, Visibility,
    WorkingKey,
};
use thicket_interconnect::{Caveats, EnvelopePayload, EnvelopeType, ErrorCode, Grant};
use thicket_net::{unix_now, Conn, LocalIdentity};
use thicket_registry::{MockEmbedder, Need, Registry};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn discover_then_connect_and_invoke() {
    let now = unix_now();

    // ---- the serving resource's single identity (used for BOTH its record and
    // its channel) ----
    let server_root = RootKey::generate();
    let server_working = WorkingKey::generate();
    let endorsement: KeyEndorsement = server_root
        .endorse(&server_working.public(), 0, now + 1_000_000)
        .unwrap();
    let server_id = server_root.id();
    let server_root_pub = server_root.public();
    let server_endorsements = vec![endorsement.clone()];

    // ---- the client identity ----
    let client_root = RootKey::generate();
    let client_local = LocalIdentity::from_root(&client_root, 1_000_000);
    let client_id = client_local.id.clone();
    let client_working_pub = client_local.working.public();

    // The server pre-authorizes the client to call "summarize".
    let grant = Grant::issue(
        server_id.clone(),
        &server_working,
        &client_working_pub,
        Caveats::new(["summarize"], now + 1_000_000),
    )
    .unwrap();

    // ---- the server binds a socket and publishes a record pointing at it ----
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let record = RecordPayload {
        schema: "thicket/record/1".into(),
        id: server_id.clone(),
        root_public_key: server_root_pub.clone(),
        keys: vec![endorsement],
        kind: "model".into(),
        locators: vec![Locator {
            protocol: "tcp".into(),
            endpoint: addr.to_string(),
        }],
        capabilities: vec![Capability::new("model", "summarize long passages of text")],
        profile: BTreeMap::new(),
        supports: BTreeMap::new(),
        visibility: Visibility::Public,
        lease: Some(Lease {
            ttl: 3600,
            issued_at: now,
            expires_at: now + 3600,
        }),
        version: 1,
        ext: BTreeMap::new(),
    }
    .sign(&server_working)
    .unwrap();

    let mut registry = Registry::new(MockEmbedder::default());
    registry.register(record, now).unwrap();

    // ---- the server accepts one connection and serves, enforcing the grant ----
    let server_id_task = server_id.clone();
    let server_local = LocalIdentity {
        id: server_id.clone(),
        root_public_key: server_root_pub.clone(),
        endorsements: server_endorsements.clone(),
        working: server_working,
    };
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let conn = Conn::connect(sock, server_local, None).await.unwrap();
        while let Some(req) = conn.recv_request().await {
            let cap = req.payload.capability.clone().unwrap_or_default();
            let authorized = req.payload.auth.as_ref().is_some_and(|g| {
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
            let resp = if authorized {
                EnvelopePayload::response(
                    server_id_task.clone(),
                    req.payload.from.clone(),
                    req.payload.correlation.clone(),
                )
                .with_body(b"summary: ...".to_vec())
            } else {
                EnvelopePayload::error(
                    server_id_task.clone(),
                    req.payload.from.clone(),
                    req.payload.correlation.clone(),
                    ErrorCode::Unauthorized,
                    "grant required",
                )
            };
            conn.send(resp).await.unwrap();
        }
    });

    // ---- the client: discover by need, resolve, connect to the locator ----
    let results = registry.search(&Need::new("help me summarize text", 1), now);
    assert_eq!(results.len(), 1);
    let found = &results[0];
    let target_id = found.id().clone();
    assert_eq!(target_id, server_id);
    let endpoint = found.payload.locators[0].endpoint.clone();

    let stream = TcpStream::connect(&endpoint).await.unwrap();
    // expected_peer = the id we resolved: the handshake must reach exactly it.
    let client = Conn::connect(stream, client_local, Some(target_id.clone()))
        .await
        .unwrap();
    assert_eq!(client.peer().id, server_id);

    // ---- invoke the discovered capability with the grant ----
    let resp = client
        .call(
            EnvelopePayload::request(client_id, target_id, "summarize").with_auth(grant),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    assert_eq!(resp.payload.typ, EnvelopeType::Response);
    assert_eq!(resp.payload.body, b"summary: ...".to_vec());

    drop(client);
    server.await.unwrap();
}
