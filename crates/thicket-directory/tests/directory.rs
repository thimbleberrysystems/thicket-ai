//! Networked-directory tests: register / resolve / search / renew / deregister
//! over a real TCP channel, plus the identity gate that stops a resource from
//! registering or withdrawing records it does not own.

use std::collections::BTreeMap;

use thicket_core::{
    Capability, Lease, Locator, RecordPayload, RootKey, SignedRecord, Visibility, WorkingKey,
};
use thicket_directory::{DirectoryClient, DirectoryServer};
use thicket_net::{unix_now, LocalIdentity};
use thicket_registry::{MockEmbedder, Need, Registry};
use tokio::net::{TcpListener, TcpStream};

/// Build a signed record for the given identity (must match the channel id used
/// to register it).
fn record_for(
    id: thicket_core::Id,
    root_pub: Vec<u8>,
    endorsements: Vec<thicket_core::KeyEndorsement>,
    working: &WorkingKey,
    desc: &str,
    now: u64,
) -> SignedRecord {
    RecordPayload {
        schema: "thicket/record/1".into(),
        id,
        root_public_key: root_pub,
        keys: endorsements,
        kind: "model".into(),
        locators: vec![Locator {
            protocol: "tcp".into(),
            endpoint: "10.0.0.1:9".into(),
        }],
        capabilities: vec![Capability::new("model", desc)],
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
    .sign(working)
    .unwrap()
}

#[tokio::test]
async fn directory_full_lifecycle_over_tcp() {
    let now = unix_now();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // The directory's own identity.
    let dir_root = RootKey::generate();
    let dir_local = LocalIdentity::from_root(&dir_root, 1_000_000);
    let dir_id = dir_local.id.clone();
    let server = DirectoryServer::new(dir_local, Registry::new(MockEmbedder::default()));
    let server_task = tokio::spawn(server.serve(listener));

    // A resource that registers itself.
    let res_local = LocalIdentity::from_root(&RootKey::generate(), 1_000_000);
    let res_id = res_local.id.clone();
    let record = record_for(
        res_id.clone(),
        res_local.root_public_key.clone(),
        res_local.endorsements.clone(),
        &res_local.working,
        "summarize long passages of text",
        now,
    );

    let client = DirectoryClient::connect(
        TcpStream::connect(addr).await.unwrap(),
        res_local,
        dir_id.clone(),
    )
    .await
    .unwrap();

    // register → resolve → search → renew → deregister
    client.register(&record).await.unwrap();

    let resolved = client.resolve(&res_id).await.unwrap().unwrap();
    assert_eq!(resolved.id(), &res_id);

    let results = client
        .search(&Need::new("help me summarize text", 5))
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id(), &res_id);

    let new_expiry = client.renew(7200).await.unwrap();
    assert!(new_expiry >= now + 7200);

    client.deregister().await.unwrap();
    assert!(client.resolve(&res_id).await.unwrap().is_none());

    server_task.abort();
}

#[tokio::test]
async fn directory_rejects_registering_another_identity() {
    let now = unix_now();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let dir_local = LocalIdentity::from_root(&RootKey::generate(), 1_000_000);
    let dir_id = dir_local.id.clone();
    let server = DirectoryServer::new(dir_local, Registry::new(MockEmbedder::default()));
    let server_task = tokio::spawn(server.serve(listener));

    // The connecting resource.
    let res_local = LocalIdentity::from_root(&RootKey::generate(), 1_000_000);

    // A record belonging to a DIFFERENT identity.
    let other_root = RootKey::generate();
    let other_working = WorkingKey::generate();
    let other_endorsement = other_root
        .endorse(&other_working.public(), 0, now + 1_000_000)
        .unwrap();
    let foreign_record = record_for(
        other_root.id(),
        other_root.public(),
        vec![other_endorsement],
        &other_working,
        "not mine to register",
        now,
    );

    let client =
        DirectoryClient::connect(TcpStream::connect(addr).await.unwrap(), res_local, dir_id)
            .await
            .unwrap();

    // The directory must refuse: you can only register your own identity.
    assert!(client.register(&foreign_record).await.is_err());

    server_task.abort();
}
