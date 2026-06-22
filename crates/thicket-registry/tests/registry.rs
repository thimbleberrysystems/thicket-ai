//! Registry behavior: registration/verification, staleness, id resolution,
//! visibility, lease expiry, revocation, and semantic ranking over mock
//! resources (mock LLMs / memory standing in for real ones).

use std::collections::BTreeMap;

use thicket_core::{
    Capability, Lease, Locator, RecordPayload, RootKey, SignedRecord, Visibility, WorkingKey,
};
use thicket_registry::{MockEmbedder, Need, Registry, RegistryError};

const NOW: u64 = 1_000_000;

/// A held identity plus its signed record, so tests can revoke/rotate.
struct Resource {
    root: RootKey,
    working: WorkingKey,
    record: SignedRecord,
}

/// Build a signed resource record. `desc` drives semantic search.
fn make_resource(
    kind: &str,
    desc: &str,
    tags: &[&str],
    visibility: Visibility,
    expires_at: u64,
    now: u64,
) -> Resource {
    let root = RootKey::generate();
    let working = WorkingKey::generate();
    let endorsement = root
        .endorse(&working.public(), now - 100, now + 100_000)
        .unwrap();

    let payload = RecordPayload {
        schema: "thicket/record/1".into(),
        id: root.id(),
        root_public_key: root.public(),
        keys: vec![endorsement],
        kind: kind.into(),
        locators: vec![Locator {
            protocol: "grpc".into(),
            endpoint: "10.0.0.9:7000".into(),
        }],
        capabilities: vec![Capability::new(kind, desc).with_tags(tags.iter().copied())],
        profile: BTreeMap::new(),
        supports: BTreeMap::new(),
        visibility,
        lease: Some(Lease {
            ttl: 3600,
            issued_at: now,
            expires_at,
        }),
        version: 1,
        ext: BTreeMap::new(),
    };

    let record = payload.sign(&working).unwrap();
    Resource {
        root,
        working,
        record,
    }
}

fn registry() -> Registry<MockEmbedder> {
    Registry::new(MockEmbedder::default())
}

#[test]
fn register_and_resolve() {
    let mut reg = registry();
    let r = make_resource(
        "model",
        "general purpose chat model",
        &["chat"],
        Visibility::Public,
        NOW + 3600,
        NOW,
    );
    let id = r.record.id().clone();
    reg.register(r.record, NOW).unwrap();
    assert_eq!(reg.len(), 1);

    let resolved = reg.resolve(&id, NOW).unwrap();
    assert_eq!(resolved.id(), &id);
    assert_eq!(resolved.payload.kind, "model");
}

#[test]
fn register_rejects_invalid_record() {
    let mut reg = registry();
    let mut r = make_resource("model", "x", &[], Visibility::Public, NOW + 3600, NOW);
    r.record.payload.kind = "tampered".into(); // breaks the signature
    let err = reg.register(r.record, NOW).unwrap_err();
    assert!(matches!(err, RegistryError::Core(_)));
    assert!(reg.is_empty());
}

#[test]
fn register_rejects_stale_version() {
    let mut reg = registry();
    let r = make_resource("model", "v1", &[], Visibility::Public, NOW + 3600, NOW);
    let id = r.record.id().clone();
    reg.register(r.record, NOW).unwrap();

    // Re-publish the same identity at version 1 again (not newer).
    let endorsement = r
        .root
        .endorse(&r.working.public(), NOW - 100, NOW + 100_000)
        .unwrap();
    let payload = RecordPayload {
        schema: "thicket/record/1".into(),
        id: id.clone(),
        root_public_key: r.root.public(),
        keys: vec![endorsement],
        kind: "model".into(),
        locators: vec![],
        capabilities: vec![],
        profile: BTreeMap::new(),
        supports: BTreeMap::new(),
        visibility: Visibility::Public,
        lease: None,
        version: 1,
        ext: BTreeMap::new(),
    };
    let stale = payload.sign(&r.working).unwrap();
    assert!(matches!(
        reg.register(stale, NOW).unwrap_err(),
        RegistryError::Stale
    ));
}

#[test]
fn search_ranks_by_semantic_relevance() {
    let mut reg = registry();
    reg.register(
        make_resource(
            "model",
            "long context reasoning and refactoring of source code",
            &["code"],
            Visibility::Public,
            NOW + 3600,
            NOW,
        )
        .record,
        NOW,
    )
    .unwrap();
    let code_model_present = reg.len();
    reg.register(
        make_resource(
            "model",
            "image generation from text prompts using diffusion",
            &["image"],
            Visibility::Public,
            NOW + 3600,
            NOW,
        )
        .record,
        NOW,
    )
    .unwrap();
    reg.register(
        make_resource(
            "memory",
            "vector store for persisting and retrieving embeddings",
            &["memory"],
            Visibility::Public,
            NOW + 3600,
            NOW,
        )
        .record,
        NOW,
    )
    .unwrap();
    assert_eq!(code_model_present, 1);
    assert_eq!(reg.len(), 3);

    let need = Need::new("help me refactor source code", 3);
    let results = reg.search(&need, NOW);
    assert!(!results.is_empty());
    // The code model shares the most vocabulary with the query.
    assert!(results[0]
        .payload
        .capabilities
        .iter()
        .any(|c| c.description.contains("source code")));
}

#[test]
fn search_excludes_non_public_and_expired() {
    let mut reg = registry();
    reg.register(
        make_resource(
            "model",
            "public chat model",
            &[],
            Visibility::Public,
            NOW + 3600,
            NOW,
        )
        .record,
        NOW,
    )
    .unwrap();

    let unlisted = make_resource(
        "model",
        "unlisted chat model",
        &[],
        Visibility::Unlisted,
        NOW + 3600,
        NOW,
    );
    let unlisted_id = unlisted.record.id().clone();
    reg.register(unlisted.record, NOW).unwrap();

    let results = reg.search(&Need::new("chat model", 10), NOW);
    assert_eq!(results.len(), 1, "search must skip unlisted records");

    // ...but unlisted is still resolvable by id.
    assert!(reg.resolve(&unlisted_id, NOW).is_ok());

    // After the lease expires, the public record drops out of search.
    let later = NOW + 100_000;
    assert!(reg.search(&Need::new("chat model", 10), later).is_empty());
}

#[test]
fn private_records_are_not_resolvable_without_authz() {
    let mut reg = registry();
    let r = make_resource(
        "tool",
        "internal deploy trigger",
        &[],
        Visibility::Private,
        NOW + 3600,
        NOW,
    );
    let id = r.record.id().clone();
    reg.register(r.record, NOW).unwrap();
    assert!(matches!(
        reg.resolve(&id, NOW).unwrap_err(),
        RegistryError::NotAuthorized
    ));
}

#[test]
fn renew_extends_lease_and_keeps_record_alive() {
    let mut reg = registry();
    // A record that expires soon.
    let r = make_resource(
        "model",
        "renewable",
        &[],
        Visibility::Public,
        NOW + 100,
        NOW,
    );
    let id = r.record.id().clone();
    reg.register(r.record, NOW).unwrap();

    // Past the original expiry it would drop out of search...
    assert!(reg.search(&Need::new("renewable", 5), NOW + 200).is_empty());

    // ...but after renewing, it is live again.
    let new_expiry = reg.renew(&id, NOW + 50, 3600).unwrap();
    assert_eq!(new_expiry, NOW + 50 + 3600);
    assert!(reg.resolve(&id, NOW + 200).is_ok());
    assert_eq!(reg.search(&Need::new("renewable", 5), NOW + 200).len(), 1);
}

#[test]
fn deregister_and_sweep_remove_records() {
    let mut reg = registry();
    let a = make_resource("model", "alpha", &[], Visibility::Public, NOW + 100, NOW);
    let b = make_resource("model", "beta", &[], Visibility::Public, NOW + 5000, NOW);
    let a_id = a.record.id().clone();
    reg.register(a.record, NOW).unwrap();
    reg.register(b.record, NOW).unwrap();

    assert!(reg.deregister(&a_id));
    assert!(!reg.deregister(&a_id)); // already gone
    assert_eq!(reg.len(), 1);

    // `b` expires at NOW+5000; sweeping past that evicts it.
    assert_eq!(reg.sweep_expired(NOW + 6000), 1);
    assert!(reg.is_empty());
}

#[test]
fn revocation_drops_the_record() {
    let mut reg = registry();
    let r = make_resource(
        "model",
        "soon revoked",
        &[],
        Visibility::Public,
        NOW + 3600,
        NOW,
    );
    let id = r.record.id().clone();
    reg.register(r.record, NOW).unwrap();
    assert!(reg.resolve(&id, NOW).is_ok());

    let revocation = r.root.revoke(&r.working.public(), NOW).unwrap();
    reg.revoke(&id, &revocation).unwrap();

    assert!(matches!(
        reg.resolve(&id, NOW).unwrap_err(),
        RegistryError::NotFound
    ));
}
