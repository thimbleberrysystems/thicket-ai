//! Federation tests: collection selection, scatter-gather merge/dedupe, closed
//! (private) membership, and the TTL resolve cache.

use thicket_core::{Capability, Lease, RecordPayload, RootKey, SignedRecord, Visibility, WorkingKey};
use thicket_federation::{Federation, RegistryPeer};
use thicket_registry::{MockEmbedder, Need, Registry};

const NOW: u64 = 1_000_000;

/// Build a signed, public model/memory record.
fn record(kind: &str, desc: &str, tags: &[&str]) -> SignedRecord {
    let root = RootKey::generate();
    let wk = WorkingKey::generate();
    let endorsement = root.endorse(&wk.public(), NOW - 100, NOW + 100_000).unwrap();
    let payload = RecordPayload {
        schema: "thicket/record/1".into(),
        id: root.id(),
        root_public_key: root.public(),
        keys: vec![endorsement],
        kind: kind.into(),
        locators: vec![],
        capabilities: vec![Capability::new(kind, desc).with_tags(tags.iter().copied())],
        profile: Default::default(),
        supports: Default::default(),
        visibility: Visibility::Public,
        lease: Some(Lease {
            ttl: 3600,
            issued_at: NOW,
            expires_at: NOW + 3600,
        }),
        version: 1,
        ext: Default::default(),
    };
    payload.sign(&wk).unwrap()
}

fn registry_with(records: Vec<SignedRecord>) -> Registry<MockEmbedder> {
    let mut r = Registry::new(MockEmbedder::default());
    for rec in records {
        r.register(rec, NOW).unwrap();
    }
    r
}

/// A federation with a code-heavy registry at index 0 and an image-heavy one at
/// index 1.
fn code_then_image_federation() -> Federation<MockEmbedder> {
    let code = registry_with(vec![
        record("model", "refactor and reason over source code", &["code"]),
        record("model", "analyze source code for bugs", &["code"]),
    ]);
    let image = registry_with(vec![
        record("model", "generate images from text via diffusion", &["image"]),
        record("model", "edit and inpaint images from a prompt", &["image"]),
    ]);

    let mut fed = Federation::new(MockEmbedder::default());
    fed.add_peer(Box::new(RegistryPeer::new(code)), NOW);
    fed.add_peer(Box::new(RegistryPeer::new(image)), NOW);
    fed
}

#[test]
fn collection_selection_ranks_relevant_registry_first() {
    let fed = code_then_image_federation();
    assert_eq!(fed.peer_count(), 2);

    let code_first = fed.select_peers("refactor source code");
    assert_eq!(code_first[0], 0, "code registry should be selected first");

    let image_first = fed.select_peers("generate an image from text");
    assert_eq!(image_first[0], 1, "image registry should be selected first");
}

#[test]
fn federated_search_merges_and_ranks() {
    let fed = code_then_image_federation();
    let results = fed.search(&Need::new("refactor source code", 5), NOW);
    assert!(!results.is_empty());
    assert!(
        results[0]
            .payload
            .capabilities
            .iter()
            .any(|c| c.description.contains("source code")),
        "top federated result should be a code model"
    );
}

#[test]
fn scatter_gather_dedupes_replicated_records() {
    // The same record is replicated across two peers; it must appear once.
    let rec = record("model", "shared replicated model for chat", &["chat"]);
    let id = rec.id().clone();
    let mut fed = Federation::new(MockEmbedder::default());
    fed.add_peer(Box::new(RegistryPeer::new(registry_with(vec![rec.clone()]))), NOW);
    fed.add_peer(Box::new(RegistryPeer::new(registry_with(vec![rec.clone()]))), NOW);

    let results = fed.search(&Need::new("shared replicated model for chat", 10), NOW);
    let occurrences = results.iter().filter(|r| r.id() == &id).count();
    assert_eq!(occurrences, 1, "replicated record must be deduped");
}

#[test]
fn closed_federation_hides_non_members() {
    let inside = record("model", "discoverable inside the federation", &[]);
    let outside = record("model", "only in a non member registry", &[]);
    let inside_id = inside.id().clone();
    let outside_id = outside.id().clone();

    let mut fed = Federation::new(MockEmbedder::default());
    fed.add_peer(Box::new(RegistryPeer::new(registry_with(vec![inside]))), NOW);
    // `outside`'s registry is deliberately NOT added.
    let _unreachable = registry_with(vec![outside]);

    // The outside record is invisible to both search and resolve.
    let results = fed.search(&Need::new("only in a non member registry", 10), NOW);
    assert!(results.iter().all(|r| r.id() != &outside_id));
    assert!(fed.resolve(&outside_id, NOW).is_none());

    // The inside record is reachable.
    assert!(fed.resolve(&inside_id, NOW).is_some());
}

#[test]
fn resolve_caches_with_ttl() {
    let rec = record("memory", "vector store for embeddings", &[]);
    let id = rec.id().clone();
    let mut fed = Federation::new(MockEmbedder::default());
    fed.add_peer(Box::new(RegistryPeer::new(registry_with(vec![rec]))), NOW);

    assert!(!fed.is_cached(&id, NOW));
    assert!(fed.resolve(&id, NOW).is_some());
    assert!(fed.is_cached(&id, NOW), "resolve should populate the cache");
    // The cache entry expires with the record's lease TTL (3600).
    assert!(!fed.is_cached(&id, NOW + 3601), "cache entry should expire");
}
