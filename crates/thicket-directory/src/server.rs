//! The directory server: a [`Registry`] served over `thicket-net`.
//!
//! Read operations (resolve/search) are open. Mutating operations
//! (register/renew/deregister) are gated by the channel identity — a caller may
//! only manage a record whose id equals the identity it authenticated with, so
//! nobody can register or revoke records on another resource's behalf.

use std::sync::Arc;

use thicket_core::{Id, SignedRecord};
use thicket_interconnect::ErrorCode;
use thicket_net::{unix_now, LocalIdentity, Reply, Request, Server};
use thicket_registry::{Embedder, Need, Registry};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::capability;
use crate::error::Result;
use crate::wire::{from_cbor, to_cbor, RenewArgs};

/// Serves a registry as a Thicket directory resource.
pub struct DirectoryServer<E: Embedder + 'static> {
    identity: LocalIdentity,
    registry: Arc<Mutex<Registry<E>>>,
}

impl<E: Embedder + 'static> std::fmt::Debug for DirectoryServer<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryServer")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl<E: Embedder + 'static> DirectoryServer<E> {
    pub fn new(identity: LocalIdentity, registry: Registry<E>) -> Self {
        Self {
            identity,
            registry: Arc::new(Mutex::new(registry)),
        }
    }

    /// Shared handle to the underlying registry (e.g. for periodic sweeping).
    pub fn registry(&self) -> Arc<Mutex<Registry<E>>> {
        self.registry.clone()
    }

    /// Accept directory clients on `listener` until it errors.
    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        let registry = self.registry;
        let server = Server::new(self.identity, move |req| {
            let registry = registry.clone();
            async move { handle(registry, req).await }
        });
        server.serve(listener).await?;
        Ok(())
    }
}

async fn handle<E: Embedder>(registry: Arc<Mutex<Registry<E>>>, req: Request) -> Reply {
    let now = unix_now();
    match req.capability.as_str() {
        capability::REGISTER => {
            let record: SignedRecord = match from_cbor(&req.body) {
                Ok(r) => r,
                Err(_) => return Reply::Error(ErrorCode::BadRequest, "malformed record".into()),
            };
            // A resource may only publish a record for its own identity.
            if record.payload.id != req.peer.id {
                return Reply::Error(
                    ErrorCode::Unauthorized,
                    "may only register your own identity".into(),
                );
            }
            match registry.lock().await.register(record, now) {
                Ok(()) => Reply::Ok(Vec::new()),
                Err(e) => Reply::Error(ErrorCode::Conflict, e.to_string()),
            }
        }
        capability::RESOLVE => {
            let id: Id = match from_cbor(&req.body) {
                Ok(i) => i,
                Err(_) => return Reply::Error(ErrorCode::BadRequest, "malformed id".into()),
            };
            match registry.lock().await.resolve(&id, now) {
                Ok(record) => encode_reply(&record),
                Err(_) => Reply::Error(ErrorCode::NotFound, "no such record".into()),
            }
        }
        capability::SEARCH => {
            let need: Need = match from_cbor(&req.body) {
                Ok(n) => n,
                Err(_) => return Reply::Error(ErrorCode::BadRequest, "malformed query".into()),
            };
            let results = registry.lock().await.search(&need, now);
            encode_reply(&results)
        }
        capability::RENEW => {
            let args: RenewArgs = match from_cbor(&req.body) {
                Ok(a) => a,
                Err(_) => return Reply::Error(ErrorCode::BadRequest, "malformed renew".into()),
            };
            if args.id != req.peer.id {
                return Reply::Error(ErrorCode::Unauthorized, "not your record".into());
            }
            match registry.lock().await.renew(&args.id, now, args.ttl) {
                Ok(expiry) => encode_reply(&expiry),
                Err(_) => Reply::Error(ErrorCode::NotFound, "no such record".into()),
            }
        }
        capability::DEREGISTER => {
            let id: Id = match from_cbor(&req.body) {
                Ok(i) => i,
                Err(_) => return Reply::Error(ErrorCode::BadRequest, "malformed id".into()),
            };
            if id != req.peer.id {
                return Reply::Error(ErrorCode::Unauthorized, "not your record".into());
            }
            registry.lock().await.deregister(&id);
            Reply::Ok(Vec::new())
        }
        other => Reply::Error(
            ErrorCode::NotFound,
            format!("unknown directory capability: {other}"),
        ),
    }
}

fn encode_reply<T: serde::Serialize>(value: &T) -> Reply {
    match to_cbor(value) {
        Ok(bytes) => Reply::Ok(bytes),
        Err(_) => Reply::Error(ErrorCode::Internal, "encode failed".into()),
    }
}
