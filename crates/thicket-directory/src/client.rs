//! A typed client for the networked directory.

use std::sync::Arc;
use std::time::Duration;

use thicket_core::{Id, SignedRecord};
use thicket_interconnect::{EnvelopePayload, EnvelopeType};
use thicket_net::{Conn, LocalIdentity};
use thicket_registry::Need;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::capability;
use crate::error::{Error, Result};
use crate::wire::{from_cbor, to_cbor, RenewArgs};

const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection to a directory, exposing the directory plane as typed calls.
pub struct DirectoryClient {
    conn: Arc<Conn>,
    local_id: Id,
    directory_id: Id,
}

impl DirectoryClient {
    /// Connect to the directory at `stream`, authenticating as `local` and
    /// requiring the directory to prove the expected `directory_id`.
    pub async fn connect<S>(stream: S, local: LocalIdentity, directory_id: Id) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let local_id = local.id.clone();
        let conn = Conn::connect(stream, local, Some(directory_id.clone())).await?;
        Ok(Self {
            conn,
            local_id,
            directory_id,
        })
    }

    async fn call(&self, capability: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let env = EnvelopePayload::request(self.local_id.clone(), self.directory_id.clone(), capability)
            .with_body(body);
        let resp = self.conn.call(env, CALL_TIMEOUT).await?;
        match resp.payload.typ {
            EnvelopeType::Error => Err(Error::Remote(
                resp.payload.error.map(|e| e.message).unwrap_or_default(),
            )),
            _ => Ok(resp.payload.body),
        }
    }

    /// Publish this resource's own signed record.
    pub async fn register(&self, record: &SignedRecord) -> Result<()> {
        self.call(capability::REGISTER, to_cbor(record)?).await?;
        Ok(())
    }

    /// Resolve a record by id; `Ok(None)` if the directory has no such record.
    pub async fn resolve(&self, id: &Id) -> Result<Option<SignedRecord>> {
        match self.call(capability::RESOLVE, to_cbor(id)?).await {
            Ok(body) => Ok(Some(from_cbor(&body)?)),
            Err(Error::Remote(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Search the directory by need; returns ranked records.
    pub async fn search(&self, need: &Need) -> Result<Vec<SignedRecord>> {
        let body = self.call(capability::SEARCH, to_cbor(need)?).await?;
        from_cbor(&body)
    }

    /// Renew this resource's lease, returning the new expiry.
    pub async fn renew(&self, ttl: u64) -> Result<u64> {
        let args = RenewArgs {
            id: self.local_id.clone(),
            ttl,
        };
        let body = self.call(capability::RENEW, to_cbor(&args)?).await?;
        from_cbor(&body)
    }

    /// Withdraw this resource's record.
    pub async fn deregister(&self) -> Result<()> {
        self.call(capability::DEREGISTER, to_cbor(&self.local_id)?).await?;
        Ok(())
    }

    pub fn directory_id(&self) -> &Id {
        &self.directory_id
    }
}
