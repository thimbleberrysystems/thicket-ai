//! A reusable serving node: accept connections, complete the handshake, and
//! dispatch each inbound request to a handler that returns a reply. Authorization
//! policy (grant verification) lives in the handler, which can capture whatever
//! key material and state it needs.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use thicket_interconnect::{EnvelopePayload, EnvelopeType, ErrorCode, Grant, SignedEnvelope};
use tokio::net::TcpListener;

use crate::conn::Conn;
use crate::error::Result;
use crate::identity::{LocalIdentity, VerifiedPeer};

/// An inbound request handed to a [`Server`] handler.
pub struct Request {
    pub capability: String,
    pub body: Vec<u8>,
    pub auth: Option<Grant>,
    pub peer: VerifiedPeer,
    pub envelope: SignedEnvelope,
}

/// What a handler returns for a request.
pub enum Reply {
    Ok(Vec<u8>),
    Error(ErrorCode, String),
}

type BoxedHandler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Reply> + Send>> + Send + Sync>;

/// A serving node bound to one identity, dispatching requests to a handler.
pub struct Server {
    identity: LocalIdentity,
    handler: BoxedHandler,
}

impl Server {
    /// Create a server. `handler` is an async function from [`Request`] to
    /// [`Reply`]; it runs once per inbound request.
    pub fn new<F, Fut>(identity: LocalIdentity, handler: F) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Reply> + Send + 'static,
    {
        Self {
            identity,
            handler: Arc::new(move |req| Box::pin(handler(req))),
        }
    }

    /// Accept connections forever, serving each on its own task. Returns only on
    /// listener error.
    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (sock, _) = listener.accept().await?;
            let identity = self.identity.clone();
            let handler = self.handler.clone();
            tokio::spawn(async move {
                if let Ok(conn) = Conn::accept(sock, identity, None).await {
                    serve_conn(conn, handler).await;
                }
            });
        }
    }
}

/// Serve one established connection until it closes.
async fn serve_conn(conn: Arc<Conn>, handler: BoxedHandler) {
    while let Some(env) = conn.recv_request().await {
        if env.payload.typ != EnvelopeType::Request {
            continue; // events/cancels are not request/reply
        }
        let req = Request {
            capability: env.payload.capability.clone().unwrap_or_default(),
            body: env.payload.body.clone(),
            auth: env.payload.auth.clone(),
            peer: conn.peer().clone(),
            envelope: env.clone(),
        };
        let reply = handler(req).await;
        let resp = match reply {
            Reply::Ok(body) => EnvelopePayload::response(
                conn.local_id().clone(),
                env.payload.from.clone(),
                env.payload.correlation.clone(),
            )
            .with_body(body),
            Reply::Error(code, message) => EnvelopePayload::error(
                conn.local_id().clone(),
                env.payload.from.clone(),
                env.payload.correlation.clone(),
                code,
                message,
            ),
        };
        let _ = conn.send(resp).await;
    }
}
