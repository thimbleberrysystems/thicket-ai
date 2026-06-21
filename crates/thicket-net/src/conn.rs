//! An authenticated channel between two resources: request/response with
//! correlation + deadlines, streaming, and an inbound queue for the serving
//! side. Built over any `AsyncRead + AsyncWrite` (in-memory duplex or TCP).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use thicket_core::{Id, WorkingKey};
use thicket_interconnect::{EnvelopePayload, EnvelopeType, SignedEnvelope};
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::error::{Error, Result};
use crate::framing::{from_cbor, read_frame, to_cbor, write_frame};
use crate::handshake::handshake;
use crate::identity::{LocalIdentity, VerifiedPeer};
use crate::unix_now;

type Pending = Arc<Mutex<HashMap<Vec<u8>, oneshot::Sender<SignedEnvelope>>>>;
type Streams = Arc<Mutex<HashMap<Vec<u8>, mpsc::Sender<SignedEnvelope>>>>;

/// How long the authentication handshake may take before the connection attempt
/// is abandoned — a silent or hostile peer must not be able to hang `connect`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// An established, authenticated connection.
pub struct Conn {
    local_id: Id,
    working: WorkingKey,
    peer: VerifiedPeer,
    out_tx: mpsc::Sender<Vec<u8>>,
    pending: Pending,
    streams: Streams,
    inbound: tokio::sync::Mutex<mpsc::Receiver<SignedEnvelope>>,
    reader_task: AbortHandle,
    writer_task: AbortHandle,
}

impl Drop for Conn {
    fn drop(&mut self) {
        // Abort the I/O tasks so both stream halves are released promptly. Until
        // the reader half drops, a split stream stays open and the peer never
        // sees EOF — which would hang the peer's receive loop on teardown.
        self.reader_task.abort();
        self.writer_task.abort();
    }
}

impl Conn {
    /// Establish a connection over `stream`: handshake, then spawn the reader and
    /// writer tasks. If `expected_peer` is set, the authenticated peer must match.
    pub async fn connect<S>(
        stream: S,
        local: LocalIdentity,
        expected_peer: Option<Id>,
    ) -> Result<Arc<Conn>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut r, mut w) = split(stream);
        let peer = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            handshake(&mut r, &mut w, &local, unix_now()),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        if let Some(expected) = expected_peer {
            if expected != peer.id {
                return Err(Error::PeerMismatch);
            }
        }

        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
        let (inbound_tx, inbound_rx) = mpsc::channel::<SignedEnvelope>(256);
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let streams: Streams = Arc::new(Mutex::new(HashMap::new()));

        // Writer task: drain queued frames to the wire.
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if write_frame(&mut w, &frame).await.is_err() {
                    break;
                }
            }
        })
        .abort_handle();

        // Reader task: demultiplex incoming envelopes.
        let peer_r = peer.clone();
        let pending_r = pending.clone();
        let streams_r = streams.clone();
        let reader_task = tokio::spawn(async move {
            loop {
                let bytes = match read_frame(&mut r).await {
                    Ok(Some(b)) => b,
                    _ => break, // EOF or error: connection done
                };
                let env: SignedEnvelope = match from_cbor(&bytes) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                // Authenticate every message against the handshake-proven key.
                if env.payload.from != peer_r.id || env.verify_with_key(&peer_r.working_pub).is_err()
                {
                    continue;
                }
                route(&env, &pending_r, &streams_r, &inbound_tx);
            }
        })
        .abort_handle();

        Ok(Arc::new(Conn {
            local_id: local.id,
            working: local.working,
            peer,
            out_tx,
            pending,
            streams,
            inbound: tokio::sync::Mutex::new(inbound_rx),
            reader_task,
            writer_task,
        }))
    }

    pub fn peer(&self) -> &VerifiedPeer {
        &self.peer
    }

    pub fn local_id(&self) -> &Id {
        &self.local_id
    }

    /// Send a unary request and await its correlated response (or error), up to
    /// `timeout`. The payload is signed with the local working key.
    pub async fn call(&self, payload: EnvelopePayload, timeout: Duration) -> Result<SignedEnvelope> {
        let correlation = payload.correlation.clone();
        let signed = payload.sign(&self.working)?;

        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap()
            .insert(correlation.clone(), tx);

        self.out_tx
            .send(to_cbor(&signed)?)
            .await
            .map_err(|_| Error::Closed)?;

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(env)) => Ok(env),
            Ok(Err(_)) => Err(Error::Closed),
            Err(_) => {
                self.pending.lock().unwrap().remove(&correlation);
                Err(Error::Timeout)
            }
        }
    }

    /// Send a request and receive a stream of correlated chunks. The returned
    /// receiver closes when a chunk with `stream_end` arrives or the channel ends.
    pub async fn call_stream(
        &self,
        payload: EnvelopePayload,
    ) -> Result<mpsc::Receiver<SignedEnvelope>> {
        let correlation = payload.correlation.clone();
        let signed = payload.sign(&self.working)?;

        let (tx, rx) = mpsc::channel(64);
        self.streams.lock().unwrap().insert(correlation, tx);

        self.out_tx
            .send(to_cbor(&signed)?)
            .await
            .map_err(|_| Error::Closed)?;
        Ok(rx)
    }

    /// Sign and send an envelope without awaiting a reply (responses, errors,
    /// events, stream chunks).
    pub async fn send(&self, payload: EnvelopePayload) -> Result<()> {
        let signed = payload.sign(&self.working)?;
        self.out_tx
            .send(to_cbor(&signed)?)
            .await
            .map_err(|_| Error::Closed)
    }

    /// Receive the next inbound request/event (serving side). `None` when the
    /// connection has closed.
    pub async fn recv_request(&self) -> Option<SignedEnvelope> {
        self.inbound.lock().await.recv().await
    }
}

/// Demultiplex one incoming envelope. Deliberately **non-blocking**: the reader
/// must never await on application consumption, or a stalled consumer on one
/// logical channel would starve response delivery on every other (head-of-line
/// deadlock). Overflow degrades gracefully — a dropped response/request makes
/// the caller time out; a dropped stream chunk truncates that one stream.
fn route(
    env: &SignedEnvelope,
    pending: &Pending,
    streams: &Streams,
    inbound_tx: &mpsc::Sender<SignedEnvelope>,
) {
    match env.payload.typ {
        EnvelopeType::Response | EnvelopeType::Error => {
            let waiter = pending.lock().unwrap().remove(&env.payload.correlation);
            if let Some(tx) = waiter {
                let _ = tx.send(env.clone());
            }
        }
        EnvelopeType::StreamChunk => {
            let corr = env.payload.correlation.clone();
            let mut map = streams.lock().unwrap();
            if let Some(tx) = map.get(&corr) {
                if tx.try_send(env.clone()).is_err() {
                    // Consumer stalled or gone: close (truncate) the stream.
                    map.remove(&corr);
                    return;
                }
            }
            if env.payload.stream_end {
                map.remove(&corr);
            }
        }
        EnvelopeType::Request | EnvelopeType::Event | EnvelopeType::Cancel => {
            // Drop on overflow rather than block the reader; the caller times out.
            let _ = inbound_tx.try_send(env.clone());
        }
    }
}
