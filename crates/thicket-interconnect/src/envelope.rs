//! The universal message envelope (plan §6).
//!
//! The framework standardizes the frame and the interaction patterns; the
//! `body` is opaque and never interpreted. Like a record, an envelope is split
//! into a signed [`EnvelopePayload`] and the signer's key + signature.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thicket_core::{
    signing_bytes, verify_signature, verify_working_key, Id, KeyEndorsement, RevocationSet,
    WorkingKey,
};

use crate::error::{Error, Result};
use crate::grant::Grant;
use crate::util::fresh_bytes;

const ENVELOPE_DOMAIN: &str = "thicket-envelope-v1";

/// The interaction-pattern discriminator (open set; plan §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeType {
    Request,
    Response,
    Event,
    Error,
    StreamChunk,
    Cancel,
}

/// A coded error reason for `EnvelopeType::Error` (plan §13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    NotFound,
    Unauthorized,
    Timeout,
    Unavailable,
    BadRequest,
    Conflict,
    Internal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: ErrorCode,
    pub message: String,
}

/// Cross-cutting context propagated in-band (plan §6): distributed tracing,
/// deadline, and budget. Fibers self-report spans against it and **tighten** it
/// for downstream calls (a child's deadline/budget can only shrink).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Context {
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    pub trace_id: Vec<u8>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    pub span_id: Vec<u8>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    pub parent_span_id: Vec<u8>,
    /// Hard deadline (unix seconds); `None` = none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<u64>,
    /// Remaining spend allowance; `None` = unmetered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<u64>,
}

impl Context {
    pub fn is_empty(&self) -> bool {
        self.trace_id.is_empty()
            && self.span_id.is_empty()
            && self.parent_span_id.is_empty()
            && self.deadline.is_none()
            && self.budget.is_none()
    }

    /// Derive the context for a downstream call: same trace, a fresh span, this
    /// span becomes the parent, and deadline/budget can only **tighten**
    /// (child ≤ parent). `local_deadline` lets the caller impose a tighter bound;
    /// `spent` debits the budget.
    pub fn child(&self, new_span_id: Vec<u8>, local_deadline: Option<u64>, spent: u64) -> Context {
        let deadline = match (self.deadline, local_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        Context {
            trace_id: self.trace_id.clone(),
            span_id: new_span_id,
            parent_span_id: self.span_id.clone(),
            deadline,
            budget: self.budget.map(|b| b.saturating_sub(spent)),
        }
    }

    /// Has the deadline passed at `now`?
    pub fn deadline_passed(&self, now: u64) -> bool {
        self.deadline.is_some_and(|d| now > d)
    }
}

/// The signed body of an envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvelopePayload {
    pub v: u32,
    pub from: Id,
    pub to: Id,
    pub typ: EnvelopeType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// Links request ↔ response(s) and a multi-turn exchange.
    #[serde(with = "serde_bytes")]
    pub correlation: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Cross-cutting context: tracing + deadline + budget (plan §6).
    #[serde(default, skip_serializing_if = "Context::is_empty")]
    pub context: Context,
    /// Authorization grant for the invocation (plan §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Grant>,
    /// Ordered stream sequence for `StreamChunk`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_seq: Option<u64>,
    #[serde(default)]
    pub stream_end: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    /// Opaque, domain-specific payload — never interpreted by the framework.
    #[serde(default, with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(default)]
    pub ext: BTreeMap<String, String>,
}

impl EnvelopePayload {
    fn base(from: Id, to: Id, typ: EnvelopeType, correlation: Vec<u8>) -> Self {
        Self {
            v: 1,
            from,
            to,
            typ,
            capability: None,
            correlation,
            content_type: None,
            context: Context::default(),
            auth: None,
            stream_seq: None,
            stream_end: false,
            error: None,
            body: Vec::new(),
            ext: BTreeMap::new(),
        }
    }

    /// Start a new request to `to` for `capability`, with a fresh correlation.
    pub fn request(from: Id, to: Id, capability: impl Into<String>) -> Self {
        let mut e = Self::base(from, to, EnvelopeType::Request, fresh_bytes(16));
        e.capability = Some(capability.into());
        e
    }

    /// A response correlated to a prior request.
    pub fn response(from: Id, to: Id, correlation: Vec<u8>) -> Self {
        Self::base(from, to, EnvelopeType::Response, correlation)
    }

    /// An error reply correlated to a prior request.
    pub fn error(
        from: Id,
        to: Id,
        correlation: Vec<u8>,
        code: ErrorCode,
        message: impl Into<String>,
    ) -> Self {
        let mut e = Self::base(from, to, EnvelopeType::Error, correlation);
        e.error = Some(ErrorInfo {
            code,
            message: message.into(),
        });
        e
    }

    /// One ordered chunk of a streamed response.
    pub fn stream_chunk(from: Id, to: Id, correlation: Vec<u8>, seq: u64, end: bool) -> Self {
        let mut e = Self::base(from, to, EnvelopeType::StreamChunk, correlation);
        e.stream_seq = Some(seq);
        e.stream_end = end;
        e
    }

    /// An event for pub/sub subscribers.
    pub fn event(from: Id, to: Id, topic: impl Into<String>) -> Self {
        let mut e = Self::base(from, to, EnvelopeType::Event, fresh_bytes(16));
        e.capability = Some(topic.into());
        e
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn with_deadline(mut self, deadline: u64) -> Self {
        self.context.deadline = Some(deadline);
        self
    }

    pub fn with_context(mut self, context: Context) -> Self {
        self.context = context;
        self
    }

    pub fn with_auth(mut self, grant: Grant) -> Self {
        self.auth = Some(grant);
        self
    }

    /// The exact canonical bytes signed for this payload (cross-language truth).
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        Ok(signing_bytes(ENVELOPE_DOMAIN, self)?)
    }

    /// Sign with a working key, producing a [`SignedEnvelope`].
    pub fn sign(self, working: &WorkingKey) -> Result<SignedEnvelope> {
        let msg = signing_bytes(ENVELOPE_DOMAIN, &self)?;
        let signature = working.sign(&msg);
        Ok(SignedEnvelope {
            payload: self,
            signer_pub: working.public(),
            signature,
        })
    }
}

/// An envelope plus the sender's working-key signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub payload: EnvelopePayload,
    #[serde(with = "serde_bytes")]
    pub signer_pub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SignedEnvelope {
    /// Has this envelope's deadline passed at `now`?
    pub fn is_expired(&self, now: u64) -> bool {
        self.payload.context.deadline_passed(now)
    }

    /// Fast per-message check for an already-authenticated channel: the sender
    /// must be the working key proven at handshake, and the signature must hold.
    /// Skips the full key-chain walk (done once at handshake).
    pub fn verify_with_key(&self, working_pub: &[u8]) -> Result<()> {
        if self.signer_pub != working_pub {
            return Err(Error::BadEnvelope);
        }
        let msg = signing_bytes(ENVELOPE_DOMAIN, &self.payload)?;
        verify_signature(&self.signer_pub, &msg, &self.signature).map_err(|_| Error::BadEnvelope)
    }

    /// Verify the sender's signature against their (already-known) key material.
    /// In a live channel the peer's keys were authenticated at handshake time.
    pub fn verify(
        &self,
        sender_root_pub: &[u8],
        sender_endorsements: &[KeyEndorsement],
        now: u64,
        revocations: &RevocationSet,
    ) -> Result<()> {
        verify_working_key(
            sender_root_pub,
            &self.payload.from,
            sender_endorsements,
            &self.signer_pub,
            now,
            revocations,
        )?;
        let msg = signing_bytes(ENVELOPE_DOMAIN, &self.payload)?;
        verify_signature(&self.signer_pub, &msg, &self.signature).map_err(|_| Error::BadEnvelope)
    }
}
