//! Capability grants: signed, attenuable authorization tokens (plan §8).
//!
//! A grant authorizes a holder to invoke specific capabilities on a target
//! resource, subject to caveats. A holder may **attenuate** — issue a strictly
//! narrower sub-grant to a delegate — but never widen. That monotonic-narrowing
//! invariant, enforced at verification, is the safety primitive for agents
//! spawning agents: a parent can hand a child only a subset of its own
//! authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thicket_core::{
    signing_bytes, verify_signature, verify_working_key, Id, KeyEndorsement, RevocationSet,
    WorkingKey,
};

use crate::error::{Error, Result};

const GRANT_DOMAIN: &str = "thicket-grant-v1";

/// The restrictions attached to a grant link.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Caveats {
    /// Allowed capability names; the wildcard `"*"` permits all.
    pub capabilities: BTreeSet<String>,
    /// Hard expiry (unix seconds).
    pub not_after: u64,
    /// Open, extensible constraints (rate, budget, audience scoping, …). A child
    /// must preserve every parent constraint exactly (cannot loosen).
    #[serde(default)]
    pub constraints: BTreeMap<String, String>,
}

impl Caveats {
    /// Convenience constructor for a capability set with an expiry.
    pub fn new(capabilities: impl IntoIterator<Item = impl Into<String>>, not_after: u64) -> Self {
        Self {
            capabilities: capabilities.into_iter().map(Into::into).collect(),
            not_after,
            constraints: BTreeMap::new(),
        }
    }

    pub fn allows_capability(&self, cap: &str) -> bool {
        self.capabilities.contains("*") || self.capabilities.contains(cap)
    }

    /// Verify that `self` only narrows `parent` (never widens).
    fn ensure_narrows(&self, parent: &Caveats) -> Result<()> {
        if !parent.capabilities.contains("*") {
            for c in &self.capabilities {
                // a child may not introduce the wildcard or any cap the parent lacks
                if c == "*" || !parent.capabilities.contains(c) {
                    return Err(Error::BadAttenuation);
                }
            }
        }
        if self.not_after > parent.not_after {
            return Err(Error::BadAttenuation);
        }
        for (k, v) in &parent.constraints {
            if self.constraints.get(k) != Some(v) {
                return Err(Error::BadAttenuation);
            }
        }
        Ok(())
    }
}

/// One link in a grant's delegation chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantLink {
    #[serde(with = "serde_bytes")]
    pub issuer_pub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub audience_pub: Vec<u8>,
    pub caveats: Caveats,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

#[derive(Serialize)]
struct LinkView<'a> {
    target: &'a Id,
    #[serde(with = "serde_bytes")]
    issuer_pub: &'a [u8],
    #[serde(with = "serde_bytes")]
    audience_pub: &'a [u8],
    caveats: &'a Caveats,
    #[serde(with = "serde_bytes")]
    prev: &'a [u8],
}

/// A capability grant: an authorization chain rooted at `target`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub target: Id,
    pub links: Vec<GrantLink>,
}

impl Grant {
    /// Issue a root grant: the target resource authorizes `audience_pub`.
    pub fn issue(
        target: Id,
        target_key: &WorkingKey,
        audience_pub: &[u8],
        caveats: Caveats,
    ) -> Result<Grant> {
        let issuer_pub = target_key.public();
        let view = LinkView {
            target: &target,
            issuer_pub: &issuer_pub,
            audience_pub,
            caveats: &caveats,
            prev: &[],
        };
        let sig = target_key.sign(&signing_bytes(GRANT_DOMAIN, &view)?);
        Ok(Grant {
            target,
            links: vec![GrantLink {
                issuer_pub,
                audience_pub: audience_pub.to_vec(),
                caveats,
                sig,
            }],
        })
    }

    /// Attenuate: the current holder issues a strictly narrower sub-grant to a
    /// new delegate. Fails if `holder_key` is not the current audience or if the
    /// new caveats widen authority.
    pub fn attenuate(
        &self,
        holder_key: &WorkingKey,
        new_audience_pub: &[u8],
        caveats: Caveats,
    ) -> Result<Grant> {
        let last = self.links.last().ok_or(Error::EmptyGrant)?;
        if holder_key.public() != last.audience_pub {
            return Err(Error::NotHolder);
        }
        caveats.ensure_narrows(&last.caveats)?;

        let issuer_pub = holder_key.public();
        let view = LinkView {
            target: &self.target,
            issuer_pub: &issuer_pub,
            audience_pub: new_audience_pub,
            caveats: &caveats,
            prev: &last.sig,
        };
        let sig = holder_key.sign(&signing_bytes(GRANT_DOMAIN, &view)?);

        let mut links = self.links.clone();
        links.push(GrantLink {
            issuer_pub,
            audience_pub: new_audience_pub.to_vec(),
            caveats,
            sig,
        });
        Ok(Grant {
            target: self.target.clone(),
            links,
        })
    }

    /// Verify, from the target's perspective, that this grant authorizes
    /// `caller_pub` to invoke `capability` at `now`. Checks: target binding,
    /// head issued by a valid target working key, each link signed by the prior
    /// audience, monotonic narrowing, expiry, and capability permission.
    pub fn verify(
        &self,
        target_root_pub: &[u8],
        target_endorsements: &[KeyEndorsement],
        caller_pub: &[u8],
        capability: &str,
        now: u64,
        revocations: &RevocationSet,
    ) -> Result<()> {
        if self.links.is_empty() {
            return Err(Error::EmptyGrant);
        }
        if Id::from_root_public(target_root_pub)? != self.target {
            return Err(Error::TargetMismatch);
        }

        let mut prev: &[u8] = &[];
        let mut parent: Option<&Caveats> = None;
        for (i, link) in self.links.iter().enumerate() {
            // Reject if any key in the chain (issuer or audience) is revoked — so a
            // resource can kill its own issuing key or a delegated sub-grant.
            if revocations.is_revoked(&link.issuer_pub) || revocations.is_revoked(&link.audience_pub) {
                return Err(thicket_core::Error::Revoked.into());
            }
            if i == 0 {
                // The head must be issued by a valid working key of the target.
                verify_working_key(
                    target_root_pub,
                    &self.target,
                    target_endorsements,
                    &link.issuer_pub,
                    now,
                    revocations,
                )?;
            } else if link.issuer_pub != self.links[i - 1].audience_pub {
                return Err(Error::BrokenChain);
            }

            if let Some(p) = parent {
                link.caveats.ensure_narrows(p)?;
            }

            let view = LinkView {
                target: &self.target,
                issuer_pub: &link.issuer_pub,
                audience_pub: &link.audience_pub,
                caveats: &link.caveats,
                prev,
            };
            verify_signature(
                &link.issuer_pub,
                &signing_bytes(GRANT_DOMAIN, &view)?,
                &link.sig,
            )
            .map_err(|_| Error::BadSignature)?;

            if !link.caveats.allows_capability(capability) {
                return Err(Error::CapabilityNotAllowed);
            }
            if now > link.caveats.not_after {
                return Err(Error::Expired);
            }

            prev = &link.sig;
            parent = Some(&link.caveats);
        }

        if self.links.last().expect("non-empty").audience_pub != caller_pub {
            return Err(Error::AudienceMismatch);
        }
        Ok(())
    }

    /// Resource-side constraint check (parity with the Python SDK's
    /// `grant.satisfies`): every constraint in the grant's effective (last-link,
    /// tightest) caveats must be matched exactly by `attributes`. A grant with no
    /// constraints is satisfied by anything. Pair with `verify` — this checks
    /// scope, not authenticity.
    pub fn satisfies(&self, attributes: &BTreeMap<String, String>) -> bool {
        match self.links.last() {
            None => true,
            Some(link) => link
                .caveats
                .constraints
                .iter()
                .all(|(k, v)| attributes.get(k) == Some(v)),
        }
    }
}
