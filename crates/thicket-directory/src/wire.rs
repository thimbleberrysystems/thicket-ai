//! Wire bodies for directory requests/responses (CBOR-encoded).

use serde::{Deserialize, Serialize};
use thicket_core::Id;

use crate::error::{Error, Result};

/// Arguments for a lease renewal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RenewArgs {
    pub id: Id,
    pub ttl: u64,
}

pub(crate) fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| Error::Codec(e.to_string()))?;
    Ok(buf)
}

pub(crate) fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|e| Error::Codec(e.to_string()))
}
