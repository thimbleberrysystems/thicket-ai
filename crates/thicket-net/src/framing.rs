//! Length-delimited framing: a 4-byte big-endian length prefix followed by a
//! CBOR-encoded message body. The baseline wire format for a Thicket channel.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// Maximum accepted frame size (16 MiB) — a guard against hostile length
/// prefixes. Bulk data should ride a stream, not a single frame.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

pub(crate) fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| Error::Codec(e.to_string()))?;
    Ok(buf)
}

pub(crate) fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|e| Error::Codec(e.to_string()))
}

/// Write one length-delimited frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(Error::FrameTooLarge);
    }
    w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-delimited frame. `Ok(None)` means a clean end-of-stream.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(Error::FrameTooLarge);
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}
