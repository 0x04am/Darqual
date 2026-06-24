//! Length-prefixed framing over any `AsyncRead` / `AsyncWrite`.
//!
//! Wire format: `u32` big-endian length prefix, then exactly `len` bytes.
//! Maximum frame payload: 16 MiB (raised in Stage 9 to support whole-block transport).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// Maximum frame payload.
///
/// 1 MiB is sufficient for individual lockbox envelopes (Stage 1).  Whole
/// ledger blocks (Stage 9) can easily exceed 1 MiB when padded with cover
/// traffic, so we raise the cap to 16 MiB.  A future wire-format revision may
/// use streaming / chunked transfer for very large blocks.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024; // 16 MiB

/// Write a length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}

/// Read a length-prefixed frame.  Rejects payloads larger than [`MAX_FRAME`].
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(Error::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}
