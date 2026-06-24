//! Length-prefixed framing over any `AsyncRead` / `AsyncWrite`.
//!
//! Wire format: `u32` big-endian length prefix, then exactly `len` bytes.
//! Maximum frame payload: 16 MiB (raised in Stage 9 to support whole-block transport).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// Per-connection I/O timeout. A slow or idle peer cannot hold a server task
/// open indefinitely (Slowloris mitigation). Used by the serve loops.
pub const CONN_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum frame payload.
///
/// 1 MiB is sufficient for individual lockbox envelopes (Stage 1).  Whole
/// ledger blocks (Stage 9) can easily exceed 1 MiB when padded with cover
/// traffic, so we raise the cap to 16 MiB.  A future wire-format revision may
/// use streaming / chunked transfer for very large blocks.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024; // 16 MiB

/// Write a length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    // Reject oversized payloads up front rather than silently truncating the
    // length prefix (`data.len() as u32`), which would desync the framing.
    if data.len() > MAX_FRAME as usize {
        return Err(Error::FrameTooLarge(MAX_FRAME));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_frame_rejects_oversize() {
        let mut sink = tokio::io::sink();
        let oversize = vec![0u8; MAX_FRAME as usize + 1];
        let r = write_frame(&mut sink, &oversize).await;
        assert!(
            matches!(r, Err(Error::FrameTooLarge(_))),
            "oversize payload must be rejected before truncating the length prefix"
        );
    }

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload = b"darqual frame roundtrip".to_vec();
        write_frame(&mut a, &payload).await.expect("write ok");
        let got = read_frame(&mut b).await.expect("read ok");
        assert_eq!(got, payload);
    }
}
