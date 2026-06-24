//! # Block transport — Stage 9: light-client integration
//!
//! Provides two async primitives that compose the full stack over the wire:
//!
//! * [`serve_block`] — bind a TCP listener and serve one serialised [`Block`]
//!   frame to every connecting client.
//! * [`fetch_block`] — dial a peer, read one frame, deserialise and return the
//!   [`Block`].
//!
//! ## Wire format
//! One length-prefixed frame (see [`crate::frame`]) containing the
//! JSON-serialised [`Block`].  JSON is chosen for debuggability; a future
//! revision may switch to a compact binary format (e.g. bincode / CBOR) without
//! changing the framing layer.
//!
//! ## Deferred items (documented — not implemented here)
//!
//! * **Tor/Arti Layer-2 channel** — real-time, onion-routed transport requires
//!   `arti-client` + v3 onion service binding.  The TCP substrate is a
//!   drop-in placeholder; swap [`TcpStream`] for an Arti stream to get Tor.
//!   Tracked as ROADMAP Stage 9 (v0.9.x next).
//!
//! * **Desktop UI / TUI** — out of scope for v0.9.0.  The `darqual-node`
//!   subcommands (`publish` / `fetch`) serve as the runnable demo surface.
//!
//! * **Group messaging** — requires a group key-agreement protocol (e.g.
//!   MLS/TreeKEM).  Documented research path; deferred.

use darqual_ledger::Block;
use tokio::net::TcpListener;
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::frame;

// ── serve_block ────────────────────────────────────────────────────────────────

/// Bind `bind_addr`, then for every incoming connection write one framed JSON
/// frame containing `block` and close the connection.
///
/// Runs until the returned future is dropped / cancelled (e.g. wrapped in
/// `tokio::select!` against a `ctrl_c` signal or a oneshot).
///
/// The same `block` is cloned and served to every connecting client — suitable
/// for the "publisher broadcasts one epoch block" pattern.
pub async fn serve_block(bind_addr: &str, block: Block) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    debug!(addr = bind_addr, "block server listening");
    serve_block_listener(listener, block).await
}

/// Like [`serve_block`] but uses a pre-bound [`TcpListener`].
///
/// Returns the bound address via the `TcpListener` — call
/// `listener.local_addr()` before passing it here to discover the ephemeral
/// port when the OS picks one.
pub async fn serve_block_listener(listener: TcpListener, block: Block) -> Result<()> {
    loop {
        let (mut stream, peer) = listener.accept().await?;
        debug!(?peer, "block client connected");
        let serialised = match serde_json::to_vec(&block) {
            Ok(b) => b,
            Err(e) => {
                warn!(?peer, "block serialisation failed: {}", e);
                continue;
            }
        };
        match tokio::time::timeout(frame::CONN_TIMEOUT, frame::write_frame(&mut stream, &serialised))
            .await
        {
            Ok(Ok(())) => debug!(?peer, bytes = serialised.len(), "block frame sent"),
            Ok(Err(e)) => warn!(?peer, "frame write error: {}", e),
            Err(_) => warn!(?peer, "block send timed out"),
        }
    }
}

// ── fetch_block ───────────────────────────────────────────────────────────────

/// Dial `peer_addr`, read one framed JSON frame, deserialise and return the
/// [`Block`].
///
/// Errors if the connection fails, the frame exceeds the cap, or the payload
/// is not valid JSON for a `Block`.
pub async fn fetch_block(peer_addr: &str) -> Result<Block> {
    let mut stream = tokio::net::TcpStream::connect(peer_addr).await?;
    let data = frame::read_frame(&mut stream).await?;
    let block: Block = serde_json::from_slice(&data)
        .map_err(|e| Error::Encoding(format!("block deserialisation failed: {e}")))?;
    debug!(
        peer = peer_addr,
        entries = block.entries.len(),
        "block fetched"
    );
    Ok(block)
}

// ── bind_ephemeral_block ──────────────────────────────────────────────────────

/// Bind on an ephemeral port and return the [`TcpListener`] plus the resolved
/// `"host:port"` string.  Useful in tests — lets the OS pick a free port.
pub async fn bind_ephemeral_block(host: &str) -> Result<(TcpListener, String)> {
    let listener = TcpListener::bind(format!("{host}:0")).await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr.to_string()))
}
