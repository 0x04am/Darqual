//! darqual-net — Network transport layer for Darqual (v0.1.0: TCP).
//!
//! Abstracts the transport behind a [`Transport`] trait so a Tor/Arti
//! implementation can be dropped in later without rewriting the protocol layer.

#![forbid(unsafe_code)]

pub mod error;
pub mod frame;
pub mod transport;

pub use error::{Error, Result};
pub use transport::tcp::TcpTransport;
pub use transport::Transport;

use tokio::net::TcpListener;
use tracing::{debug, warn};

/// Dial `peer_addr`, send one framed envelope, then close the connection.
pub async fn send_lockbox(peer_addr: &str, envelope: &str) -> Result<()> {
    let mut stream = tokio::net::TcpStream::connect(peer_addr).await?;
    frame::write_frame(&mut stream, envelope.as_bytes()).await?;
    debug!(peer = peer_addr, bytes = envelope.len(), "lockbox sent");
    Ok(())
}

/// Bind a TCP listener on `bind_addr` and call `on_envelope` for every received
/// lockbox envelope.  Runs until the returned future is dropped / cancelled.
///
/// `on_envelope` is invoked in the accept loop per connection — keep it cheap
/// (e.g. send on a channel).
pub async fn serve(
    bind_addr: &str,
    on_envelope: impl FnMut(String) + Send + 'static,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    debug!(addr = bind_addr, "darqual-net listening");
    serve_listener(listener, on_envelope).await
}

/// Bind on an ephemeral port and return the bound [`TcpListener`] plus the
/// resolved socket address string (`"127.0.0.1:<port>"`).
///
/// Useful in tests — lets the OS pick a free port.
pub async fn bind_ephemeral(host: &str) -> Result<(TcpListener, String)> {
    let listener = TcpListener::bind(format!("{}:0", host)).await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr.to_string()))
}

/// Like [`serve`] but uses a pre-bound [`TcpListener`] instead of binding a new one.
/// Useful when the caller needs the address before starting the server.
pub async fn serve_listener(
    listener: TcpListener,
    mut on_envelope: impl FnMut(String) + Send + 'static,
) -> Result<()> {
    loop {
        let (mut stream, peer) = listener.accept().await?;
        debug!(?peer, "accepted connection");
        match frame::read_frame(&mut stream).await {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(envelope) => on_envelope(envelope),
                Err(e) => warn!(?peer, "non-UTF8 frame: {}", e),
            },
            Err(e) => warn!(?peer, "frame read error: {}", e),
        }
    }
}
