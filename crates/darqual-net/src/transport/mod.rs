//! `Transport` trait — the abstraction boundary between the protocol and the
//! underlying connection medium (TCP now; Tor/Arti later).

pub mod tcp;

use std::future::Future;

use crate::Result;

/// Abstraction over a connection medium.
///
/// v0.1.0 ships [`tcp::TcpTransport`].  A future `TorTransport` will implement
/// this trait with the same surface, enabling protocol code to be reused.
pub trait Transport {
    type Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send;
    type Listener: Send;

    /// Bind a listener on `bind_addr`.
    fn listen(bind: &str) -> impl Future<Output = Result<Self::Listener>> + Send;

    /// Dial an outbound connection to `addr`.
    fn dial(addr: &str) -> impl Future<Output = Result<Self::Stream>> + Send;
}

impl Transport for tcp::TcpTransport {
    type Stream = tokio::net::TcpStream;
    type Listener = tokio::net::TcpListener;

    async fn listen(bind: &str) -> Result<Self::Listener> {
        Ok(tokio::net::TcpListener::bind(bind).await?)
    }

    async fn dial(addr: &str) -> Result<Self::Stream> {
        Ok(tokio::net::TcpStream::connect(addr).await?)
    }
}
