//! Darqual Tor transport — Arti onion services.
//!
//! EXPERIMENTAL (Stage 1 Tor increment). Each node IS a v3 onion service:
//! location-hidden, self-authenticating `.onion` address, NAT-traversed. Nodes
//! connect by `.onion` — no IPs, no firewall holes, no port forwarding.
//!
//! Milestone 1: bootstrap onto Tor.  Milestone 2 (this file): host an onion
//! service + dial a peer's `.onion` + exchange a length-framed message.
//!
//! NOTE: Arti's `DataStream` is **futures-io** (not tokio-io), so framing here
//! uses `futures::io` traits, independent of darqual-net's tokio framing.
#![allow(dead_code)]

pub mod relay;

use std::sync::Arc;

use anyhow::Context;
use arti_client::{TorClient, TorClientConfig};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use safelog::DisplayRedacted;
use tor_cell::relaycell::msg::{Connected, End};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, RunningOnionService, StreamRequest};
use tor_proto::client::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;

const MAX_FRAME: usize = 16 * 1024 * 1024;

type Client = TorClient<PreferredRuntime>;

/// Install the ring-based rustls crypto provider once, process-wide. Idempotent.
pub fn install_crypto_provider() {
    use rustls::crypto::CryptoProvider;
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// Bootstrap a Tor client onto the live Tor network (~10-30s first run).
pub async fn bootstrap() -> anyhow::Result<Arc<Client>> {
    install_crypto_provider();
    let client = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
    Ok(client)
}

/// A launched onion service: keep `service` alive for as long as you want the
/// service reachable. `onion` is the `.onion` address peers dial.
pub struct Host {
    pub service: Arc<RunningOnionService>,
    pub onion: String,
    pub streams: futures::stream::BoxStream<'static, StreamRequest>,
}

/// Launch an onion service with the given nickname, returning its `.onion`
/// address and the stream of incoming connection requests.
pub fn host(client: &Client, nickname: &str, _port: u16) -> anyhow::Result<Host> {
    let config = OnionServiceConfigBuilder::default()
        .nickname(nickname.parse().context("invalid nickname")?)
        .build()
        .context("build onion service config")?;
    let (service, rend) = client
        .launch_onion_service(config)
        .context("launch onion service")?
        .context("onion service disabled in config")?;
    let onion = service
        .onion_address()
        .context("onion name not yet available")?
        .display_unredacted()
        .to_string();
    let streams = handle_rend_requests(rend).boxed();
    Ok(Host {
        service,
        onion,
        streams,
    })
}

/// Accept the next inbound `BEGIN` to `port` and read one framed message from it.
/// Returns `None` if the request stream ends.
pub async fn accept_one(host: &mut Host, port: u16) -> anyhow::Result<Option<Vec<u8>>> {
    while let Some(req) = host.streams.next().await {
        match req.request() {
            IncomingStreamRequest::Begin(b) if b.port() == port => {
                let mut ds = req.accept(Connected::new_empty()).await?;
                let frame = read_frame(&mut ds).await?;
                return Ok(Some(frame));
            }
            _ => {
                let _ = req.reject(End::new_misc()).await;
            }
        }
    }
    Ok(None)
}

/// Accept the next inbound request, pass its frame to `handler`, and send the
/// returned response on the same onion stream. Returns `None` if the request
/// stream ends.
pub async fn accept_and_reply<F>(
    host: &mut Host,
    port: u16,
    handler: F,
) -> anyhow::Result<Option<()>>
where
    F: FnOnce(Vec<u8>) -> Vec<u8>,
{
    while let Some(req) = host.streams.next().await {
        match req.request() {
            IncomingStreamRequest::Begin(b) if b.port() == port => {
                let mut ds = req.accept(Connected::new_empty()).await?;
                let frame = read_frame(&mut ds).await?;
                let response = handler(frame);
                write_frame(&mut ds, &response).await?;
                ds.flush().await?;
                ds.close().await.ok();
                return Ok(Some(()));
            }
            _ => {
                let _ = req.reject(End::new_misc()).await;
            }
        }
    }
    Ok(None)
}

/// Dial a relay onion, send one framed request, then read one framed response.
pub async fn dial_request(
    client: &Client,
    onion: &str,
    port: u16,
    data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let addr = format!("{onion}:{port}");
    let mut stream = client.connect(addr).await.context("connect onion")?;
    write_frame(&mut stream, data).await?;
    stream.flush().await?;
    let response = read_frame(&mut stream).await?;
    stream.close().await.ok();
    Ok(response)
}

/// Dial a peer's `.onion` address and send one framed message.
pub async fn dial_send(client: &Client, onion: &str, port: u16, data: &[u8]) -> anyhow::Result<()> {
    let addr = format!("{onion}:{port}");
    let mut stream = client.connect(addr).await.context("connect onion")?;
    write_frame(&mut stream, data).await?;
    stream.flush().await?;
    stream.close().await.ok();
    Ok(())
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(data.len() <= MAX_FRAME, "frame too large");
    w.write_all(&(data.len() as u32).to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(len <= MAX_FRAME, "frame too large");
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Single-process onion round-trip over LIVE Tor: host a transient onion
    /// service, then dial our own `.onion` and exchange a message. The address
    /// is never shared, and the service stops when the test ends.
    /// Run: `cargo test --release -- --ignored --nocapture onion_roundtrip`
    #[tokio::test]
    #[ignore]
    async fn onion_roundtrip() {
        let client = bootstrap().await.expect("bootstrap");
        let mut h = host(&client, "darqualtest", 9999).expect("host");
        eprintln!("[onion] {}", h.onion);
        let onion = h.onion.clone();

        // Serve task: accept one inbound message.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let serve = tokio::spawn(async move {
            if let Ok(Some(frame)) = accept_one(&mut h, 9999).await {
                let _ = tx.send(frame);
            }
            drop(h); // keep service alive until here
        });

        // Dial with retries — descriptor publication takes ~30-90s.
        let msg = b"hello over real tor".to_vec();
        let mut reached = false;
        for attempt in 0..40 {
            match dial_send(&client, &onion, 9999, &msg).await {
                Ok(()) => {
                    reached = true;
                    break;
                }
                Err(e) => {
                    eprintln!("[dial] attempt {attempt} not yet reachable: {e}");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
        assert!(reached, "onion service never became reachable");

        let got = tokio::time::timeout(Duration::from_secs(15), rx)
            .await
            .expect("recv timed out")
            .expect("serve task dropped");
        assert_eq!(got, msg, "round-trip payload mismatch");
        serve.abort();
    }
}
