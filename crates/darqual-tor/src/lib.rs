//! Darqual Tor transport — Arti onion services.
//!
//! EXPERIMENTAL (Stage 1 Tor increment). Swaps the plaintext TCP transport for
//! Tor v3 onion services: each node IS an onion service (location-hidden,
//! self-authenticating address, NAT-traversed), and nodes connect by `.onion`
//! address. No IPs, no firewall holes, no port forwarding.
//!
//! Milestone 1 (this file): bootstrap an Arti `TorClient` onto the live Tor
//! network. This validates the dependency compiles and links on the host.
#![allow(dead_code)]

use std::sync::Arc;

use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

/// Bootstrap a Tor client onto the live Tor network.
///
/// Takes ~10-30s on first run (downloads a consensus + builds circuits).
pub async fn bootstrap() -> anyhow::Result<Arc<TorClient<PreferredRuntime>>> {
    // rustls 0.23 requires a process-wide CryptoProvider to be installed before
    // any TLS is used. Arti does not install one for us, so do it here (ring).
    install_crypto_provider();
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config).await?;
    Ok(client)
}

/// Install the ring-based rustls crypto provider once, process-wide. Idempotent.
pub fn install_crypto_provider() {
    use rustls::crypto::CryptoProvider;
    if CryptoProvider::get_default().is_none() {
        // If another thread won the race, ignore the resulting error.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Network smoke test — requires outbound access to the Tor network.
    /// `#[ignore]` so the normal gate (verify.sh) doesn't try to bootstrap Tor.
    /// Run manually: `cargo test -p darqual-tor -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn bootstrap_smoke() {
        let client = bootstrap().await.expect("bootstrap onto Tor");
        // If we got here, we have a live Tor client.
        drop(client);
    }
}
