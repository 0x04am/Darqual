//! darqual-tor-node — the Darqual node running over Tor v3 onion services.
//!
//! `host`  — bootstrap Tor, host an onion service, receive + decrypt lockboxes
//!           addressed to the local identity.
//! `send`  — seal a message to a contact card, dial a peer's `.onion`, deliver it.
//!
//! No IPs, no firewall, no NAT — peers find each other by `.onion` address.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use darqual_core::{ContactCard, Identity, Lockbox};
use darqual_tor::{accept_one, bootstrap, dial_send, host};

#[derive(Parser)]
#[command(name = "darqual-tor-node", about = "Darqual node over Tor onion services")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Host an onion service; receive + decrypt lockboxes for the local identity.
    Host {
        #[arg(long, default_value = "darqual")]
        nickname: String,
        #[arg(long, default_value_t = 9999)]
        port: u16,
    },
    /// Seal a message to a contact card and send it to a peer's `.onion`.
    Send {
        /// Peer onion address (e.g. abcd...xyz.onion)
        #[arg(long)]
        onion: String,
        /// Recipient contact card (dqcard1...)
        #[arg(long)]
        to: String,
        #[arg(long)]
        message: String,
        #[arg(long, default_value_t = 9999)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Host { nickname, port } => host_cmd(&nickname, port).await,
        Cmd::Send {
            onion,
            to,
            message,
            port,
        } => send_cmd(&onion, &to, &message, port).await,
    }
}

async fn host_cmd(nickname: &str, port: u16) -> Result<()> {
    let id_path = Identity::default_path().context("could not determine identity path")?;
    let identity =
        Identity::load(&id_path).context("failed to load identity — run `darqual keygen` first")?;

    println!("[tor] bootstrapping onto the Tor network…");
    let client = bootstrap().await.context("bootstrap")?;
    let mut h = host(&client, nickname, port).context("launch onion service")?;

    println!("[tor] onion service: {}", h.onion);
    println!("[tor] my address:    {}", identity.address());
    println!("[tor] share the .onion above with senders. listening on port {port} (Ctrl-C to stop)…");

    loop {
        match accept_one(&mut h, port).await {
            Ok(Some(frame)) => {
                let opened = String::from_utf8(frame)
                    .ok()
                    .and_then(|env| Lockbox::open(&identity, &env).ok());
                match opened {
                    Some(pt) => println!("[recv] {}", String::from_utf8_lossy(&pt)),
                    None => println!("[recv] (not addressed to me)"),
                }
            }
            Ok(None) => {
                println!("[tor] request stream ended");
                break;
            }
            Err(e) => eprintln!("[tor] accept error: {e}"),
        }
    }
    Ok(())
}

async fn send_cmd(onion: &str, to: &str, message: &str, port: u16) -> Result<()> {
    let card = to.parse::<ContactCard>().context("invalid contact card")?;
    let lb = Lockbox::seal_to_card(&card, message.as_bytes()).context("seal failed")?;

    println!("[tor] bootstrapping onto the Tor network…");
    let client = bootstrap().await.context("bootstrap")?;
    println!("[tor] dialing {onion} over Tor…");
    dial_send(&client, onion, port, lb.envelope.as_bytes())
        .await
        .context("dial/send")?;
    println!("[sent] {} bytes to {}", lb.envelope.len(), onion);
    Ok(())
}
