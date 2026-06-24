//! `darqual-node` — Darqual network daemon (v0.1.0: TCP transport).
//!
//! Subcommands:
//!   listen  --addr <host:port>         Accept lockboxes and try to open them.
//!   send    --peer <host:port>
//!           --to   <dqcard1...>
//!           --message <text>           Seal and send a message.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use darqual_core::{ContactCard, Identity, Lockbox};
use darqual_net::{send_lockbox, serve};
use tracing::{error, info};

#[derive(Parser)]
#[command(
    name = "darqual-node",
    version = "0.1.0",
    about = "Darqual network daemon — TCP transport"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Listen for incoming lockboxes and attempt to open them.
    Listen {
        /// Address to bind, e.g. 127.0.0.1:9939
        #[arg(long, default_value = "127.0.0.1:9939")]
        addr: String,
    },
    /// Seal a message to a recipient and send it to a peer node.
    Send {
        /// Peer node address, e.g. 127.0.0.1:9939
        #[arg(long)]
        peer: String,
        /// Recipient contact card string (dqcard1...)
        #[arg(long)]
        to: String,
        /// Plaintext message to seal and send
        #[arg(long)]
        message: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("darqual_node=info".parse()?)
                .add_directive("darqual_net=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Listen { addr } => cmd_listen(&addr).await,
        Command::Send { peer, to, message } => cmd_send(&peer, &to, &message).await,
    }
}

async fn cmd_listen(addr: &str) -> Result<()> {
    let identity_path =
        Identity::default_path().context("could not determine identity path — is HOME set?")?;
    let identity = Identity::load(&identity_path)
        .context("failed to load identity — run `darqual keygen` first")?;

    info!("Listening on {} — Ctrl-C to stop", addr);

    let serve_fut = serve(addr, move |envelope| {
        match Lockbox::open(&identity, &envelope) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => println!("[recv] {}", text),
                Err(_) => println!("[recv] (binary message, {} bytes)", envelope.len()),
            },
            Err(darqual_core::Error::Decrypt) => println!("[recv] (not addressed to me)"),
            Err(e) => error!("open error: {}", e),
        }
    });

    // Run until Ctrl-C
    tokio::select! {
        res = serve_fut => {
            res.context("serve error")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down.");
        }
    }

    Ok(())
}

async fn cmd_send(peer: &str, to: &str, message: &str) -> Result<()> {
    let identity_path =
        Identity::default_path().context("could not determine identity path — is HOME set?")?;
    let _identity = Identity::load(&identity_path)
        .context("failed to load identity — run `darqual keygen` first")?;

    let card: ContactCard = to
        .parse()
        .context("invalid contact card — expected dqcard1... string")?;

    let lockbox =
        Lockbox::seal_to_card(&card, message.as_bytes()).context("failed to seal message")?;

    let bytes = lockbox.envelope.len();
    send_lockbox(peer, &lockbox.envelope)
        .await
        .context("failed to send lockbox")?;

    println!("[sent] {} bytes to {}", bytes, peer);
    Ok(())
}
