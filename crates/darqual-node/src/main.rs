//! `darqual-node` — Darqual network daemon (v0.9.0).
//!
//! ## Subcommands
//!
//! ### Stage 1 (TCP lockbox point-to-point)
//! * `listen  --addr <host:port>`      — Accept lockboxes, try to open them.
//! * `send    --peer <addr> --to <card> --message <text>` — Seal + send.
//!
//! ### Stage 9 (light-client block transport)
//! * `publish --addr <bind> --to <card> --message <text> [--cover <N>]`
//!   Build a ledger block (real lockbox + cover traffic) and serve it.
//!
//! * `fetch   --peer <addr> --from <card>`
//!   Light-client: fetch a block, derive your conversation label, extract
//!   only your messages — no trial-decrypt, no full ledger.
//!
//! ## Deferred items (v0.9.x next / research)
//! * **Tor/Arti Layer-2 channel** — real-time, onion-routed transport.
//!   Requires `arti-client` + v3 onion service; TCP is a placeholder.
//! * **Desktop UI / TUI** — out of scope for v0.9.0.
//! * **Group messaging** — requires MLS/TreeKEM; research-grade, deferred.
//! * **Mobile light-client** — provider-pull model; deferred pending stable API.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use darqual_core::{ContactCard, Conversation, Identity, Lockbox};
use darqual_cover::pad_block;
use darqual_ledger::{Block, LedgerEntry, epoch_now, fetch_open, notify};
use darqual_net::{fetch_block, send_lockbox, serve, serve_block};
use rand::thread_rng;
use tracing::{error, info};
use x25519_dalek::PublicKey as X25519PK;

// ── CLI schema ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "darqual-node",
    version = "0.9.0",
    about = "Darqual network daemon — TCP transport (Stage 9: light-client integration)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// [Stage 1] Listen for incoming lockboxes and attempt to open them.
    Listen {
        /// Address to bind, e.g. 127.0.0.1:9939
        #[arg(long, default_value = "127.0.0.1:9939")]
        addr: String,
    },

    /// [Stage 1] Seal a message to a recipient and send it to a peer node.
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

    /// [Stage 9] Build a ledger block and serve it over TCP.
    ///
    /// Loads your identity, seals <message> into a labelled LedgerEntry for
    /// the recipient <to>, pads with <cover> cover entries (default 8), builds
    /// a Block for epoch_now(), and serves it to any connecting light-client.
    Publish {
        /// Address to bind the block server, e.g. 127.0.0.1:9940
        #[arg(long, default_value = "127.0.0.1:9940")]
        addr: String,
        /// Recipient contact card (dqcard1...)
        #[arg(long)]
        to: String,
        /// Plaintext message to seal and publish
        #[arg(long)]
        message: String,
        /// Number of cover entries to pad the block with (default 8)
        #[arg(long, default_value_t = 8)]
        cover: usize,
    },

    /// [Stage 9] Light-client: fetch a block and extract messages addressed to you.
    ///
    /// Loads your identity, dials <peer>, fetches one block, derives the
    /// conversation label for the sender's card, and opens any matching
    /// lockboxes — no trial-decrypt, no full-ledger storage.
    ///
    /// Tries epoch_now() and epoch_now()-1 to handle small clock skews.
    Fetch {
        /// Peer (publisher) address, e.g. 127.0.0.1:9940
        #[arg(long)]
        peer: String,
        /// Sender contact card (dqcard1...)
        #[arg(long)]
        from: String,
    },
}

// ── main ──────────────────────────────────────────────────────────────────────

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
        Command::Publish {
            addr,
            to,
            message,
            cover,
        } => cmd_publish(&addr, &to, &message, cover).await,
        Command::Fetch { peer, from } => cmd_fetch(&peer, &from).await,
    }
}

// ── Stage 1: listen ───────────────────────────────────────────────────────────

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

// ── Stage 1: send ─────────────────────────────────────────────────────────────

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

// ── Stage 9: publish ──────────────────────────────────────────────────────────

async fn cmd_publish(bind: &str, to: &str, message: &str, cover: usize) -> Result<()> {
    let identity_path =
        Identity::default_path().context("could not determine identity path — is HOME set?")?;
    let identity = Identity::load(&identity_path)
        .context("failed to load identity — run `darqual keygen` first")?;

    let recipient: ContactCard = to
        .parse()
        .context("invalid recipient contact card — expected dqcard1... string")?;

    let epoch = epoch_now();
    let conv = Conversation::new(&identity, &recipient);

    // Label via static-PRF (symmetric with fetch's Conversation::label)
    let label = conv.label(epoch);

    // Seal the lockbox
    let their_x_pub = X25519PK::from(recipient.x_pub);
    let lockbox =
        Lockbox::seal(&their_x_pub, message.as_bytes()).context("failed to seal message")?;
    let envelope_bytes: Vec<u8> = lockbox.envelope.into_bytes();

    let entry = LedgerEntry::mint(label, envelope_bytes, 0);
    let mut entries = vec![entry];
    pad_block(&mut entries, cover + 1, &mut thread_rng());

    let block = Block::new(epoch, [0u8; 32], entries);

    println!(
        "[publish] epoch={} entries={} (1 real + {} cover) addr={}",
        block.header.epoch,
        block.entries.len(),
        block.entries.len() - 1,
        bind
    );
    println!("[publish] label={} — serving on {} (Ctrl-C to stop)", label, bind);

    let serve_fut = serve_block(bind, block);

    tokio::select! {
        res = serve_fut => {
            res.context("serve_block error")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down publisher.");
        }
    }

    Ok(())
}

// ── Stage 9: fetch (light client) ────────────────────────────────────────────

async fn cmd_fetch(peer: &str, from: &str) -> Result<()> {
    let identity_path =
        Identity::default_path().context("could not determine identity path — is HOME set?")?;
    let identity = Identity::load(&identity_path)
        .context("failed to load identity — run `darqual keygen` first")?;

    let sender: ContactCard = from
        .parse()
        .context("invalid sender contact card — expected dqcard1... string")?;

    println!("[fetch] dialing {} …", peer);
    let block = fetch_block(peer)
        .await
        .context("failed to fetch block from peer")?;

    println!(
        "[fetch] block epoch={} entries={}",
        block.header.epoch,
        block.entries.len()
    );

    let conv = Conversation::new(&identity, &sender);
    let epoch_now = epoch_now();

    // Try current epoch and one prior to handle small clock skews between
    // publisher and fetcher.
    let mut found_any = false;
    for epoch in [epoch_now, epoch_now.saturating_sub(1)] {
        let notified = notify(&conv, epoch, &block);
        if notified {
            let msgs = fetch_open(&conv, epoch, &block, &identity);
            for msg in &msgs {
                match std::str::from_utf8(msg) {
                    Ok(text) => println!("[msg] {}", text),
                    Err(_) => println!("[msg] (binary, {} bytes)", msg.len()),
                }
            }
            if !msgs.is_empty() {
                found_any = true;
                break;
            }
        }
    }

    if !found_any {
        println!("[fetch] no messages for me this epoch");
    }

    Ok(())
}
