//! darqual-tor-node — the Darqual node running over Tor v3 onion services.
//!
//! `host`  — bootstrap Tor, host an onion service, receive ratchet-encrypted
//!           messages addressed to the local identity.
//! `send`  — load or bootstrap a ratchet session to a contact card, encrypt,
//!           dial the peer's `.onion`, deliver.
//!
//! The node's transport unit is the Double Ratchet message — forward secrecy,
//! post-compromise security, and encrypted headers per session. Spec:
//! `notes/projects/anon-messenger-research/17-session-wiring.md`.
//!
//! Wire frame:  `[sender_x_pub : 32B][ bincode(RatchetMessage) ]`
//!
//! Lockbox v2 remains the CLI primitive / sessionless bootstrap — it is just
//! no longer the node's transport unit.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use darqual_core::{ContactCard, Identity, RatchetMessage, SessionStore};
use darqual_tor::{accept_one, bootstrap, dial_send, host};

#[derive(Parser)]
#[command(name = "darqual-tor-node", about = "Darqual node over Tor onion services")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Host an onion service; receive + ratchet-decrypt messages for the local identity.
    Host {
        #[arg(long, default_value = "darqual")]
        nickname: String,
        #[arg(long, default_value_t = 9999)]
        port: u16,
    },
    /// Encrypt a message under a ratchet session and send it to a peer's `.onion`.
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
    let store = SessionStore::open_default().context("open session store")?;

    println!("[tor] bootstrapping onto the Tor network…");
    let client = bootstrap().await.context("bootstrap")?;
    let mut h = host(&client, nickname, port).context("launch onion service")?;

    println!("[tor] onion service: {}", h.onion);
    println!("[tor] my address:    {}", identity.address());
    println!("[tor] sessions:      {}", store.dir().display());
    println!("[tor] share the .onion above with senders. listening on port {port} (Ctrl-C to stop)…");

    loop {
        match accept_one(&mut h, port).await {
            Ok(Some(frame)) => handle_frame(&identity, &store, &frame),
            Ok(None) => {
                println!("[tor] request stream ended");
                break;
            }
            Err(e) => eprintln!("[tor] accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_frame(identity: &Identity, store: &SessionStore, frame: &[u8]) {
    if frame.len() < 32 {
        eprintln!("[recv] short frame ({} bytes)", frame.len());
        return;
    }
    let (sender_x_pub_slice, rm_bytes) = frame.split_at(32);
    let mut sender_x_pub = [0u8; 32];
    sender_x_pub.copy_from_slice(sender_x_pub_slice);

    let rm: RatchetMessage = match bincode::deserialize(rm_bytes) {
        Ok(rm) => rm,
        Err(e) => {
            eprintln!("[recv] malformed ratchet message: {e}");
            return;
        }
    };

    let mut sess = match store.load_or_init_responder(identity, &sender_x_pub) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[recv] session load failed: {e}");
            return;
        }
    };

    match sess.decrypt(&rm) {
        Ok(pt) => {
            // Persist advanced state IMMEDIATELY after a successful decrypt.
            if let Err(e) = store.save(&sender_x_pub, &sess) {
                eprintln!("[recv] session save failed: {e}");
                // Still print the plaintext — decrypt succeeded.
            }
            println!("[recv] {}", String::from_utf8_lossy(&pt));
        }
        Err(e) => {
            // Failed decrypt: DO NOT save — state must not advance on failure.
            eprintln!("[recv] decrypt failed: {e}");
        }
    }
}

async fn send_cmd(onion: &str, to: &str, message: &str, port: u16) -> Result<()> {
    let card = to.parse::<ContactCard>().context("invalid contact card")?;
    let id_path = Identity::default_path().context("could not determine identity path")?;
    let identity =
        Identity::load(&id_path).context("failed to load identity — run `darqual keygen` first")?;
    let store = SessionStore::open_default().context("open session store")?;

    // Outbound: existing session, else bootstrap as initiator.
    let mut sess = store
        .load_or_init_initiator(&identity, &card)
        .context("load/init initiator session")?;
    let rm = sess.encrypt(message.as_bytes()).context("ratchet encrypt")?;
    // Persist advanced state IMMEDIATELY after encrypt.
    store
        .save(&card.x_pub, &sess)
        .context("persist session after encrypt")?;

    let rm_bytes = bincode::serialize(&rm).context("bincode serialize ratchet message")?;
    let mut frame = Vec::with_capacity(32 + rm_bytes.len());
    frame.extend_from_slice(&identity.x_pub());
    frame.extend_from_slice(&rm_bytes);

    println!("[tor] bootstrapping onto the Tor network…");
    let client = bootstrap().await.context("bootstrap")?;
    println!("[tor] dialing {onion} over Tor…");
    dial_send(&client, onion, port, &frame)
        .await
        .context("dial/send")?;
    println!("[sent] {} bytes to {}", frame.len(), onion);
    Ok(())
}
