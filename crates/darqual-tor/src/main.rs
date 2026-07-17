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
//! Wire frame (versioned envelope — F-2):
//!
//!   Frame v1 (first-contact bootstrap):
//!     `[0x01][lockbox-v2 envelope bytes]`
//!     Lockbox v2 (Noise IK) hides the sender's static x25519 pubkey inside
//!     its first AEAD layer; only a fresh ephemeral is visible on the wire.
//!     The RatchetMessage is the lockbox plaintext (inside the AEAD).
//!
//!   Frame v2 (established session):
//!     `[0x02][bincode(RatchetMessage)]`
//!     Fully opaque; receiver trial-decrypts against all known sessions.
//!
//! NOTE: the version byte itself tells an observer "first contact" vs
//! "established", but reveals no identity — lockbox v2 frames are pairwise
//! unlinkable (fresh ephemeral each time). No back-compat with pre-F-2 nodes
//! (flag-day acceptable; pre-release software).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use darqual_core::{ContactCard, Identity, Lockbox, RatchetMessage, SessionStore};
use darqual_tor::{accept_one, bootstrap, dial_send, host};

/// Frame version byte: lockbox-v2-wrapped RatchetMessage (first-contact bootstrap).
const FRAME_BOOTSTRAP: u8 = 0x01;
/// Frame version byte: bare RatchetMessage, trial-decrypted against known sessions.
const FRAME_SESSION: u8 = 0x02;

#[derive(Parser)]
#[command(
    name = "darqual-tor-node",
    about = "Darqual node over Tor onion services"
)]
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
    println!(
        "[tor] share the .onion above with senders. listening on port {port} (Ctrl-C to stop)…"
    );

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
    let Some((&ver, body)) = frame.split_first() else {
        eprintln!("[recv] empty frame");
        return;
    };
    match ver {
        FRAME_BOOTSTRAP => handle_bootstrap(identity, store, body),
        FRAME_SESSION => handle_session(store, body),
        v => eprintln!("[recv] unknown frame version 0x{v:02x}"),
    }
}

/// v1 branch: lockbox-v2 decrypt → recover sender → responder bootstrap → ratchet decrypt.
fn handle_bootstrap(identity: &Identity, store: &SessionStore, body: &[u8]) {
    let envelope = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[recv] bootstrap body is not valid UTF-8");
            return;
        }
    };

    // Sender identity is recovered from INSIDE the AEAD (lockbox.rs:284-289).
    let (rm_bytes, sender) = match Lockbox::open_authenticated(identity, envelope) {
        Ok((pt, Some(sender))) => (pt, sender),
        Ok((_, None)) => {
            // A lockbox-v1 (anonymous) cannot bootstrap a session — reject.
            eprintln!("[recv] anonymous v1 lockbox rejected as bootstrap");
            return;
        }
        Err(e) => {
            eprintln!("[recv] bootstrap open failed: {e}");
            return;
        }
    };

    let rm: RatchetMessage = match bincode::deserialize(&rm_bytes) {
        Ok(rm) => rm,
        Err(e) => {
            eprintln!("[recv] bootstrap ratchet message deserialize failed: {e}");
            return;
        }
    };

    // Idempotent: loads existing session if one exists, else init_responder.
    let mut sess = match store.load_or_init_responder(identity, &sender) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[recv] bootstrap session load failed: {e}");
            return;
        }
    };

    match sess.decrypt(&rm) {
        Ok(pt) => {
            // Persist advanced state IMMEDIATELY after successful decrypt.
            if let Err(e) = store.save(&sender, &sess) {
                eprintln!("[recv] bootstrap session save failed: {e}");
                // Still print — decrypt succeeded.
            }
            println!("[recv] {}", String::from_utf8_lossy(&pt));
        }
        Err(e) => {
            // DO NOT save — state must not advance on failure.
            eprintln!("[recv] bootstrap ratchet decrypt failed: {e}");
        }
    }
}

/// v2 branch: trial-decrypt the RatchetMessage against every known session.
fn handle_session(store: &SessionStore, body: &[u8]) {
    let rm: RatchetMessage = match bincode::deserialize(body) {
        Ok(rm) => rm,
        Err(e) => {
            eprintln!("[recv] v2 frame ratchet message deserialize failed: {e}");
            return;
        }
    };

    let sessions = match store.list() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[recv] session list failed: {e}");
            return;
        }
    };

    let n = sessions.len();
    for (peer, mut sess) in sessions {
        match sess.decrypt(&rm) {
            Ok(pt) => {
                // Persist advanced state IMMEDIATELY after successful decrypt.
                if let Err(e) = store.save(&peer, &sess) {
                    eprintln!("[recv] session save failed: {e}");
                }
                println!("[recv] {}", String::from_utf8_lossy(&pt));
                return;
            }
            Err(_) => continue, // wrong session — safe (clone-and-commit in decrypt)
        }
    }

    eprintln!("[recv] v2 frame matched no session ({n} tried) — dropped");
}

async fn send_cmd(onion: &str, to: &str, message: &str, port: u16) -> Result<()> {
    let card = to.parse::<ContactCard>().context("invalid contact card")?;
    let id_path = Identity::default_path().context("could not determine identity path")?;
    let identity =
        Identity::load(&id_path).context("failed to load identity — run `darqual keygen` first")?;
    let store = SessionStore::open_default().context("open session store")?;

    // Decide bootstrap vs session BEFORE load_or_init_initiator may create new state.
    let had_session = store
        .load(&card.x_pub)
        .context("check existing session")?
        .is_some();

    // Outbound: existing session, else bootstrap as initiator.
    let mut sess = store
        .load_or_init_initiator(&identity, &card)
        .context("load/init initiator session")?;

    // Send v1 (bootstrap) until we have evidence the peer has our session:
    // i.e. until we have received at least one message from them (ckr is Some).
    let use_bootstrap_frame = !had_session || !sess.received_from_peer();

    let rm = sess
        .encrypt(message.as_bytes())
        .context("ratchet encrypt")?;
    // Persist advanced state IMMEDIATELY after encrypt.
    store
        .save(&card.x_pub, &sess)
        .context("persist session after encrypt")?;

    let rm_bytes = bincode::serialize(&rm).context("bincode serialize ratchet message")?;

    let frame = if use_bootstrap_frame {
        // Recipient may not know who we are yet → wrap in lockbox v2 (Noise IK).
        // Sender's static x_pub is AEAD-encrypted inside the lockbox; only a fresh
        // ephemeral is visible on the wire.
        let lb = Lockbox::seal_authenticated(&identity, &card, &rm_bytes)
            .context("lockbox seal_authenticated")?;
        let mut f = vec![FRAME_BOOTSTRAP];
        f.extend_from_slice(lb.envelope.as_bytes());
        f
    } else {
        let mut f = vec![FRAME_SESSION];
        f.extend_from_slice(&rm_bytes);
        f
    };

    println!("[tor] bootstrapping onto the Tor network…");
    let client = bootstrap().await.context("bootstrap")?;
    println!("[tor] dialing {onion} over Tor…");
    dial_send(&client, onion, port, &frame)
        .await
        .context("dial/send")?;
    println!("[sent] {} bytes to {}", frame.len(), onion);
    Ok(())
}
