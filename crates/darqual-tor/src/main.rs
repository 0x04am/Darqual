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

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use darqual_core::{ContactCard, Conversation, Identity, Lockbox, RatchetMessage, SessionStore};
use darqual_ledger::{epoch_now, fetch_open, LedgerEntry, RelayState};
use darqual_tor::relay::{
    decode_request, decode_response, encode_ledger_response_bounded, encode_request,
    encode_response, RelayRequest, RelayResponse,
};
use darqual_tor::{accept_and_reply, accept_one, bootstrap, dial_request, dial_send, host};

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
    /// Host a Tier-1 single-relay async dead-drop ledger over Tor.
    Relay {
        #[arg(long, default_value = "darqualrelay")]
        nickname: String,
        #[arg(long, default_value_t = 9999)]
        port: u16,
        #[arg(long)]
        state: PathBuf,
        #[arg(long, default_value_t = 60)]
        window: usize,
        #[arg(long, default_value_t = 12)]
        pow_difficulty: u32,
    },
    /// Submit an encrypted dead-drop to a relay; never dials the recipient.
    DropSend {
        #[arg(long)]
        relay: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        message: String,
        #[arg(long, default_value_t = 9999)]
        port: u16,
        #[arg(long, default_value_t = 12)]
        pow_difficulty: u32,
    },
    /// Fetch public relay blocks and open dead-drops for one known sender.
    DropFetch {
        #[arg(long)]
        relay: String,
        #[arg(long)]
        from: String,
        #[arg(long, default_value_t = 9999)]
        port: u16,
        #[arg(long)]
        since_epoch: Option<u64>,
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
        Cmd::Relay {
            nickname,
            port,
            state,
            window,
            pow_difficulty,
        } => relay_cmd(&nickname, port, &state, window, pow_difficulty).await,
        Cmd::DropSend {
            relay,
            to,
            message,
            port,
            pow_difficulty,
        } => drop_send_cmd(&relay, &to, &message, port, pow_difficulty).await,
        Cmd::DropFetch {
            relay,
            from,
            port,
            since_epoch,
        } => drop_fetch_cmd(&relay, &from, port, since_epoch).await,
        Cmd::Send {
            onion,
            to,
            message,
            port,
        } => send_cmd(&onion, &to, &message, port).await,
    }
}

async fn relay_cmd(
    nickname: &str,
    port: u16,
    state_path: &Path,
    window: usize,
    pow_difficulty: u32,
) -> Result<()> {
    let state = if state_path.exists() {
        RelayState::load(state_path).context("load relay state")?
    } else {
        RelayState::new(window, pow_difficulty).context("create relay state")?
    };
    anyhow::ensure!(
        state.window() == window && state.pow_difficulty() == pow_difficulty,
        "saved relay configuration differs from --window/--pow-difficulty"
    );
    let state = Arc::new(Mutex::new(state));

    println!("[relay] bootstrapping onto the Tor network…");
    let client = bootstrap().await.context("bootstrap")?;
    let mut h = host(&client, nickname, port).context("launch relay onion service")?;
    println!("[relay] onion service: {}", h.onion);
    println!("[relay] state: {}", state_path.display());
    println!("[relay] Tier-1 single relay — NOT global-observer resistant");

    loop {
        let state = Arc::clone(&state);
        let path = state_path.to_path_buf();
        match accept_and_reply(&mut h, port, move |frame| {
            handle_relay_request(&state, &path, &frame)
        })
        .await
        {
            Ok(Some(())) => {}
            Ok(None) => break,
            Err(e) => eprintln!("[relay] request error: {e}"),
        }
    }
    Ok(())
}

fn handle_relay_request(
    state: &Arc<Mutex<RelayState>>,
    state_path: &Path,
    frame: &[u8],
) -> Vec<u8> {
    let response = match decode_request(frame) {
        Err(e) => RelayResponse::Rejected(format!("invalid request: {e}")),
        Ok(RelayRequest::Submit(entry)) => match state.lock() {
            Err(_) => RelayResponse::Rejected("relay state lock poisoned".into()),
            Ok(mut relay) => {
                let mut candidate = relay.clone();
                match candidate.submit(epoch_now(), entry) {
                    Err(e) => RelayResponse::Rejected(e.to_string()),
                    Ok(receipt) => match candidate.save(state_path) {
                        Ok(()) => {
                            *relay = candidate;
                            RelayResponse::Accepted {
                                epoch: receipt.epoch,
                                entries: receipt.entries,
                            }
                        }
                        Err(e) => RelayResponse::Rejected(format!("persistence failed: {e}")),
                    },
                }
            }
        },
        Ok(RelayRequest::Fetch { since_epoch }) => match state.lock() {
            Err(_) => RelayResponse::Rejected("relay state lock poisoned".into()),
            Ok(relay) => RelayResponse::Ledger(relay.fetch(since_epoch)),
        },
    };
    match &response {
        RelayResponse::Ledger(blocks) => encode_ledger_response_bounded(blocks.clone()),
        _ => encode_response(&response),
    }
    .unwrap_or_else(|e| {
        encode_response(&RelayResponse::Rejected(format!(
            "response encoding failed: {e}"
        )))
        .expect("small rejection response must encode")
    })
}

async fn relay_round_trip(relay: &str, port: u16, request: &RelayRequest) -> Result<RelayResponse> {
    println!("[tor] bootstrapping onto the Tor network…");
    let client = bootstrap().await.context("bootstrap")?;
    let request = encode_request(request).context("encode relay request")?;
    let response = dial_request(&client, relay, port, &request)
        .await
        .context("relay request")?;
    decode_response(&response).context("decode relay response")
}

async fn drop_send_cmd(
    relay: &str,
    to: &str,
    message: &str,
    port: u16,
    pow_difficulty: u32,
) -> Result<()> {
    let card = to.parse::<ContactCard>().context("invalid contact card")?;
    let id_path = Identity::default_path().context("could not determine identity path")?;
    let identity =
        Identity::load(&id_path).context("failed to load identity — run `darqual keygen` first")?;
    let epoch = epoch_now();
    let conv = Conversation::new(&identity, &card);
    let (label, envelope) = conv
        .seal(&card, epoch, message.as_bytes())
        .context("seal dead-drop")?;
    let entry = LedgerEntry::mint(label, envelope, pow_difficulty);

    match relay_round_trip(relay, port, &RelayRequest::Submit(entry)).await? {
        RelayResponse::Accepted { epoch, entries } => {
            println!("[drop-sent] relay={relay} epoch={epoch} entries={entries}");
            Ok(())
        }
        RelayResponse::Rejected(reason) => anyhow::bail!("relay rejected write: {reason}"),
        RelayResponse::Ledger(_) => anyhow::bail!("relay returned an unexpected ledger response"),
    }
}

async fn drop_fetch_cmd(
    relay: &str,
    from: &str,
    port: u16,
    since_epoch: Option<u64>,
) -> Result<()> {
    let sender = from
        .parse::<ContactCard>()
        .context("invalid contact card")?;
    let id_path = Identity::default_path().context("could not determine identity path")?;
    let identity =
        Identity::load(&id_path).context("failed to load identity — run `darqual keygen` first")?;
    let blocks = match relay_round_trip(relay, port, &RelayRequest::Fetch { since_epoch }).await? {
        RelayResponse::Ledger(blocks) => blocks,
        RelayResponse::Rejected(reason) => anyhow::bail!("relay rejected fetch: {reason}"),
        RelayResponse::Accepted { .. } => anyhow::bail!("relay returned an unexpected receipt"),
    };

    let conv = Conversation::new(&identity, &sender);
    let mut found = 0usize;
    for block in &blocks {
        for message in fetch_open(&conv, block.header.epoch, block, &identity) {
            println!("[drop-recv] {}", String::from_utf8_lossy(&message));
            found += 1;
        }
    }
    println!(
        "[drop-fetch] relay={relay} blocks={} messages={found}",
        blocks.len()
    );
    Ok(())
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

#[cfg(test)]
mod tier1_tests {
    use std::fs;

    use darqual_core::{Identity, Label};

    use super::*;

    fn entry_for(recipient: &Identity, message: &[u8]) -> LedgerEntry {
        let lockbox = Lockbox::seal_to_card(&recipient.contact_card(), message).expect("seal");
        LedgerEntry::mint(Label([3; 16]), lockbox.envelope.into_bytes(), 0)
    }

    #[test]
    fn accepted_submit_is_fetchable_after_reloading_snapshot() {
        let bob = Identity::generate();
        let state = Arc::new(Mutex::new(RelayState::new(4, 0).expect("state")));
        let dir =
            std::env::temp_dir().join(format!("darqual-relay-accepted-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("relay.bin");
        let encoded = encode_request(&RelayRequest::Submit(entry_for(
            &bob,
            b"durable acceptance",
        )))
        .expect("encode");

        let response = decode_response(&handle_relay_request(&state, &path, &encoded))
            .expect("decode response");
        assert!(matches!(response, RelayResponse::Accepted { .. }));

        drop(state);
        let restored = RelayState::load(&path).expect("load accepted state");
        assert_eq!(restored.fetch(None)[0].entries.len(), 1);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn malformed_request_is_rejected_then_valid_fetch_succeeds() {
        let state = Arc::new(Mutex::new(RelayState::new(4, 0).expect("state")));
        let dir =
            std::env::temp_dir().join(format!("darqual-relay-malformed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("relay.bin");

        let malformed = decode_response(&handle_relay_request(&state, &path, b"not bincode"))
            .expect("decode rejection");
        assert!(matches!(malformed, RelayResponse::Rejected(_)));

        let fetch = encode_request(&RelayRequest::Fetch { since_epoch: None }).expect("encode");
        let after = decode_response(&handle_relay_request(&state, &path, &fetch))
            .expect("decode valid response");
        assert_eq!(after, RelayResponse::Ledger(Vec::new()));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn persistence_failure_does_not_accept_or_mutate_relay_state() {
        let bob = Identity::generate();
        let state = Arc::new(Mutex::new(RelayState::new(4, 0).expect("state")));
        let dir = std::env::temp_dir().join(format!("darqual-relay-dir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        // Renaming an atomic temp file over a directory must fail.
        let response = handle_relay_request(
            &state,
            &dir,
            &encode_request(&RelayRequest::Submit(entry_for(&bob, b"must roll back")))
                .expect("encode"),
        );
        let response = decode_response(&response).expect("decode");

        assert!(matches!(response, RelayResponse::Rejected(_)));
        assert!(state.lock().expect("lock").fetch(None).is_empty());
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
