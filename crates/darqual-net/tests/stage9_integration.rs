//! # Stage 9 Integration Test — End-to-End Light-Client
//!
//! THE capstone: a publisher node builds a real ledger block (real lockboxes +
//! cover traffic), serves it over TCP; a light-client fetches the block and
//! uses its Conversation label to extract ONLY its own messages without
//! trial-decrypting everything.
//!
//! ## Scenario
//! * **Alice** (publisher) → seals "end to end works" for Bob; pads with cover.
//! * **Bob** (light client) → fetches block, matches label, opens his message.
//! * **Eve** (adversary) → fetches same block, her label doesn't match → zero msgs.
//!
//! ## Label derivation
//! Both sides use `Conversation::new(me, them_card).label(epoch)` — the static
//! PRF dead-drop label from Stage 3, which is what `notify` / `fetch_open`
//! already use.  The keywheel (forward-secret ratchet, Stage 7) is tested
//! separately in [`stage9_keywheel_label_light_client`].
//!
//! Privacy guarantee: Eve's conversation label never matches Alice-Bob's.

use std::time::Duration;

use darqual_core::{Conversation, Identity, Lockbox};
use darqual_cover::pad_block;
use darqual_ledger::{Block, LedgerEntry, fetch_open, notify};
use darqual_net::{bind_ephemeral_block, fetch_block, serve_block_listener};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(10);

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a block: one real entry (Alice→Bob, static-PRF label) + cover padding.
fn build_block_static(
    alice: &Identity,
    bob: &Identity,
    epoch: u64,
    message: &[u8],
    cover_n: usize,
) -> Block {
    let bob_card = bob.contact_card();
    let alice_conv = Conversation::new(alice, &bob_card);

    // Label and seal via Conversation::seal (static PRF, same as notify/fetch_open)
    let (label, envelope_bytes) = alice_conv
        .seal(&bob_card, epoch, message)
        .expect("seal failed");

    let entry = LedgerEntry::mint(label, envelope_bytes, 0 /* difficulty=0 for tests */);

    let mut entries = vec![entry];
    let mut rng = ChaCha8Rng::seed_from_u64(0xCAFE_F00D);
    // pad to (1 real + cover_n) total entries
    pad_block(&mut entries, 1 + cover_n, &mut rng);

    Block::new(epoch, [0u8; 32], entries)
}

/// Build a block: one real entry using the KEYWHEEL label (Stage 7 forward-secret path).
fn build_block_keywheel(
    alice: &Identity,
    bob: &Identity,
    epoch: u64,
    message: &[u8],
    cover_n: usize,
) -> Block {
    let bob_card = bob.contact_card();
    let alice_conv = Conversation::new(alice, &bob_card);

    // Keywheel label at the given epoch
    let kw = alice_conv.keywheel(epoch);
    let label = kw.label();

    // Seal the lockbox directly (not via conv.seal — that uses static PRF label)
    use x25519_dalek::PublicKey as X25519PK;
    let their_x_pub = X25519PK::from(bob_card.x_pub);
    let lockbox = Lockbox::seal(&their_x_pub, message).expect("seal failed");
    let envelope_bytes: Vec<u8> = lockbox.envelope.into_bytes();

    let entry = LedgerEntry::mint(label, envelope_bytes, 0);

    let mut entries = vec![entry];
    let mut rng = ChaCha8Rng::seed_from_u64(0xBEEF_CAFE);
    pad_block(&mut entries, 1 + cover_n, &mut rng);

    Block::new(epoch, [0u8; 32], entries)
}

// ── capstone test 1: static-PRF label path (notify / fetch_open API) ─────────

#[tokio::test]
async fn stage9_light_client_end_to_end() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let eve = Identity::generate();

    // Fixed epoch — both sides must agree.  The CLI uses epoch_now() ±1 window.
    let epoch: u64 = 5;

    let block = build_block_static(&alice, &bob, epoch, b"end to end works", 8);
    assert!(
        block.entries.len() >= 9,
        "block must have at least 1 real + 8 cover entries, got {}",
        block.entries.len()
    );

    // ── spin up publisher ──────────────────────────────────────────────────
    let (listener, addr) = bind_ephemeral_block("127.0.0.1")
        .await
        .expect("bind_ephemeral_block");

    let block_clone = block.clone();
    tokio::spawn(async move {
        serve_block_listener(listener, block_clone)
            .await
            .ok(); // loop exits when dropped
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    // ── Bob: light client — fetch, label-match, open ──────────────────────
    let bob_block = timeout(TIMEOUT, fetch_block(&addr))
        .await
        .expect("Bob fetch timed out")
        .expect("Bob fetch_block failed");

    let alice_card = alice.contact_card();
    let bob_conv = Conversation::new(&bob, &alice_card);

    let bob_notified = notify(&bob_conv, epoch, &bob_block);
    assert!(bob_notified, "notify() must return true for Bob");

    let bob_msgs = fetch_open(&bob_conv, epoch, &bob_block, &bob);
    assert_eq!(
        bob_msgs.len(),
        1,
        "Bob must recover exactly one message (label-matched, not trial-decrypt)"
    );
    assert_eq!(
        bob_msgs[0],
        b"end to end works",
        "plaintext mismatch: {:?}",
        String::from_utf8_lossy(&bob_msgs[0])
    );

    // ── Eve: fetches the same block, gets nothing ─────────────────────────
    let eve_block = timeout(TIMEOUT, fetch_block(&addr))
        .await
        .expect("Eve fetch timed out")
        .expect("Eve fetch_block failed");

    let eve_conv = Conversation::new(&eve, &alice_card);
    let eve_notified = notify(&eve_conv, epoch, &eve_block);
    assert!(
        !eve_notified,
        "Eve must NOT be notified — her conversation label != Alice-Bob label"
    );
    let eve_msgs = fetch_open(&eve_conv, epoch, &eve_block, &eve);
    assert!(
        eve_msgs.is_empty(),
        "Eve must recover zero messages (privacy holds end-to-end through cover traffic)"
    );
}

// ── capstone test 2: keywheel label path (forward-secret metadata) ────────────

#[tokio::test]
async fn stage9_keywheel_label_light_client() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let eve = Identity::generate();

    let epoch: u64 = 7;

    let block = build_block_keywheel(&alice, &bob, epoch, b"keywheel end to end", 8);
    assert!(block.entries.len() >= 9);

    // ── publisher ──────────────────────────────────────────────────────────
    let (listener, addr) = bind_ephemeral_block("127.0.0.1")
        .await
        .expect("bind");

    let block_clone = block.clone();
    tokio::spawn(async move {
        serve_block_listener(listener, block_clone).await.ok();
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    // ── Bob fetches ────────────────────────────────────────────────────────
    let bob_block = timeout(TIMEOUT, fetch_block(&addr))
        .await
        .expect("Bob kw fetch timed out")
        .expect("Bob kw fetch_block failed");

    let alice_card = alice.contact_card();
    let bob_conv = Conversation::new(&bob, &alice_card);
    let bob_kw = bob_conv.keywheel(epoch);
    let bob_label = bob_kw.label();

    let bob_has_mail = bob_block.entries.iter().any(|e| e.label == bob_label);
    assert!(bob_has_mail, "Bob's keywheel label must appear in the block");

    let bob_msgs: Vec<Vec<u8>> = bob_block
        .entries
        .iter()
        .filter(|e| e.label == bob_label)
        .filter_map(|e| {
            let s = std::str::from_utf8(&e.envelope).ok()?;
            Lockbox::open(&bob, s).ok()
        })
        .collect();

    assert_eq!(bob_msgs.len(), 1, "Bob must recover exactly one message (kw path)");
    assert_eq!(bob_msgs[0], b"keywheel end to end");

    // ── Eve's keywheel label doesn't match ────────────────────────────────
    let eve_conv = Conversation::new(&eve, &alice_card);
    let eve_kw = eve_conv.keywheel(epoch);
    let eve_label = eve_kw.label();

    // Labels must differ (with overwhelming probability — different ECDH shared secret)
    assert_ne!(
        bob_label, eve_label,
        "Bob's and Eve's keywheel labels must differ"
    );

    let eve_has_mail = bob_block.entries.iter().any(|e| e.label == eve_label);
    assert!(!eve_has_mail, "Eve's keywheel label must NOT appear in the block");

    let eve_msgs: Vec<Vec<u8>> = bob_block
        .entries
        .iter()
        .filter(|e| e.label == eve_label)
        .filter_map(|e| {
            let s = std::str::from_utf8(&e.envelope).ok()?;
            Lockbox::open(&eve, s).ok()
        })
        .collect();
    assert!(eve_msgs.is_empty(), "Eve recovers zero messages (kw path)");
}

// ── privacy isolation: cover traffic hides real entry (in-process) ───────────

#[tokio::test]
async fn stage9_cover_traffic_hides_real_entry() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let stranger = Identity::generate();
    let epoch: u64 = 42;

    let block = build_block_static(&alice, &bob, epoch, b"private message", 16);

    // Stranger: label doesn't match, zero messages
    let stranger_conv = Conversation::new(&stranger, &alice.contact_card());
    assert!(
        !notify(&stranger_conv, epoch, &block),
        "stranger label must not match"
    );
    let stranger_msgs = fetch_open(&stranger_conv, epoch, &block, &stranger);
    assert!(stranger_msgs.is_empty(), "stranger must recover zero messages");

    // Bob still recovers his message (no network, in-proc)
    let bob_conv = Conversation::new(&bob, &alice.contact_card());
    assert!(notify(&bob_conv, epoch, &block), "Bob notify must be true");
    let bob_msgs = fetch_open(&bob_conv, epoch, &block, &bob);
    assert_eq!(bob_msgs.len(), 1);
    assert_eq!(bob_msgs[0], b"private message");
}
