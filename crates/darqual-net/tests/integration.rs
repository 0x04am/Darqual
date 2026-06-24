//! Integration tests: two nodes exchange an encrypted lockbox over real TCP.
//!
//! Tests:
//! - `stage1_send_recv_over_wire`       — Alice seals to Bob; Bob opens and gets plaintext.
//! - `stage1_wrong_recipient_over_wire` — Eve's lockbox sent to Bob's listener fails (Decrypt).

use std::time::Duration;

use darqual_core::{Identity, Lockbox};
use darqual_net::{bind_ephemeral, send_lockbox, serve_listener};
use tokio::sync::oneshot;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_MSG: &str = "stage1 over the wire";

// ── helper: spin up a listener backed by Bob's identity ─────────────────────

async fn spawn_bob_listener(
    bob: &Identity,
) -> (
    String,
    oneshot::Receiver<Result<Vec<u8>, darqual_core::Error>>,
) {
    let (listener, addr) = bind_ephemeral("127.0.0.1")
        .await
        .expect("bind_ephemeral failed");

    // Persist Bob to a temp file so we can move Identity into the closure
    let tmp = std::env::temp_dir().join(format!(
        "darqual_test_bob_{}.toml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time ok")
            .subsec_nanos()
    ));
    bob.save(&tmp).expect("save bob");
    let bob_identity = Identity::load(&tmp).expect("load bob");

    let (tx, rx) = oneshot::channel::<Result<Vec<u8>, darqual_core::Error>>();
    let mut tx_opt = Some(tx);

    tokio::spawn(async move {
        serve_listener(listener, move |envelope| {
            let result = Lockbox::open(&bob_identity, &envelope);
            if let Some(sender) = tx_opt.take() {
                let _ = sender.send(result);
            }
        })
        .await
        .ok();
    });

    (addr, rx)
}

// ── test 1: correct recipient receives plaintext ─────────────────────────────

#[tokio::test]
async fn stage1_send_recv_over_wire() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let bob_card = bob.contact_card();

    let (addr, rx) = spawn_bob_listener(&bob).await;

    // Give the listener a tick to start accepting
    tokio::time::sleep(Duration::from_millis(25)).await;

    let lockbox = Lockbox::seal_to_card(&bob_card, TEST_MSG.as_bytes()).expect("seal failed");

    send_lockbox(&addr, &lockbox.envelope)
        .await
        .expect("send_lockbox failed");

    let result = timeout(TEST_TIMEOUT, rx)
        .await
        .expect("test timed out — listener never responded")
        .expect("oneshot channel was dropped");

    let plaintext = result.expect("Bob failed to open lockbox");
    assert_eq!(
        plaintext,
        TEST_MSG.as_bytes(),
        "plaintext mismatch: {:?}",
        String::from_utf8_lossy(&plaintext)
    );

    // alice is the implicit sender — suppress unused-variable lint
    let _ = alice;
}

// ── test 2: wrong recipient — Bob's listener gets Eve's lockbox → Decrypt ───

#[tokio::test]
async fn stage1_wrong_recipient_over_wire() {
    let bob = Identity::generate();
    let eve = Identity::generate();
    let eve_card = eve.contact_card();

    let (addr, rx) = spawn_bob_listener(&bob).await;

    tokio::time::sleep(Duration::from_millis(25)).await;

    // Sealed to Eve, delivered to Bob's listener
    let lockbox = Lockbox::seal_to_card(&eve_card, b"secret for eve only").expect("seal failed");

    send_lockbox(&addr, &lockbox.envelope)
        .await
        .expect("send_lockbox failed");

    let result = timeout(TEST_TIMEOUT, rx)
        .await
        .expect("test timed out — listener never responded")
        .expect("oneshot channel was dropped");

    assert!(
        matches!(result, Err(darqual_core::Error::Decrypt)),
        "expected Decrypt error when wrong recipient opens lockbox, got: {:?}",
        result
    );
}
