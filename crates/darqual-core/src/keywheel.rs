//! # Keywheel — forward-secret dead-drop labels (Stage 7, v0.7.0)
//!
//! A hash-ratchet that rotates the per-conversation dead-drop label each epoch.
//! Unlike the static PRF in [`crate::conversation`] (Stage 3), a keywheel advances
//! its state one-way: compromising state at epoch N cannot reveal labels used at
//! epochs < N (forward-secret metadata).
//!
//! ## Design
//! ```text
//! state[0]  --ratchet-->  state[1]  --ratchet-->  state[2]  ...
//!    |                       |                       |
//!  label[0]               label[1]               label[2]
//! ```
//! `ratchet_state(s) = BLAKE3(RATCHET_DOMAIN ++ s)` — one-way, non-invertible.
//! `label(s)        = BLAKE3_keyed(s, LABEL_DOMAIN)[..16]`
//!
//! Both peers seed identically from `BLAKE3_keyed(shared_secret, "keywheel-seed")`,
//! so they derive the same wheel without an extra round-trip.
//!
//! ## Alpenhorn IBE (not implemented — documented research path)
//! Alpenhorn-style IBE add-friend (contact bootstrap without leaking the contact
//! graph) requires pairing-based identity-based encryption (BLS12-381) — research-
//! grade, not implemented here.  This keywheel provides forward-secret metadata for
//! **existing conversations** (the dialing/ratchet half of Alpenhorn); the IBE
//! add-friend half remains an open research item for a future stage.

use std::fmt;

use crate::label::Label;

// ── Domain separators ────────────────────────────────────────────────────────

/// Domain for the one-way state ratchet.  Must never equal `LABEL_DOMAIN`.
const RATCHET_DOMAIN: &[u8] = b"darqual-keywheel-ratchet-v1";

/// Domain for label derivation from the current wheel state.
const LABEL_DOMAIN: &[u8] = b"darqual-keywheel-label-v1";

/// Domain for seeding the wheel from a conversation shared secret.
pub(crate) const SEED_CONTEXT: &str = "keywheel-seed";

// ── Keywheel ─────────────────────────────────────────────────────────────────

/// A forward-secret label ratchet for a single conversation.
///
/// State is advanced one-way each epoch; the `Debug` impl redacts the secret
/// to prevent accidental exposure in logs.
pub struct Keywheel {
    /// Current epoch counter.
    pub epoch: u64,
    /// Current ratchet state — secret, never printed.
    state: [u8; 32],
}

impl fmt::Debug for Keywheel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keywheel")
            .field("epoch", &self.epoch)
            .field("state", &"<redacted>")
            .finish()
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// One step of the hash ratchet.  Non-invertible by BLAKE3's one-way property.
fn ratchet_state(state: [u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(RATCHET_DOMAIN.len() + 32);
    input.extend_from_slice(RATCHET_DOMAIN);
    input.extend_from_slice(&state);
    *blake3::hash(&input).as_bytes()
}

/// Derive a label from the current state using a keyed hash.
fn derive_label(state: &[u8; 32]) -> Label {
    // LABEL_DOMAIN must fit in 32 bytes for blake3::keyed_hash key; we use it
    // as the data and state as the key (state is already 32 bytes — perfect).
    let hash = blake3::keyed_hash(state, LABEL_DOMAIN);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    Label(bytes)
}

// ── Public API ────────────────────────────────────────────────────────────────

impl Keywheel {
    /// Construct a keywheel seeded from a raw 32-byte secret and a starting epoch.
    ///
    /// The seed is hashed through `SEED_CONTEXT` so the raw secret is never
    /// used directly as ratchet state.
    pub(crate) fn from_seed(seed: &[u8; 32], start_epoch: u64) -> Self {
        // Use keyed_hash: key=seed, data=SEED_CONTEXT bytes — produces 32-byte state.
        let state = *blake3::keyed_hash(seed, SEED_CONTEXT.as_bytes()).as_bytes();
        Keywheel {
            epoch: start_epoch,
            state,
        }
    }

    /// Advance the ratchet by one epoch.  The previous state is irrecoverably lost.
    pub fn advance(&mut self) {
        self.state = ratchet_state(self.state);
        self.epoch += 1;
    }

    /// Derive the dead-drop label for the **current** epoch.
    pub fn label(&self) -> Label {
        derive_label(&self.state)
    }

    /// Derive the dead-drop label for `target_epoch`.
    ///
    /// Returns `None` if `target_epoch < self.epoch` — forward secrecy: once
    /// the ratchet has advanced past an epoch, that state is gone.
    pub fn label_at(&self, target_epoch: u64) -> Option<Label> {
        if target_epoch < self.epoch {
            return None; // forward-secrecy: cannot go backward
        }
        // Clone current state and advance to target without mutating self.
        let mut state = self.state;
        let mut epoch = self.epoch;
        while epoch < target_epoch {
            state = ratchet_state(state);
            epoch += 1;
        }
        Some(derive_label(&state))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::{ContactCard, Conversation, Identity};

    /// Helper: build two conversations (Alice→Bob, Bob→Alice) sharing the same secret.
    fn alice_bob_conversations() -> (Conversation, Conversation) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card: ContactCard = bob.contact_card();
        let alice_card: ContactCard = alice.contact_card();
        let conv_alice = Conversation::new(&alice, &bob_card);
        let conv_bob = Conversation::new(&bob, &alice_card);
        (conv_alice, conv_bob)
    }

    // ── keywheel_label_is_symmetric ──────────────────────────────────────────
    /// Alice's and Bob's keywheels (seeded from their respective sides of the
    /// ECDH) produce the same label at the same epoch.
    #[test]
    fn keywheel_label_is_symmetric() {
        let (conv_alice, conv_bob) = alice_bob_conversations();
        let wheel_alice = conv_alice.keywheel(0);
        let wheel_bob = conv_bob.keywheel(0);
        assert_eq!(
            wheel_alice.label(),
            wheel_bob.label(),
            "both sides must derive the same label at epoch 0"
        );
    }

    // ── keywheel_label_rotates ───────────────────────────────────────────────
    /// The label changes each time the ratchet advances.
    #[test]
    fn keywheel_label_rotates() {
        let (conv, _) = alice_bob_conversations();
        let mut wheel = conv.keywheel(0);
        let label0 = wheel.label();
        wheel.advance();
        let label1 = wheel.label();
        assert_ne!(label0, label1, "label must change after advance");
        wheel.advance();
        let label2 = wheel.label();
        assert_ne!(label1, label2, "label must change on second advance");
    }

    // ── keywheel_cannot_go_backward ──────────────────────────────────────────
    /// Once the ratchet has advanced past an epoch, `label_at` returns `None`
    /// — you cannot recover past labels.
    #[test]
    fn keywheel_cannot_go_backward() {
        let (conv, _) = alice_bob_conversations();
        let mut wheel = conv.keywheel(5);
        // advance to epoch 7
        wheel.advance(); // 6
        wheel.advance(); // 7
        assert_eq!(wheel.epoch, 7);
        // can't look back
        assert!(
            wheel.label_at(5).is_none(),
            "label_at(5) must be None after advancing to 7"
        );
        assert!(
            wheel.label_at(6).is_none(),
            "label_at(6) must be None after advancing to 7"
        );
        // current epoch works
        assert!(wheel.label_at(7).is_some());
    }

    // ── keywheel_forward_only_deterministic ──────────────────────────────────
    /// Two independent clones advanced the same number of steps yield identical
    /// state (and thus the same label).
    #[test]
    fn keywheel_forward_only_deterministic() {
        let (conv, _) = alice_bob_conversations();
        let mut w1 = conv.keywheel(0);
        let mut w2 = conv.keywheel(0);
        for _ in 0..10 {
            w1.advance();
            w2.advance();
        }
        assert_eq!(
            w1.label(),
            w2.label(),
            "two wheels advanced identically must produce the same label"
        );
        assert_eq!(w1.epoch, w2.epoch);
    }

    // ── keywheel_different_conversations_differ ──────────────────────────────
    /// Wheels seeded from different conversations must produce different labels
    /// at the same epoch.
    #[test]
    fn keywheel_different_conversations_differ() {
        let (conv1, _) = alice_bob_conversations();
        let (conv2, _) = alice_bob_conversations(); // fresh random identities
        let label1 = conv1.keywheel(0).label();
        let label2 = conv2.keywheel(0).label();
        assert_ne!(
            label1, label2,
            "different conversations must produce different labels"
        );
    }

    // ── forward_secrecy_state_is_one_way ────────────────────────────────────
    /// Structural demonstration that the API provides no backward path.
    ///
    /// 1. Once advanced, `label_at(earlier)` is `None`.
    /// 2. Two wheels seeded differently never collide (with overwhelming probability).
    /// 3. `label_at(target)` is consistent with manually advancing a clone.
    #[test]
    fn forward_secrecy_state_is_one_way() {
        let (conv_a, _) = alice_bob_conversations();
        let (conv_b, _) = alice_bob_conversations();

        let mut wheel_a = conv_a.keywheel(0);
        let wheel_b = conv_b.keywheel(0);

        // Capture label at epoch 0 before advancing
        let label_a0 = wheel_a.label();

        // Advance wheel_a to epoch 3
        wheel_a.advance();
        wheel_a.advance();
        wheel_a.advance();

        // (1) API gives no backward path
        assert!(
            wheel_a.label_at(0).is_none(),
            "no backward path: label_at(0) must be None from epoch 3"
        );
        assert!(
            wheel_a.label_at(1).is_none(),
            "no backward path: label_at(1) must be None from epoch 3"
        );
        assert!(
            wheel_a.label_at(2).is_none(),
            "no backward path: label_at(2) must be None from epoch 3"
        );

        // (2) Different seeds never collide
        let label_b0 = wheel_b.label();
        assert_ne!(label_a0, label_b0, "different seeds must not collide");

        // (3) label_at(target) == manually advance clone to same epoch
        let via_label_at = wheel_b.label_at(4).expect("label_at(4) should succeed");
        let mut manual = conv_b.keywheel(0);
        for _ in 0..4 {
            manual.advance();
        }
        assert_eq!(
            via_label_at,
            manual.label(),
            "label_at(4) must equal manually-advanced wheel at epoch 4"
        );
    }
}
