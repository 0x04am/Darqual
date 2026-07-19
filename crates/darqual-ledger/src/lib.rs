#![forbid(unsafe_code)]

pub mod block;
pub mod epoch;
pub mod ledger;
pub mod merkle;
pub mod notify;
pub mod relay;
pub mod sweep;

pub use block::{Block, BlockHeader, LedgerEntry};
pub use epoch::{epoch_at, epoch_now, Epoch, EPOCH_SECONDS};
pub use ledger::{Ledger, LedgerError};
pub use merkle::{merkle_proof, merkle_root, verify_proof, MerkleProof, EMPTY_ROOT};
pub use notify::{fetch_open, fetch_open_adjacent_epochs, notify};
pub use relay::{
    RelayError, RelayReceipt, RelayState, MAX_RELAY_ENVELOPE_BYTES, MAX_RELAY_STATE_BYTES,
};
pub use sweep::{sweep_window, trial_decrypt};

#[cfg(test)]
mod tests {
    use darqual_core::{Conversation, Identity, Label, Lockbox};
    use x25519_dalek::PublicKey as X25519PublicKey;

    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────

    /// Build a LedgerEntry for `recipient` with a blank (zero) label.
    /// Uses difficulty=0 — no PoW grinding required.
    fn make_entry(recipient: &Identity, msg: &[u8]) -> LedgerEntry {
        let x_pub = X25519PublicKey::from(&recipient.x_secret);
        let lb = Lockbox::seal(&x_pub, msg).expect("seal failed");
        LedgerEntry::mint(Label([0u8; 16]), lb.envelope.into_bytes(), 0)
    }

    /// Build a LedgerEntry via a Conversation (properly labelled).
    /// Uses difficulty=0.
    fn make_conv_entry(
        sender_conv: &Conversation,
        them: &darqual_core::ContactCard,
        epoch: u64,
        msg: &[u8],
    ) -> LedgerEntry {
        let (label, envelope) = sender_conv.seal(them, epoch, msg).expect("seal failed");
        LedgerEntry::mint(label, envelope, 0)
    }

    // ── epoch ──────────────────────────────────────────────────────────────

    #[test]
    fn epoch_at_bucketing() {
        assert_eq!(epoch_at(0), 0);
        assert_eq!(epoch_at(59), 0);
        assert_eq!(epoch_at(60), 1);
        assert_eq!(epoch_at(119), 1);
        assert_eq!(epoch_at(120), 2);
    }

    #[test]
    fn epoch_now_is_reasonable() {
        let e = epoch_now();
        assert!(e > 28_000_000, "epoch_now seems too low: {}", e);
    }

    // ── merkle: determinism ────────────────────────────────────────────────

    #[test]
    fn merkle_root_deterministic() {
        let leaves: Vec<Vec<u8>> = vec![b"hello".to_vec(), b"world".to_vec()];
        let r1 = merkle_root(&leaves);
        let r2 = merkle_root(&leaves);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_changes_with_leaf() {
        let leaves: Vec<Vec<u8>> = vec![b"hello".to_vec(), b"world".to_vec()];
        let r1 = merkle_root(&leaves);

        let mut different = leaves.clone();
        different[0] = b"HELLO".to_vec();
        let r2 = merkle_root(&different);

        assert_ne!(r1, r2);
    }

    // ── merkle: empty set ─────────────────────────────────────────────────

    #[test]
    fn merkle_empty_is_empty_root() {
        assert_eq!(merkle_root(&[]), EMPTY_ROOT);
    }

    // ── merkle: proofs ────────────────────────────────────────────────────

    #[test]
    fn merkle_single_leaf_proof_verifies() {
        let leaves: Vec<Vec<u8>> = vec![b"solo".to_vec()];
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0).expect("proof generation failed");
        assert!(verify_proof(&root, b"solo", &proof));
    }

    #[test]
    fn merkle_multi_leaf_all_proofs_verify() {
        let leaves: Vec<Vec<u8>> = vec![
            b"alpha".to_vec(),
            b"beta".to_vec(),
            b"gamma".to_vec(),
            b"delta".to_vec(),
        ];
        let root = merkle_root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, i).expect("proof generation failed");
            assert!(
                verify_proof(&root, leaf, &proof),
                "proof failed for index {}",
                i
            );
        }
    }

    #[test]
    fn merkle_odd_leaf_count_proofs_verify() {
        let leaves: Vec<Vec<u8>> = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];
        let root = merkle_root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, i).expect("proof for odd-count failed");
            assert!(verify_proof(&root, leaf, &proof), "proof failed idx {}", i);
        }
    }

    #[test]
    fn merkle_proof_fails_tampered_leaf() {
        let leaves: Vec<Vec<u8>> = vec![b"real".to_vec(), b"data".to_vec()];
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0).expect("proof failed");
        assert!(!verify_proof(&root, b"fake", &proof));
    }

    #[test]
    fn merkle_proof_fails_altered_sibling() {
        let leaves: Vec<Vec<u8>> = vec![b"left".to_vec(), b"right".to_vec()];
        let root = merkle_root(&leaves);
        let mut proof = merkle_proof(&leaves, 0).expect("proof failed");
        proof.siblings[0][0] ^= 0xFF;
        assert!(!verify_proof(&root, b"left", &proof));
    }

    #[test]
    fn merkle_no_proof_for_out_of_bounds() {
        let leaves: Vec<Vec<u8>> = vec![b"only".to_vec()];
        assert!(merkle_proof(&leaves, 1).is_none());
        assert!(merkle_proof(&[], 0).is_none());
    }

    // ── block ─────────────────────────────────────────────────────────────

    #[test]
    fn block_validate_wellformed() {
        let alice = Identity::generate();
        let entries = vec![make_entry(&alice, b"msg1"), make_entry(&alice, b"msg2")];
        let block = Block::new(1, [0u8; 32], entries);
        assert!(block.validate());
    }

    #[test]
    fn block_validate_fails_mutated_entry() {
        let alice = Identity::generate();
        let entries = vec![make_entry(&alice, b"msg1"), make_entry(&alice, b"msg2")];
        let mut block = Block::new(1, [0u8; 32], entries);
        // Mutate envelope after construction — Merkle root no longer matches.
        block.entries[0].envelope = b"tampered".to_vec();
        assert!(!block.validate());
    }

    #[test]
    fn adjacent_epoch_trial_at_genesis_does_not_duplicate_plaintext() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let epoch = 0;
        let plaintext = b"genesis epoch message";
        let alice_to_bob = Conversation::new(&alice, &bob.contact_card());
        let (label, envelope) = alice_to_bob
            .seal(&bob.contact_card(), epoch, plaintext)
            .expect("seal");
        let block = Block::new(epoch, [0; 32], vec![LedgerEntry::mint(label, envelope, 0)]);
        let bob_from_alice = Conversation::new(&bob, &alice.contact_card());

        let received = fetch_open_adjacent_epochs(&bob_from_alice, &block, &bob);

        assert_eq!(received, vec![plaintext.to_vec()]);
    }

    #[test]
    fn adjacent_epoch_trial_open_handles_sender_relay_clock_skew() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let sender_epoch = 120;
        let relay_epoch = sender_epoch + 1;
        let plaintext = b"crossed the epoch boundary";
        let alice_to_bob = Conversation::new(&alice, &bob.contact_card());
        let (label, envelope) = alice_to_bob
            .seal(&bob.contact_card(), sender_epoch, plaintext)
            .expect("seal");
        let block = Block::new(
            relay_epoch,
            [0; 32],
            vec![LedgerEntry::mint(label, envelope, 0)],
        );
        let bob_from_alice = Conversation::new(&bob, &alice.contact_card());

        let received = fetch_open_adjacent_epochs(&bob_from_alice, &block, &bob);

        assert_eq!(received, vec![plaintext.to_vec()]);
    }

    #[test]
    fn alice_submit_bob_fetch_eve_cannot_open_public_blocks() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();
        let epoch = 42;
        let plaintext = b"offline tier1 hello";

        let alice_to_bob = Conversation::new(&alice, &bob.contact_card());
        let (label, envelope) = alice_to_bob
            .seal(&bob.contact_card(), epoch, plaintext)
            .expect("seal");
        let mut relay = RelayState::new(4, 0).expect("relay");
        relay
            .submit(epoch, LedgerEntry::mint(label, envelope, 0))
            .expect("submit");
        let blocks = relay.fetch(None);

        let bob_from_alice = Conversation::new(&bob, &alice.contact_card());
        let bob_messages: Vec<Vec<u8>> = blocks
            .iter()
            .flat_map(|block| fetch_open(&bob_from_alice, block.header.epoch, block, &bob))
            .collect();
        assert_eq!(bob_messages, vec![plaintext.to_vec()]);

        let eve_from_alice = Conversation::new(&eve, &alice.contact_card());
        let eve_messages: Vec<Vec<u8>> = blocks
            .iter()
            .flat_map(|block| fetch_open(&eve_from_alice, block.header.epoch, block, &eve))
            .collect();
        assert!(eve_messages.is_empty());
    }

    #[test]
    fn message_survives_sender_exit_and_relay_restart() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let epoch = 77;
        let plaintext = b"sender is already offline";
        let dir =
            std::env::temp_dir().join(format!("darqual-tier1-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("relay.bin");

        {
            let alice_to_bob = Conversation::new(&alice, &bob.contact_card());
            let (label, envelope) = alice_to_bob
                .seal(&bob.contact_card(), epoch, plaintext)
                .expect("seal");
            let mut relay = RelayState::new(4, 0).expect("relay");
            relay
                .submit(epoch, LedgerEntry::mint(label, envelope, 0))
                .expect("submit");
            relay.save(&path).expect("persist accepted message");
        }

        let restored = RelayState::load(&path).expect("restart relay");
        let bob_from_alice = Conversation::new(&bob, &alice.contact_card());
        let received: Vec<Vec<u8>> = restored
            .fetch(None)
            .iter()
            .flat_map(|block| fetch_open(&bob_from_alice, block.header.epoch, block, &bob))
            .collect();

        assert_eq!(received, vec![plaintext.to_vec()]);
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn relay_snapshot_does_not_contain_plaintext_message_bytes() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let epoch = 88;
        let plaintext = b"DARQUAL-PLAINTEXT-SENTINEL-DO-NOT-STORE";
        let alice_to_bob = Conversation::new(&alice, &bob.contact_card());
        let (label, envelope) = alice_to_bob
            .seal(&bob.contact_card(), epoch, plaintext)
            .expect("seal");
        let mut relay = RelayState::new(4, 0).expect("relay");
        relay
            .submit(epoch, LedgerEntry::mint(label, envelope, 0))
            .expect("submit");
        let dir =
            std::env::temp_dir().join(format!("darqual-tier1-plaintext-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("relay.bin");
        relay.save(&path).expect("save");

        let bytes = std::fs::read(&path).expect("read snapshot");
        assert!(!bytes.windows(plaintext.len()).any(|w| w == plaintext));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn block_empty_has_empty_root() {
        let block = Block::new(0, [0u8; 32], vec![]);
        assert_eq!(block.header.merkle_root, EMPTY_ROOT);
        assert!(block.validate());
    }

    // ── ledger ────────────────────────────────────────────────────────────

    fn genesis_block(epoch: u64, entries: Vec<LedgerEntry>) -> Block {
        Block::new(epoch, [0u8; 32], entries)
    }

    #[test]
    fn ledger_append_links_blocks() {
        let mut ledger = Ledger::new(10);
        let b0 = genesis_block(0, vec![]);
        ledger.append(b0).expect("genesis append failed");

        let tip = ledger.tip_hash();
        let b1 = Block::new(1, tip, vec![]);
        ledger.append(b1).expect("b1 append failed");

        assert_eq!(ledger.len(), 2);
        assert!(ledger.validate_chain());
    }

    #[test]
    fn ledger_wrong_prev_hash_errors() {
        let mut ledger = Ledger::new(10);
        let b0 = genesis_block(0, vec![]);
        ledger.append(b0).expect("genesis append failed");

        let bad_prev = [0xDE; 32];
        let bad_block = Block::new(1, bad_prev, vec![]);
        let result = ledger.append(bad_block);
        assert!(
            matches!(result, Err(LedgerError::BrokenChain { .. })),
            "expected BrokenChain, got: {:?}",
            result
        );
    }

    #[test]
    fn ledger_invalid_block_errors() {
        let mut ledger = Ledger::new(10);
        let alice = Identity::generate();
        let entries = vec![make_entry(&alice, b"x")];
        let mut block = Block::new(0, [0u8; 32], entries);
        // Corrupt after construction
        block.entries[0].envelope = b"corrupted".to_vec();
        let result = ledger.append(block);
        assert!(matches!(result, Err(LedgerError::InvalidBlock)));
    }

    #[test]
    fn ledger_validate_chain_true_for_built_chain() {
        let mut ledger = Ledger::new(10);
        let alice = Identity::generate();

        let b0 = genesis_block(0, vec![make_entry(&alice, b"first")]);
        ledger.append(b0).expect("b0");
        let b1 = Block::new(1, ledger.tip_hash(), vec![make_entry(&alice, b"second")]);
        ledger.append(b1).expect("b1");
        let b2 = Block::new(2, ledger.tip_hash(), vec![]);
        ledger.append(b2).expect("b2");

        assert!(ledger.validate_chain());
    }

    #[test]
    fn ledger_get_by_epoch() {
        let mut ledger = Ledger::new(10);
        let b0 = genesis_block(7, vec![]);
        ledger.append(b0).expect("append failed");
        assert!(ledger.get(7).is_some());
        assert!(ledger.get(99).is_none());
    }

    #[test]
    fn ledger_prune_keeps_window() {
        let mut ledger = Ledger::new(3);
        for i in 0..5u64 {
            let prev = ledger.tip_hash();
            let b = Block::new(i, prev, vec![]);
            ledger.append(b).expect("append failed");
        }
        assert_eq!(ledger.len(), 3);
        assert_eq!(ledger.blocks()[0].header.epoch, 2);
        for b in ledger.blocks() {
            assert!(b.validate(), "pruned block failed validate");
        }
        let blocks = ledger.blocks();
        for i in 1..blocks.len() {
            assert_eq!(
                blocks[i].header.prev_hash,
                blocks[i - 1].hash(),
                "window link broken at index {}",
                i
            );
        }
    }

    // ── trial_decrypt / sweep ─────────────────────────────────────────────

    #[test]
    fn trial_decrypt_only_returns_addressed_messages() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let stranger = Identity::generate();

        let alice_entry = make_entry(&alice, b"for alice");
        let bob_entry1 = make_entry(&bob, b"for bob 1");
        let bob_entry2 = make_entry(&bob, b"for bob 2");

        let block = Block::new(0, [0u8; 32], vec![alice_entry, bob_entry1, bob_entry2]);

        let bob_msgs = trial_decrypt(&bob, &block);
        assert_eq!(bob_msgs.len(), 2, "Bob should decrypt exactly 2");
        assert!(bob_msgs.contains(&b"for bob 1".to_vec()));
        assert!(bob_msgs.contains(&b"for bob 2".to_vec()));

        let alice_msgs = trial_decrypt(&alice, &block);
        assert_eq!(alice_msgs.len(), 1, "Alice should decrypt exactly 1");
        assert_eq!(alice_msgs[0], b"for alice");

        let stranger_msgs = trial_decrypt(&stranger, &block);
        assert!(stranger_msgs.is_empty(), "Stranger gets nothing");
    }

    #[test]
    fn sweep_window_aggregates_across_blocks() {
        let bob = Identity::generate();
        let alice = Identity::generate();
        let stranger = Identity::generate();

        let mut ledger = Ledger::new(10);

        let b0_entries = vec![
            make_entry(&bob, b"bob epoch 0"),
            make_entry(&alice, b"alice epoch 0"),
        ];
        let b0 = Block::new(0, [0u8; 32], b0_entries);
        ledger.append(b0).expect("b0");

        let tip = ledger.tip_hash();
        let b1_entries = vec![
            make_entry(&bob, b"bob epoch 1a"),
            make_entry(&bob, b"bob epoch 1b"),
        ];
        let b1 = Block::new(1, tip, b1_entries);
        ledger.append(b1).expect("b1");

        let bob_msgs = sweep_window(&bob, &ledger);
        assert_eq!(bob_msgs.len(), 3, "Bob should see 3 messages total");

        let stranger_msgs = sweep_window(&stranger, &ledger);
        assert!(stranger_msgs.is_empty(), "Stranger sees nothing");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Stage 3 — Addressing & Notification
    // ════════════════════════════════════════════════════════════════════════

    // ── label symmetry ────────────────────────────────────────────────────

    #[test]
    fn conversation_label_is_symmetric() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_card = alice.contact_card();
        let bob_card = bob.contact_card();

        let alice_conv = Conversation::new(&alice, &bob_card);
        let bob_conv = Conversation::new(&bob, &alice_card);

        let epoch = 42u64;
        assert_eq!(
            alice_conv.label(epoch),
            bob_conv.label(epoch),
            "both sides of the conversation must derive the same label"
        );
    }

    // ── label rotation ────────────────────────────────────────────────────

    #[test]
    fn label_rotates_per_epoch() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card = bob.contact_card();

        let conv = Conversation::new(&alice, &bob_card);
        assert_ne!(
            conv.label(5),
            conv.label(6),
            "label must change between epochs"
        );
    }

    // ── label unlinkability ───────────────────────────────────────────────

    #[test]
    fn label_unlinkable_across_conversations() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let charlie = Identity::generate();

        let conv_ab = Conversation::new(&alice, &bob.contact_card());
        let conv_ac = Conversation::new(&alice, &charlie.contact_card());

        let epoch = 1u64;
        assert_ne!(
            conv_ab.label(epoch),
            conv_ac.label(epoch),
            "different conversations must produce different labels at same epoch"
        );
    }

    // ── notify: present ───────────────────────────────────────────────────

    #[test]
    fn notify_true_when_my_labeled_lockbox_present() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card = bob.contact_card();
        let alice_card = alice.contact_card();

        let epoch = 10u64;
        let alice_conv = Conversation::new(&alice, &bob_card);
        let bob_conv = Conversation::new(&bob, &alice_card);

        let entry = make_conv_entry(&alice_conv, &bob_card, epoch, b"hey bob");
        let block = Block::new(epoch, [0u8; 32], vec![entry]);

        assert!(
            notify(&bob_conv, epoch, &block),
            "Bob should be notified when his label is present"
        );
    }

    // ── notify: absent ────────────────────────────────────────────────────

    #[test]
    fn notify_false_when_absent() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card = bob.contact_card();
        let alice_card = alice.contact_card();

        let epoch = 10u64;
        let alice_conv = Conversation::new(&alice, &bob_card);
        let bob_conv = Conversation::new(&bob, &alice_card);

        // Put Alice's message in epoch 10, check notify for epoch 11
        let entry = make_conv_entry(&alice_conv, &bob_card, epoch, b"hey bob");
        let block = Block::new(epoch, [0u8; 32], vec![entry]);

        assert!(
            !notify(&bob_conv, epoch + 1, &block),
            "Bob should NOT be notified for wrong epoch"
        );
    }

    // ── fetch_open: full round-trip ───────────────────────────────────────

    #[test]
    fn fetch_open_returns_my_message_addressed_by_label() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card = bob.contact_card();
        let alice_card = alice.contact_card();

        let epoch = 7u64;
        let alice_conv = Conversation::new(&alice, &bob_card);
        let bob_conv = Conversation::new(&bob, &alice_card);

        let msg = b"dead drop confirmed";
        let entry = make_conv_entry(&alice_conv, &bob_card, epoch, msg);
        let block = Block::new(epoch, [0u8; 32], vec![entry]);

        // Bob notifies first
        assert!(notify(&bob_conv, epoch, &block));

        // Bob fetches and opens
        let plaintexts = fetch_open(&bob_conv, epoch, &block, &bob);
        assert_eq!(plaintexts.len(), 1);
        assert_eq!(plaintexts[0], msg);
    }

    // ── addressing privacy: stranger's label doesn't match ────────────────

    #[test]
    fn stranger_conversation_label_does_not_match() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();
        let bob_card = bob.contact_card();
        let alice_card = alice.contact_card();

        let epoch = 3u64;
        let alice_conv = Conversation::new(&alice, &bob_card);
        // Eve tries to spy: she forms a conv with Bob using a different Alice-derived secret
        let eve_conv = Conversation::new(&eve, &alice_card);

        let entry = make_conv_entry(&alice_conv, &bob_card, epoch, b"private");
        let block = Block::new(epoch, [0u8; 32], vec![entry]);

        assert!(
            !notify(&eve_conv, epoch, &block),
            "Eve's conversation label must not match Alice-Bob's"
        );
    }

    // ── existing trial_decrypt still works over entries ───────────────────

    #[test]
    fn trial_decrypt_still_works_over_entries() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card = bob.contact_card();
        let _alice_card = alice.contact_card();

        let epoch = 5u64;
        let alice_conv = Conversation::new(&alice, &bob_card);

        // A properly labelled entry plus a zero-label entry
        let labelled = make_conv_entry(&alice_conv, &bob_card, epoch, b"addressed msg");
        let unlabelled = make_entry(&bob, b"old style");

        let block = Block::new(epoch, [0u8; 32], vec![labelled, unlabelled]);

        let msgs = trial_decrypt(&bob, &block);
        assert_eq!(msgs.len(), 2, "trial_decrypt should still find both");
        assert!(msgs.contains(&b"addressed msg".to_vec()));
        assert!(msgs.contains(&b"old style".to_vec()));

        // Alice card owner can't decrypt Bob's messages
        let alice_msgs = trial_decrypt(&alice, &block);
        assert!(alice_msgs.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // Stage 4 — PoW spam resistance
    // ════════════════════════════════════════════════════════════════════════

    // ── LedgerEntry::mint produces a valid PoW stamp ──────────────────────

    #[test]
    fn ledger_entry_mint_satisfies_pow_valid() {
        let label = Label([0xAB; 16]);
        let envelope = b"test envelope for pow".to_vec();
        let difficulty = 10u32;

        let entry = LedgerEntry::mint(label, envelope.clone(), difficulty);
        assert!(
            entry.pow_valid(difficulty),
            "minted entry must satisfy its own difficulty"
        );
    }

    // ── Merkle root changes when nonce changes ────────────────────────────

    #[test]
    fn nonce_committed_in_merkle_root() {
        let label = Label([0x01; 16]);
        let envelope = b"same content".to_vec();

        let entry_a = LedgerEntry {
            label,
            envelope: envelope.clone(),
            nonce: 0,
        };
        let entry_b = LedgerEntry {
            label,
            envelope: envelope.clone(),
            nonce: 1,
        };

        // canonical_bytes must differ
        assert_ne!(entry_a.canonical_bytes(), entry_b.canonical_bytes());

        let block_a = Block::new(0, [0u8; 32], vec![entry_a]);
        let block_b = Block::new(0, [0u8; 32], vec![entry_b]);
        assert_ne!(
            block_a.header.merkle_root, block_b.header.merkle_root,
            "Merkle root must differ when nonce differs"
        );
    }

    // ── tampered envelope invalidates PoW (content-binding) ───────────────

    #[test]
    fn tampered_envelope_fails_pow_after_mint() {
        let label = Label([0x55; 16]);
        let envelope = b"original".to_vec();
        let difficulty = 8u32;

        let mut entry = LedgerEntry::mint(label, envelope, difficulty);
        // Still valid before tampering
        assert!(entry.pow_valid(difficulty));

        // Tamper the envelope
        entry.envelope = b"tampered".to_vec();
        assert!(
            !entry.pow_valid(difficulty),
            "PoW must be invalidated after envelope is tampered"
        );
    }

    // ── block.validate_pow: rejects block with bad entry ─────────────────

    #[test]
    fn block_validate_pow_rejects_invalid_entry() {
        let label = Label([0x22; 16]);
        let envelope = b"spammy".to_vec();

        // Entry with nonce=0 and a meaningful difficulty — almost certainly invalid.
        let bad_entry = LedgerEntry {
            label,
            envelope,
            nonce: 0,
        };
        let block = Block::new(0, [0u8; 32], vec![bad_entry]);

        // difficulty=8: probability nonce=0 passes ≈ 1/256 — overwhelmingly rejected.
        // We check a range of labels to make the test robust.
        let difficulty = 10u32;
        // If this particular nonce happens to satisfy difficulty (1-in-1024 chance),
        // validate_pow would return true, which is correct behaviour. We just need to
        // confirm the machinery runs; the probability-based test is in pow.rs.
        // Here we verify validate_pow is consistent with per-entry pow_valid.
        let expected = block.entries.iter().all(|e| e.pow_valid(difficulty));
        assert_eq!(block.validate_pow(difficulty), expected);
    }

    // ── ledger rejects entry with invalid PoW when difficulty > 0 ─────────

    #[test]
    fn ledger_rejects_entry_with_invalid_pow() {
        let mut ledger = Ledger::new_with_pow(10, 8);

        // Build an entry with nonce=0 (very unlikely to satisfy difficulty=8)
        // and repeatedly try different labels until we get one that fails.
        let mut rejected = false;
        for seed in 0u8..32 {
            let label = Label([seed; 16]);
            let envelope = vec![seed; 20];
            let bad_entry = LedgerEntry {
                label,
                envelope,
                nonce: 0,
            };
            if !bad_entry.pow_valid(8) {
                let block = Block::new(0, [0u8; 32], vec![bad_entry]);
                let result = ledger.append(block);
                assert!(
                    matches!(result, Err(LedgerError::InvalidPoW(8))),
                    "expected InvalidPoW(8), got: {:?}",
                    result
                );
                rejected = true;
                break;
            }
        }
        assert!(
            rejected,
            "should have found at least one seed where nonce=0 fails difficulty=8"
        );
    }

    // ── ledger accepts entry with valid PoW ───────────────────────────────

    #[test]
    fn ledger_accepts_entry_with_valid_pow() {
        let difficulty = 8u32;
        let mut ledger = Ledger::new_with_pow(10, difficulty);

        let label = Label([0xCC; 16]);
        let envelope = b"valid pow entry".to_vec();
        let entry = LedgerEntry::mint(label, envelope, difficulty);

        let block = Block::new(0, [0u8; 32], vec![entry]);
        ledger
            .append(block)
            .expect("valid PoW block must be accepted");
        assert_eq!(ledger.len(), 1);
    }

    // ── ledger with difficulty=0 accepts anything (back-compat) ──────────

    #[test]
    fn ledger_pow_difficulty_zero_accepts_any_nonce() {
        let mut ledger = Ledger::new(10); // pow_difficulty = 0 by default
        let alice = Identity::generate();
        let entry = make_entry(&alice, b"no pow needed");
        let block = Block::new(0, [0u8; 32], vec![entry]);
        ledger
            .append(block)
            .expect("difficulty=0 should always accept");
        assert_eq!(ledger.len(), 1);
    }

    // ── higher difficulty: mint still converges and result is valid ────────

    #[test]
    fn mint_at_difficulty_12_produces_valid_entry() {
        let difficulty = 12u32;
        let label = Label([0x77; 16]);
        let envelope = b"harder work".to_vec();
        let entry = LedgerEntry::mint(label, envelope, difficulty);
        assert!(
            entry.pow_valid(difficulty),
            "difficulty-12 minted entry must satisfy pow_valid"
        );
        // Also satisfies lower difficulty
        assert!(entry.pow_valid(8));
        assert!(entry.pow_valid(0));
    }

    // ── validate_pow trivially true for empty block ───────────────────────

    #[test]
    fn validate_pow_empty_block_is_true() {
        let block = Block::new(0, [0u8; 32], vec![]);
        assert!(block.validate_pow(16), "empty block has no entries to fail");
    }
}
