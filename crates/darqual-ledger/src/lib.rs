#![forbid(unsafe_code)]

pub mod block;
pub mod epoch;
pub mod ledger;
pub mod merkle;
pub mod sweep;

pub use block::{Block, BlockHeader};
pub use epoch::{epoch_at, epoch_now, Epoch, EPOCH_SECONDS};
pub use ledger::{Ledger, LedgerError};
pub use merkle::{merkle_proof, merkle_root, verify_proof, MerkleProof, EMPTY_ROOT};
pub use sweep::{sweep_window, trial_decrypt};

#[cfg(test)]
mod tests {
    use darqual_core::{Identity, Lockbox};
    use x25519_dalek::PublicKey as X25519PublicKey;

    use super::*;

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
        // Epoch 0 would be before 1970; sanity-check it's > 0 and sane
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
        // Flip a byte in the first sibling
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

    fn make_lockbox_bytes(recipient: &Identity, msg: &[u8]) -> Vec<u8> {
        let x_pub = X25519PublicKey::from(&recipient.x_secret);
        let lb = Lockbox::seal(&x_pub, msg).expect("seal failed");
        lb.envelope.into_bytes()
    }

    #[test]
    fn block_validate_wellformed() {
        let alice = Identity::generate();
        let lbs = vec![
            make_lockbox_bytes(&alice, b"msg1"),
            make_lockbox_bytes(&alice, b"msg2"),
        ];
        let block = Block::new(1, [0u8; 32], lbs);
        assert!(block.validate());
    }

    #[test]
    fn block_validate_fails_mutated_lockbox() {
        let alice = Identity::generate();
        let lbs = vec![
            make_lockbox_bytes(&alice, b"msg1"),
            make_lockbox_bytes(&alice, b"msg2"),
        ];
        let mut block = Block::new(1, [0u8; 32], lbs);
        // Mutate a lockbox after construction
        block.lockboxes[0] = b"tampered".to_vec();
        assert!(!block.validate());
    }

    #[test]
    fn block_empty_has_empty_root() {
        let block = Block::new(0, [0u8; 32], vec![]);
        assert_eq!(block.header.merkle_root, EMPTY_ROOT);
        assert!(block.validate());
    }

    // ── ledger ────────────────────────────────────────────────────────────

    fn genesis_block(epoch: u64, lockboxes: Vec<Vec<u8>>) -> Block {
        Block::new(epoch, [0u8; 32], lockboxes)
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

        // Build a block with a wrong prev_hash
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
        let lbs = vec![make_lockbox_bytes(&alice, b"x")];
        let mut block = Block::new(0, [0u8; 32], lbs);
        // Corrupt after construction
        block.lockboxes[0] = b"corrupted".to_vec();
        let result = ledger.append(block);
        assert!(matches!(result, Err(LedgerError::InvalidBlock)));
    }

    #[test]
    fn ledger_validate_chain_true_for_built_chain() {
        let mut ledger = Ledger::new(10);
        let alice = Identity::generate();

        let b0 = genesis_block(0, vec![make_lockbox_bytes(&alice, b"first")]);
        ledger.append(b0).expect("b0");
        let b1 = Block::new(
            1,
            ledger.tip_hash(),
            vec![make_lockbox_bytes(&alice, b"second")],
        );
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
        // Append 5 blocks
        for i in 0..5u64 {
            let prev = ledger.tip_hash();
            let b = Block::new(i, prev, vec![]);
            ledger.append(b).expect("append failed");
        }
        // Should only keep 3
        assert_eq!(ledger.len(), 3);
        // The oldest retained block's epoch should be 2 (blocks 0,1 were pruned).
        assert_eq!(ledger.blocks()[0].header.epoch, 2);
        // Each retained block individually validates.
        for b in ledger.blocks() {
            assert!(b.validate(), "pruned block failed validate");
        }
        // Adjacent blocks link correctly within the retained window.
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

        // Build a block with: alice's msg, bob's msg, bob's msg #2
        let alice_lb = make_lockbox_bytes(&alice, b"for alice");
        let bob_lb1 = make_lockbox_bytes(&bob, b"for bob 1");
        let bob_lb2 = make_lockbox_bytes(&bob, b"for bob 2");

        let block = Block::new(0, [0u8; 32], vec![alice_lb, bob_lb1, bob_lb2]);

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

        // Block 0: one message for Bob, one for Alice
        let b0_lbs = vec![
            make_lockbox_bytes(&bob, b"bob epoch 0"),
            make_lockbox_bytes(&alice, b"alice epoch 0"),
        ];
        let b0 = Block::new(0, [0u8; 32], b0_lbs);
        ledger.append(b0).expect("b0");

        // Block 1: two messages for Bob
        let tip = ledger.tip_hash();
        let b1_lbs = vec![
            make_lockbox_bytes(&bob, b"bob epoch 1a"),
            make_lockbox_bytes(&bob, b"bob epoch 1b"),
        ];
        let b1 = Block::new(1, tip, b1_lbs);
        ledger.append(b1).expect("b1");

        let bob_msgs = sweep_window(&bob, &ledger);
        assert_eq!(bob_msgs.len(), 3, "Bob should see 3 messages total");

        let stranger_msgs = sweep_window(&stranger, &ledger);
        assert!(stranger_msgs.is_empty(), "Stranger sees nothing");
    }
}
