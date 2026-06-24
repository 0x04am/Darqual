//! Stage 10 — fuzz-style property tests for darqual-ledger Block deserialization.
//!
//! Feeds arbitrary byte strings to `serde_json::from_str::<Block>()` and
//! verifies the call never panics — only Ok or Err.
use darqual_ledger::Block;

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feeding completely arbitrary UTF-8 strings to serde_json Block
    /// deserialization must never panic.
    #[test]
    fn fuzz_block_deserialize_arbitrary_string(s in ".*") {
        let _: Result<Block, _> = serde_json::from_str(&s);
    }

    /// Feeding arbitrary raw bytes (converted via lossy UTF-8) must never panic.
    #[test]
    fn fuzz_block_deserialize_arbitrary_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let s = String::from_utf8_lossy(&raw).into_owned();
        let _: Result<Block, _> = serde_json::from_str(&s);
    }

    /// JSON-shaped strings (objects, arrays, numbers) — exercises the serde path
    /// that gets past initial JSON parsing but fails on schema validation.
    #[test]
    fn fuzz_block_deserialize_json_shaped(
        key   in "[a-z]{1,16}",
        value in "[a-zA-Z0-9]{0,64}",
    ) {
        let s = format!(r#"{{"{key}": "{value}"}}"#);
        let _: Result<Block, _> = serde_json::from_str(&s);
    }

    /// A valid Block serializes to JSON and deserializes back correctly.
    /// (Roundtrip sanity — ensures serde derives are consistent.)
    #[test]
    fn prop_block_serde_roundtrip(_seed in 0u8..=255u8) {
        use darqual_core::{Identity, Label, Lockbox};
        use darqual_ledger::{Block, LedgerEntry};
        use x25519_dalek::PublicKey as X25519PublicKey;

        let recipient = Identity::generate();
        let x_pub = X25519PublicKey::from(&recipient.x_secret);
        let lb = Lockbox::seal(&x_pub, b"serde test").expect("seal");
        let entry = LedgerEntry::mint(Label([0u8; 16]), lb.envelope.into_bytes(), 0);
        let block = Block::new(42, [0u8; 32], vec![entry]);

        let json = serde_json::to_string(&block).expect("serialize must succeed");
        let back: Block = serde_json::from_str(&json).expect("deserialize must succeed for valid JSON");
        prop_assert!(back.validate(), "deserialized block must validate");
    }

    /// A valid Block serializes and then we feed truncated JSON — must be Err, not panic.
    #[test]
    fn fuzz_block_deserialize_truncated_json(cut in 0usize..200usize) {
        use darqual_core::{Identity, Label, Lockbox};
        use darqual_ledger::{Block, LedgerEntry};
        use x25519_dalek::PublicKey as X25519PublicKey;

        let recipient = Identity::generate();
        let x_pub = X25519PublicKey::from(&recipient.x_secret);
        let lb = Lockbox::seal(&x_pub, b"truncation test").expect("seal");
        let entry = LedgerEntry::mint(Label([0u8; 16]), lb.envelope.into_bytes(), 0);
        let block = Block::new(1, [0u8; 32], vec![entry]);
        let json = serde_json::to_string(&block).expect("serialize");

        let truncated: String = json.chars().take(cut).collect();
        let _: Result<Block, _> = serde_json::from_str(&truncated);
    }
}
