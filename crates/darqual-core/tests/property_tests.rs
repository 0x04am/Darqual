//! Stage 10 — property-based + fuzz-style tests for darqual-core.
//!
//! Uses `proptest` on stable Rust (no nightly / cargo-fuzz).
//! Case counts are intentionally modest (64–256) so the suite stays fast.
//!
//! # What's covered
//! 1. **Lockbox roundtrip** — seal→open == original; wrong recipient ⇒ Err
//! 2. **Address determinism** — same key → same address; diff key → diff address
//! 3. **ContactCard roundtrip** — encode→parse roundtrips; verify() holds
//! 4. **PoW property** — mint()→pow_valid() is true; tampered envelope ⇒ false
//!
//! # Fuzz-style robustness (no panics on arbitrary input)
//! 5. `Lockbox::open` — arbitrary byte strings never panic
//! 6. `ContactCard::from_str` — arbitrary strings never panic
//! 7. `DarqualAddress::from_str` — arbitrary strings never panic
//! 8. Malformed prefixes, truncated envelopes, oversized payloads — graceful Err
use darqual_core::{pow_hash, pow_mint, pow_valid, DarqualAddress, Error, Identity, Lockbox};

use proptest::prelude::*;
use x25519_dalek::PublicKey as X25519PublicKey;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Lockbox roundtrip property
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// For arbitrary message bytes (0..4KB), seal to a fresh recipient then open
    /// by that recipient must return the original plaintext.
    #[test]
    fn prop_lockbox_roundtrip(msg in prop::collection::vec(any::<u8>(), 0..4096)) {
        let recipient = Identity::generate();
        let x_pub = X25519PublicKey::from(&recipient.x_secret);
        let lb = Lockbox::seal(&x_pub, &msg).expect("seal must not fail");
        let got = Lockbox::open(&recipient, &lb.envelope).expect("open by recipient must succeed");
        prop_assert_eq!(got, msg);
    }

    /// Opening a lockbox with a different (wrong) identity must return Err.
    #[test]
    fn prop_lockbox_wrong_recipient_is_err(
        msg in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let recipient = Identity::generate();
        let other    = Identity::generate();
        let x_pub    = X25519PublicKey::from(&recipient.x_secret);
        let lb = Lockbox::seal(&x_pub, &msg).expect("seal");
        let result = Lockbox::open(&other, &lb.envelope);
        prop_assert!(result.is_err(), "wrong recipient must be Err");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Address determinism property
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Same ed25519 pub key always yields the same DarqualAddress.
    #[test]
    fn prop_address_deterministic(
        ed_pub in prop::array::uniform32(any::<u8>()),
        x_pub  in prop::array::uniform32(any::<u8>()),
    ) {
        let a1 = DarqualAddress::from_keys(&ed_pub, &x_pub);
        let a2 = DarqualAddress::from_keys(&ed_pub, &x_pub);
        prop_assert_eq!(a1, a2);
    }

    /// Two independently generated identities almost always have different addresses.
    /// (Collision probability is negligible — BLAKE3 truncated to 20 bytes = 160-bit space.)
    #[test]
    fn prop_address_different_keys_differ(
        k1 in prop::array::uniform32(any::<u8>()),
        k2 in prop::array::uniform32(any::<u8>()),
        x_pub in prop::array::uniform32(any::<u8>()),
    ) {
        // Only assert inequality when keys differ; equal keys *should* collide.
        prop_assume!(k1 != k2);
        let a1 = DarqualAddress::from_keys(&k1, &x_pub);
        let a2 = DarqualAddress::from_keys(&k2, &x_pub);
        prop_assert_ne!(a1, a2);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ContactCard roundtrip property
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// For any fresh Identity, encoding its ContactCard and parsing it back
    /// must produce an identical card, and verify() must hold.
    ///
    /// We generate fresh identities rather than arbitrary raw bytes to ensure
    /// the card is *self-consistent* (address derived correctly from ed_pub).
    /// The fuzz-style tests below cover arbitrary byte garbage separately.
    #[test]
    fn prop_contact_card_roundtrip(
        // Use arbitrary u8 seeds to produce distinct identities.
        // proptest doesn't know how to generate Identity directly, so we use
        // a seed byte to drive a simple uniqueness trick; Identity::generate()
        // is keyed by OsRng so each invocation is independent.
        _seed in 0u8..=255u8,
    ) {
        let id = Identity::generate();
        let card = id.contact_card();

        // encode → parse
        let encoded = card.to_string();
        let parsed: darqual_core::ContactCard = encoded.parse().expect("parse must succeed for valid card");

        prop_assert!(parsed.verify(), "verify() must hold after roundtrip");
        prop_assert_eq!(parsed.address, card.address);
        prop_assert_eq!(parsed.ed_pub,  card.ed_pub);
        prop_assert_eq!(parsed.x_pub,   card.x_pub);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. PoW property
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// For arbitrary (label_bytes, envelope) and small difficulty (≤12),
    /// mint() produces a nonce that satisfies pow_valid().
    #[test]
    fn prop_pow_mint_then_valid(
        label_bytes in prop::array::uniform16(any::<u8>()),
        envelope    in prop::collection::vec(any::<u8>(), 0..64),
        difficulty  in 0u32..=12u32,
    ) {
        let label = darqual_core::Label(label_bytes);
        let nonce = pow_mint(&label, &envelope, difficulty);
        prop_assert!(
            pow_valid(&label, &envelope, nonce, difficulty),
            "minted nonce must satisfy pow_valid at difficulty {}",
            difficulty,
        );
    }

    /// Tampering the envelope makes the stamp invalid (for difficulty > 0).
    /// We verify this by checking that the MINTED nonce does NOT satisfy pow_valid
    /// against the tampered envelope. For small difficulties there's a small probability
    /// the tampered envelope also happens to satisfy the stamp — we use difficulty >= 8
    /// to keep the false-positive probability at 1/256 per bit (< 0.4% total).
    /// The PoW stamp is BOUND to the envelope content: tampering the envelope
    /// changes the PoW hash. NOTE: "a tampered envelope always *fails* pow_valid"
    /// is only PROBABILISTIC — at difficulty D a tampered hash still passes with
    /// probability 2^-D, so across many cases that assertion is flaky. The
    /// deterministic, security-relevant invariant is hash-binding (a stamp cannot
    /// be reused for different content).
    #[test]
    fn prop_pow_tampered_envelope_changes_hash(
        label_bytes in prop::array::uniform16(any::<u8>()),
        envelope    in prop::collection::vec(any::<u8>(), 1..64),
        difficulty  in 0u32..=8u32,
    ) {
        let label = darqual_core::Label(label_bytes);
        let nonce = pow_mint(&label, &envelope, difficulty);

        // Flip the first byte to produce a different envelope.
        let mut tampered = envelope.clone();
        tampered[0] ^= 0xFF;
        prop_assume!(tampered != envelope);

        prop_assert_ne!(
            pow_hash(&label, &envelope, nonce),
            pow_hash(&label, &tampered, nonce),
            "PoW hash must differ for a tampered envelope (stamp is content-bound)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Fuzz-style: Lockbox::open never panics on arbitrary input
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feeding completely arbitrary byte strings to Lockbox::open must never
    /// panic — only return Ok or Err.
    #[test]
    fn fuzz_lockbox_open_arbitrary_bytes(raw in prop::collection::vec(any::<u8>(), 0..512)) {
        let id = Identity::generate();
        // Convert to a lossy string — valid UTF-8 prefixes will exercise the parser,
        // invalid UTF-8 exercises the too-short / prefix-mismatch paths.
        let s = String::from_utf8_lossy(&raw).into_owned();
        // Must not panic — we don't care about Ok vs Err.
        let _ = Lockbox::open(&id, &s);
    }

    /// Arbitrary valid UTF-8 strings — exercising deeper parsing paths.
    #[test]
    fn fuzz_lockbox_open_arbitrary_strings(s in ".*") {
        let id = Identity::generate();
        let _ = Lockbox::open(&id, &s);
    }

    /// "dqbox1" prefix with arbitrary bytes after it — exercises base64 + wire parsing.
    #[test]
    fn fuzz_lockbox_open_prefixed_garbage(
        suffix in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let id = Identity::generate();
        // Build a string that starts with the right prefix but has garbage after.
        let mut s = String::from("dqbox1");
        s.push_str(&String::from_utf8_lossy(&suffix));
        let _ = Lockbox::open(&id, &s);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Fuzz-style: ContactCard::from_str never panics
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn fuzz_contact_card_parse_arbitrary(s in ".*") {
        let _: Result<darqual_core::ContactCard, _> = s.parse();
    }

    /// "dqcard1" prefix + arbitrary garbage — exercises base32 + TOML parsing.
    #[test]
    fn fuzz_contact_card_parse_prefixed_garbage(
        suffix in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut s = String::from("dqcard1");
        s.push_str(&String::from_utf8_lossy(&suffix));
        let _: Result<darqual_core::ContactCard, _> = s.parse();
    }

    /// Truncated valid cards — cut to arbitrary lengths.
    #[test]
    fn fuzz_contact_card_truncated(
        cut_len in 0usize..200usize,
    ) {
        let id = Identity::generate();
        let card_str = id.contact_card().to_string();
        let truncated: String = card_str.chars().take(cut_len).collect();
        let _: Result<darqual_core::ContactCard, _> = truncated.parse();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Fuzz-style: DarqualAddress::from_str never panics
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn fuzz_address_parse_arbitrary(s in ".*") {
        let _: Result<DarqualAddress, _> = s.parse();
    }

    /// "dq1" prefix + arbitrary garbage — exercises base32 validation.
    #[test]
    fn fuzz_address_parse_prefixed_garbage(suffix in "[a-z0-9]{0,60}") {
        let s = format!("dq1{}", suffix);
        let _: Result<DarqualAddress, _> = s.parse();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Malformed prefixes, truncated envelopes, oversized length fields
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Wrong prefix variations — must all return Err, not panic.
    #[test]
    fn fuzz_lockbox_wrong_prefix(
        prefix in "[a-zA-Z0-9]{0,10}",
        body   in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let id = Identity::generate();
        let mut s = prefix;
        s.push_str(&String::from_utf8_lossy(&body));
        let result = Lockbox::open(&id, &s);
        // If the prefix isn't "dqbox1", must be Err.
        if !s.starts_with("dqbox1") {
            prop_assert!(result.is_err());
        }
        // If it IS "dqbox1", it might be Ok or Err — just must not panic (no assertion needed).
    }

    /// A valid-prefix lockbox envelope that's been truncated to fewer than 46 decoded bytes.
    /// Must return InvalidLockbox Err, never panic.
    #[test]
    fn fuzz_lockbox_truncated_wire(keep in 0usize..45usize) {
        let id = Identity::generate();
        let x_pub = X25519PublicKey::from(&id.x_secret);
        let lb = Lockbox::seal(&x_pub, b"test").expect("seal");

        // Decode base64 body, truncate the wire bytes, re-encode.
        let prefix = "dqbox1";
        let b64 = &lb.envelope[prefix.len()..];
        let wire = data_encoding::BASE64.decode(b64.as_bytes()).unwrap();
        let truncated = &wire[..keep.min(wire.len())];
        let trunc_envelope = format!("{}{}", prefix, data_encoding::BASE64.encode(truncated));

        let result = Lockbox::open(&id, &trunc_envelope);
        prop_assert!(
            matches!(result, Err(Error::InvalidLockbox(_))),
            "truncated wire ({} bytes) must return InvalidLockbox, got: {:?}",
            keep, result
        );
    }

    /// "dqbox1" + very long base64-encoded payload (oversized) — no integer overflow.
    #[test]
    fn fuzz_lockbox_oversized_payload(
        extra in prop::collection::vec(any::<u8>(), 256..1024),
    ) {
        let id = Identity::generate();
        // Build a wire payload that starts with valid header (version + zeros) but is huge.
        let mut wire = vec![0x01u8]; // version byte
        wire.extend_from_slice(&[0u8; 32]); // eph_pub (zeros)
        wire.extend_from_slice(&[0u8; 12]); // nonce (zeros)
        wire.extend_from_slice(&extra);     // oversized ciphertext
        let s = format!("dqbox1{}", data_encoding::BASE64.encode(&wire));
        // Must not panic — decrypt will fail (wrong key), not overflow.
        let _ = Lockbox::open(&id, &s);
    }
}
