//! Proof-of-Work spam gate — the tractable v0.4.0 write-rate limiter.
//!
//! # What this is
//! A client-side hashcash-style PoW: before committing a ledger entry the
//! writer must find a `nonce` such that
//! `BLAKE3(DOMAIN ++ label ++ envelope ++ nonce_le)` has ≥ `difficulty`
//! leading zero **bits**.  The work is cheap to verify (one hash) but
//! O(2^difficulty) to produce, making mass-flooding expensive without requiring
//! any identity or payment.
//!
//! # Advanced upgrade path (not built here)
//! **RLN (Rate-Limiting Nullifiers) + DPF (Distributed Point Functions)**
//! are the production-grade upgrade:
//!
//! - RLN (Semaphore-style zk-SNARKs) enables *anonymous* rate limiting — a
//!   writer proves membership in a registered set and that they haven't exceeded
//!   their epoch quota, without revealing who they are.
//!
//! - DPF private writes (Riposte) hide *which* dead-drop slot is being written
//!   to, closing the write-pattern side-channel.
//!
//! Both are research-grade, require zk-SNARK tooling (arkworks/bellman) and a
//! registration/slashing substrate.  They are documented in ROADMAP Stage 4 and
//! SPEC §2, and will be implemented in a future increment.  PoW is the
//! tractable v0.4.0 mechanism.

use crate::label::Label;

/// Domain separator — isolates PoW hashes from every other BLAKE3 usage.
pub const POW_DOMAIN: &[u8] = b"darqual-pow-v1";

/// Compute the PoW hash for a given (label, envelope, nonce) triple.
///
/// `H = BLAKE3(POW_DOMAIN ++ label.0 ++ envelope ++ nonce.to_le_bytes())`
pub fn pow_hash(label: &Label, envelope: &[u8], nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(POW_DOMAIN);
    h.update(&label.0);
    h.update(envelope);
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Count the number of leading zero **bits** in a 32-byte hash.
///
/// Scans bytes from most-significant first; within each byte scans bits from
/// most-significant first.
pub fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for &byte in h.iter() {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Return `true` iff the PoW stamp for `(label, envelope, nonce)` satisfies
/// `difficulty` leading zero bits.
pub fn pow_valid(label: &Label, envelope: &[u8], nonce: u64, difficulty: u32) -> bool {
    if difficulty == 0 {
        return true;
    }
    let h = pow_hash(label, envelope, nonce);
    leading_zero_bits(&h) >= difficulty
}

/// Grind nonces starting at 0 until `pow_valid` passes, then return the nonce.
///
/// # Panics
/// Panics only if all 2^64 nonces are exhausted — practically impossible for
/// any sane difficulty.
pub fn mint(label: &Label, envelope: &[u8], difficulty: u32) -> u64 {
    if difficulty == 0 {
        return 0;
    }
    for nonce in 0u64..=u64::MAX {
        if pow_valid(label, envelope, nonce, difficulty) {
            return nonce;
        }
    }
    // Unreachable in practice — difficulty would need to be 64+.
    panic!("pow::mint exhausted all nonces — difficulty too high");
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_label() -> Label {
        Label([0xAB; 16])
    }

    // ── leading_zero_bits: known vectors ─────────────────────────────────

    #[test]
    fn leading_zero_bits_all_ff() {
        let h = [0xFF_u8; 32];
        assert_eq!(leading_zero_bits(&h), 0);
    }

    #[test]
    fn leading_zero_bits_first_byte_zero() {
        let mut h = [0xFF_u8; 32];
        h[0] = 0x00;
        assert!(leading_zero_bits(&h) >= 8);
    }

    #[test]
    fn leading_zero_bits_exact_8() {
        // First byte 0x00, second byte 0xFF → exactly 8 leading zero bits.
        let mut h = [0xFF_u8; 32];
        h[0] = 0x00;
        h[1] = 0xFF;
        assert_eq!(leading_zero_bits(&h), 8);
    }

    #[test]
    fn leading_zero_bits_all_zero() {
        let h = [0x00_u8; 32];
        assert_eq!(leading_zero_bits(&h), 256);
    }

    #[test]
    fn leading_zero_bits_partial_first_byte() {
        // 0x0F = 0000_1111 → 4 leading zeros.
        let mut h = [0xFF_u8; 32];
        h[0] = 0x0F;
        assert_eq!(leading_zero_bits(&h), 4);
    }

    // ── mint + pow_valid roundtrip ────────────────────────────────────────

    #[test]
    fn minted_nonce_satisfies_pow_valid() {
        let label = test_label();
        let envelope = b"hello ledger";
        let difficulty = 10u32;
        let nonce = mint(&label, envelope, difficulty);
        assert!(
            pow_valid(&label, envelope, nonce, difficulty),
            "minted nonce must satisfy pow_valid at difficulty {}",
            difficulty
        );
    }

    #[test]
    fn higher_difficulty_mint_still_valid() {
        let label = test_label();
        let envelope = b"spam is expensive";
        let difficulty = 12u32;
        let nonce = mint(&label, envelope, difficulty);
        assert!(pow_valid(&label, envelope, nonce, difficulty));
    }

    // ── PoW is bound to content + label ──────────────────────────────────

    #[test]
    fn tampered_envelope_invalidates_pow() {
        let label = test_label();
        let envelope = b"original content";
        let difficulty = 8u32;
        let nonce = mint(&label, envelope, difficulty);

        // Valid for original
        assert!(pow_valid(&label, envelope, nonce, difficulty));

        // Invalid after tampering
        let tampered = b"tampered content";
        assert!(
            !pow_valid(&label, tampered, nonce, difficulty),
            "PoW must be bound to envelope content"
        );
    }

    #[test]
    fn different_label_invalidates_pow() {
        let label = test_label();
        let other_label = Label([0x11; 16]);
        let envelope = b"some message";
        let difficulty = 8u32;
        let nonce = mint(&label, envelope, difficulty);

        assert!(pow_valid(&label, envelope, nonce, difficulty));
        assert!(
            !pow_valid(&other_label, envelope, nonce, difficulty),
            "PoW must be bound to the label"
        );
    }

    // ── difficulty enforcement ────────────────────────────────────────────

    #[test]
    fn nonce_zero_fails_nontrivial_difficulty() {
        // nonce=0 with a high-enough difficulty is almost certainly invalid.
        // We try a few labels/envelopes to make this robust.
        let difficulty = 10u32;
        let mut any_pass = false;
        for i in 0u8..20 {
            let label = Label([i; 16]);
            let envelope = [i; 32];
            if pow_valid(&label, &envelope, 0, difficulty) {
                any_pass = true;
            }
        }
        // Probability all 20 happen to pass ≈ (1/1024)^20 ≈ 10^-60.
        assert!(
            !any_pass,
            "nonce=0 should almost never satisfy difficulty {} for diverse inputs",
            difficulty
        );
    }

    // ── difficulty=0 is always valid (back-compat) ───────────────────────

    #[test]
    fn difficulty_zero_always_passes() {
        let label = test_label();
        assert!(pow_valid(&label, b"anything", 0, 0));
        assert!(pow_valid(&label, b"anything", 999, 0));
    }
}
