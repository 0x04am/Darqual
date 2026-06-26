//! Cover-traffic generation — indistinguishable dummy `LedgerEntry` values.
//!
//! # Design
//!
//! A cover entry is a **real** `Lockbox::seal` envelope sealed to a freshly
//! generated, throwaway X25519 public key whose secret is immediately
//! discarded.  Because it goes through the exact same `pad() → AEAD → wire →
//! base64` path as a real lockbox, a cover envelope is byte-for-byte
//! length-indistinguishable from a real one carrying a plaintext that falls
//! in the same padding bucket.  No identity holds the matching secret, so
//! `Lockbox::open` returns `Err(Decrypt)` for everyone.
//!
//! The default cover plaintext is a single random byte → smallest padding
//! bucket (256 B).  Real messages of length 1..=252 produce the same envelope
//! length.
//!
//! ## PoW on cover entries
//!
//! In tests `LedgerEntry::mint` is called with `difficulty = 0`.
//! **Production cover entries MUST carry the same PoW difficulty as real
//! entries** — otherwise an adversary distinguishes them by work.

use darqual_core::{Label, Lockbox};
use darqual_ledger::LedgerEntry;
use rand::Rng;
use std::sync::OnceLock;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Canonical cover envelope length — equal to `Lockbox::seal` of a 1-byte
/// plaintext (which lands in the 256-byte padding bucket).  Computed once on
/// first call so the constant tracks `Lockbox`/padding changes automatically.
pub fn cover_envelope_len() -> usize {
    static LEN: OnceLock<usize> = OnceLock::new();
    *LEN.get_or_init(|| {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let pub_key = X25519PublicKey::from(&secret);
        let lb = Lockbox::seal(&pub_key, &[0u8]).expect("seal of 1 byte must succeed");
        lb.envelope.len()
    })
}

/// Generate a single cover `LedgerEntry`.
///
/// Internally seals a 1-byte random plaintext to a throwaway X25519 public
/// key.  The resulting envelope is a structurally-valid `Lockbox` of canonical
/// (256-bucket) length, openable by nobody.
pub fn cover_entry(rng: &mut impl Rng) -> LedgerEntry {
    // Random label — same size/distribution as a real PRF-derived label.
    let mut label_bytes = [0u8; 16];
    rng.fill(&mut label_bytes);
    let label = Label(label_bytes);

    // Throwaway recipient — secret is dropped at end of scope.
    // Uses a fresh CSPRNG (not the caller's `Rng`, which may not be CryptoRng).
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let pub_key = X25519PublicKey::from(&secret);
    drop(secret);

    // One random plaintext byte → smallest (256 B) padding bucket.
    let mut pt = [0u8; 1];
    rng.fill(&mut pt);
    let lockbox = Lockbox::seal(&pub_key, &pt).expect("seal must succeed");
    let envelope = lockbox.envelope.into_bytes();
    debug_assert_eq!(envelope.len(), cover_envelope_len());

    LedgerEntry::mint(label, envelope, 0)
}

/// Pad `entries` with cover entries until `entries.len() >= min_count`.
///
/// A node ALWAYS emits `>= min_count` entries per epoch, even when it has zero
/// real messages to send.  Existing entries are untouched; cover entries are
/// appended (callers should shuffle for stronger anonymity).
pub fn pad_block(entries: &mut Vec<LedgerEntry>, min_count: usize, rng: &mut impl Rng) {
    while entries.len() < min_count {
        entries.push(cover_entry(rng));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use darqual_core::{Identity, Label, Lockbox};
    use darqual_ledger::LedgerEntry;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use x25519_dalek::PublicKey as X25519PublicKey;

    fn seeded_rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(0xDEAD_BEEF)
    }

    // ── size-indistinguishability ─────────────────────────────────────────

    /// Cover entry envelope length must equal a REAL padded lockbox envelope
    /// for any plaintext in the same padding bucket.  Verifies the cover
    /// path goes through the same pad → AEAD → base64 pipeline.
    #[test]
    fn cover_envelope_len_matches_real_lockbox() {
        let identity = Identity::generate();
        let x_pub = X25519PublicKey::from(&identity.x_secret);

        // Real lockboxes for several plaintexts in the 256-byte bucket
        // (need = pt.len() + 4 ≤ 256 → pt.len() ≤ 252) must all share the
        // same envelope length, and equal the cover envelope length.
        let lens: Vec<usize> = [1usize, 10, 200, 252]
            .iter()
            .map(|&n| {
                Lockbox::seal(&x_pub, &vec![0u8; n])
                    .expect("seal failed")
                    .envelope
                    .len()
            })
            .collect();
        for w in lens.windows(2) {
            assert_eq!(w[0], w[1], "real lockboxes in 256-bucket must share length");
        }
        let real_len = lens[0];

        assert_eq!(
            cover_envelope_len(),
            real_len,
            "cover_envelope_len() must equal real padded lockbox length"
        );

        let mut rng = seeded_rng();
        let entry = cover_entry(&mut rng);
        assert_eq!(
            entry.envelope.len(),
            real_len,
            "cover entry envelope length {} != real lockbox length {}",
            entry.envelope.len(),
            real_len
        );
    }

    // ── cover entries decrypt for nobody ─────────────────────────────────

    #[test]
    fn cover_entries_decrypt_for_nobody() {
        let mut rng = seeded_rng();
        let entries: Vec<LedgerEntry> = (0..10).map(|_| cover_entry(&mut rng)).collect();

        for _ in 0..3 {
            let id = Identity::generate();
            let recovered: Vec<Vec<u8>> = entries
                .iter()
                .filter_map(|e| {
                    let s = std::str::from_utf8(&e.envelope).ok()?;
                    Lockbox::open(&id, s).ok()
                })
                .collect();
            assert!(
                recovered.is_empty(),
                "cover entry should not be openable by any identity"
            );
        }
    }

    // ── pad_block ────────────────────────────────────────────────────────

    #[test]
    fn pad_block_zero_real_reaches_min_count() {
        let mut rng = seeded_rng();
        let mut entries: Vec<LedgerEntry> = vec![];
        pad_block(&mut entries, 20, &mut rng);
        assert_eq!(entries.len(), 20);
    }

    #[test]
    fn pad_block_already_full_unchanged() {
        let mut rng = seeded_rng();
        let mut entries: Vec<LedgerEntry> = (0..5).map(|_| cover_entry(&mut rng)).collect();
        pad_block(&mut entries, 3, &mut rng);
        assert_eq!(entries.len(), 5);
    }

    // ── real + cover mix: Bob still recovers his message ─────────────────

    #[test]
    fn real_message_survives_cover_mixing() {
        let mut rng = seeded_rng();
        let bob = Identity::generate();
        let x_pub = X25519PublicKey::from(&bob.x_secret);
        let msg = b"hello from Alice, via cover-padded block";

        let lockbox = Lockbox::seal(&x_pub, msg).expect("seal failed");
        let label = Label([0x42; 16]);
        let real_entry = LedgerEntry::mint(label, lockbox.envelope.into_bytes(), 0);

        let mut entries = vec![real_entry];
        pad_block(&mut entries, 25, &mut rng);
        assert!(entries.len() >= 25);

        let recovered: Vec<Vec<u8>> = entries
            .iter()
            .filter_map(|e| {
                let s = std::str::from_utf8(&e.envelope).ok()?;
                Lockbox::open(&bob, s).ok()
            })
            .collect();

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0], msg);
    }
}
