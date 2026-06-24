//! Cover-traffic generation — indistinguishable dummy `LedgerEntry` values.
//!
//! # Design
//!
//! ## Why cover entries work
//! A `LedgerEntry` contains three fields:
//!   * `label`    — 16 random bytes (same as a real PRF-derived label)
//!   * `envelope` — the lockbox wire format as a UTF-8 string
//!   * `nonce`    — PoW stamp
//!
//! For cover entries to be **size-indistinguishable** from real ones, the
//! envelope must have the same byte length as a genuine `Lockbox::seal` call
//! on a fixed-size message.
//!
//! ## Canonical envelope size
//!
//! A real lockbox wire encoding is:
//! ```text
//! [version 1 byte][eph_pub 32 bytes][nonce 12 bytes][ciphertext N+16 bytes]
//! ```
//! where `N` is the plaintext length and `+16` is the Poly1305 AEAD tag.
//!
//! For a **256-byte** padded plaintext:
//! ```text
//! wire   = 1 + 32 + 12 + (256 + 16) = 317 bytes
//! base64 = ceil(317/3)*4             = 424 chars
//! prefix = "dqbox1"                  =   6 chars
//! total  = 430 bytes (as UTF-8)
//! ```
//!
//! Cover envelopes are **430 random bytes** generated as a valid base64 string
//! (so they parse as UTF-8 and have the same length as a real sealed envelope
//! for a 256-byte padded message).  They are **not** structurally valid
//! lockboxes, so `Lockbox::open` will return `Err(Decrypt)` for everyone.
//!
//! The base64 alphabet is `[A-Za-z0-9+/=]` — covers only printable ASCII, so
//! the random bytes are drawn from that alphabet to make the encoding valid.
//!
//! ## PoW on cover entries
//!
//! In these tests `LedgerEntry::mint` is called with `difficulty = 0` (zero
//! work required).  **Production cover entries MUST carry the same PoW
//! difficulty as real entries.**  If cover entries were free and real entries
//! cost work, an adversary could distinguish them trivially.  The cost parity
//! is enforced by the caller at epoch-commit time.

use darqual_core::Label;
use darqual_ledger::LedgerEntry;
use rand::Rng;

/// The fixed canonical envelope length for a cover entry (bytes).
///
/// Matches `Lockbox::seal` on a 256-byte padded message:
/// `"dqbox1"` (6) + BASE64(317 wire bytes) (424) = 430 bytes.
pub const COVER_ENVELOPE_LEN: usize = 430;

/// Base64 alphabet — used to build a syntactically valid but un-openable
/// lockbox-shaped string of the canonical length.
const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Generate a single cover `LedgerEntry`.
///
/// * `label`    — 16 random bytes, indistinguishable from a real PRF label.
/// * `envelope` — `COVER_ENVELOPE_LEN` bytes starting with `"dqbox1"` then
///   random base64 characters; same length as a real sealed 256-byte message.
/// * `nonce`    — minted with `difficulty = 0`.  **Production callers MUST use
///   the same difficulty as real entries** (see module doc).
///
/// The entry decrypts for nobody: the base64 body encodes random bytes that are
/// not a valid Sphinx/lockbox packet, so `Lockbox::open` returns `Err(Decrypt)`
/// for every identity.
pub fn cover_entry(rng: &mut impl Rng) -> LedgerEntry {
    // Random label — same size/distribution as a real PRF-derived label.
    let mut label_bytes = [0u8; 16];
    rng.fill(&mut label_bytes);
    let label = Label(label_bytes);

    // Build envelope: "dqbox1" + (424 random base64 chars)
    let mut envelope = Vec::with_capacity(COVER_ENVELOPE_LEN);
    // Prefix
    envelope.extend_from_slice(b"dqbox1");
    // Random base64 body — drawn from the alphabet so it looks like real base64
    let body_len = COVER_ENVELOPE_LEN - 6; // 424
    for _ in 0..body_len {
        let idx: usize = rng.gen_range(0..B64_ALPHABET.len());
        envelope.push(B64_ALPHABET[idx]);
    }
    debug_assert_eq!(envelope.len(), COVER_ENVELOPE_LEN);

    // Mint with difficulty=0 for tests / staging.
    // Production callers: pass the real epoch difficulty to LedgerEntry::mint
    // directly or replace this nonce with a properly-ground stamp.
    LedgerEntry::mint(label, envelope, 0)
}

/// Pad `entries` with cover entries until `entries.len() >= min_count`.
///
/// A node ALWAYS emits `>= min_count` entries per epoch, even when it has zero
/// real messages to send.  This hides the send-or-didn't-send bit entirely:
/// every node's epoch output looks identical in size.
///
/// Existing entries (real messages) are untouched.  Cover entries are appended
/// at the end; their positions are random among all entries in a real
/// implementation (shuffle after padding in production for stronger anonymity).
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

    /// Cover entry envelope length must equal a REAL lockbox envelope sealed
    /// over a 256-byte padded message.
    #[test]
    fn cover_envelope_len_matches_real_lockbox() {
        let identity = Identity::generate();
        let x_pub = X25519PublicKey::from(&identity.x_secret);
        let padded_msg = [0u8; 256];
        let real_box = Lockbox::seal(&x_pub, &padded_msg).expect("seal failed");
        let real_len = real_box.envelope.len();

        // Computed expectation
        assert_eq!(
            real_len, COVER_ENVELOPE_LEN,
            "COVER_ENVELOPE_LEN ({}) does not match real lockbox envelope ({}) \
             — update the constant",
            COVER_ENVELOPE_LEN, real_len
        );

        // Cover entry matches
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

    /// Build a block with several cover entries; trial-decrypt with multiple
    /// identities — zero messages recovered.
    #[test]
    fn cover_entries_decrypt_for_nobody() {
        let mut rng = seeded_rng();
        let entries: Vec<LedgerEntry> = (0..10).map(|_| cover_entry(&mut rng)).collect();

        // Three random identities — none should recover anything
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

    // ── pad_block: zero real entries ──────────────────────────────────────

    #[test]
    fn pad_block_zero_real_reaches_min_count() {
        let mut rng = seeded_rng();
        let mut entries: Vec<LedgerEntry> = vec![];
        pad_block(&mut entries, 20, &mut rng);
        assert!(
            entries.len() >= 20,
            "expected >= 20 entries, got {}",
            entries.len()
        );
        assert_eq!(entries.len(), 20, "should be exactly 20 (0 + 20 cover)");
    }

    #[test]
    fn pad_block_already_full_unchanged() {
        let mut rng = seeded_rng();
        // Pre-fill with 5 cover entries
        let mut entries: Vec<LedgerEntry> = (0..5).map(|_| cover_entry(&mut rng)).collect();
        pad_block(&mut entries, 3, &mut rng);
        assert_eq!(
            entries.len(),
            5,
            "pad_block must not remove entries when already at min_count"
        );
    }

    // ── real + cover mix: Bob still recovers his message ─────────────────

    #[test]
    fn real_message_survives_cover_mixing() {
        let mut rng = seeded_rng();
        let bob = Identity::generate();
        let x_pub = X25519PublicKey::from(&bob.x_secret);
        let msg = b"hello from Alice, via cover-padded block";

        // Seal a real message to Bob
        let lockbox = Lockbox::seal(&x_pub, msg).expect("seal failed");
        let label = Label([0x42; 16]);
        let real_entry = LedgerEntry::mint(label, lockbox.envelope.into_bytes(), 0);

        // Mix with cover entries
        let mut entries = vec![real_entry];
        pad_block(&mut entries, 25, &mut rng);
        assert!(entries.len() >= 25);

        // Trial-decrypt: Bob finds exactly his message
        let recovered: Vec<Vec<u8>> = entries
            .iter()
            .filter_map(|e| {
                let s = std::str::from_utf8(&e.envelope).ok()?;
                Lockbox::open(&bob, s).ok()
            })
            .collect();

        assert_eq!(recovered.len(), 1, "Bob should recover exactly one message");
        assert_eq!(recovered[0], msg, "recovered message must match original");
    }
}
