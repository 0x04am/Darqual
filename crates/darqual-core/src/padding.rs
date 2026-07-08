//! Fixed-bucket length padding — closes the message-size metadata leak.
//!
//! A global passive observer would otherwise learn `plaintext.len()` from
//! `ciphertext.len()` (AEAD = `pt.len() + tag`). We pad every plaintext to the
//! next bucket on a fixed ladder *before* it goes into the AEAD, so ciphertexts
//! collapse into a small set of discrete sizes.
//!
//! Spec: `notes/projects/anon-messenger-research/18-length-padding.md` (§1).
//!
//! Wire form of the padded plaintext:
//!   `u32_le(pt.len()) || pt || zeros(bucket - 4 - pt.len())`
//!
//! Padding lives **inside** the AEAD; the zero bytes are encrypted so they
//! reveal nothing. There is no compression anywhere in the stack, so no length
//! oracle.
//!
//! `unpad` is hostile-input safe — an attacker-controlled length prefix can
//! never panic; mismatch returns `Error::MalformedPadding`.

use crate::error::{Error, Result};

/// Bucket ladder (bytes). Plaintexts pad up to the smallest bucket ≥
/// `pt.len() + 4`; oversize plaintexts pad to the next multiple of the largest
/// bucket. Tunable — this is the size-leak ↔ bandwidth dial.
pub const BUCKETS: [usize; 6] = [256, 1024, 4096, 16384, 65536, 262144];

const LEN_PREFIX: usize = 4;

/// Pad a plaintext to the next bucket size. Always returns a buffer whose
/// length is one of `BUCKETS` (or a multiple of the largest for oversize).
pub fn pad(pt: &[u8]) -> Vec<u8> {
    let need = pt.len() + LEN_PREFIX;
    let bucket = match BUCKETS.iter().find(|&&b| b >= need) {
        Some(&b) => b,
        None => {
            let largest = *BUCKETS.last().expect("BUCKETS non-empty");
            need.div_ceil(largest) * largest
        }
    };

    let mut out = vec![0u8; bucket];
    let n = pt.len() as u32;
    out[..LEN_PREFIX].copy_from_slice(&n.to_le_bytes());
    out[LEN_PREFIX..LEN_PREFIX + pt.len()].copy_from_slice(pt);
    out
}

/// Reverse of `pad`. Defensive against hostile input — never panics on
/// out-of-bounds length prefixes.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < LEN_PREFIX {
        return Err(Error::MalformedPadding(format!(
            "padded buffer too short ({} bytes, need ≥ {})",
            padded.len(),
            LEN_PREFIX
        )));
    }
    let mut len_le = [0u8; LEN_PREFIX];
    len_le.copy_from_slice(&padded[..LEN_PREFIX]);
    let n = u32::from_le_bytes(len_le) as usize;
    let avail = padded.len() - LEN_PREFIX;
    if n > avail {
        return Err(Error::MalformedPadding(format!(
            "length prefix {} exceeds available {} bytes",
            n, avail
        )));
    }
    Ok(padded[LEN_PREFIX..LEN_PREFIX + n].to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests (spec §4)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // 1. Round-trip at many lengths.
    #[test]
    fn round_trip_many_lengths() {
        for &len in &[0usize, 1, 200, 255, 256, 1000, 5000, 70000] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let padded = pad(&pt);
            let recovered = unpad(&padded).expect("unpad");
            assert_eq!(recovered, pt, "round-trip failed for len {}", len);
        }
    }

    // 2a. Indistinguishability at the padding layer: 1/10/200 byte plaintexts
    //     all bucket to 256.
    #[test]
    fn indistinguishability_padding_layer() {
        let a = pad(&[0u8; 1]);
        let b = pad(&[0u8; 10]);
        let c = pad(&[0u8; 200]);
        assert_eq!(a.len(), 256);
        assert_eq!(b.len(), 256);
        assert_eq!(c.len(), 256);
    }

    // 2b. Indistinguishability through real RatchetSession — three plaintexts of
    //     length 1/10/200 must produce IDENTICAL ciphertext lengths.
    #[test]
    fn indistinguishability_through_ratchet() {
        use crate::conversation::Conversation;
        use crate::identity::Identity;
        use crate::ratchet::RatchetSession;

        let alice = Identity::generate();
        let bob = Identity::generate();
        let sk = *Conversation::new(&alice, &bob.contact_card()).shared_secret();
        let mut a = RatchetSession::init_initiator(&sk, &bob.contact_card());

        let m1 = a.encrypt(&[0xAB; 1]).unwrap();
        let m10 = a.encrypt(&[0xAB; 10]).unwrap();
        let m200 = a.encrypt(&[0xAB; 200]).unwrap();

        assert_eq!(
            m1.ciphertext.len(),
            m10.ciphertext.len(),
            "1B vs 10B ratchet ciphertext lengths differ"
        );
        assert_eq!(
            m10.ciphertext.len(),
            m200.ciphertext.len(),
            "10B vs 200B ratchet ciphertext lengths differ"
        );
        // 256-byte padded plaintext + 16-byte Poly1305 tag.
        assert_eq!(m1.ciphertext.len(), 256 + 16);
    }

    // 2c. Indistinguishability through Lockbox v1 (seal/open) — three plaintexts
    //     of length 1/10/200 must produce IDENTICAL envelope lengths.
    #[test]
    fn indistinguishability_through_lockbox() {
        use crate::identity::Identity;
        use crate::lockbox::Lockbox;
        use x25519_dalek::PublicKey as X25519PublicKey;

        let bob = Identity::generate();
        let bob_x_pub = X25519PublicKey::from(&bob.x_secret);

        let lb1 = Lockbox::seal(&bob_x_pub, &[0xAB; 1]).unwrap();
        let lb10 = Lockbox::seal(&bob_x_pub, &[0xAB; 10]).unwrap();
        let lb200 = Lockbox::seal(&bob_x_pub, &[0xAB; 200]).unwrap();

        assert_eq!(lb1.envelope.len(), lb10.envelope.len());
        assert_eq!(lb10.envelope.len(), lb200.envelope.len());
    }

    // 3. Boundary: 252 → 256; 253 → 1024.
    #[test]
    fn boundary_252_253() {
        assert_eq!(
            pad(&vec![0u8; 252]).len(),
            256,
            "252 + 4 = 256 fits exactly"
        );
        assert_eq!(
            pad(&vec![0u8; 253]).len(),
            1024,
            "253 + 4 = 257 overflows 256"
        );
    }

    // 4. Oversize: 300_000 → next multiple of 262144 = 524288.
    #[test]
    fn oversize_300k() {
        let p = pad(&vec![0u8; 300_000]);
        assert_eq!(p.len(), 524_288);
        let r = unpad(&p).unwrap();
        assert_eq!(r.len(), 300_000);
    }

    // 5. unpad rejects malformed: length prefix > available bytes.
    #[test]
    fn unpad_rejects_oob_length_prefix() {
        // Buffer of 256 bytes whose u32 prefix claims 999_999 bytes follow.
        let mut hostile = vec![0u8; 256];
        hostile[..4].copy_from_slice(&999_999u32.to_le_bytes());
        let r = unpad(&hostile);
        assert!(matches!(r, Err(Error::MalformedPadding(_))));
    }

    #[test]
    fn unpad_rejects_too_short() {
        assert!(matches!(unpad(&[]), Err(Error::MalformedPadding(_))));
        assert!(matches!(unpad(&[0, 0, 0]), Err(Error::MalformedPadding(_))));
    }

    // Exact-boundary sanity for buckets.
    #[test]
    fn bucket_ladder_exact_sizes() {
        for &b in &BUCKETS {
            // Largest pt that still fits in bucket b is b - 4.
            assert_eq!(pad(&vec![0u8; b - 4]).len(), b);
        }
    }
}
