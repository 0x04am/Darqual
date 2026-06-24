//! Poor-man's VRF built on ed25519 deterministic signatures.
//!
//! Construction:
//! ```text
//! vrf_output(sk, seed) = blake3(DOMAIN || ed25519_sign(sk, seed))
//! vrf_proof            = ed25519_sign(sk, seed)   [64 bytes]
//! vrf_verify(pk, seed, output, proof)
//!     = ed25519_verify(pk, seed, proof)
//!       AND blake3(DOMAIN || proof) == output
//! ```
//!
//! Security properties (informal):
//! - **Determinism**: same (sk, seed) → same output. No randomness in ed25519 sign (RFC 8032).
//! - **Uniqueness**: two distinct proofs for the same (pk, seed) cannot both verify
//!   (ed25519 is a function, not a relation).
//! - **Pseudorandomness**: output is indistinguishable from random without sk, because
//!   ed25519 signatures are binding on the key and message.
//! - **Verifiability**: anyone with pk can check the proof.
//! - **Non-biasability**: once the seed is fixed externally (ledger tip), the keyholder
//!   cannot choose a different output.
//!
//! **Not** a standard ECVRF (RFC 9381). See crate-level docs.

use darqual_core::{verify_ed, Identity};

/// Domain separation tag for the darqual VRF.
pub const DOMAIN: &[u8] = b"darqual-vrf-v1";

/// Evaluate the VRF for `id` over `seed`.
///
/// Returns `(output, proof)` where:
/// - `output` is a 32-byte pseudorandom value derived from the signature.
/// - `proof`  is the 64-byte ed25519 signature over `seed`; anyone with the public key
///   can verify it.
pub fn vrf_eval(id: &Identity, seed: &[u8]) -> ([u8; 32], [u8; 64]) {
    let proof: [u8; 64] = id.sign(seed);
    let output = proof_to_output(&proof);
    (output, proof)
}

/// Verify a VRF output/proof pair against a public key and seed.
///
/// Returns `true` iff:
/// 1. `proof` is a valid ed25519 signature over `seed` by the key at `ed_pub`.
/// 2. `output` == blake3(DOMAIN || proof).
pub fn vrf_verify(ed_pub: &[u8; 32], seed: &[u8], output: &[u8; 32], proof: &[u8; 64]) -> bool {
    if !verify_ed(ed_pub, seed, proof) {
        return false;
    }
    &proof_to_output(proof) == output
}

// ── internal ──────────────────────────────────────────────────────────────────

fn proof_to_output(proof: &[u8; 64]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(proof.as_slice());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use darqual_core::Identity;

    #[test]
    fn vrf_eval_deterministic() {
        let id = Identity::generate();
        let seed = b"epoch-seed-1234";
        let (out1, proof1) = vrf_eval(&id, seed);
        let (out2, proof2) = vrf_eval(&id, seed);
        assert_eq!(out1, out2, "output must be deterministic");
        assert_eq!(proof1, proof2, "proof must be deterministic");
    }

    #[test]
    fn vrf_verify_accepts_valid() {
        let id = Identity::generate();
        let seed = b"test-seed";
        let (output, proof) = vrf_eval(&id, seed);
        let ed_pub = id.ed_pub();
        assert!(vrf_verify(&ed_pub, seed, &output, &proof));
    }

    #[test]
    fn vrf_verify_rejects_tampered_output() {
        let id = Identity::generate();
        let seed = b"test-seed";
        let (mut output, proof) = vrf_eval(&id, seed);
        output[0] ^= 0xFF;
        let ed_pub = id.ed_pub();
        assert!(!vrf_verify(&ed_pub, seed, &output, &proof));
    }

    #[test]
    fn vrf_verify_rejects_tampered_proof() {
        let id = Identity::generate();
        let seed = b"test-seed";
        let (output, mut proof) = vrf_eval(&id, seed);
        proof[0] ^= 0xFF;
        let ed_pub = id.ed_pub();
        assert!(!vrf_verify(&ed_pub, seed, &output, &proof));
    }

    #[test]
    fn vrf_verify_rejects_wrong_pubkey() {
        let id = Identity::generate();
        let other = Identity::generate();
        let seed = b"test-seed";
        let (output, proof) = vrf_eval(&id, seed);
        let wrong_pub = other.ed_pub();
        assert!(!vrf_verify(&wrong_pub, seed, &output, &proof));
    }

    #[test]
    fn vrf_output_fully_determined_by_key_and_seed() {
        // Changing the seed changes the output — the keyholder cannot bias it once
        // the seed is fixed by the external ledger.
        let id = Identity::generate();
        let (out_a, _) = vrf_eval(&id, b"seed-A");
        let (out_b, _) = vrf_eval(&id, b"seed-B");
        assert_ne!(out_a, out_b, "different seeds must yield different outputs");

        // Changing nothing yields the same output (stability).
        let (out_a2, _) = vrf_eval(&id, b"seed-A");
        assert_eq!(out_a, out_a2, "output must be stable");
    }
}
