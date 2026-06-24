//! Per-epoch committee election from a candidate set.
//!
//! Each candidate computes a VRF output over the epoch seed. Valid candidates (those
//! whose proof verifies) are sorted ascending by output; the first `committee_size`
//! are elected. The election is:
//! - **Deterministic**: same candidates + seed → same committee.
//! - **Verifiable**: any observer can re-run verification.
//! - **Rotation**: the seed is derived from the ledger tip (`seed_for_epoch`), so the
//!   committee changes as the chain progresses.

use crate::vrf::vrf_verify;

/// A candidate presenting their VRF claim for a given epoch seed.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The candidate's ed25519 public key (32 bytes).
    pub ed_pub: [u8; 32],
    /// The VRF output they claim: blake3(DOMAIN || signature).
    pub output: [u8; 32],
    /// The VRF proof: their ed25519 signature over the epoch seed.
    pub proof: [u8; 64],
}

/// Construct the epoch seed from epoch number and the previous block's Merkle root.
///
/// Ties committee rotation to the ledger tip — the seed changes every epoch because
/// `prev_root` changes, so even a fixed participant set yields a different committee.
///
/// Format: `b"darqual-epoch-seed-v1" || epoch_le_8 || prev_root_32`
pub fn seed_for_epoch(epoch: u64, prev_root: &[u8; 32]) -> Vec<u8> {
    const PREFIX: &[u8] = b"darqual-epoch-seed-v1";
    let mut seed = Vec::with_capacity(PREFIX.len() + 8 + 32);
    seed.extend_from_slice(PREFIX);
    seed.extend_from_slice(&epoch.to_le_bytes());
    seed.extend_from_slice(prev_root.as_slice());
    seed
}

/// Elect a committee from `candidates` given an epoch `seed`.
///
/// Algorithm:
/// 1. Verify each candidate's VRF proof; discard any that fail.
/// 2. Sort valid candidates ascending by their `output` (deterministic ordering).
/// 3. Return the ed_pub of the first `committee_size` candidates.
///
/// Returns an empty vec if there are fewer valid candidates than `committee_size`.
/// (The caller can decide whether to treat that as an error — see `CommitteeError`.)
pub fn elect(candidates: &[Candidate], seed: &[u8], committee_size: usize) -> Vec<[u8; 32]> {
    let mut valid: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| vrf_verify(&c.ed_pub, seed, &c.output, &c.proof))
        .collect();

    // Deterministic sort: ascending by VRF output (lexicographic on [u8;32]).
    valid.sort_by_key(|c| c.output);

    valid
        .into_iter()
        .take(committee_size)
        .map(|c| c.ed_pub)
        .collect()
}

/// Check whether `ed_pub` is a member of an elected `committee`.
pub fn is_member(committee: &[[u8; 32]], ed_pub: &[u8; 32]) -> bool {
    committee.contains(ed_pub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vrf::vrf_eval;
    use darqual_core::Identity;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_candidate(id: &Identity, seed: &[u8]) -> Candidate {
        let (output, proof) = vrf_eval(id, seed);
        Candidate {
            ed_pub: id.ed_pub(),
            output,
            proof,
        }
    }

    fn make_candidates(n: usize, seed: &[u8]) -> (Vec<Identity>, Vec<Candidate>) {
        let ids: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
        let candidates = ids.iter().map(|id| make_candidate(id, seed)).collect();
        (ids, candidates)
    }

    // ── election determinism ──────────────────────────────────────────────────

    #[test]
    fn elect_deterministic() {
        let seed = b"determinism-seed";
        let (_ids, candidates) = make_candidates(8, seed);
        let c1 = elect(&candidates, seed, 3);
        let c2 = elect(&candidates, seed, 3);
        assert_eq!(c1, c2, "election must be deterministic");
    }

    #[test]
    fn elect_returns_exact_committee_size() {
        let seed = b"size-seed";
        let (_ids, candidates) = make_candidates(10, seed);
        let committee = elect(&candidates, seed, 4);
        assert_eq!(committee.len(), 4);
    }

    // ── invalid proof rejection ───────────────────────────────────────────────

    #[test]
    fn elect_drops_candidate_with_invalid_proof() {
        let seed = b"drop-bad-seed";
        let (ids, mut candidates) = make_candidates(5, seed);

        // Corrupt the first candidate's proof.
        candidates[0].proof[0] ^= 0xFF;

        let committee = elect(&candidates, seed, 5);

        // Bad candidate dropped → only 4 valid, so we get 4 even though we asked for 5.
        assert_eq!(committee.len(), 4, "bad candidate must be excluded");

        let bad_pub = ids[0].ed_pub();
        assert!(
            !committee.contains(&bad_pub),
            "corrupted candidate must not appear in committee"
        );
    }

    // ── rotation: different epoch seeds → different committees ────────────────

    #[test]
    fn elect_rotation_yields_different_committees() {
        // Use a large-enough candidate set so different seeds almost certainly sort
        // them differently (probability of identical order is 1/n! ≈ negligible for n≥5).
        let seed_a = seed_for_epoch(1, &[0u8; 32]);
        let seed_b = seed_for_epoch(2, &[0u8; 32]);

        let ids: Vec<Identity> = (0..8).map(|_| Identity::generate()).collect();

        // Build candidates for each epoch seed (outputs differ because seed differs).
        let cands_a: Vec<Candidate> = ids.iter().map(|id| make_candidate(id, &seed_a)).collect();
        let cands_b: Vec<Candidate> = ids.iter().map(|id| make_candidate(id, &seed_b)).collect();

        let committee_a = elect(&cands_a, &seed_a, 3);
        let committee_b = elect(&cands_b, &seed_b, 3);

        // They *could* be the same by cosmic coincidence (1/56 at n=8,k=3) but won't be
        // with randomly generated keys — assert and re-run if it ever fires.
        assert_ne!(
            committee_a, committee_b,
            "different epoch seeds must generally produce different committees"
        );
    }

    // ── is_member ─────────────────────────────────────────────────────────────

    #[test]
    fn is_member_true_for_elected_false_for_others() {
        let seed = b"member-seed";
        let (ids, candidates) = make_candidates(6, seed);
        let committee = elect(&candidates, seed, 3);

        for id in &ids {
            let pub_key = id.ed_pub();
            let expected = committee.contains(&pub_key);
            assert_eq!(
                is_member(&committee, &pub_key),
                expected,
                "is_member mismatch for a key"
            );
        }

        // A totally fresh identity is definitely not in the committee.
        let outsider = Identity::generate();
        assert!(!is_member(&committee, &outsider.ed_pub()));
    }

    // ── seed_for_epoch ties rotation to ledger tip ───────────────────────────

    #[test]
    fn seed_for_epoch_differs_across_epochs_and_roots() {
        let root_a = [0u8; 32];
        let mut root_b = [0u8; 32];
        root_b[0] = 1;

        let s1 = seed_for_epoch(1, &root_a);
        let s2 = seed_for_epoch(2, &root_a);
        let s3 = seed_for_epoch(1, &root_b);

        assert_ne!(s1, s2, "different epochs → different seed");
        assert_ne!(s1, s3, "different prev_root → different seed");
    }
}
