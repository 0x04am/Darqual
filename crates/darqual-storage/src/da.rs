//! Data-availability (DA) sampling — Celestia-style.
//!
//! A `ShardCommitment` commits to the entire shard set via:
//!   - A Merkle root over per-shard BLAKE3 hashes (compact, 32 bytes).
//!   - Per-shard hashes stored explicitly for O(1) spot-checking without
//!     needing a full Merkle proof.
//!
//! `sample` picks `n_samples` random shard indices; the node is considered
//! *available* if every sampled shard is present **and** its BLAKE3 hash
//! matches the commitment.  With ~30 samples, a node withholding even a
//! single shard is detected with probability ≥ 1 − (1 − 1/n)^30 which for
//! small n is very high.

use darqual_ledger::merkle::merkle_root;
use rand::Rng;

/// A commitment to a set of erasure-coded shards.
#[derive(Debug, Clone)]
pub struct ShardCommitment {
    /// Merkle root over the per-shard BLAKE3 hashes.
    pub root: [u8; 32],
    /// Number of shards committed to.
    pub n: usize,
    /// Per-shard BLAKE3 hashes — used for O(1) sampling without a full proof.
    pub shard_hashes: Vec<[u8; 32]>,
}

/// Hash a single shard with BLAKE3.
fn shard_hash(shard: &[u8]) -> [u8; 32] {
    *blake3::hash(shard).as_bytes()
}

/// Commit to a slice of shards.
///
/// Stores the Merkle root over per-shard hashes and the hashes themselves.
pub fn commit(shards: &[Vec<u8>]) -> ShardCommitment {
    let hashes: Vec<[u8; 32]> = shards.iter().map(|s| shard_hash(s)).collect();
    let leaves: Vec<Vec<u8>> = hashes.iter().map(|h| h.to_vec()).collect();
    let root = merkle_root(&leaves);
    ShardCommitment {
        root,
        n: shards.len(),
        shard_hashes: hashes,
    }
}

/// Sample `n_samples` random shards to check data availability.
///
/// Returns `true` iff every sampled shard is:
/// 1. Present (`Some`) in `shards`.
/// 2. Its BLAKE3 hash matches the stored hash in `commitment`.
///
/// Returns `false` immediately on the first failure.
///
/// `rng` is any `rand::Rng` implementor (e.g. `rand::thread_rng()`).
pub fn sample<R: Rng>(
    commitment: &ShardCommitment,
    shards: &[Option<Vec<u8>>],
    n_samples: usize,
    rng: &mut R,
) -> bool {
    if shards.len() != commitment.n {
        return false;
    }
    for _ in 0..n_samples {
        let idx = rng.gen_range(0..commitment.n);
        match &shards[idx] {
            None => return false,
            Some(shard) => {
                if shard_hash(shard) != commitment.shard_hashes[idx] {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;

    fn make_shards(n: usize, fill: u8) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![(fill + i as u8) % 255; 32]).collect()
    }

    fn all_present(shards: &[Vec<u8>]) -> Vec<Option<Vec<u8>>> {
        shards.iter().map(|s| Some(s.clone())).collect()
    }

    #[test]
    fn commit_then_sample_all_present_passes() {
        let shards = make_shards(6, 0xAA);
        let commitment = commit(&shards);
        let present = all_present(&shards);
        let mut rng = SmallRng::seed_from_u64(42);
        assert!(
            sample(&commitment, &present, 30, &mut rng),
            "all shards present and valid — should pass"
        );
    }

    #[test]
    fn sample_fails_on_withheld_shard() {
        let shards = make_shards(6, 0xBB);
        let commitment = commit(&shards);

        // Deterministically use the shard index that the rng will pick first
        // by marking ALL shards None — guaranteed to fail
        let missing: Vec<Option<Vec<u8>>> = vec![None; 6];
        let mut rng = SmallRng::seed_from_u64(42);
        assert!(
            !sample(&commitment, &missing, 1, &mut rng),
            "withheld shard should cause sample to fail"
        );
    }

    #[test]
    fn sample_fails_on_tampered_shard() {
        let shards = make_shards(6, 0xCC);
        let commitment = commit(&shards);

        // Tamper every shard
        let tampered: Vec<Option<Vec<u8>>> = shards
            .iter()
            .map(|s| {
                let mut t = s.clone();
                t[0] ^= 0xFF; // flip bits
                Some(t)
            })
            .collect();

        let mut rng = SmallRng::seed_from_u64(99);
        assert!(
            !sample(&commitment, &tampered, 6, &mut rng),
            "tampered shard should fail hash check"
        );
    }

    #[test]
    fn commit_merkle_root_is_deterministic() {
        let shards = make_shards(4, 0x11);
        let c1 = commit(&shards);
        let c2 = commit(&shards);
        assert_eq!(c1.root, c2.root);
        assert_eq!(c1.shard_hashes, c2.shard_hashes);
    }
}
