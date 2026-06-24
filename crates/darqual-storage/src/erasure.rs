//! Reed-Solomon erasure coding for cold-archive block shards.
//!
//! `encode` splits arbitrary bytes into `data` equal-length shards and
//! produces `data + parity` shards total.  `reconstruct` recovers the
//! original bytes from any `data` of the `data + parity` shards.
//!
//! Padding: the input is zero-padded to the next multiple of `data` bytes
//! so shards are equal-length.  The original length is stored in `Encoded`
//! and the padding is stripped on reconstruct.

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::{Result, StorageError};

/// Configuration for an erasure-coding scheme.
#[derive(Debug, Clone)]
pub struct ErasureConfig {
    /// Number of data shards.
    pub data: usize,
    /// Number of parity shards.
    pub parity: usize,
}

/// The result of encoding: shards + bookkeeping.
#[derive(Debug, Clone)]
pub struct Encoded {
    /// `data + parity` equal-length shards.
    pub shards: Vec<Vec<u8>>,
    /// Byte length of the original (un-padded) input.
    pub orig_len: usize,
    /// The config used during encoding (needed for reconstruct).
    pub cfg: ErasureConfig,
}

/// Erasure-encode `data_bytes` into `cfg.data + cfg.parity` shards.
///
/// Returns an `Encoded` containing the shards and original length.
/// All shards are equal length (padding applied as needed).
pub fn encode(data_bytes: &[u8], cfg: &ErasureConfig) -> Result<Encoded> {
    let n_data = cfg.data;
    let n_parity = cfg.parity;

    // Pad to a multiple of n_data
    let shard_len = {
        let base = data_bytes.len().max(1); // avoid 0-length shards
        base.div_ceil(n_data)
    };

    let mut padded = data_bytes.to_vec();
    padded.resize(shard_len * n_data, 0u8);

    // Build data shards
    let mut shards: Vec<Vec<u8>> = padded.chunks_exact(shard_len).map(<[u8]>::to_vec).collect();

    // Append empty parity shards
    for _ in 0..n_parity {
        shards.push(vec![0u8; shard_len]);
    }

    // RS encode — fills in the parity shards
    let rs = ReedSolomon::new(n_data, n_parity).map_err(|e| StorageError::Rs(e.to_string()))?;
    rs.encode(&mut shards)
        .map_err(|e| StorageError::Rs(e.to_string()))?;

    Ok(Encoded {
        shards,
        orig_len: data_bytes.len(),
        cfg: cfg.clone(),
    })
}

/// Reconstruct the original bytes from an `Encoded` with some shards missing.
///
/// `present[i]` must be `true` if `enc.shards[i]` is a valid shard and
/// `false` if it has been zeroed/lost.  At least `cfg.data` shards must be
/// present; otherwise returns `TooFewShards`.
///
/// On success the original bytes (without padding) are returned.  `enc` is
/// NOT mutated — missing shards stay zeroed.
pub fn reconstruct(enc: &Encoded, present: &[bool]) -> Result<Vec<u8>> {
    let n_data = enc.cfg.data;
    let n_parity = enc.cfg.parity;
    let total = n_data + n_parity;

    if present.len() != total {
        return Err(StorageError::BadEncoded);
    }

    let have = present.iter().filter(|&&p| p).count();
    if have < n_data {
        return Err(StorageError::TooFewShards { need: n_data, have });
    }

    // Build Option<Vec<u8>> shards for the RS library
    let mut opt_shards: Vec<Option<Vec<u8>>> = enc
        .shards
        .iter()
        .zip(present.iter())
        .map(|(s, &p)| if p { Some(s.clone()) } else { None })
        .collect();

    let rs = ReedSolomon::new(n_data, n_parity).map_err(|e| StorageError::Rs(e.to_string()))?;
    rs.reconstruct(&mut opt_shards)
        .map_err(|e| StorageError::Rs(e.to_string()))?;

    // Re-assemble from data shards only, trim padding
    let mut out: Vec<u8> = opt_shards
        .into_iter()
        .take(n_data)
        .flat_map(|s| s.unwrap_or_default())
        .collect();
    out.truncate(enc.orig_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg46() -> ErasureConfig {
        ErasureConfig { data: 4, parity: 2 }
    }

    #[test]
    fn encode_reconstruct_exact_roundtrip() {
        let data = b"hello darqual erasure coding";
        let cfg = cfg46();
        let enc = encode(data, &cfg).unwrap();
        let present = vec![true; enc.shards.len()];
        let recovered = reconstruct(&enc, &present).unwrap();
        assert_eq!(
            recovered, data,
            "roundtrip should return exact original bytes"
        );
    }

    #[test]
    fn encode_reconstruct_non_multiple_length() {
        // Length not a multiple of `data` shards — exercises padding
        let data = b"odd"; // 3 bytes, data=4 → pad to 4 bytes (1 byte per shard)
        let cfg = cfg46();
        let enc = encode(data, &cfg).unwrap();
        assert_eq!(enc.orig_len, 3);
        let present = vec![true; enc.shards.len()];
        let recovered = reconstruct(&enc, &present).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn reconstruct_with_parity_shards_missing() {
        // Drop up to `parity` shards — should still succeed
        let data: Vec<u8> = (0u8..37).collect(); // non-multiple of 4
        let cfg = cfg46();
        let enc = encode(&data, &cfg).unwrap();

        // Drop last 2 shards (the parity shards)
        let mut present = vec![true; enc.shards.len()];
        present[4] = false;
        present[5] = false;

        let recovered = reconstruct(&enc, &present).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn reconstruct_with_data_shards_missing_within_parity_budget() {
        // Drop 2 data shards (parity = 2, so just within budget)
        let data: Vec<u8> = (0u8..100).collect();
        let cfg = cfg46();
        let enc = encode(&data, &cfg).unwrap();

        let mut present = vec![true; enc.shards.len()];
        present[0] = false;
        present[2] = false;

        let recovered = reconstruct(&enc, &present).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn reconstruct_fails_with_too_many_missing() {
        // Drop parity+1 shards — must fail
        let data = b"cannot recover this";
        let cfg = cfg46(); // data=4 parity=2; drop 3 shards
        let enc = encode(data, &cfg).unwrap();

        let mut present = vec![true; enc.shards.len()];
        present[0] = false;
        present[1] = false;
        present[2] = false; // 3 missing > parity(2)

        let result = reconstruct(&enc, &present);
        assert!(
            result.is_err(),
            "should fail when parity+1 shards are missing"
        );
    }
}
