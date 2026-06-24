//! Shard repair — RS-reconstruct missing shards in place.
//!
//! When a node detects missing shards (via DA sampling or direct inventory
//! check), `repair` uses Reed-Solomon to refill them, restoring full
//! replication factor.

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::erasure::Encoded;
use crate::{Result, StorageError};

/// Repair an `Encoded` shard set in place.
///
/// Missing shards (where `present[i] == false`) are reconstructed using
/// Reed-Solomon and written back into `enc.shards[i]`.  `present` is
/// updated to `true` for every repaired shard.
///
/// Returns `Ok(())` if reconstruction succeeded (all shards are now present).
/// Returns `TooFewShards` if fewer than `cfg.data` shards are present.
pub fn repair(enc: &mut Encoded, present: &mut [bool]) -> Result<()> {
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

    if have == total {
        // Nothing to do
        return Ok(());
    }

    // Build Option shards for the RS library
    let mut opt_shards: Vec<Option<Vec<u8>>> = enc
        .shards
        .iter()
        .zip(present.iter())
        .map(|(s, &p)| if p { Some(s.clone()) } else { None })
        .collect();

    let rs = ReedSolomon::new(n_data, n_parity).map_err(|e| StorageError::Rs(e.to_string()))?;
    rs.reconstruct(&mut opt_shards).map_err(|e| StorageError::Rs(e.to_string()))?;

    // Write reconstructed shards back into enc and mark present
    for (i, opt) in opt_shards.into_iter().enumerate() {
        if let Some(shard) = opt {
            enc.shards[i] = shard;
            present[i] = true;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erasure::{encode, ErasureConfig};

    fn cfg46() -> ErasureConfig {
        ErasureConfig { data: 4, parity: 2 }
    }

    #[test]
    fn repair_drops_parity_shards_and_refills() {
        let original: Vec<u8> = (0u8..50).collect();
        let cfg = cfg46();
        let mut enc = encode(&original, &cfg).unwrap();

        // Save original shards to compare after repair
        let original_shards = enc.shards.clone();

        // Drop both parity shards
        let mut present = vec![true; enc.shards.len()];
        present[4] = false;
        present[5] = false;

        // Zero out the dropped shards to simulate loss
        enc.shards[4] = vec![0u8; enc.shards[0].len()];
        enc.shards[5] = vec![0u8; enc.shards[0].len()];

        repair(&mut enc, &mut present).unwrap();

        assert!(present.iter().all(|&p| p), "all shards should be marked present after repair");
        assert_eq!(enc.shards, original_shards, "repaired shards must match original encode output");
    }

    #[test]
    fn repair_fails_when_too_many_missing() {
        let original = b"not enough shards".to_vec();
        let cfg = cfg46(); // data=4 parity=2; drop 3 → fail
        let mut enc = encode(&original, &cfg).unwrap();

        let mut present = vec![true; enc.shards.len()];
        present[0] = false;
        present[1] = false;
        present[2] = false;

        for i in [0, 1, 2] {
            let slen = enc.shards[0].len();
            enc.shards[i] = vec![0u8; slen];
        }

        let result = repair(&mut enc, &mut present);
        assert!(result.is_err(), "repair should fail when parity+1 shards are missing");
    }

    #[test]
    fn repair_noop_when_all_present() {
        let original: Vec<u8> = (0u8..20).collect();
        let cfg = cfg46();
        let mut enc = encode(&original, &cfg).unwrap();
        let shards_before = enc.shards.clone();
        let mut present = vec![true; enc.shards.len()];

        repair(&mut enc, &mut present).unwrap();

        assert_eq!(enc.shards, shards_before, "no-op repair should not change shards");
    }
}
