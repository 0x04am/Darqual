//! Prefix-bucket sharding — the privacy ↔ bandwidth dial.
//!
//! A node holding bucket `b` only stores entries whose label hashes into `b`.
//! More buckets → less bandwidth per node, but a smaller anonymity set per
//! bucket (weaker k-anonymity). Fewer buckets → stronger anonymity, more
//! bandwidth.  Choose `n_buckets` based on the threat model and node capacity.

use darqual_core::Label;
use darqual_ledger::block::LedgerEntry;

/// Derive the bucket index for a label given `n_buckets`.
///
/// Uses the first four bytes of the label interpreted as a big-endian `u32`,
/// modulo `n_buckets`. The mapping is purely deterministic — the same label
/// always falls into the same bucket for a given `n_buckets`.
///
/// # Panics
/// Panics if `n_buckets == 0`.
pub fn bucket_of(label: &Label, n_buckets: u32) -> u32 {
    assert!(n_buckets > 0, "n_buckets must be > 0");
    let high = u32::from_be_bytes([label.0[0], label.0[1], label.0[2], label.0[3]]);
    high % n_buckets
}

/// Partition a slice of `LedgerEntry` into `n_buckets` groups.
///
/// Returns a `Vec` of length `n_buckets`; each inner `Vec` contains the
/// *indices* (into `entries`) of the entries belonging to that bucket.
///
/// Every entry appears in exactly one bucket, so the index sets are disjoint
/// and their union is `0..entries.len()`.
pub fn partition(entries: &[LedgerEntry], n_buckets: u32) -> Vec<Vec<usize>> {
    assert!(n_buckets > 0, "n_buckets must be > 0");
    let mut buckets: Vec<Vec<usize>> = (0..n_buckets).map(|_| Vec::new()).collect();
    for (i, entry) in entries.iter().enumerate() {
        let b = bucket_of(&entry.label, n_buckets) as usize;
        buckets[b].push(i);
    }
    buckets
}

#[cfg(test)]
mod tests {
    use super::*;
    use darqual_core::Label;
    use darqual_ledger::block::LedgerEntry;

    fn make_entry(byte: u8) -> LedgerEntry {
        let mut raw = [0u8; 16];
        raw[0] = byte;
        LedgerEntry::mint(Label(raw), b"envelope".to_vec(), 0)
    }

    #[test]
    fn bucket_of_is_deterministic() {
        let label = Label([0xAB, 0xCD, 0xEF, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let b1 = bucket_of(&label, 8);
        let b2 = bucket_of(&label, 8);
        assert_eq!(b1, b2);
        assert!(b1 < 8);
    }

    #[test]
    fn bucket_of_respects_n_buckets() {
        let label = Label([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        for n in 1u32..=16 {
            let b = bucket_of(&label, n);
            assert!(b < n, "bucket {b} >= n_buckets {n}");
        }
    }

    #[test]
    fn partition_covers_all_entries_exactly_once() {
        let entries: Vec<LedgerEntry> = (0u8..16).map(make_entry).collect();
        let buckets = partition(&entries, 4);
        assert_eq!(buckets.len(), 4);

        // Flatten, sort, and check we have exactly 0..16
        let mut all: Vec<usize> = buckets.into_iter().flatten().collect();
        all.sort_unstable();
        let expected: Vec<usize> = (0..16).collect();
        assert_eq!(all, expected, "every entry should appear exactly once");
    }

    #[test]
    fn partition_entries_spread_across_buckets() {
        // Build entries whose high u32 (first 4 bytes) are spread across 0,1,2,3
        // by setting the low byte of the 4-byte prefix — ensures modular spread.
        let entries: Vec<LedgerEntry> = (0u8..16)
            .map(|i| {
                // Set byte[3] = i so u32::from_be_bytes([0,0,0,i]) == i — covers 0..16 mod 4
                let mut raw = [0u8; 16];
                raw[3] = i;
                LedgerEntry::mint(Label(raw), b"envelope".to_vec(), 0)
            })
            .collect();
        let buckets = partition(&entries, 4);
        let non_empty = buckets.iter().filter(|b| !b.is_empty()).count();
        assert_eq!(non_empty, 4, "entries should spread across all 4 buckets");
    }
}
