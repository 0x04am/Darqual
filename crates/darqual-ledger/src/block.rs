use serde::{Deserialize, Serialize};

use crate::epoch::Epoch;
use crate::merkle;

/// The header of a ledger block — this is what gets hash-linked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub epoch: Epoch,
    /// Hash of the previous block's header (all zeros for genesis).
    pub prev_hash: [u8; 32],
    /// Merkle root over the lockbox bytes in this block.
    pub merkle_root: [u8; 32],
    pub n_messages: u32,
    pub created_unix: u64,
}

/// A ledger block: a header + the raw lockbox envelopes (UTF-8 strings as bytes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    /// Each entry is the UTF-8 bytes of a lockbox envelope string.
    pub lockboxes: Vec<Vec<u8>>,
}

impl Block {
    /// Construct a block, computing the Merkle root and n_messages automatically.
    pub fn new(epoch: Epoch, prev_hash: [u8; 32], lockboxes: Vec<Vec<u8>>) -> Self {
        let root = merkle::merkle_root(&lockboxes);
        let n = lockboxes.len() as u32;
        let created_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Block {
            header: BlockHeader {
                epoch,
                prev_hash,
                merkle_root: root,
                n_messages: n,
                created_unix,
            },
            lockboxes,
        }
    }

    /// Canonical hash of this block's header (used as the next block's `prev_hash`).
    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.header.epoch.to_le_bytes());
        h.update(&self.header.prev_hash);
        h.update(&self.header.merkle_root);
        h.update(&self.header.n_messages.to_le_bytes());
        h.update(&self.header.created_unix.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// Recompute the Merkle root from lockboxes and verify it matches the header.
    pub fn validate(&self) -> bool {
        let computed = merkle::merkle_root(&self.lockboxes);
        computed == self.header.merkle_root && self.lockboxes.len() as u32 == self.header.n_messages
    }
}
