use darqual_core::Label;
use serde::{Deserialize, Serialize};

use crate::epoch::Epoch;
use crate::merkle;

/// A single addressed entry in a block: a dead-drop label + the lockbox envelope bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub label: Label,
    /// Raw UTF-8 bytes of the lockbox envelope string.
    pub envelope: Vec<u8>,
}

impl LedgerEntry {
    /// Canonical byte representation used as Merkle leaf content.
    /// Format: label.0 (16 bytes) || envelope bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + self.envelope.len());
        v.extend_from_slice(&self.label.0);
        v.extend_from_slice(&self.envelope);
        v
    }
}

/// The header of a ledger block — this is what gets hash-linked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub epoch: Epoch,
    /// Hash of the previous block's header (all zeros for genesis).
    pub prev_hash: [u8; 32],
    /// Merkle root over the canonical bytes of each entry in this block.
    pub merkle_root: [u8; 32],
    pub n_messages: u32,
    pub created_unix: u64,
}

/// A ledger block: a header + addressed entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub entries: Vec<LedgerEntry>,
}

impl Block {
    /// Construct a block, computing the Merkle root and n_messages automatically.
    pub fn new(epoch: Epoch, prev_hash: [u8; 32], entries: Vec<LedgerEntry>) -> Self {
        let leaves: Vec<Vec<u8>> = entries.iter().map(|e| e.canonical_bytes()).collect();
        let root = merkle::merkle_root(&leaves);
        let n = entries.len() as u32;
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
            entries,
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

    /// Recompute the Merkle root from entries and verify it matches the header.
    pub fn validate(&self) -> bool {
        let leaves: Vec<Vec<u8>> = self.entries.iter().map(|e| e.canonical_bytes()).collect();
        let computed = merkle::merkle_root(&leaves);
        computed == self.header.merkle_root && self.entries.len() as u32 == self.header.n_messages
    }

    /// Check whether any entry in this block carries the given label.
    pub fn has_label(&self, label: &Label) -> bool {
        self.entries.iter().any(|e| &e.label == label)
    }

    /// Return all envelope byte slices for entries with the given label.
    pub fn fetch(&self, label: &Label) -> Vec<&[u8]> {
        self.entries
            .iter()
            .filter(|e| &e.label == label)
            .map(|e| e.envelope.as_slice())
            .collect()
    }
}
