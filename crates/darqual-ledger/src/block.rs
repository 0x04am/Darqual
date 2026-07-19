use darqual_core::{pow_mint, pow_valid, Label};
use serde::{Deserialize, Serialize};

use crate::epoch::Epoch;
use crate::merkle;

/// A single addressed entry in a block: a dead-drop label + lockbox envelope + PoW stamp.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub label: Label,
    /// Raw UTF-8 bytes of the lockbox envelope string.
    pub envelope: Vec<u8>,
    /// Proof-of-Work nonce.  The PoW stamp binds this entry's (label, envelope)
    /// to the nonce so it cannot be reused or forged cheaply.
    pub nonce: u64,
}

impl LedgerEntry {
    /// Construct a `LedgerEntry` by grinding a valid PoW nonce for the given difficulty.
    ///
    /// Use `difficulty = 0` for back-compat / fast tests (no work required).
    pub fn mint(label: Label, envelope: Vec<u8>, difficulty: u32) -> Self {
        let nonce = pow_mint(&label, &envelope, difficulty);
        LedgerEntry {
            label,
            envelope,
            nonce,
        }
    }

    /// Canonical byte representation used as Merkle leaf content.
    ///
    /// Format: `label.0 (16 bytes) || envelope bytes || nonce.to_le_bytes() (8 bytes)`.
    /// The nonce is included so the PoW stamp is committed into the Merkle tree.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + self.envelope.len() + 8);
        v.extend_from_slice(&self.label.0);
        v.extend_from_slice(&self.envelope);
        v.extend_from_slice(&self.nonce.to_le_bytes());
        v
    }

    /// Stable identifier for this exact logical write across replicated relays.
    ///
    /// Domain separation prevents accidental reuse as a generic block or envelope hash.
    pub fn id(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"darqual-ledger-entry-id-v1");
        hasher.update(&self.canonical_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Check that this entry's PoW stamp is valid for the given minimum difficulty.
    ///
    /// Always returns `true` when `difficulty == 0`.
    pub fn pow_valid(&self, difficulty: u32) -> bool {
        pow_valid(&self.label, &self.envelope, self.nonce, difficulty)
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
        let created_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::new_at(epoch, prev_hash, entries, created_unix)
    }

    /// Construct a block with an explicit creation timestamp.
    ///
    /// Relays use the epoch boundary here so repeated snapshots of an in-progress
    /// epoch have a stable hash instead of changing with wall-clock time.
    pub fn new_at(
        epoch: Epoch,
        prev_hash: [u8; 32],
        entries: Vec<LedgerEntry>,
        created_unix: u64,
    ) -> Self {
        let leaves: Vec<Vec<u8>> = entries.iter().map(|e| e.canonical_bytes()).collect();
        let root = merkle::merkle_root(&leaves);
        let n = entries.len() as u32;

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

    /// Validate all entry PoW stamps against `difficulty`.
    ///
    /// Returns `true` if every entry satisfies the required difficulty
    /// (trivially true when `difficulty == 0`).
    pub fn validate_pow(&self, difficulty: u32) -> bool {
        if difficulty == 0 {
            return true;
        }
        self.entries.iter().all(|e| e.pow_valid(difficulty))
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
