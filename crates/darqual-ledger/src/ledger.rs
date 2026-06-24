use thiserror::Error;

use crate::block::Block;
use crate::epoch::Epoch;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("block validation failed: Merkle root mismatch")]
    InvalidBlock,
    #[error("block chain linkage broken: expected prev_hash {expected}, got {got}")]
    BrokenChain { expected: String, got: String },
    #[error("block rejected: one or more entries fail PoW at difficulty {0}")]
    InvalidPoW(u32),
}

/// The hot-window ledger — a sliding window of recent epochs.
#[derive(Debug, Clone)]
pub struct Ledger {
    blocks: Vec<Block>,
    /// Maximum number of blocks to retain.
    pub window: usize,
    /// Minimum PoW difficulty required for every entry appended to this ledger.
    /// `0` disables the check (back-compat / tests that don't care about PoW).
    pub pow_difficulty: u32,
}

impl Ledger {
    /// Create an empty ledger with a given hot-window size and no PoW requirement.
    pub fn new(window: usize) -> Self {
        Ledger {
            blocks: Vec::new(),
            window,
            pow_difficulty: 0,
        }
    }

    /// Create an empty ledger that enforces a minimum PoW difficulty on every entry.
    pub fn new_with_pow(window: usize, pow_difficulty: u32) -> Self {
        Ledger {
            blocks: Vec::new(),
            window,
            pow_difficulty,
        }
    }

    /// Append a validated, chain-linked block.
    ///
    /// Checks (in order):
    /// 1. block Merkle root is internally consistent;
    /// 2. `prev_hash` links to the current tip;
    /// 3. every entry satisfies `self.pow_difficulty`.
    ///
    /// Prunes to `self.window` blocks after a successful append.
    pub fn append(&mut self, block: Block) -> Result<(), LedgerError> {
        if !block.validate() {
            return Err(LedgerError::InvalidBlock);
        }

        let expected_prev = self.tip_hash();
        if block.header.prev_hash != expected_prev {
            return Err(LedgerError::BrokenChain {
                expected: format!("{:x?}", expected_prev),
                got: format!("{:x?}", block.header.prev_hash),
            });
        }

        if !block.validate_pow(self.pow_difficulty) {
            return Err(LedgerError::InvalidPoW(self.pow_difficulty));
        }

        self.blocks.push(block);

        // Prune to last `window` blocks
        if self.blocks.len() > self.window {
            let drain_count = self.blocks.len() - self.window;
            self.blocks.drain(..drain_count);
        }

        Ok(())
    }

    /// Hash of the tip block. Genesis expects [0u8; 32].
    pub fn tip_hash(&self) -> [u8; 32] {
        match self.blocks.last() {
            Some(b) => b.hash(),
            None => [0u8; 32],
        }
    }

    /// Number of blocks currently in the hot window.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// True if the ledger holds no blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Look up a block by epoch number.
    pub fn get(&self, epoch: Epoch) -> Option<&Block> {
        self.blocks.iter().find(|b| b.header.epoch == epoch)
    }

    /// Iterate over all blocks in the hot window (oldest first).
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// Validate the full chain: every block validates AND links to its predecessor.
    pub fn validate_chain(&self) -> bool {
        let mut prev = [0u8; 32];
        for block in &self.blocks {
            if !block.validate() {
                return false;
            }
            if block.header.prev_hash != prev {
                return false;
            }
            prev = block.hash();
        }
        true
    }
}
