//! Transport-neutral state machine for the Tier-1 single-relay dead drop.

use std::fs;
use std::io::Write;
use std::path::Path;

use bincode::Options;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Block, Epoch, LedgerEntry};

const SNAPSHOT_VERSION: u8 = 1;
const MAX_WINDOW: usize = 4096;
const SNAPSHOT_OVERHEAD_BYTES: usize = 1024 * 1024;
/// Maximum encoded relay snapshot size accepted before allocation/decoding.
const MAX_RELAY_SNAPSHOT_BYTES: usize = MAX_RELAY_STATE_BYTES + SNAPSHOT_OVERHEAD_BYTES;
/// Per-entry envelope limit shared with the Tier-1 wire protocol.
pub const MAX_RELAY_ENVELOPE_BYTES: usize = 256 * 1024;
/// Total opaque envelope bytes retained by one relay process.
pub const MAX_RELAY_STATE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay hot window must be between 1 and {MAX_WINDOW} blocks")]
    InvalidWindow,
    #[error("entry fails PoW at difficulty {0}")]
    InvalidPoW(u32),
    #[error("relay storage capacity exceeded")]
    CapacityExceeded,
    #[error("duplicate entry already retained by relay")]
    Duplicate,
    #[error("relay epoch moved backward from {current} to {got}")]
    EpochRegression { current: Epoch, got: Epoch },
    #[error("relay snapshot I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("relay snapshot decode failed: {0}")]
    Decode(String),
    #[error("relay snapshot is internally invalid: {0}")]
    InvalidSnapshot(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayReceipt {
    pub epoch: Epoch,
    pub entries: u32,
}

/// One designated relay's bounded hot window plus its current in-progress epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayState {
    version: u8,
    window: usize,
    pow_difficulty: u32,
    committed: Vec<Block>,
    current_epoch: Option<Epoch>,
    current_entries: Vec<LedgerEntry>,
}

impl RelayState {
    pub fn new(window: usize, pow_difficulty: u32) -> Result<Self, RelayError> {
        if !(1..=MAX_WINDOW).contains(&window) {
            return Err(RelayError::InvalidWindow);
        }
        Ok(Self {
            version: SNAPSHOT_VERSION,
            window,
            pow_difficulty,
            committed: Vec::new(),
            current_epoch: None,
            current_entries: Vec::new(),
        })
    }

    pub fn submit(
        &mut self,
        now_epoch: Epoch,
        entry: LedgerEntry,
    ) -> Result<RelayReceipt, RelayError> {
        if !entry.pow_valid(self.pow_difficulty) {
            return Err(RelayError::InvalidPoW(self.pow_difficulty));
        }
        if self.contains_entry(&entry) {
            return Err(RelayError::Duplicate);
        }
        if entry.envelope.len() > MAX_RELAY_ENVELOPE_BYTES
            || self
                .retained_envelope_bytes()
                .saturating_add(entry.envelope.len())
                > MAX_RELAY_STATE_BYTES
        {
            return Err(RelayError::CapacityExceeded);
        }
        self.rotate_to(now_epoch)?;
        self.current_entries.push(entry);
        Ok(RelayReceipt {
            epoch: now_epoch,
            entries: self.current_entries.len() as u32,
        })
    }

    /// Return committed blocks plus a stable snapshot of the current in-progress epoch.
    ///
    /// Fetch is deliberately a pure read: elapsed wall-clock epochs do not fabricate
    /// history or mutate the relay chain. A pending entry remains labelled with the
    /// epoch in which the relay accepted it, so an offline recipient can still derive
    /// the same label later.
    pub fn fetch(&self, since_epoch: Option<Epoch>) -> Vec<Block> {
        let mut blocks: Vec<Block> = self
            .committed
            .iter()
            .filter(|block| since_epoch.is_none_or(|since| block.header.epoch >= since))
            .cloned()
            .collect();
        if let Some(epoch) = self.current_epoch {
            if !self.current_entries.is_empty() && since_epoch.is_none_or(|since| epoch >= since) {
                blocks.push(Block::new_at(
                    epoch,
                    self.tip_hash(),
                    self.current_entries.clone(),
                    epoch.saturating_mul(crate::EPOCH_SECONDS),
                ));
            }
        }
        blocks
    }

    pub fn save(&self, path: &Path) -> Result<(), RelayError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let bytes = bincode::serialize(self).map_err(|e| RelayError::Decode(e.to_string()))?;
        let tmp = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("relay"),
            std::process::id()
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        if let Err(err) = (|| -> std::io::Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&tmp, path)?;
            Ok(())
        })() {
            let _ = fs::remove_file(&tmp);
            return Err(RelayError::Io(err));
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, RelayError> {
        let file_len = fs::metadata(path)?.len();
        if file_len > MAX_RELAY_SNAPSHOT_BYTES as u64 {
            return Err(RelayError::CapacityExceeded);
        }
        let bytes = fs::read(path)?;
        let state: Self = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .with_limit(MAX_RELAY_SNAPSHOT_BYTES as u64)
            .deserialize(&bytes)
            .map_err(|e| RelayError::Decode(e.to_string()))?;
        state.validate()?;
        Ok(state)
    }

    pub fn window(&self) -> usize {
        self.window
    }

    pub fn pow_difficulty(&self) -> u32 {
        self.pow_difficulty
    }

    fn rotate_to(&mut self, epoch: Epoch) -> Result<(), RelayError> {
        match self.current_epoch {
            None => self.current_epoch = Some(epoch),
            Some(current) if epoch < current => {
                return Err(RelayError::EpochRegression {
                    current,
                    got: epoch,
                });
            }
            Some(current) if epoch > current => {
                if !self.current_entries.is_empty() {
                    let block = Block::new_at(
                        current,
                        self.tip_hash(),
                        std::mem::take(&mut self.current_entries),
                        current.saturating_mul(crate::EPOCH_SECONDS),
                    );
                    self.committed.push(block);
                    self.prune();
                }
                self.current_epoch = Some(epoch);
            }
            Some(_) => {}
        }
        Ok(())
    }

    fn tip_hash(&self) -> [u8; 32] {
        self.committed.last().map_or([0u8; 32], Block::hash)
    }

    fn contains_entry(&self, candidate: &LedgerEntry) -> bool {
        self.committed
            .iter()
            .flat_map(|block| &block.entries)
            .chain(&self.current_entries)
            .any(|entry| entry == candidate)
    }

    fn retained_envelope_bytes(&self) -> usize {
        self.committed
            .iter()
            .flat_map(|block| &block.entries)
            .chain(&self.current_entries)
            .fold(0usize, |total, entry| {
                total.saturating_add(entry.envelope.len())
            })
    }

    fn prune(&mut self) {
        // Reserve one slot for the current in-progress epoch returned by fetch().
        let committed_limit = self.window.saturating_sub(1);
        if self.committed.len() > committed_limit {
            let remove = self.committed.len() - committed_limit;
            self.committed.drain(..remove);
        }
    }

    fn validate(&self) -> Result<(), RelayError> {
        if self.version != SNAPSHOT_VERSION {
            return Err(RelayError::InvalidSnapshot("unsupported version".into()));
        }
        if !(1..=MAX_WINDOW).contains(&self.window) {
            return Err(RelayError::InvalidWindow);
        }
        if self.committed.len() > self.window.saturating_sub(1) {
            return Err(RelayError::InvalidSnapshot(
                "hot window exceeds bound".into(),
            ));
        }
        if self.retained_envelope_bytes() > MAX_RELAY_STATE_BYTES
            || self
                .committed
                .iter()
                .flat_map(|block| &block.entries)
                .chain(&self.current_entries)
                .any(|entry| entry.envelope.len() > MAX_RELAY_ENVELOPE_BYTES)
        {
            return Err(RelayError::InvalidSnapshot(
                "relay storage capacity exceeded".into(),
            ));
        }
        let mut prev = self
            .committed
            .first()
            .map_or([0u8; 32], |block| block.header.prev_hash);
        for block in &self.committed {
            if !block.validate() || block.header.prev_hash != prev {
                return Err(RelayError::InvalidSnapshot(
                    "invalid block or chain link".into(),
                ));
            }
            if !block.validate_pow(self.pow_difficulty) {
                return Err(RelayError::InvalidSnapshot("invalid entry PoW".into()));
            }
            prev = block.hash();
        }
        if self
            .current_entries
            .iter()
            .any(|entry| !entry.pow_valid(self.pow_difficulty))
        {
            return Err(RelayError::InvalidSnapshot("invalid pending PoW".into()));
        }
        if self.current_entries.is_empty() && self.current_epoch.is_some() {
            return Err(RelayError::InvalidSnapshot(
                "empty current epoch should not be persisted".into(),
            ));
        }
        if !self.current_entries.is_empty() && self.current_epoch.is_none() {
            return Err(RelayError::InvalidSnapshot(
                "pending entries have no epoch".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use darqual_core::{Identity, Label, Lockbox};
    use x25519_dalek::PublicKey as X25519PublicKey;

    use super::*;

    fn entry_for(recipient: &Identity, label_byte: u8, msg: &[u8], difficulty: u32) -> LedgerEntry {
        let x_pub = X25519PublicKey::from(&recipient.x_secret);
        let lockbox = Lockbox::seal(&x_pub, msg).expect("seal");
        LedgerEntry::mint(
            Label([label_byte; 16]),
            lockbox.envelope.into_bytes(),
            difficulty,
        )
    }

    #[test]
    fn submit_is_immediately_visible_in_current_epoch_snapshot() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(4, 0).expect("relay");
        let receipt = relay
            .submit(10, entry_for(&bob, 7, b"offline hello", 0))
            .expect("submit");
        let blocks = relay.fetch(None);
        assert_eq!(
            receipt,
            RelayReceipt {
                epoch: 10,
                entries: 1
            }
        );
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].header.epoch, 10);
        assert_eq!(blocks[0].entries.len(), 1);
    }

    #[test]
    fn invalid_pow_does_not_mutate_state() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(4, 12).expect("relay");
        let mut bad = entry_for(&bob, 1, b"cheap write", 0);
        while bad.pow_valid(12) {
            bad.nonce = bad.nonce.wrapping_add(1);
        }
        let err = relay.submit(10, bad).expect_err("must reject bad PoW");
        assert!(matches!(err, RelayError::InvalidPoW(12)));
        assert!(relay.fetch(None).is_empty());
    }

    #[test]
    fn epoch_rotation_commits_a_hash_linked_block() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(4, 0).expect("relay");
        relay
            .submit(10, entry_for(&bob, 1, b"one", 0))
            .expect("one");
        relay
            .submit(11, entry_for(&bob, 2, b"two", 0))
            .expect("two");
        let blocks = relay.fetch(None);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1].header.prev_hash, blocks[0].hash());
    }

    #[test]
    fn atomic_snapshot_round_trip_preserves_pruned_hot_window_and_pending() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(2, 0).expect("relay");
        for epoch in 10..14 {
            relay
                .submit(epoch, entry_for(&bob, epoch as u8, &[epoch as u8], 0))
                .expect("submit");
        }
        let dir = std::env::temp_dir().join(format!("darqual-relay-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("relay.bin");
        relay.save(&path).expect("save");
        let restored = RelayState::load(&path).expect("load");
        assert_eq!(restored.fetch(None), relay.fetch(None));
        assert_eq!(restored.window(), 2);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn snapshot_with_trailing_bytes_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("darqual-relay-trailing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("relay.bin");
        RelayState::new(4, 0)
            .expect("relay")
            .save(&path)
            .expect("save");
        let mut bytes = fs::read(&path).expect("read");
        bytes.push(0xaa);
        fs::write(&path, bytes).expect("append trailing byte");

        let err = RelayState::load(&path).expect_err("trailing bytes must fail");

        assert!(matches!(err, RelayError::Decode(_)));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn oversized_snapshot_is_rejected_before_decode() {
        let dir =
            std::env::temp_dir().join(format!("darqual-relay-oversized-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("relay.bin");
        let file = fs::File::create(&path).expect("create");
        file.set_len(MAX_RELAY_SNAPSHOT_BYTES as u64 + 1)
            .expect("make sparse oversized file");

        let err = RelayState::load(&path).expect_err("oversized snapshot must fail");

        assert!(matches!(err, RelayError::CapacityExceeded));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn malformed_snapshot_is_rejected() {
        let dir = std::env::temp_dir().join(format!("darqual-relay-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("relay.bin");
        fs::write(&path, b"not a relay snapshot").expect("write");
        let err = RelayState::load(&path).expect_err("malformed snapshot must fail");
        assert!(matches!(err, RelayError::Decode(_)));
        fs::remove_dir_all(dir).expect("cleanup");
    }
}

#[cfg(test)]
mod hardening_tests {
    use darqual_core::{Identity, Label, Lockbox};
    use x25519_dalek::PublicKey as X25519PublicKey;

    use super::*;

    fn entry(recipient: &Identity, byte: u8, envelope_bytes: usize) -> LedgerEntry {
        let x_pub = X25519PublicKey::from(&recipient.x_secret);
        let lockbox = Lockbox::seal(&x_pub, &vec![byte; envelope_bytes]).expect("seal");
        LedgerEntry::mint(Label([byte; 16]), lockbox.envelope.into_bytes(), 0)
    }

    #[test]
    fn current_epoch_snapshot_hash_is_stable_across_fetches() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(4, 0).expect("relay");
        relay.submit(10, entry(&bob, 1, 8)).expect("submit");
        let first = relay.fetch(None).pop().expect("block").hash();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = relay.fetch(None).pop().expect("block").hash();
        assert_eq!(first, second);
    }

    #[test]
    fn pruning_does_not_rewrite_retained_block_hashes() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(3, 0).expect("relay");
        relay.submit(10, entry(&bob, 1, 8)).expect("10");
        relay.submit(11, entry(&bob, 2, 8)).expect("11");
        let epoch_10_hash = relay.fetch(Some(10))[0].hash();
        relay.submit(12, entry(&bob, 3, 8)).expect("12");
        relay.submit(13, entry(&bob, 4, 8)).expect("13");
        let retained = relay.fetch(None);
        assert_eq!(retained[0].header.prev_hash, epoch_10_hash);
    }

    #[test]
    fn state_rejects_an_entry_that_exceeds_total_capacity() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(4, 0).expect("relay");
        let before = relay.fetch(None);
        let err = relay
            .submit(10, entry(&bob, 9, MAX_RELAY_ENVELOPE_BYTES + 1))
            .expect_err("oversized state must reject");
        assert!(matches!(err, RelayError::CapacityExceeded));
        assert_eq!(relay.fetch(None), before);
    }

    #[test]
    fn large_idle_gap_does_not_fabricate_empty_epoch_chain() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(4, 0).expect("relay");
        relay.submit(10, entry(&bob, 1, 8)).expect("submit");

        let blocks = relay.fetch(None);

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].header.epoch, 10);
        assert_eq!(blocks[0].entries.len(), 1);
    }

    #[test]
    fn duplicate_entry_is_rejected_without_mutation() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(4, 0).expect("relay");
        let repeated = entry(&bob, 4, 8);
        relay.submit(10, repeated.clone()).expect("first submit");
        let before = relay.fetch(None);

        let err = relay
            .submit(10, repeated)
            .expect_err("duplicate must be rejected");

        assert!(matches!(err, RelayError::Duplicate));
        assert_eq!(relay.fetch(None), before);
    }

    #[test]
    fn idle_time_does_not_rewrite_the_pending_epoch() {
        let bob = Identity::generate();
        let mut relay = RelayState::new(4, 0).expect("relay");
        relay.submit(10, entry(&bob, 1, 8)).expect("submit");

        let first = relay.fetch(None);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let second = relay.fetch(None);

        assert_eq!(second, first);
        assert_eq!(second[0].header.epoch, 10);
        assert_eq!(second[0].entries.len(), 1);
    }
}
