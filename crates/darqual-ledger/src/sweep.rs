use darqual_core::{Identity, Lockbox};

use crate::block::Block;
use crate::ledger::Ledger;

/// Try to open every entry's envelope in a block with `identity`.
/// Returns the plaintexts of the ones that decrypt successfully.
pub fn trial_decrypt(identity: &Identity, block: &Block) -> Vec<Vec<u8>> {
    block
        .entries
        .iter()
        .filter_map(|entry| {
            let envelope = std::str::from_utf8(&entry.envelope).ok()?;
            Lockbox::open(identity, envelope).ok()
        })
        .collect()
}

/// Sweep the entire hot window and return all plaintexts that decrypt for `identity`.
pub fn sweep_window(identity: &Identity, ledger: &Ledger) -> Vec<Vec<u8>> {
    ledger
        .blocks()
        .iter()
        .flat_map(|block| trial_decrypt(identity, block))
        .collect()
}
