use darqual_core::{Identity, Lockbox};

use crate::block::Block;
use crate::ledger::Ledger;

/// Try to open every lockbox in a block with `identity`.
/// Returns the plaintexts of the ones that decrypt successfully.
pub fn trial_decrypt(identity: &Identity, block: &Block) -> Vec<Vec<u8>> {
    block
        .lockboxes
        .iter()
        .filter_map(|raw| {
            // Each entry is the UTF-8 bytes of an envelope string.
            let envelope = std::str::from_utf8(raw).ok()?;
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
