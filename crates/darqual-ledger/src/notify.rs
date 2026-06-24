use darqual_core::{Conversation, Identity, Lockbox};

use crate::block::Block;

/// Check cheaply whether the current block holds a dead-drop entry for this conversation/epoch.
/// This is the Talek-style "do I have mail?" notification check.
pub fn notify(conv: &Conversation, epoch: u64, block: &Block) -> bool {
    block.has_label(&conv.label(epoch))
}

/// Fetch and open all envelopes addressed to this conversation in the given block/epoch.
/// Returns plaintexts for every lockbox that successfully decrypts with `me`.
pub fn fetch_open(conv: &Conversation, epoch: u64, block: &Block, me: &Identity) -> Vec<Vec<u8>> {
    let label = conv.label(epoch);
    block
        .fetch(&label)
        .into_iter()
        .filter_map(|raw| {
            let envelope = std::str::from_utf8(raw).ok()?;
            Lockbox::open(me, envelope).ok()
        })
        .collect()
}
