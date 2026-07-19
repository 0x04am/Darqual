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

/// Open entries whose sender clock was within one epoch of the relay-stamped block.
///
/// Tor bootstrap and network delay can cross the 60-second epoch boundary between
/// sealing and relay acceptance. Trying the adjacent labels preserves delivery while
/// bounding work to three labels per block.
pub fn fetch_open_adjacent_epochs(
    conv: &Conversation,
    block: &Block,
    me: &Identity,
) -> Vec<Vec<u8>> {
    let epoch = block.header.epoch;
    let candidates = [epoch.saturating_sub(1), epoch, epoch.saturating_add(1)];
    let mut opened = Vec::new();
    let mut previous = None;
    for candidate in candidates {
        if previous == Some(candidate) {
            continue;
        }
        opened.extend(fetch_open(conv, candidate, block, me));
        previous = Some(candidate);
    }
    opened
}
