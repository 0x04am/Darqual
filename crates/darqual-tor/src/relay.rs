//! Bounded request/response protocol for the Tier-1 single-relay dead drop.

use anyhow::Context;
use bincode::Options;
use darqual_ledger::{Block, Epoch, LedgerEntry, MAX_RELAY_ENVELOPE_BYTES};
use serde::{Deserialize, Serialize};

/// Hard ceiling below the transport's 16 MiB frame cap.
pub const MAX_RELAY_PAYLOAD: usize = 8 * 1024 * 1024;
pub const MAX_ENTRY_ENVELOPE: usize = MAX_RELAY_ENVELOPE_BYTES;
pub const MAX_FETCH_BLOCKS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RelayRequest {
    Submit(LedgerEntry),
    Fetch { since_epoch: Option<Epoch> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RelayResponse {
    Accepted { epoch: Epoch, entries: u32 },
    Ledger(Vec<Block>),
    Rejected(String),
}

pub fn encode_request(request: &RelayRequest) -> anyhow::Result<Vec<u8>> {
    if let RelayRequest::Submit(entry) = request {
        anyhow::ensure!(
            entry.envelope.len() <= MAX_ENTRY_ENVELOPE,
            "entry envelope exceeds {} bytes",
            MAX_ENTRY_ENVELOPE
        );
    }
    encode_bounded(request)
}

pub fn decode_request(bytes: &[u8]) -> anyhow::Result<RelayRequest> {
    let request: RelayRequest = decode_bounded(bytes)?;
    if let RelayRequest::Submit(entry) = &request {
        anyhow::ensure!(
            entry.envelope.len() <= MAX_ENTRY_ENVELOPE,
            "entry envelope exceeds {} bytes",
            MAX_ENTRY_ENVELOPE
        );
    }
    Ok(request)
}

pub fn encode_response(response: &RelayResponse) -> anyhow::Result<Vec<u8>> {
    if let RelayResponse::Ledger(blocks) = response {
        anyhow::ensure!(
            blocks.len() <= MAX_FETCH_BLOCKS,
            "ledger response exceeds {MAX_FETCH_BLOCKS} blocks"
        );
    }
    encode_bounded(response)
}

/// Encode as many newest ledger blocks as fit in one bounded response.
///
/// A full hot window may exceed one Tor frame. Returning the newest suffix keeps
/// the relay available and lets clients advance `since_epoch` instead of turning
/// a large ledger into a permanent rejected response.
pub fn encode_ledger_response_bounded(blocks: Vec<Block>) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        blocks.len() <= MAX_FETCH_BLOCKS,
        "ledger response exceeds {MAX_FETCH_BLOCKS} blocks"
    );
    if let Ok(encoded) = encode_response(&RelayResponse::Ledger(blocks.clone())) {
        return Ok(encoded);
    }
    let mut low = 0usize;
    let mut high = blocks.len();
    while low < high {
        let mid = (low + high).div_ceil(2);
        if encode_response(&RelayResponse::Ledger(
            blocks[blocks.len() - mid..].to_vec(),
        ))
        .is_ok()
        {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    anyhow::ensure!(low > 0, "even one ledger block exceeds relay payload limit");
    encode_response(&RelayResponse::Ledger(
        blocks[blocks.len() - low..].to_vec(),
    ))
}

pub fn decode_response(bytes: &[u8]) -> anyhow::Result<RelayResponse> {
    let response: RelayResponse = decode_bounded(bytes)?;
    if let RelayResponse::Ledger(blocks) = &response {
        anyhow::ensure!(
            blocks.len() <= MAX_FETCH_BLOCKS,
            "ledger response exceeds {MAX_FETCH_BLOCKS} blocks"
        );
    }
    Ok(response)
}

fn encode_bounded<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let bytes = bincode_options()
        .serialize(value)
        .context("serialize relay protocol")?;
    anyhow::ensure!(
        bytes.len() <= MAX_RELAY_PAYLOAD,
        "relay payload exceeds {MAX_RELAY_PAYLOAD} bytes"
    );
    Ok(bytes)
}

fn decode_bounded<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> anyhow::Result<T> {
    anyhow::ensure!(
        bytes.len() <= MAX_RELAY_PAYLOAD,
        "relay payload exceeds {MAX_RELAY_PAYLOAD} bytes"
    );
    bincode_options()
        .deserialize(bytes)
        .context("decode relay protocol")
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RELAY_PAYLOAD as u64)
        .reject_trailing_bytes()
}

#[cfg(test)]
mod tests {
    use darqual_core::Label;

    use super::*;

    #[test]
    fn submit_request_round_trip() {
        let request = RelayRequest::Submit(LedgerEntry::mint(
            Label([7; 16]),
            b"dqbox1example".to_vec(),
            0,
        ));
        let encoded = encode_request(&request).expect("encode");
        assert_eq!(decode_request(&encoded).expect("decode"), request);
    }

    #[test]
    fn accepted_response_round_trip() {
        let response = RelayResponse::Accepted {
            epoch: 42,
            entries: 3,
        };
        let encoded = encode_response(&response).expect("encode");
        assert_eq!(decode_response(&encoded).expect("decode"), response);
    }

    #[test]
    fn oversized_entry_is_rejected_before_serialization() {
        let request = RelayRequest::Submit(LedgerEntry::mint(
            Label([1; 16]),
            vec![0; MAX_ENTRY_ENVELOPE + 1],
            0,
        ));
        assert!(encode_request(&request).is_err());
    }

    #[test]
    fn malformed_request_is_rejected() {
        assert!(decode_request(b"not bincode").is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded =
            encode_request(&RelayRequest::Fetch { since_epoch: None }).expect("encode");
        encoded.push(0);
        assert!(decode_request(&encoded).is_err());
    }

    #[test]
    fn oversized_ledger_response_returns_the_newest_bounded_suffix() {
        let huge = vec![9u8; MAX_ENTRY_ENVELOPE];
        let mut blocks = Vec::new();
        let mut prev = [0u8; 32];
        for epoch in 0..40 {
            let block = Block::new(
                epoch,
                prev,
                vec![LedgerEntry::mint(Label([epoch as u8; 16]), huge.clone(), 0)],
            );
            prev = block.hash();
            blocks.push(block);
        }
        assert!(encode_response(&RelayResponse::Ledger(blocks.clone())).is_err());

        let encoded = encode_ledger_response_bounded(blocks).expect("bounded encode");
        let RelayResponse::Ledger(returned) = decode_response(&encoded).expect("decode") else {
            panic!("expected ledger response");
        };
        assert!(!returned.is_empty());
        assert_eq!(returned.last().expect("last").header.epoch, 39);
        assert!(encoded.len() <= MAX_RELAY_PAYLOAD);
    }
}
