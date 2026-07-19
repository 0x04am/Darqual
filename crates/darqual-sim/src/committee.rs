use std::collections::BTreeMap;

use darqual_committee::CommitteeManifest;
use darqual_ledger::{Block, LedgerEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayWriteOutcome {
    Stored,
    Duplicate,
    Unavailable,
    Rejected(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteOutcome {
    pub threshold_met: bool,
    pub stored_acknowledgements: usize,
    pub relays: BTreeMap<String, RelayWriteOutcome>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PageObservation {
    pub relay: String,
    pub blocks: Vec<Block>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationEvidence {
    pub relay: String,
    pub epoch: u64,
    pub first_hash: [u8; 32],
    pub second_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeakageFacts {
    pub relays_observe_write: bool,
    pub relays_observe_fetch: bool,
    pub global_observer_privacy_claimed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FetchOutcome {
    pub entries: Vec<LedgerEntry>,
    pub sources: BTreeMap<[u8; 32], Vec<String>>,
    pub rejected_relays: Vec<String>,
    pub equivocations: Vec<EquivocationEvidence>,
    pub leakage: LeakageFacts,
}

#[derive(Debug, Clone)]
pub struct CommitteeSimulation {
    manifest: CommitteeManifest,
}

impl CommitteeSimulation {
    pub fn new(manifest: CommitteeManifest) -> Self {
        Self { manifest }
    }

    pub fn aggregate_write(
        &self,
        outcomes: impl IntoIterator<Item = (String, RelayWriteOutcome)>,
    ) -> WriteOutcome {
        let relays: BTreeMap<_, _> = outcomes.into_iter().collect();
        let stored_acknowledgements = relays
            .values()
            .filter(|outcome| {
                matches!(
                    outcome,
                    RelayWriteOutcome::Stored | RelayWriteOutcome::Duplicate
                )
            })
            .count();
        WriteOutcome {
            threshold_met: stored_acknowledgements >= self.manifest.write_threshold,
            stored_acknowledgements,
            relays,
        }
    }

    pub fn aggregate_fetch(&self, pages: Vec<PageObservation>) -> FetchOutcome {
        let mut by_id: BTreeMap<[u8; 32], LedgerEntry> = BTreeMap::new();
        let mut sources: BTreeMap<[u8; 32], Vec<String>> = BTreeMap::new();
        let mut rejected_relays = Vec::new();
        let mut equivocations = Vec::new();
        let mut commitments: BTreeMap<(String, u64), [u8; 32]> = BTreeMap::new();

        for page in pages {
            let mut valid = true;
            let mut previous_epoch = None;
            for block in &page.blocks {
                if !block.validate()
                    || previous_epoch.is_some_and(|epoch| block.header.epoch <= epoch)
                {
                    valid = false;
                    break;
                }
                previous_epoch = Some(block.header.epoch);
                let key = (page.relay.clone(), block.header.epoch);
                let hash = block.hash();
                if let Some(first_hash) = commitments.insert(key, hash) {
                    if first_hash != hash {
                        equivocations.push(EquivocationEvidence {
                            relay: page.relay.clone(),
                            epoch: block.header.epoch,
                            first_hash,
                            second_hash: hash,
                        });
                    }
                }
            }
            if !valid {
                rejected_relays.push(page.relay);
                continue;
            }
            for block in page.blocks {
                for entry in block.entries {
                    let id = entry.id();
                    by_id.entry(id).or_insert(entry);
                    let entry_sources = sources.entry(id).or_default();
                    if !entry_sources.contains(&page.relay) {
                        entry_sources.push(page.relay.clone());
                    }
                }
            }
        }

        FetchOutcome {
            entries: by_id.into_values().collect(),
            sources,
            rejected_relays,
            equivocations,
            leakage: LeakageFacts {
                relays_observe_write: true,
                relays_observe_fetch: true,
                global_observer_privacy_claimed: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use darqual_committee::RelayEndpoint;
    use darqual_core::Label;

    use super::*;

    fn endpoint(name: &str) -> RelayEndpoint {
        RelayEndpoint {
            name: name.into(),
            onion: format!("{name}.onion"),
            port: 9999,
        }
    }

    fn simulation() -> CommitteeSimulation {
        CommitteeSimulation::new(
            CommitteeManifest::new(2, vec![endpoint("a"), endpoint("b"), endpoint("c")])
                .expect("manifest"),
        )
    }

    fn entry(byte: u8) -> LedgerEntry {
        LedgerEntry::mint(Label([byte; 16]), vec![byte; 8], 0)
    }

    #[test]
    fn threshold_two_accepts_two_stored_acknowledgements() {
        let outcome = simulation().aggregate_write([
            ("a".into(), RelayWriteOutcome::Stored),
            ("b".into(), RelayWriteOutcome::Stored),
            ("c".into(), RelayWriteOutcome::Unavailable),
        ]);
        assert!(outcome.threshold_met);
        assert_eq!(outcome.stored_acknowledgements, 2);
    }

    #[test]
    fn threshold_failure_preserves_partial_outcomes() {
        let outcome = simulation().aggregate_write([
            ("a".into(), RelayWriteOutcome::Stored),
            ("b".into(), RelayWriteOutcome::Unavailable),
            ("c".into(), RelayWriteOutcome::Unavailable),
        ]);
        assert!(!outcome.threshold_met);
        assert_eq!(outcome.stored_acknowledgements, 1);
        assert_eq!(outcome.relays.len(), 3);
    }

    #[test]
    fn replicated_entry_is_deduplicated_with_source_provenance() {
        let entry = entry(7);
        let mut pages = Vec::new();
        for relay in ["a", "b", "c"] {
            pages.push(PageObservation {
                relay: relay.into(),
                blocks: vec![Block::new_at(10, [0; 32], vec![entry.clone()], 600)],
            });
        }

        let outcome = simulation().aggregate_fetch(pages);

        assert_eq!(outcome.entries, vec![entry.clone()]);
        assert_eq!(outcome.sources[&entry.id()], vec!["a", "b", "c"]);
        assert!(!outcome.leakage.global_observer_privacy_claimed);
        assert!(outcome.leakage.relays_observe_write);
        assert!(outcome.leakage.relays_observe_fetch);
    }

    #[test]
    fn malformed_page_is_isolated_without_losing_honest_entry() {
        let entry = entry(8);
        let honest = Block::new_at(10, [0; 32], vec![entry.clone()], 600);
        let mut malformed = honest.clone();
        malformed.header.n_messages += 1;

        let outcome = simulation().aggregate_fetch(vec![
            PageObservation {
                relay: "a".into(),
                blocks: vec![malformed],
            },
            PageObservation {
                relay: "b".into(),
                blocks: vec![honest],
            },
        ]);

        assert_eq!(outcome.rejected_relays, vec!["a"]);
        assert_eq!(outcome.entries, vec![entry]);
    }
}
