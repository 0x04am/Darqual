use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReplicaObservation {
    pub relay: String,
    pub epoch: u64,
    pub block_hash: [u8; 32],
}

/// Evidence that one canonical entry was independently served by a threshold
/// of distinct committee members. This is replication evidence, not consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryReplicationEvidence {
    pub entry_id: [u8; 32],
    pub supporters: Vec<String>,
    pub observations: Vec<ReplicaObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmissionEvidence {
    pub entry_id: [u8; 32],
    /// Valid, observed committee members whose pages omitted this replicated entry.
    pub relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FetchOutcome {
    /// Entries present in a block hash served by at least `write_threshold`
    /// distinct committee members. This is replication evidence, not finality.
    pub entries: Vec<LedgerEntry>,
    /// Member provenance for replicated entries only.
    pub sources: BTreeMap<[u8; 32], Vec<String>>,
    pub replicated: Vec<EntryReplicationEvidence>,
    pub unconfirmed_entries: Vec<LedgerEntry>,
    pub omissions: Vec<OmissionEvidence>,
    pub rejected_relays: Vec<String>,
    pub equivocations: Vec<EquivocationEvidence>,
    pub leakage: LeakageFacts,
}

#[derive(Debug, Clone)]
pub struct CommitteeSimulation {
    manifest: CommitteeManifest,
    expected_pow_difficulty: u32,
}

#[derive(Debug, Clone, PartialEq)]
struct ValidBlockObservation {
    relay: String,
    block: Block,
}

impl CommitteeSimulation {
    pub fn new(manifest: CommitteeManifest, expected_pow_difficulty: u32) -> Self {
        Self {
            manifest,
            expected_pow_difficulty,
        }
    }

    pub fn aggregate_write(
        &self,
        outcomes: impl IntoIterator<Item = (String, RelayWriteOutcome)>,
    ) -> WriteOutcome {
        let member_names: BTreeSet<&str> = self
            .manifest
            .members
            .iter()
            .map(|member| member.name.as_str())
            .collect();
        let mut relays = BTreeMap::new();
        for (name, outcome) in outcomes {
            if member_names.contains(name.as_str()) {
                relays.entry(name).or_insert(outcome);
            }
        }
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
        let member_names: BTreeSet<String> = self
            .manifest
            .members
            .iter()
            .map(|member| member.name.clone())
            .collect();
        let observed_members: BTreeSet<String> = pages
            .iter()
            .filter(|page| member_names.contains(&page.relay))
            .map(|page| page.relay.clone())
            .collect();
        let mut rejected_relays: BTreeSet<String> = pages
            .iter()
            .filter(|page| !member_names.contains(&page.relay))
            .map(|page| page.relay.clone())
            .collect();
        let mut candidates = Vec::new();

        // Validate each page atomically. Nothing from a partially invalid page enters
        // replication, provenance, or equivocation state.
        for page in pages {
            if !member_names.contains(&page.relay) {
                continue;
            }
            let mut previous: Option<&Block> = None;
            let valid = page.blocks.iter().all(|block| {
                let block_valid = block.validate()
                    && block.validate_pow(self.expected_pow_difficulty)
                    && previous.is_none_or(|prior| {
                        block.header.epoch > prior.header.epoch
                            && block.header.prev_hash == prior.hash()
                    });
                previous = Some(block);
                block_valid
            });
            if !valid {
                rejected_relays.insert(page.relay);
                continue;
            }
            candidates.extend(page.blocks.into_iter().map(|block| ValidBlockObservation {
                relay: page.relay.clone(),
                block,
            }));
        }

        // A relay serving more than one valid hash for one epoch has equivocated.
        let mut hashes_by_relay_epoch: BTreeMap<(String, u64), BTreeSet<[u8; 32]>> =
            BTreeMap::new();
        for candidate in &candidates {
            hashes_by_relay_epoch
                .entry((candidate.relay.clone(), candidate.block.header.epoch))
                .or_default()
                .insert(candidate.block.hash());
        }
        let mut equivocations = Vec::new();
        let mut equivocating: BTreeSet<(String, u64)> = BTreeSet::new();
        for ((relay, epoch), hashes) in hashes_by_relay_epoch {
            if hashes.len() > 1 {
                equivocating.insert((relay.clone(), epoch));
                let ordered: Vec<[u8; 32]> = hashes.into_iter().collect();
                for pair in ordered.windows(2) {
                    equivocations.push(EquivocationEvidence {
                        relay: relay.clone(),
                        epoch,
                        first_hash: pair[0],
                        second_hash: pair[1],
                    });
                }
            }
        }

        // Valid entries remain recoverable by union from any honest reachable relay.
        // Separately, collect per-entry replication evidence across distinct members;
        // this is not consensus and does not require identical independent chains.
        let mut all_valid_entries: BTreeMap<[u8; 32], LedgerEntry> = BTreeMap::new();
        let mut entry_observations: BTreeMap<[u8; 32], BTreeSet<ReplicaObservation>> =
            BTreeMap::new();
        let mut served_ids_by_relay: BTreeMap<String, BTreeSet<[u8; 32]>> = BTreeMap::new();
        for candidate in candidates {
            let epoch = candidate.block.header.epoch;
            let is_equivocating = equivocating.contains(&(candidate.relay.clone(), epoch));
            let block_hash = candidate.block.hash();
            for entry in &candidate.block.entries {
                let id = entry.id();
                all_valid_entries.entry(id).or_insert_with(|| entry.clone());
                if is_equivocating {
                    continue;
                }
                entry_observations
                    .entry(id)
                    .or_default()
                    .insert(ReplicaObservation {
                        relay: candidate.relay.clone(),
                        epoch,
                        block_hash,
                    });
                served_ids_by_relay
                    .entry(candidate.relay.clone())
                    .or_default()
                    .insert(id);
            }
        }

        let mut entries = Vec::new();
        let mut unconfirmed_entries = Vec::new();
        let mut sources = BTreeMap::new();
        let mut replicated = Vec::new();
        for (id, entry) in all_valid_entries {
            let observations: Vec<ReplicaObservation> = entry_observations
                .remove(&id)
                .unwrap_or_default()
                .into_iter()
                .collect();
            let supporters: Vec<String> = observations
                .iter()
                .map(|observation| observation.relay.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            if supporters.len() >= self.manifest.write_threshold {
                entries.push(entry);
                sources.insert(id, supporters.clone());
                replicated.push(EntryReplicationEvidence {
                    entry_id: id,
                    supporters,
                    observations,
                });
            } else {
                unconfirmed_entries.push(entry);
            }
        }

        // Omission evidence requires a valid observed page. Unavailable/rejected/nonmember
        // relays are not accused merely because they did not provide data.
        let accepted_members: Vec<String> = member_names
            .iter()
            .filter(|relay| observed_members.contains(*relay) && !rejected_relays.contains(*relay))
            .cloned()
            .collect();
        let mut omissions = Vec::new();
        for evidence in &replicated {
            let relays: Vec<String> = accepted_members
                .iter()
                .filter(|relay| {
                    !served_ids_by_relay
                        .get(*relay)
                        .is_some_and(|served| served.contains(&evidence.entry_id))
                })
                .cloned()
                .collect();
            if !relays.is_empty() {
                omissions.push(OmissionEvidence {
                    entry_id: evidence.entry_id,
                    relays,
                });
            }
        }

        FetchOutcome {
            entries,
            sources,
            replicated,
            unconfirmed_entries,
            omissions,
            rejected_relays: rejected_relays.into_iter().collect(),
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
            0,
        )
    }

    fn simulation_with_pow(difficulty: u32) -> CommitteeSimulation {
        CommitteeSimulation::new(
            CommitteeManifest::new(2, vec![endpoint("a"), endpoint("b"), endpoint("c")])
                .expect("manifest"),
            difficulty,
        )
    }

    fn entry(byte: u8) -> LedgerEntry {
        LedgerEntry::mint(Label([byte; 16]), vec![byte; 8], 0)
    }

    #[test]
    fn non_member_write_acknowledgement_does_not_count_toward_threshold() {
        let outcome = simulation().aggregate_write([
            ("a".into(), RelayWriteOutcome::Stored),
            ("mallory".into(), RelayWriteOutcome::Stored),
        ]);

        assert!(!outcome.threshold_met);
        assert_eq!(outcome.stored_acknowledgements, 1);
        assert!(!outcome.relays.contains_key("mallory"));
    }

    #[test]
    fn duplicate_write_report_counts_one_distinct_member() {
        let outcome = simulation().aggregate_write([
            ("a".into(), RelayWriteOutcome::Stored),
            ("a".into(), RelayWriteOutcome::Stored),
            ("b".into(), RelayWriteOutcome::Unavailable),
        ]);

        assert!(!outcome.threshold_met);
        assert_eq!(outcome.stored_acknowledgements, 1);
        assert_eq!(outcome.relays.len(), 2);
    }

    #[test]
    fn duplicate_write_acknowledgement_counts_as_stored() {
        let outcome = simulation().aggregate_write([
            ("a".into(), RelayWriteOutcome::Duplicate),
            ("b".into(), RelayWriteOutcome::Stored),
        ]);

        assert!(outcome.threshold_met);
        assert_eq!(outcome.stored_acknowledgements, 2);
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
    fn non_member_fetch_page_cannot_inject_entry_or_provenance() {
        let injected = entry(99);
        let replicated = entry(7);
        let pages = vec![
            PageObservation {
                relay: "mallory".into(),
                blocks: vec![Block::new_at(10, [0; 32], vec![injected.clone()], 600)],
            },
            PageObservation {
                relay: "a".into(),
                blocks: vec![Block::new_at(10, [0; 32], vec![replicated.clone()], 600)],
            },
            PageObservation {
                relay: "b".into(),
                blocks: vec![Block::new_at(10, [0; 32], vec![replicated.clone()], 600)],
            },
        ];

        let outcome = simulation().aggregate_fetch(pages);

        assert_eq!(outcome.entries, vec![replicated.clone()]);
        assert!(!outcome.sources.contains_key(&injected.id()));
        assert!(!outcome.unconfirmed_entries.contains(&injected));
        assert_eq!(outcome.rejected_relays, vec!["mallory"]);
    }

    #[test]
    fn single_member_entry_is_unconfirmed_not_replicated() {
        let lone = entry(4);
        let outcome = simulation().aggregate_fetch(vec![PageObservation {
            relay: "a".into(),
            blocks: vec![Block::new_at(10, [0; 32], vec![lone.clone()], 600)],
        }]);

        assert!(outcome.entries.is_empty());
        assert!(outcome.sources.is_empty());
        assert!(outcome.replicated.is_empty());
        assert_eq!(outcome.unconfirmed_entries, vec![lone]);
    }

    #[test]
    fn repeated_pages_from_one_member_do_not_inflate_replication_support() {
        let lone = entry(5);
        let block = Block::new_at(10, [0; 32], vec![lone.clone()], 600);
        let outcome = simulation().aggregate_fetch(vec![
            PageObservation {
                relay: "a".into(),
                blocks: vec![block.clone()],
            },
            PageObservation {
                relay: "a".into(),
                blocks: vec![block],
            },
        ]);

        assert!(outcome.entries.is_empty());
        assert_eq!(outcome.unconfirmed_entries, vec![lone]);
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
        assert_eq!(outcome.replicated.len(), 1);
        assert_eq!(outcome.replicated[0].supporters, vec!["a", "b", "c"]);
        assert!(outcome.unconfirmed_entries.is_empty());
        assert!(!outcome.leakage.global_observer_privacy_claimed);
        assert!(outcome.leakage.relays_observe_write);
        assert!(outcome.leakage.relays_observe_fetch);
    }

    #[test]
    fn valid_member_omitting_replicated_entry_is_reported() {
        let replicated = entry(6);
        let block = Block::new_at(10, [0; 32], vec![replicated.clone()], 600);
        let outcome = simulation().aggregate_fetch(vec![
            PageObservation {
                relay: "a".into(),
                blocks: vec![block.clone()],
            },
            PageObservation {
                relay: "b".into(),
                blocks: vec![block],
            },
            PageObservation {
                relay: "c".into(),
                blocks: Vec::new(),
            },
        ]);

        assert_eq!(outcome.entries, vec![replicated.clone()]);
        assert_eq!(
            outcome.omissions,
            vec![OmissionEvidence {
                entry_id: replicated.id(),
                relays: vec!["c".into()],
            }]
        );
    }

    #[test]
    fn rejected_or_unobserved_member_is_not_accused_of_omission() {
        let replicated = entry(11);
        let block = Block::new_at(10, [0; 32], vec![replicated.clone()], 600);
        let mut malformed = Block::new_at(10, [0; 32], Vec::new(), 600);
        malformed.header.n_messages = 1;
        let outcome = simulation().aggregate_fetch(vec![
            PageObservation {
                relay: "a".into(),
                blocks: vec![block.clone()],
            },
            PageObservation {
                relay: "b".into(),
                blocks: vec![block],
            },
            PageObservation {
                relay: "c".into(),
                blocks: vec![malformed],
            },
        ]);

        assert!(outcome.omissions.is_empty());
        assert_eq!(outcome.rejected_relays, vec!["c"]);
    }

    #[test]
    fn invalid_pow_page_is_isolated_without_losing_honest_entry() {
        let entry = entry(9);
        let honest_entry = LedgerEntry::mint(entry.label, entry.envelope.clone(), 12);
        let honest = Block::new_at(10, [0; 32], vec![honest_entry.clone()], 600);
        let mut invalid = entry.clone();
        while invalid.pow_valid(12) {
            invalid.nonce = invalid.nonce.wrapping_add(1);
        }
        let invalid_pow = Block::new_at(10, [0; 32], vec![invalid], 600);

        let outcome = simulation_with_pow(12).aggregate_fetch(vec![
            PageObservation {
                relay: "a".into(),
                blocks: vec![invalid_pow],
            },
            PageObservation {
                relay: "b".into(),
                blocks: vec![honest],
            },
        ]);

        assert_eq!(outcome.rejected_relays, vec!["a"]);
        assert!(outcome.entries.is_empty());
        assert_eq!(outcome.unconfirmed_entries, vec![honest_entry]);
    }

    #[test]
    fn same_member_conflicting_epoch_blocks_emit_evidence_and_no_support() {
        let first_entry = entry(12);
        let second_entry = entry(13);
        let first = Block::new_at(10, [0; 32], vec![first_entry.clone()], 600);
        let second = Block::new_at(10, [0; 32], vec![second_entry.clone()], 600);
        let outcome = simulation().aggregate_fetch(vec![
            PageObservation {
                relay: "a".into(),
                blocks: vec![first],
            },
            PageObservation {
                relay: "a".into(),
                blocks: vec![second],
            },
        ]);

        assert_eq!(outcome.equivocations.len(), 1);
        assert_eq!(outcome.equivocations[0].relay, "a");
        assert_eq!(outcome.equivocations[0].epoch, 10);
        assert!(outcome.entries.is_empty());
        assert!(outcome.sources.is_empty());
        let mut expected = vec![first_entry, second_entry];
        expected.sort_by_key(LedgerEntry::id);
        assert_eq!(outcome.unconfirmed_entries, expected);
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
        assert!(outcome.entries.is_empty());
        assert_eq!(outcome.unconfirmed_entries, vec![entry]);
    }
}
