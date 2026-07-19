#![forbid(unsafe_code)]

mod committee;

pub use committee::{
    CommitteeSimulation, EquivocationEvidence, FetchOutcome, LeakageFacts, PageObservation,
    RelayWriteOutcome, WriteOutcome,
};

use std::collections::{BTreeMap, BTreeSet};

pub type Epoch = u64;
pub type NodeId = u16;
pub type ClientId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimConfig {
    pub committee_size: usize,
    pub max_byzantine: usize,
    pub finalization_quorum: usize,
    pub epoch_count: Epoch,
}

impl SimConfig {
    pub const fn research_default() -> Self {
        Self {
            committee_size: 4,
            max_byzantine: 1,
            finalization_quorum: 3,
            epoch_count: 32,
        }
    }

    pub fn validate(self) -> Result<Self, ConfigError> {
        if self.committee_size == 0 {
            return Err(ConfigError::EmptyCommittee);
        }
        if self.finalization_quorum == 0 || self.finalization_quorum > self.committee_size {
            return Err(ConfigError::InvalidQuorum);
        }
        if self.max_byzantine >= self.finalization_quorum {
            return Err(ConfigError::UnsafeThreshold);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    EmptyCommittee,
    InvalidQuorum,
    UnsafeThreshold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    EpochStart,
    ClientSubmit { client: ClientId },
    Corrupt { node: NodeId },
    Exclude { client: ClientId },
    DropSubmission { client: ClientId },
    Finalize,
    Handoff,
    EraseOldShares,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub epoch: Epoch,
    pub sequence: u64,
    pub kind: EventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochOutcome {
    pub epoch: Epoch,
    pub finalized: bool,
    pub privacy_safe: bool,
    pub included_clients: BTreeSet<ClientId>,
    pub excluded_clients: BTreeSet<ClientId>,
    pub corrupt_members: BTreeSet<NodeId>,
}

#[derive(Debug, Clone)]
pub struct Simulator {
    config: SimConfig,
    events: Vec<Event>,
}

impl Simulator {
    pub fn new(config: SimConfig) -> Result<Self, ConfigError> {
        Ok(Self {
            config: config.validate()?,
            events: Vec::new(),
        })
    }

    pub fn schedule(&mut self, event: Event) {
        self.events.push(event);
    }

    pub fn run(mut self) -> Vec<EpochOutcome> {
        self.events
            .sort_by_key(|event| (event.epoch, event.sequence));
        let mut states: BTreeMap<Epoch, EpochOutcome> = BTreeMap::new();

        for event in self.events {
            let state = states.entry(event.epoch).or_insert_with(|| EpochOutcome {
                epoch: event.epoch,
                finalized: false,
                privacy_safe: true,
                included_clients: BTreeSet::new(),
                excluded_clients: BTreeSet::new(),
                corrupt_members: BTreeSet::new(),
            });

            match event.kind {
                EventKind::EpochStart | EventKind::Handoff | EventKind::EraseOldShares => {}
                EventKind::ClientSubmit { client } => {
                    if !state.excluded_clients.contains(&client) {
                        state.included_clients.insert(client);
                    }
                }
                EventKind::Corrupt { node } => {
                    state.corrupt_members.insert(node);
                    if state.corrupt_members.len() > self.config.max_byzantine {
                        state.privacy_safe = false;
                    }
                }
                EventKind::Exclude { client } | EventKind::DropSubmission { client } => {
                    state.included_clients.remove(&client);
                    state.excluded_clients.insert(client);
                }
                EventKind::Finalize => {
                    let responsive = self
                        .config
                        .committee_size
                        .saturating_sub(state.corrupt_members.len());
                    state.finalized = state.privacy_safe
                        && responsive >= self.config.finalization_quorum
                        && state.excluded_clients.is_empty();
                }
            }
        }

        states.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn research_defaults_are_four_member_f_one() {
        let config = SimConfig::research_default();
        assert_eq!(config.committee_size, 4);
        assert_eq!(config.max_byzantine, 1);
        assert_eq!(config.finalization_quorum, 3);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn deterministic_event_order_produces_same_outcome() {
        let config = SimConfig::research_default();
        let events = [
            Event {
                epoch: 1,
                sequence: 3,
                kind: EventKind::Finalize,
            },
            Event {
                epoch: 1,
                sequence: 1,
                kind: EventKind::ClientSubmit { client: 7 },
            },
            Event {
                epoch: 1,
                sequence: 2,
                kind: EventKind::Corrupt { node: 2 },
            },
        ];

        let mut first = Simulator::new(config).unwrap();
        let mut second = Simulator::new(config).unwrap();
        for event in events {
            first.schedule(event);
        }
        for event in events.into_iter().rev() {
            second.schedule(event);
        }

        assert_eq!(first.run(), second.run());
    }

    #[test]
    fn one_byzantine_member_still_allows_finalization() {
        let mut sim = Simulator::new(SimConfig::research_default()).unwrap();
        sim.schedule(Event {
            epoch: 1,
            sequence: 1,
            kind: EventKind::ClientSubmit { client: 7 },
        });
        sim.schedule(Event {
            epoch: 1,
            sequence: 2,
            kind: EventKind::Corrupt { node: 2 },
        });
        sim.schedule(Event {
            epoch: 1,
            sequence: 3,
            kind: EventKind::Finalize,
        });

        let outcome = sim.run().pop().unwrap();
        assert!(outcome.privacy_safe);
        assert!(outcome.finalized);
    }

    #[test]
    fn second_byzantine_member_forces_privacy_safe_abort() {
        let mut sim = Simulator::new(SimConfig::research_default()).unwrap();
        sim.schedule(Event {
            epoch: 1,
            sequence: 1,
            kind: EventKind::Corrupt { node: 1 },
        });
        sim.schedule(Event {
            epoch: 1,
            sequence: 2,
            kind: EventKind::Corrupt { node: 2 },
        });
        sim.schedule(Event {
            epoch: 1,
            sequence: 3,
            kind: EventKind::Finalize,
        });

        let outcome = sim.run().pop().unwrap();
        assert!(!outcome.privacy_safe);
        assert!(!outcome.finalized);
    }

    #[test]
    fn excluded_client_prevents_finalization() {
        let mut sim = Simulator::new(SimConfig::research_default()).unwrap();
        sim.schedule(Event {
            epoch: 1,
            sequence: 1,
            kind: EventKind::ClientSubmit { client: 7 },
        });
        sim.schedule(Event {
            epoch: 1,
            sequence: 2,
            kind: EventKind::Exclude { client: 7 },
        });
        sim.schedule(Event {
            epoch: 1,
            sequence: 3,
            kind: EventKind::Finalize,
        });

        let outcome = sim.run().pop().unwrap();
        assert!(outcome.privacy_safe);
        assert!(!outcome.finalized);
        assert!(outcome.excluded_clients.contains(&7));
    }
}
