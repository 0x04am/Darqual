use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommitteeError {
    #[error("committee_size ({requested}) exceeds valid candidate count ({available})")]
    NotEnoughCandidates { requested: usize, available: usize },
}
