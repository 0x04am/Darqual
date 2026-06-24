//! darqual-storage — prefix-bucket sharding, erasure coding, DA sampling, shard repair.
//!
//! Stage 5 of the Darqual roadmap: beating the bandwidth wall while keeping
//! availability under churn.
#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod bucket;
pub mod da;
pub mod erasure;
pub mod repair;

pub use bucket::{bucket_of, partition};
pub use da::{commit, sample, ShardCommitment};
pub use erasure::{encode, reconstruct, Encoded, ErasureConfig};
pub use repair::repair;

use thiserror::Error;

/// Unified error type for the storage crate.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("not enough shards to reconstruct: need {need}, have {have}")]
    TooFewShards { need: usize, have: usize },

    #[error("reed-solomon error: {0}")]
    Rs(String),

    #[error("shard length mismatch")]
    ShardLengthMismatch,

    #[error("encoded metadata is inconsistent")]
    BadEncoded,
}

pub type Result<T> = std::result::Result<T, StorageError>;
