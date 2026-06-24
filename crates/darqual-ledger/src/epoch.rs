use std::time::{SystemTime, UNIX_EPOCH};

/// An epoch number — wall-clock time bucketed into fixed windows.
pub type Epoch = u64;

/// Duration of one epoch in seconds.
pub const EPOCH_SECONDS: u64 = 60;

/// Return the epoch number for a given unix timestamp.
pub fn epoch_at(unix_secs: u64) -> Epoch {
    unix_secs / EPOCH_SECONDS
}

/// Return the epoch number for the current time.
pub fn epoch_now() -> Epoch {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    epoch_at(secs)
}
