use std::fmt;

use serde::{Deserialize, Serialize};

/// A 16-byte dead-drop label — the "slot address" for a per-epoch dead drop.
/// Derived from a shared secret via PRF; unlinkable across epochs and conversations.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Label(pub [u8; 16]);

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label({})", hex::encode(self.0))
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
