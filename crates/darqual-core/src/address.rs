use std::fmt;
use std::str::FromStr;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const PREFIX: &str = "dq1";

/// A self-authenticating Darqual address.
/// Format: "dq1" + base32_nopad_lowercase(blake3(ed_verifying_key)[..20])
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DarqualAddress(String);

impl DarqualAddress {
    /// Derive an address from a raw ed25519 verifying key (32 bytes).
    pub fn from_ed_pubkey(ed_pub: &[u8; 32]) -> Self {
        let hash = blake3::hash(ed_pub);
        let truncated = &hash.as_bytes()[..20];
        let encoded = BASE32_NOPAD.encode(truncated).to_lowercase();
        DarqualAddress(format!("{}{}", PREFIX, encoded))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DarqualAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for DarqualAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let lower = s.to_lowercase();
        if !lower.starts_with(PREFIX) {
            return Err(Error::InvalidAddress(format!(
                "missing '{}' prefix",
                PREFIX
            )));
        }
        let body = &lower[PREFIX.len()..];
        // validate: must be valid base32
        BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|e| Error::InvalidAddress(format!("invalid base32: {}", e)))?;
        Ok(DarqualAddress(lower))
    }
}
