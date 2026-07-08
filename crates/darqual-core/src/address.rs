use std::fmt;
use std::str::FromStr;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const PREFIX: &str = "dq1";

/// A self-authenticating Darqual address.
/// Format: "dq1" + base32_nopad_lowercase(blake3(ed_pub || x_pub)[..20]).
/// The address commits to BOTH the ed25519 signing key AND the x25519 encryption
/// key, so a ContactCard cannot substitute the encryption key without changing the
/// address — this prevents identity-substitution / MITM on the encryption key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DarqualAddress(String);

impl DarqualAddress {
    /// Derive an address from the identity's ed25519 + x25519 public keys (32 bytes each).
    pub fn from_keys(ed_pub: &[u8; 32], x_pub: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ed_pub);
        hasher.update(x_pub);
        let hash = hasher.finalize();
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
        // validate: must be valid base32 decoding to exactly 20 bytes
        let decoded = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|e| Error::InvalidAddress(format!("invalid base32: {}", e)))?;
        if decoded.len() != 20 {
            return Err(Error::InvalidAddress(format!(
                "decoded address must be 20 bytes, got {}",
                decoded.len()
            )));
        }
        Ok(DarqualAddress(lower))
    }
}
