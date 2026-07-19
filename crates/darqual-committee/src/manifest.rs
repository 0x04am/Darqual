use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MANIFEST_VERSION: u8 = 1;

/// One independently operated Tier-1 relay endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEndpoint {
    pub name: String,
    pub onion: String,
    pub port: u16,
}

/// Static authenticated-out-of-band relay set used by the Tier-1.5 client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeManifest {
    pub version: u8,
    pub write_threshold: usize,
    pub members: Vec<RelayEndpoint>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("unsupported committee manifest version {0}")]
    UnsupportedVersion(u8),
    #[error("committee must contain at least one relay")]
    Empty,
    #[error("write threshold must be between 1 and committee size")]
    InvalidThreshold,
    #[error("relay name cannot be empty")]
    EmptyName,
    #[error("relay endpoint cannot be empty")]
    EmptyEndpoint,
    #[error("relay port cannot be zero")]
    ZeroPort,
    #[error("duplicate relay name: {0}")]
    DuplicateName(String),
    #[error("duplicate relay endpoint: {0}")]
    DuplicateEndpoint(String),
}

impl CommitteeManifest {
    pub fn new(write_threshold: usize, members: Vec<RelayEndpoint>) -> Result<Self, ManifestError> {
        let mut manifest = Self {
            version: MANIFEST_VERSION,
            write_threshold,
            members,
        };
        manifest.validate_and_normalize()?;
        Ok(manifest)
    }

    /// Validate the manifest and sort members into deterministic endpoint order.
    pub fn validate_and_normalize(&mut self) -> Result<(), ManifestError> {
        if self.version != MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion(self.version));
        }
        if self.members.is_empty() {
            return Err(ManifestError::Empty);
        }
        if !(1..=self.members.len()).contains(&self.write_threshold) {
            return Err(ManifestError::InvalidThreshold);
        }

        let mut names = HashSet::with_capacity(self.members.len());
        let mut endpoints = HashSet::with_capacity(self.members.len());
        for member in &self.members {
            if member.name.trim().is_empty() {
                return Err(ManifestError::EmptyName);
            }
            if member.onion.trim().is_empty() {
                return Err(ManifestError::EmptyEndpoint);
            }
            if member.port == 0 {
                return Err(ManifestError::ZeroPort);
            }
            if !names.insert(member.name.clone()) {
                return Err(ManifestError::DuplicateName(member.name.clone()));
            }
            let endpoint = format!("{}:{}", member.onion, member.port);
            if !endpoints.insert(endpoint.clone()) {
                return Err(ManifestError::DuplicateEndpoint(endpoint));
            }
        }
        self.members
            .sort_by(|a, b| (&a.onion, a.port, &a.name).cmp(&(&b.onion, b.port, &b.name)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(name: &str, onion: &str, port: u16) -> RelayEndpoint {
        RelayEndpoint {
            name: name.into(),
            onion: onion.into(),
            port,
        }
    }

    #[test]
    fn valid_manifest_is_sorted_deterministically() {
        let manifest = CommitteeManifest::new(
            2,
            vec![
                endpoint("z", "z.onion", 9999),
                endpoint("a", "a.onion", 9999),
                endpoint("m", "m.onion", 9999),
            ],
        )
        .expect("valid");
        let order: Vec<&str> = manifest.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(order, vec!["a", "m", "z"]);
    }

    #[test]
    fn invalid_thresholds_fail_closed() {
        assert_eq!(
            CommitteeManifest::new(0, vec![endpoint("a", "a.onion", 1)]),
            Err(ManifestError::InvalidThreshold)
        );
        assert_eq!(
            CommitteeManifest::new(2, vec![endpoint("a", "a.onion", 1)]),
            Err(ManifestError::InvalidThreshold)
        );
    }

    #[test]
    fn duplicate_names_and_endpoints_are_rejected() {
        assert_eq!(
            CommitteeManifest::new(
                1,
                vec![
                    endpoint("same", "a.onion", 1),
                    endpoint("same", "b.onion", 1),
                ],
            ),
            Err(ManifestError::DuplicateName("same".into()))
        );
        assert_eq!(
            CommitteeManifest::new(
                1,
                vec![
                    endpoint("a", "same.onion", 1),
                    endpoint("b", "same.onion", 1),
                ],
            ),
            Err(ManifestError::DuplicateEndpoint("same.onion:1".into()))
        );
    }

    #[test]
    fn empty_or_malformed_member_fields_are_rejected() {
        assert_eq!(
            CommitteeManifest::new(1, Vec::new()),
            Err(ManifestError::Empty)
        );
        assert_eq!(
            CommitteeManifest::new(1, vec![endpoint("", "a.onion", 1)]),
            Err(ManifestError::EmptyName)
        );
        assert_eq!(
            CommitteeManifest::new(1, vec![endpoint("a", "", 1)]),
            Err(ManifestError::EmptyEndpoint)
        );
        assert_eq!(
            CommitteeManifest::new(1, vec![endpoint("a", "a.onion", 0)]),
            Err(ManifestError::ZeroPort)
        );
    }
}
