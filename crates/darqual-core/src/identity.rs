use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::address::DarqualAddress;
use crate::contact::ContactCard;
use crate::error::{Error, Result};

/// Serialized form stored on disk.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    /// hex-encoded 32-byte seed for ed25519 SigningKey
    ed_seed: String,
    /// hex-encoded 32-byte seed for x25519 StaticSecret
    x_seed: String,
}

/// A Darqual identity: ed25519 signing key + x25519 static secret.
pub struct Identity {
    pub signing_key: SigningKey,
    pub x_secret: StaticSecret,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("address", &self.address().to_string())
            .finish()
    }
}

impl Identity {
    /// Generate a fresh identity with cryptographically secure randomness.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let x_secret = StaticSecret::random_from_rng(OsRng);
        Identity {
            signing_key,
            x_secret,
        }
    }

    /// Derive the Darqual address for this identity.
    pub fn address(&self) -> DarqualAddress {
        let ed_pub: [u8; 32] = self.signing_key.verifying_key().to_bytes();
        DarqualAddress::from_ed_pubkey(&ed_pub)
    }

    /// Build a shareable ContactCard for this identity.
    pub fn contact_card(&self) -> ContactCard {
        let ed_pub: [u8; 32] = self.signing_key.verifying_key().to_bytes();
        let x_pub: [u8; 32] = X25519PublicKey::from(&self.x_secret).to_bytes();
        ContactCard::new(self.address(), ed_pub, x_pub)
    }

    /// Save the identity to a TOML file. Creates parent dirs. Sets 0600 perms.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut ed_seed = self.signing_key.to_bytes();
        let mut x_seed = self.x_secret.to_bytes();

        let file = IdentityFile {
            ed_seed: hex::encode(ed_seed),
            x_seed: hex::encode(x_seed),
        };

        ed_seed.zeroize();
        x_seed.zeroize();

        let toml_str = toml::to_string(&file)?;
        fs::write(path, toml_str.as_bytes())?;

        // 0600 perms
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)?;

        Ok(())
    }

    /// Load an identity from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let file: IdentityFile = toml::from_str(&content)?;

        let mut ed_bytes = decode_hex_32(&file.ed_seed)?;
        let mut x_bytes = decode_hex_32(&file.x_seed)?;

        let signing_key = SigningKey::from_bytes(&ed_bytes);
        let x_secret = StaticSecret::from(x_bytes);

        ed_bytes.zeroize();
        x_bytes.zeroize();

        Ok(Identity {
            signing_key,
            x_secret,
        })
    }

    /// Sign `msg` with this identity's ed25519 signing key.
    /// The signature is deterministic (RFC 8032 — no randomness needed).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.signing_key.sign(msg);
        sig.to_bytes()
    }

    /// The ed25519 public key (verifying key) bytes for this identity.
    pub fn ed_pub(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Default identity path: ~/.darqual/identity.toml
    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not determine home directory",
            ))
        })?;
        Ok(home.join(".darqual").join("identity.toml"))
    }
}

fn decode_hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| Error::Encoding(format!("hex decode: {}", e)))?;
    bytes
        .try_into()
        .map_err(|_| Error::Key("expected 32-byte seed".to_string()))
}

/// Verify an ed25519 `sig` over `msg` using the raw 32-byte compressed public key.
/// Returns `false` on any error (bad key bytes, bad signature, or mismatch).
pub fn verify_ed(ed_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let vk = match VerifyingKey::from_bytes(ed_pub) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}
