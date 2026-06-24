use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use data_encoding::BASE64;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::contact::ContactCard;
use crate::error::{Error, Result};
use crate::identity::Identity;

const VERSION: u8 = 0x01;
const KDF_CONTEXT: &str = "darqual lockbox v1 :: x25519-chacha20poly1305";
const BOX_PREFIX: &str = "dqbox1";

/// An encrypted anonymous lockbox. Sender identity is NOT included.
#[derive(Debug, Clone)]
pub struct Lockbox {
    /// The wire-format envelope string: "dqbox1" + BASE64(bytes)
    pub envelope: String,
}

impl Lockbox {
    /// Seal a message to a recipient's x25519 public key.
    pub fn seal(recipient_x_pub: &X25519PublicKey, msg: &[u8]) -> Result<Self> {
        // Ephemeral keypair
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_secret);

        // ECDH
        let shared = eph_secret.diffie_hellman(recipient_x_pub);

        // KDF
        let key_bytes = blake3::derive_key(KDF_CONTEXT, shared.as_bytes());
        let key = Key::from(key_bytes);

        // Random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt
        let cipher = ChaCha20Poly1305::new(&key);
        let ct = cipher
            .encrypt(&nonce, msg)
            .map_err(|_| Error::Encoding("encryption failed".to_string()))?;

        // Wire: [version 1][eph_pub 32][nonce 12][ciphertext]
        let mut wire = Vec::with_capacity(1 + 32 + 12 + ct.len());
        wire.push(VERSION);
        wire.extend_from_slice(eph_pub.as_bytes());
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ct);

        let envelope = format!("{}{}", BOX_PREFIX, BASE64.encode(&wire));
        Ok(Lockbox { envelope })
    }

    /// Convenience: seal to a ContactCard.
    pub fn seal_to_card(card: &ContactCard, msg: &[u8]) -> Result<Self> {
        let x_pub = X25519PublicKey::from(card.x_pub);
        Self::seal(&x_pub, msg)
    }

    /// Open a lockbox using the recipient's identity.
    /// Returns Err(Error::Decrypt) if wrong recipient or tampered.
    pub fn open(identity: &Identity, envelope: &str) -> Result<Vec<u8>> {
        let lower_prefix = envelope
            .get(..BOX_PREFIX.len())
            .ok_or_else(|| Error::InvalidLockbox("too short".to_string()))?;

        if lower_prefix != BOX_PREFIX {
            return Err(Error::InvalidLockbox(format!(
                "missing '{}' prefix",
                BOX_PREFIX
            )));
        }

        let b64_body = &envelope[BOX_PREFIX.len()..];
        let wire = BASE64
            .decode(b64_body.as_bytes())
            .map_err(|e| Error::InvalidLockbox(format!("base64: {}", e)))?;

        // Parse wire: [version 1][eph_pub 32][nonce 12][ct ...]
        if wire.len() < 1 + 32 + 12 + 1 {
            return Err(Error::InvalidLockbox("wire too short".to_string()));
        }

        let version = wire[0];
        if version != VERSION {
            return Err(Error::InvalidLockbox(format!(
                "unknown version: {}",
                version
            )));
        }

        let eph_pub_bytes: [u8; 32] = wire[1..33]
            .try_into()
            .map_err(|_| Error::InvalidLockbox("eph_pub slice".to_string()))?;
        let nonce_bytes: [u8; 12] = wire[33..45]
            .try_into()
            .map_err(|_| Error::InvalidLockbox("nonce slice".to_string()))?;
        let ct = &wire[45..];

        let eph_pub = X25519PublicKey::from(eph_pub_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // ECDH with recipient's static secret
        let shared = identity.x_secret.diffie_hellman(&eph_pub);

        // Same KDF
        let key_bytes = blake3::derive_key(KDF_CONTEXT, shared.as_bytes());
        let key = Key::from(key_bytes);

        let cipher = ChaCha20Poly1305::new(&key);
        let plaintext = cipher.decrypt(&nonce, ct).map_err(|_| Error::Decrypt)?;

        Ok(plaintext)
    }
}
