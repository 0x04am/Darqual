use std::fmt;

use x25519_dalek::PublicKey as X25519PublicKey;

use crate::contact::ContactCard;
use crate::error::Result;
use crate::identity::Identity;
use crate::label::Label;
use crate::lockbox::Lockbox;

/// Domain separator for dead-drop label derivation — keeps label PRF output
/// distinct from any key material derived elsewhere.
const LABEL_DOMAIN: &[u8] = b"darqual-deaddrop-v1";

/// A shared conversation context between two parties.
/// Holds the ECDH shared secret; never prints it.
pub struct Conversation {
    shared: [u8; 32],
}

impl fmt::Debug for Conversation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conversation")
            .field("shared", &"<redacted>")
            .finish()
    }
}

impl Conversation {
    /// Derive a conversation from a static-static X25519 ECDH.
    ///
    /// Symmetric: `Conversation::new(alice, bob_card)` and
    /// `Conversation::new(bob, alice_card)` yield the same shared secret.
    pub fn new(me: &Identity, them: &ContactCard) -> Self {
        let their_x_pub = X25519PublicKey::from(them.x_pub);
        let shared = me.x_secret.diffie_hellman(&their_x_pub);
        Conversation {
            shared: *shared.as_bytes(),
        }
    }

    /// Derive the dead-drop label for a given epoch.
    ///
    /// Uses `blake3::keyed_hash` with the shared secret as the key.
    /// The data is domain-prefixed to isolate this PRF from any key-derivation paths.
    pub fn label(&self, epoch: u64) -> Label {
        let mut data = Vec::with_capacity(LABEL_DOMAIN.len() + 8);
        data.extend_from_slice(LABEL_DOMAIN);
        data.extend_from_slice(&epoch.to_le_bytes());

        let hash = blake3::keyed_hash(&self.shared, &data);
        let bytes = hash.as_bytes();
        let mut label = [0u8; 16];
        label.copy_from_slice(&bytes[..16]);
        Label(label)
    }

    /// Seal a message to `them`, tagged with the dead-drop label for this epoch.
    ///
    /// Returns `(label, lockbox_envelope_bytes)`.
    /// Reuses `Lockbox::seal` — no new crypto invented here.
    pub fn seal(&self, them: &ContactCard, epoch: u64, msg: &[u8]) -> Result<(Label, Vec<u8>)> {
        let lbl = self.label(epoch);
        let their_x_pub = X25519PublicKey::from(them.x_pub);
        let lockbox = Lockbox::seal(&their_x_pub, msg)?;
        Ok((lbl, lockbox.envelope.into_bytes()))
    }
}
