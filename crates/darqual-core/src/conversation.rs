use std::fmt;

use x25519_dalek::PublicKey as X25519PublicKey;

use crate::contact::ContactCard;
use crate::error::Result;
use crate::identity::Identity;
use crate::keywheel::Keywheel;
use crate::label::Label;
use crate::lockbox::Lockbox;

/// Domain separator for dead-drop label derivation — keeps label PRF output
/// distinct from any key material derived elsewhere.
const LABEL_DOMAIN: &[u8] = b"darqual-deaddrop-v1";

/// SK = the symmetric static-static X25519 secret derived from a raw peer x25519
/// public key. MUST produce identical bytes to
/// `Conversation::new(me, peer_card).shared_secret()`. Used by the session layer
/// where the responder only knows the sender's raw `x_pub` (from the wire frame),
/// not a full `ContactCard`.
pub fn shared_secret_with(me: &Identity, peer_x_pub: &[u8; 32]) -> [u8; 32] {
    let their = X25519PublicKey::from(*peer_x_pub);
    *me.x_secret.diffie_hellman(&their).as_bytes()
}

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
        Conversation {
            shared: shared_secret_with(me, &them.x_pub),
        }
    }

    /// 32-byte symmetric shared secret from the static-static ECDH.
    /// Used as the Double Ratchet root-key seed (SK in Signal terms).
    pub fn shared_secret(&self) -> &[u8; 32] {
        &self.shared
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

    /// Build a forward-secret [`Keywheel`] seeded from this conversation's shared secret.
    ///
    /// Both parties independently calling `keywheel(same_start_epoch)` will produce
    /// identical label sequences — symmetric by ECDH symmetry.
    pub fn keywheel(&self, start_epoch: u64) -> Keywheel {
        Keywheel::from_seed(&self.shared, start_epoch)
    }
}
