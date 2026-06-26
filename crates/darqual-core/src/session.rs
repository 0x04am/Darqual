//! File-backed Double-Ratchet session persistence.
//!
//! Spec: `notes/projects/anon-messenger-research/17-session-wiring.md` §4.
//!
//! `SessionStore` maps a peer's 32-byte x25519 public key to a serialized
//! [`RatchetSession`] on disk (one file per peer: `<dir>/<hex(peer_x_pub)>.bin`,
//! bincode-encoded). Sessions advance state on every message, so callers MUST
//! [`SessionStore::save`] immediately after every successful encrypt/decrypt.
//!
//! ## At-rest security (caller responsibility)
//!
//! The persisted state holds long-lived ratchet secrets (root key, chain keys,
//! current DH secret, skipped message keys). **No file-level encryption is
//! applied.** Treat `~/.darqual/sessions/` as sensitive — same threat model as
//! `~/.darqual/identity.toml`. A future phase will encrypt these under a key
//! derived from the identity; not built now.

use std::fs;
use std::path::{Path, PathBuf};

use crate::contact::ContactCard;
use crate::conversation::shared_secret_with;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::ratchet::RatchetSession;

/// File-backed store of per-peer [`RatchetSession`] state.
pub struct SessionStore {
    dir: PathBuf,
}

impl SessionStore {
    /// Default store at `~/.darqual/sessions/`. Creates the directory if missing.
    pub fn open_default() -> Result<Self> {
        let home = dirs::home_dir().ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not determine home directory",
            ))
        })?;
        let dir = home.join(".darqual").join("sessions");
        fs::create_dir_all(&dir)?;
        Ok(SessionStore { dir })
    }

    /// Construct a store rooted at `dir` (for tests / custom layouts).
    pub fn with_dir(dir: PathBuf) -> Self {
        SessionStore { dir }
    }

    fn path_for(&self, peer_x_pub: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.bin", hex::encode(peer_x_pub)))
    }

    /// Load a session for `peer_x_pub`, if one is persisted.
    pub fn load(&self, peer_x_pub: &[u8; 32]) -> Result<Option<RatchetSession>> {
        let p = self.path_for(peer_x_pub);
        if !p.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&p)?;
        let sess: RatchetSession = bincode::deserialize(&bytes)
            .map_err(|e| Error::Ratchet(format!("session deserialize: {e}")))?;
        Ok(Some(sess))
    }

    /// Persist `sess` for `peer_x_pub`. Atomic via tmp+rename. 0600 perms.
    pub fn save(&self, peer_x_pub: &[u8; 32], sess: &RatchetSession) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        let final_path = self.path_for(peer_x_pub);
        let tmp_path = final_path.with_extension("bin.tmp");
        let bytes = bincode::serialize(sess)
            .map_err(|e| Error::Ratchet(format!("session serialize: {e}")))?;
        fs::write(&tmp_path, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    /// Outbound: return the existing session for `peer`, else create an
    /// initiator session (sender-with-no-session ⇒ initiator, per spec §1).
    pub fn load_or_init_initiator(
        &self,
        me: &Identity,
        peer: &ContactCard,
    ) -> Result<RatchetSession> {
        if let Some(s) = self.load(&peer.x_pub)? {
            return Ok(s);
        }
        let sk = shared_secret_with(me, &peer.x_pub);
        Ok(RatchetSession::init_initiator(&sk, peer))
    }

    /// Inbound: return the existing session keyed by `sender_x_pub`, else
    /// create a responder session (receiver-with-no-session ⇒ responder).
    pub fn load_or_init_responder(
        &self,
        me: &Identity,
        sender_x_pub: &[u8; 32],
    ) -> Result<RatchetSession> {
        if let Some(s) = self.load(sender_x_pub)? {
            return Ok(s);
        }
        let sk = shared_secret_with(me, sender_x_pub);
        Ok(RatchetSession::init_responder(&sk, me))
    }

    /// Directory backing this store (mostly for diagnostics / tests).
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::Conversation;
    use crate::ratchet::RatchetMessage;
    use tempfile::TempDir;

    fn store(dir: &TempDir) -> SessionStore {
        SessionStore::with_dir(dir.path().to_path_buf())
    }

    /// Encode the node wire frame for a given sender x_pub + ratchet message.
    /// Mirrors `crates/darqual-tor/src/main.rs` to keep the round-trip honest.
    fn frame(sender_x_pub: &[u8; 32], rm: &RatchetMessage) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 256);
        out.extend_from_slice(sender_x_pub);
        out.extend_from_slice(&bincode::serialize(rm).unwrap());
        out
    }

    fn parse_frame(frame: &[u8]) -> ([u8; 32], RatchetMessage) {
        let mut sx = [0u8; 32];
        sx.copy_from_slice(&frame[..32]);
        let rm: RatchetMessage = bincode::deserialize(&frame[32..]).unwrap();
        (sx, rm)
    }

    // (1) Full session exchange via the store — initiator/responder bootstrap,
    //     multi-round back-and-forth, all plaintexts correct.
    #[test]
    fn store_full_session_exchange() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let sa = store(&dir_a);
        let sb = store(&dir_b);

        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card = bob.contact_card();
        let alice_card = alice.contact_card();

        // A → B  (first contact, A initiates)
        let mut a = sa.load_or_init_initiator(&alice, &bob_card).unwrap();
        let rm = a.encrypt(b"hello bob").unwrap();
        sa.save(&bob_card.x_pub, &a).unwrap();
        let f = frame(&alice.x_pub(), &rm);

        let (sx, rm) = parse_frame(&f);
        let mut b = sb.load_or_init_responder(&bob, &sx).unwrap();
        let pt = b.decrypt(&rm).unwrap();
        sb.save(&sx, &b).unwrap();
        assert_eq!(pt, b"hello bob");

        // B → A (reply on established session)
        let mut b = sb.load_or_init_initiator(&bob, &alice_card).unwrap();
        let rm = b.encrypt(b"hi alice").unwrap();
        sb.save(&alice_card.x_pub, &b).unwrap();
        let f = frame(&bob.x_pub(), &rm);
        let (sx, rm) = parse_frame(&f);
        let mut a = sa.load_or_init_responder(&alice, &sx).unwrap();
        let pt = a.decrypt(&rm).unwrap();
        sa.save(&sx, &a).unwrap();
        assert_eq!(pt, b"hi alice");

        // Multi-round
        for i in 0..5u32 {
            let mut a = sa.load_or_init_initiator(&alice, &bob_card).unwrap();
            let m = format!("a→b #{i}");
            let rm = a.encrypt(m.as_bytes()).unwrap();
            sa.save(&bob_card.x_pub, &a).unwrap();
            let (sx, rm) = parse_frame(&frame(&alice.x_pub(), &rm));
            let mut b = sb.load_or_init_responder(&bob, &sx).unwrap();
            let pt = b.decrypt(&rm).unwrap();
            sb.save(&sx, &b).unwrap();
            assert_eq!(pt, m.as_bytes());

            let mut b = sb.load_or_init_initiator(&bob, &alice_card).unwrap();
            let m = format!("b→a #{i}");
            let rm = b.encrypt(m.as_bytes()).unwrap();
            sb.save(&alice_card.x_pub, &b).unwrap();
            let (sx, rm) = parse_frame(&frame(&bob.x_pub(), &rm));
            let mut a = sa.load_or_init_responder(&alice, &sx).unwrap();
            let pt = a.decrypt(&rm).unwrap();
            sa.save(&sx, &a).unwrap();
            assert_eq!(pt, m.as_bytes());
        }
    }

    // (2) Persistence across reload: drop in-memory session, reload from disk,
    //     resume mid-conversation.
    #[test]
    fn persistence_across_reload() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let sa = store(&dir_a);
        let sb = store(&dir_b);
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card = bob.contact_card();

        // Round 1: A → B
        let mut a = sa.load_or_init_initiator(&alice, &bob_card).unwrap();
        let rm = a.encrypt(b"m1").unwrap();
        sa.save(&bob_card.x_pub, &a).unwrap();
        let mut b = sb
            .load_or_init_responder(&bob, &alice.x_pub())
            .unwrap();
        assert_eq!(b.decrypt(&rm).unwrap(), b"m1");
        sb.save(&alice.x_pub(), &b).unwrap();

        // Drop in-memory; reload from disk.
        drop(a);
        drop(b);

        // Round 2: A → B (state must come from disk)
        let mut a = sa.load(&bob_card.x_pub).unwrap().expect("alice session");
        let rm = a.encrypt(b"m2").unwrap();
        sa.save(&bob_card.x_pub, &a).unwrap();
        let mut b = sb.load(&alice.x_pub()).unwrap().expect("bob session");
        assert_eq!(b.decrypt(&rm).unwrap(), b"m2");
        sb.save(&alice.x_pub(), &b).unwrap();
    }

    // (3) First-contact bootstrap both directions (independent fresh stores).
    #[test]
    fn first_contact_both_directions() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        // A → B
        {
            let dir_a = TempDir::new().unwrap();
            let dir_b = TempDir::new().unwrap();
            let sa = store(&dir_a);
            let sb = store(&dir_b);
            let mut a = sa.load_or_init_initiator(&alice, &bob.contact_card()).unwrap();
            let rm = a.encrypt(b"a-first").unwrap();
            let mut b = sb.load_or_init_responder(&bob, &alice.x_pub()).unwrap();
            assert_eq!(b.decrypt(&rm).unwrap(), b"a-first");
        }
        // B → A (fresh stores; no prior state)
        {
            let dir_a = TempDir::new().unwrap();
            let dir_b = TempDir::new().unwrap();
            let sa = store(&dir_a);
            let sb = store(&dir_b);
            let mut b = sb.load_or_init_initiator(&bob, &alice.contact_card()).unwrap();
            let rm = b.encrypt(b"b-first").unwrap();
            let mut a = sa.load_or_init_responder(&alice, &bob.x_pub()).unwrap();
            assert_eq!(a.decrypt(&rm).unwrap(), b"b-first");
        }
    }

    // (4) Decrypt-failure does not corrupt state: tampered frame ⇒ Err ⇒ do NOT
    //     save ⇒ next valid message still decrypts.
    #[test]
    fn tamper_does_not_corrupt_state() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let sa = store(&dir_a);
        let sb = store(&dir_b);
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card = bob.contact_card();

        // Good message #1 — establish + persist Bob's responder side.
        let mut a = sa.load_or_init_initiator(&alice, &bob_card).unwrap();
        let rm1 = a.encrypt(b"good-1").unwrap();
        sa.save(&bob_card.x_pub, &a).unwrap();
        let mut b = sb.load_or_init_responder(&bob, &alice.x_pub()).unwrap();
        assert_eq!(b.decrypt(&rm1).unwrap(), b"good-1");
        sb.save(&alice.x_pub(), &b).unwrap();

        // Good message #2 produced by Alice; we will tamper a COPY of it,
        // attempt decrypt, see Err, and NOT save Bob's session.
        let mut a = sa.load(&bob_card.x_pub).unwrap().unwrap();
        let rm2 = a.encrypt(b"good-2").unwrap();
        sa.save(&bob_card.x_pub, &a).unwrap();

        let mut tampered = rm2.clone();
        if let Some(b0) = tampered.ciphertext.first_mut() {
            *b0 ^= 0xFF;
        }

        // Try-decrypt tampered against a freshly loaded Bob session — must Err.
        let mut b_try = sb.load(&alice.x_pub()).unwrap().unwrap();
        assert!(b_try.decrypt(&tampered).is_err());
        // CRITICAL: do NOT save b_try.

        // Real rm2 must still decrypt cleanly against the on-disk state.
        let mut b = sb.load(&alice.x_pub()).unwrap().unwrap();
        assert_eq!(b.decrypt(&rm2).unwrap(), b"good-2");
        sb.save(&alice.x_pub(), &b).unwrap();
    }

    // (5) Parity: shared_secret_with(me, peer.x_pub) == Conversation::new(...).shared_secret()
    #[test]
    fn shared_secret_with_matches_conversation_new() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_card = bob.contact_card();

        let via_helper = shared_secret_with(&alice, &bob_card.x_pub);
        let via_conv = *Conversation::new(&alice, &bob_card).shared_secret();
        assert_eq!(via_helper, via_conv);

        // Symmetric the other way too.
        let via_helper_b = shared_secret_with(&bob, &alice.contact_card().x_pub);
        assert_eq!(via_helper_b, via_conv);
    }
}
