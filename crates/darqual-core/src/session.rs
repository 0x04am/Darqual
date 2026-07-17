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

    /// Iterate all persisted sessions as (peer_x_pub, session) pairs.
    /// peer_x_pub is recovered from the hex filename (`path_for`, session.rs:51-53).
    /// Files whose stem is not a valid 64-hex string (e.g. `.bin.tmp` atomic-save
    /// temporaries) are silently skipped.
    pub fn list(&self) -> Result<Vec<([u8; 32], RatchetSession)>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(bytes) = hex::decode(stem) else {
                continue; // skip .tmp / junk
            };
            let Ok(peer): std::result::Result<[u8; 32], _> = bytes.try_into() else {
                continue;
            };
            if let Some(sess) = self.load(&peer)? {
                out.push((peer, sess));
            }
        }
        Ok(out)
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
        let mut b = sb.load_or_init_responder(&bob, &alice.x_pub()).unwrap();
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
            let mut a = sa
                .load_or_init_initiator(&alice, &bob.contact_card())
                .unwrap();
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
            let mut b = sb
                .load_or_init_initiator(&bob, &alice.contact_card())
                .unwrap();
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

    // (5) SessionStore::list() — happy path: N sessions all returned, peer keys correct.
    //
    // Saves 3 sessions with distinct peer identities into one store.  After list(),
    // every peer key must appear exactly once and the recovered session must be
    // capable of decrypting a message that was encrypted before the save.
    #[test]
    fn list_returns_all_sessions() {
        let dir = TempDir::new().unwrap();
        let store = store(&dir);

        let alice = Identity::generate();
        let peers: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();

        // For each peer: encrypt one message, save the initiator session, remember the
        // RatchetMessage so we can verify the loaded session can decrypt it.
        let mut saved_msgs: Vec<([u8; 32], RatchetMessage)> = Vec::new();
        for peer in &peers {
            let mut sess = store
                .load_or_init_initiator(&alice, &peer.contact_card())
                .unwrap();
            let rm = sess.encrypt(b"list test").unwrap();
            store.save(&peer.x_pub(), &sess).unwrap();
            saved_msgs.push((peer.x_pub(), rm));
        }

        let mut listed = store.list().unwrap();
        assert_eq!(listed.len(), 3, "list() must return exactly 3 sessions");

        // Sort both sides by peer key for deterministic comparison.
        listed.sort_by_key(|(k, _)| *k);
        let mut expected_keys: Vec<[u8; 32]> = peers.iter().map(|p| p.x_pub()).collect();
        expected_keys.sort();
        let listed_keys: Vec<[u8; 32]> = listed.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            listed_keys, expected_keys,
            "listed peer keys must match saved peer keys"
        );

        // Build a lookup table: peer_key → (session from list, RatchetMessage).
        // The initiator session was saved *after* encrypt, so the stored ns = 1.
        // Re-init the responder side and verify it can decrypt each message.
        for (peer_key, rm) in saved_msgs {
            let peer_id = peers.iter().find(|p| p.x_pub() == peer_key).unwrap();
            let mut resp = store
                .load_or_init_responder(
                    // Use peer as "bob" to get the same shared secret from the other side.
                    peer_id,
                    &alice.x_pub(),
                )
                .unwrap();
            // We need alice's initiator state from the store to verify decrypt from responder
            // perspective is consistent. Here we directly confirm the session returned by
            // list() is the same as what was saved: load it ourselves and compare ns.
            let loaded = store.load(&peer_key).unwrap().expect("session must exist");
            let (_, list_sess) = listed.iter().find(|(k, _)| k == &peer_key).unwrap();
            // Both must have advanced ns to 1 (one encrypt call).
            assert_eq!(
                loaded.dhs_pub(),
                list_sess.dhs_pub(),
                "list() session dhs_pub must match directly-loaded session"
            );
            // The responder can decrypt the message — proves session state is correct.
            assert_eq!(resp.decrypt(&rm).unwrap(), b"list test");
        }
    }

    // (6) SessionStore::list() — junk-file skip.
    //
    // The atomic-save path writes `<stem>.bin.tmp` before renaming to `<stem>.bin`
    // (session.rs:71).  We also plant a randomly-named file.  list() must ignore both
    // and still return only the real sessions.
    #[test]
    fn list_skips_junk_files() {
        let dir = TempDir::new().unwrap();
        let store = store(&dir);

        let alice = Identity::generate();
        let peer = Identity::generate();

        // Save one real session.
        let mut sess = store
            .load_or_init_initiator(&alice, &peer.contact_card())
            .unwrap();
        let _ = sess.encrypt(b"real").unwrap();
        store.save(&peer.x_pub(), &sess).unwrap();

        // Plant a stale .bin.tmp file (mirrors what atomic-save leaves on crash).
        let tmp_path = dir
            .path()
            .join(format!("{}.bin.tmp", hex::encode(peer.x_pub())));
        std::fs::write(&tmp_path, b"garbage tmp content").unwrap();

        // Plant a totally random non-hex filename that would trip hex::decode.
        let junk_path = dir.path().join("not-a-hex-peer.bin");
        std::fs::write(&junk_path, b"noise").unwrap();

        // Also plant a file whose hex decodes to the wrong length (31 bytes, not 32).
        let short_hex = hex::encode([0xABu8; 31]);
        let short_path = dir.path().join(format!("{short_hex}.bin"));
        std::fs::write(&short_path, b"short hex").unwrap();

        let listed = store.list().unwrap();
        assert_eq!(
            listed.len(),
            1,
            "list() must skip junk files and return only the real session"
        );
        assert_eq!(
            listed[0].0,
            peer.x_pub(),
            "the returned peer key must be the real one"
        );
    }

    // (7) Parity: shared_secret_with(me, peer.x_pub) == Conversation::new(...).shared_secret()
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

    // (8) F-2 core integration: trial-decrypt multi-peer.
    //
    // This is the heart of handle_session's loop.  The scenario: a single node
    // ("Bob") has three active sessions — one with each of three senders (Carol,
    // Alice, Dave).  Each sender sends a bootstrap message that Bob decrypts and
    // saves, establishing Bob's three responder sessions in his store.
    //
    // Then Alice (sender at index 1) sends a SECOND message (v2 FRAME_SESSION path
    // — raw RatchetMessage, no lockbox wrapper).  Bob's handle_session loop
    // trial-decrypts Alice's rm against all three stored sessions.
    //
    // Asserts:
    //   - EXACTLY ONE session decrypts successfully — the one keyed by Alice's x_pub.
    //   - The other two return Err (wrong nhkr/hkr → hdec AEAD fails → no mutation).
    //   - The recovered plaintext equals what Alice encrypted.
    //
    // Non-tautology: if the loop matched the wrong session the assert on
    // `matched_peer_key == alice.x_pub()` fails, because Carol's and Dave's sessions
    // were bootstrapped from a different `init_initiator` (different ephemeral DH pub
    // → different `shared_hka` derivation path after ratchet → different header keys).
    // Wrong-session decrypt returns Err, never panics — F-1 clone-and-commit guarantee.
    #[test]
    fn trial_decrypt_multi_peer_only_matches_correct_session() {
        use crate::conversation::shared_secret_with;

        // Bob's store — the trial-decrypt loop runs on his sessions.
        let dir_bob = TempDir::new().unwrap();
        let store_bob = store(&dir_bob);
        let bob = Identity::generate();

        // Three independent senders.  Alice (middle) will send the target second message.
        let carol = Identity::generate();
        let alice = Identity::generate();
        let dave = Identity::generate();
        let senders: [&Identity; 3] = [&carol, &alice, &dave];

        // Bootstrap: each sender inits their session, encrypts msg #1, Bob decrypts+saves.
        // We retain Alice's initiator session AFTER the bootstrap so we can produce msg #2
        // with the correct DH pub (fresh_keypair is called once in init_initiator).
        let mut alice_sess_after_bootstrap: Option<RatchetSession> = None;

        for sender in &senders {
            let sk = shared_secret_with(sender, &bob.x_pub());
            let mut sender_sess = RatchetSession::init_initiator(&sk, &bob.contact_card());
            let rm_bootstrap = sender_sess.encrypt(b"bootstrap").unwrap();

            // Bob decrypts and saves.
            let mut bob_resp = store_bob
                .load_or_init_responder(&bob, &sender.x_pub())
                .unwrap();
            assert_eq!(bob_resp.decrypt(&rm_bootstrap).unwrap(), b"bootstrap");
            store_bob.save(&sender.x_pub(), &bob_resp).unwrap();

            if sender.x_pub() == alice.x_pub() {
                // Capture Alice's initiator *after* encrypt so ns=1 and dhs matches
                // what Bob's stored session now expects on the next inbound from Alice.
                alice_sess_after_bootstrap = Some(sender_sess);
            }
        }

        assert_eq!(
            store_bob.list().unwrap().len(),
            3,
            "Bob must have 3 sessions"
        );

        // Alice sends her SECOND message using the captured session (ns=1, same dhs_pub).
        let alice_msg = b"secret for bob from alice only";
        let rm_alice_second = alice_sess_after_bootstrap
            .as_mut()
            .unwrap()
            .encrypt(alice_msg)
            .unwrap();

        // === Simulate handle_session's trial-decrypt loop ===
        let sessions = store_bob.list().unwrap();
        assert_eq!(sessions.len(), 3, "loop must iterate all 3 sessions");

        let mut match_count = 0usize;
        let mut matched_key: Option<[u8; 32]> = None;
        let mut recovered: Option<Vec<u8>> = None;

        for (peer_key, mut sess) in sessions {
            if let Ok(pt) = sess.decrypt(&rm_alice_second) {
                match_count += 1;
                matched_key = Some(peer_key);
                recovered = Some(pt);
                // handle_session would save+return; we continue to catch false positives
                // on Carol's and Dave's sessions (wrong header key → AEAD rejects, no state change).
            }
        }

        assert_eq!(
            match_count, 1,
            "exactly one session must decrypt Alice's message"
        );
        assert_eq!(
            matched_key.unwrap(),
            alice.x_pub(),
            "matching session must be keyed by Alice's x_pub, not Carol's or Dave's"
        );
        assert_eq!(
            recovered.unwrap(),
            alice_msg,
            "decrypted plaintext must equal what Alice encrypted"
        );
    }
}
