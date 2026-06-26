//! Signal Double Ratchet — per-message forward secrecy + post-compromise security.
//!
//! Phase 2 of the Darqual content-crypto stack. Sits *above* Lockbox v2 (which is the
//! session bootstrap / sessionless one-shot) and gives the ongoing conversation:
//!
//! - **Forward secrecy** per message: each message key (`mk`) is single-use, chain keys
//!   (`ck`) advance and overwrite, so a later compromise can't decrypt earlier messages.
//! - **Post-compromise security** (self-healing): every honest round-trip injects fresh
//!   x25519 entropy into the root key via the DH ratchet.
//!
//! Algorithm: Signal Double Ratchet (Perrin & Marlinspike spec) — implemented exactly,
//! no improvisation. Darqual-specific choices are pinned in
//! `notes/projects/anon-messenger-research/15-double-ratchet.md`:
//!
//! - x25519 for DH (matches identity key type).
//! - blake3 keyed-hash for `KDF_CK`, blake3 XOF for `KDF_RK` (64B output split).
//! - ChaCha20-Poly1305 for AEAD, key = `mk`, 12-byte nonce derived from `mk`, AD = the
//!   serialized header (binds header → ciphertext).
//! - Domain separation: `DOMAIN_RK`, `DOMAIN_NONCE` constants distinct from chain-KDF
//!   personalization bytes.
//! - Hard `MAX_SKIP` bound to prevent DoS via malicious headers asking for unbounded work.

use std::collections::BTreeMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::contact::ContactCard;
use crate::error::{Error, Result};
use crate::identity::Identity;

// ── domain-separation constants ──────────────────────────────────────────────
const DOMAIN_RK: &[u8] = b"darqual ratchet :: root v1";
const DOMAIN_NONCE: &[u8] = b"darqual ratchet :: nonce v1";

// ── DoS bounds (see spec §6) ──────────────────────────────────────────────────
/// Maximum number of message keys that may be skipped in a single call (per chain).
/// A header demanding more skips than this returns `Err(Error::Ratchet)`.
pub const MAX_SKIP: u32 = 1000;
/// Maximum total skipped message keys retained across all chains; oldest evicted.
pub const MAX_SKIP_STORE: usize = 2000;

// ─────────────────────────────────────────────────────────────────────────────
//  Wire types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Sender's current DH-ratchet public key.
    pub dh_pub: [u8; 32],
    /// Number of messages in the previous sending chain (for skip accounting).
    pub pn: u32,
    /// Message index within the current sending chain.
    pub n: u32,
}

impl Header {
    /// Deterministic serialization used as AEAD associated data.
    /// Fixed-layout: 32 bytes dh_pub || 4 bytes pn (LE) || 4 bytes n (LE) = 40 bytes.
    fn to_ad(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.dh_pub);
        out[32..36].copy_from_slice(&self.pn.to_le_bytes());
        out[36..40].copy_from_slice(&self.n.to_le_bytes());
        out
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RatchetMessage {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Session state (spec §2)
// ─────────────────────────────────────────────────────────────────────────────

/// Per-conversation Double Ratchet session.
///
/// STATEFUL: holds secret key material. The app must persist this between messages
/// (serde `Serialize`/`Deserialize` provided) — and must encrypt it at rest.
#[derive(Serialize, Deserialize, Clone)]
pub struct RatchetSession {
    /// Root key.
    rk: [u8; 32],
    /// My current ratchet secret (stored as 32-byte seed for serde + reconstruction).
    dhs_secret: [u8; 32],
    /// My current ratchet public.
    dhs_pub: [u8; 32],
    /// Their current ratchet public (None until first receive on responder side).
    dhr: Option<[u8; 32]>,
    /// Sending chain key.
    cks: Option<[u8; 32]>,
    /// Receiving chain key.
    ckr: Option<[u8; 32]>,
    /// Messages sent in the current sending chain.
    ns: u32,
    /// Messages received in the current receiving chain.
    nr: u32,
    /// Number of messages in the previous sending chain.
    pn: u32,
    /// Out-of-order message keys: (ratchet_pub, n) -> mk.
    skipped: BTreeMap<SkippedKey, [u8; 32]>,
    /// FIFO of skipped-key insertion order, for MAX_SKIP_STORE eviction.
    skipped_order: Vec<SkippedKey>,
}

type SkippedKey = ([u8; 32], u32);

impl std::fmt::Debug for RatchetSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetSession")
            .field("dhs_pub", &hex::encode(self.dhs_pub))
            .field("dhr", &self.dhr.map(hex::encode))
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped_count", &self.skipped.len())
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  KDFs (spec §3)
// ─────────────────────────────────────────────────────────────────────────────

/// `KDF_RK(rk, dh_out) -> (rk', ck)` using blake3 XOF, 64 bytes output, split 32/32.
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = blake3::Hasher::new_keyed(rk);
    hasher.update(DOMAIN_RK);
    hasher.update(dh_out);
    let mut xof = hasher.finalize_xof();
    let mut out = [0u8; 64];
    xof.fill(&mut out);
    let mut rk_next = [0u8; 32];
    let mut ck = [0u8; 32];
    rk_next.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    (rk_next, ck)
}

/// `KDF_CK(ck) -> (ck', mk)` using two keyed_hash calls with distinct personalization bytes.
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = blake3::keyed_hash(ck, &[0x01]);
    let ck_next = blake3::keyed_hash(ck, &[0x02]);
    (*ck_next.as_bytes(), *mk.as_bytes())
}

/// Derive a 12-byte AEAD nonce from a message key.
/// `mk` is single-use (chain advances each message) so this is safe and deterministic.
fn nonce_from_mk(mk: &[u8; 32]) -> [u8; 12] {
    let h = blake3::keyed_hash(mk, DOMAIN_NONCE);
    let mut n = [0u8; 12];
    n.copy_from_slice(&h.as_bytes()[..12]);
    n
}

fn aead_seal(mk: &[u8; 32], pt: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(mk));
    let nonce = nonce_from_mk(mk);
    cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad: ad })
        .map_err(|_| Error::Ratchet("AEAD seal failed".to_string()))
}

fn aead_open(mk: &[u8; 32], ct: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(mk));
    let nonce = nonce_from_mk(mk);
    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad: ad })
        .map_err(|_| Error::Decrypt)
}

fn dh(secret: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let s = StaticSecret::from(*secret);
    let p = X25519PublicKey::from(*peer_pub);
    *s.diffie_hellman(&p).as_bytes()
}

fn fresh_keypair() -> ([u8; 32], [u8; 32]) {
    let s = StaticSecret::random_from_rng(OsRng);
    let p = X25519PublicKey::from(&s);
    (s.to_bytes(), p.to_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
//  RatchetSession impl
// ─────────────────────────────────────────────────────────────────────────────

impl RatchetSession {
    /// Initiator (Alice). `shared_secret` = `Conversation::shared_secret()` between Alice
    /// and Bob (32B). `them` carries Bob's static x25519 pub, which is Bob's *initial*
    /// ratchet public — Alice DHs against it to derive her first sending chain.
    pub fn init_initiator(shared_secret: &[u8; 32], them: &ContactCard) -> Self {
        let (dhs_secret, dhs_pub) = fresh_keypair();
        let dhr = them.x_pub;
        let dh_out = dh(&dhs_secret, &dhr);
        let (rk, cks) = kdf_rk(shared_secret, &dh_out);

        RatchetSession {
            rk,
            dhs_secret,
            dhs_pub,
            dhr: Some(dhr),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: BTreeMap::new(),
            skipped_order: Vec::new(),
        }
    }

    /// Responder (Bob). His static x25519 keypair IS the initial ratchet keypair (the one
    /// Alice targeted as `dhr`), so he can decrypt the first inbound message before
    /// performing his own DH ratchet step. PCS kicks in after the first round-trip.
    pub fn init_responder(shared_secret: &[u8; 32], me: &Identity) -> Self {
        let dhs_secret = me.x_secret.to_bytes();
        let dhs_pub = X25519PublicKey::from(&me.x_secret).to_bytes();

        RatchetSession {
            rk: *shared_secret,
            dhs_secret,
            dhs_pub,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: BTreeMap::new(),
            skipped_order: Vec::new(),
        }
    }

    /// Encrypt the next message in the sending chain. Advances `ns`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        let cks = self
            .cks
            .as_ref()
            .ok_or_else(|| Error::Ratchet("no sending chain (responder must receive first)".to_string()))?;
        let (cks_next, mk) = kdf_ck(cks);
        self.cks = Some(cks_next);

        let header = Header {
            dh_pub: self.dhs_pub,
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let ad = header.to_ad();
        let ct = aead_seal(&mk, plaintext, &ad)?;
        // mk goes out of scope here — single-use, not retained.
        Ok(RatchetMessage {
            header,
            ciphertext: ct,
        })
    }

    /// Decrypt. Handles DH ratchet, out-of-order, and skipped message keys.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        // Fast path: previously-skipped key.
        if let Some(pt) = self.try_skipped(&msg.header, &msg.ciphertext)? {
            return Ok(pt);
        }

        // New DH ratchet step?
        if self.dhr.is_none() || self.dhr.as_ref() != Some(&msg.header.dh_pub) {
            self.skip_message_keys(msg.header.pn)?;
            self.dh_ratchet(&msg.header)?;
        }

        // Catch up within the current receiving chain.
        self.skip_message_keys(msg.header.n)?;

        let ckr = self
            .ckr
            .as_ref()
            .ok_or_else(|| Error::Ratchet("no receiving chain".to_string()))?;
        let (ckr_next, mk) = kdf_ck(ckr);
        self.ckr = Some(ckr_next);
        self.nr += 1;

        let ad = msg.header.to_ad();
        aead_open(&mk, &msg.ciphertext, &ad)
    }

    // ── internals ─────────────────────────────────────────────────────────────

    fn try_skipped(&mut self, header: &Header, ct: &[u8]) -> Result<Option<Vec<u8>>> {
        let key: SkippedKey = (header.dh_pub, header.n);
        if let Some(mk) = self.skipped.remove(&key) {
            // Drop from FIFO too.
            if let Some(pos) = self.skipped_order.iter().position(|k| k == &key) {
                self.skipped_order.remove(pos);
            }
            let ad = header.to_ad();
            return Ok(Some(aead_open(&mk, ct, &ad)?));
        }
        Ok(None)
    }

    /// Advance the receiving chain up to (not including) `until`, storing each derived
    /// message key in `skipped` for later out-of-order delivery.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if let Some(ckr) = self.ckr.as_ref() {
            // Bound: never skip more than MAX_SKIP within a single call.
            if until > self.nr && until - self.nr > MAX_SKIP {
                return Err(Error::Ratchet(format!(
                    "header demands {} skips, MAX_SKIP = {}",
                    until - self.nr,
                    MAX_SKIP
                )));
            }
            let dhr = self
                .dhr
                .ok_or_else(|| Error::Ratchet("skip without dhr".to_string()))?;
            let mut ckr = *ckr;
            while self.nr < until {
                let (ckr_next, mk) = kdf_ck(&ckr);
                let key: SkippedKey = (dhr, self.nr);
                self.skipped.insert(key, mk);
                self.skipped_order.push(key);
                // Cap total stored keys; evict oldest.
                while self.skipped_order.len() > MAX_SKIP_STORE {
                    let oldest = self.skipped_order.remove(0);
                    self.skipped.remove(&oldest);
                }
                ckr = ckr_next;
                self.nr += 1;
            }
            self.ckr = Some(ckr);
        }
        Ok(())
    }

    /// DH ratchet step (spec §4): finalize old receiving chain, derive a new one from the
    /// peer's new ratchet pub, then rotate our own ratchet keypair and derive a new
    /// sending chain. This is where PCS happens.
    fn dh_ratchet(&mut self, header: &Header) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh_pub);

        let dh_out = dh(&self.dhs_secret, &header.dh_pub);
        let (rk_next, ckr) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk_next;
        self.ckr = Some(ckr);

        let (new_secret, new_pub) = fresh_keypair();
        self.dhs_secret = new_secret;
        self.dhs_pub = new_pub;

        let dh_out2 = dh(&self.dhs_secret, &header.dh_pub);
        let (rk_next2, cks) = kdf_rk(&self.rk, &dh_out2);
        self.rk = rk_next2;
        self.cks = Some(cks);
        Ok(())
    }

    /// My current ratchet public — exposed for test/inspection only.
    #[doc(hidden)]
    pub fn dhs_pub(&self) -> [u8; 32] {
        self.dhs_pub
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests (spec §10)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::Conversation;

    fn pair() -> (Identity, Identity, RatchetSession, RatchetSession) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let sk_a = *Conversation::new(&alice, &bob.contact_card()).shared_secret();
        let sk_b = *Conversation::new(&bob, &alice.contact_card()).shared_secret();
        assert_eq!(sk_a, sk_b, "static-static ECDH must be symmetric");

        let a = RatchetSession::init_initiator(&sk_a, &bob.contact_card());
        let b = RatchetSession::init_responder(&sk_b, &bob);
        (alice, bob, a, b)
    }

    // 1. In-order multi-message back-and-forth.
    #[test]
    fn in_order_back_and_forth() {
        let (_alice, _bob, mut a, mut b) = pair();

        let m1 = a.encrypt(b"hello bob").unwrap();
        assert_eq!(b.decrypt(&m1).unwrap(), b"hello bob");

        let m2 = b.encrypt(b"hi alice").unwrap();
        assert_eq!(a.decrypt(&m2).unwrap(), b"hi alice");

        let m3 = a.encrypt(b"how are you").unwrap();
        let m4 = a.encrypt(b"are you there").unwrap();
        assert_eq!(b.decrypt(&m3).unwrap(), b"how are you");
        assert_eq!(b.decrypt(&m4).unwrap(), b"are you there");

        let m5 = b.encrypt(b"yes").unwrap();
        let m6 = b.encrypt(b"hi").unwrap();
        assert_eq!(a.decrypt(&m5).unwrap(), b"yes");
        assert_eq!(a.decrypt(&m6).unwrap(), b"hi");
    }

    // 2. DH-ratchet self-heal: pubs change after round-trips.
    #[test]
    fn pcs_dh_ratchet_rotates_pubs() {
        let (_alice, _bob, mut a, mut b) = pair();
        let a_pub_0 = a.dhs_pub();
        let b_pub_0 = b.dhs_pub();

        for i in 0..5 {
            let m = a.encrypt(format!("a->b #{}", i).as_bytes()).unwrap();
            b.decrypt(&m).unwrap();
            let m = b.encrypt(format!("b->a #{}", i).as_bytes()).unwrap();
            a.decrypt(&m).unwrap();
        }

        assert_ne!(a.dhs_pub(), a_pub_0, "Alice's ratchet pub must rotate");
        assert_ne!(b.dhs_pub(), b_pub_0, "Bob's ratchet pub must rotate");
    }

    // 3. Out-of-order delivery: msg #3 before #2 via skipped-key path.
    #[test]
    fn out_of_order_skipped_keys() {
        let (_alice, _bob, mut a, mut b) = pair();
        let m1 = a.encrypt(b"one").unwrap();
        let m2 = a.encrypt(b"two").unwrap();
        let m3 = a.encrypt(b"three").unwrap();

        assert_eq!(b.decrypt(&m1).unwrap(), b"one");
        // Deliver #3 before #2 — must skip #2's key.
        assert_eq!(b.decrypt(&m3).unwrap(), b"three");
        // Now #2 arrives — must be served from the skipped map.
        assert_eq!(b.decrypt(&m2).unwrap(), b"two");
    }

    // 4. Forward secrecy: a state captured *after* an earlier message was consumed cannot
    //    decrypt that earlier message — its mk and the chain key that produced it are gone.
    #[test]
    fn forward_secrecy_earlier_message_unrecoverable() {
        let (_alice, _bob, mut a, mut b) = pair();
        let m1 = a.encrypt(b"earlier secret").unwrap();
        let m2 = a.encrypt(b"later").unwrap();

        assert_eq!(b.decrypt(&m1).unwrap(), b"earlier secret");
        // Snapshot Bob's state AFTER consuming m1.
        let bob_after_m1 = b.clone();
        assert_eq!(b.decrypt(&m2).unwrap(), b"later");

        // A fresh attempt to decrypt m1 from the post-m1 state must fail —
        // the chain has advanced, the mk for n=0 is gone, no skipped entry exists.
        let mut captured = bob_after_m1;
        assert!(
            captured.decrypt(&m1).is_err(),
            "captured later state must NOT decrypt earlier message — FS broken"
        );
    }

    // 5. MAX_SKIP guard.
    #[test]
    fn max_skip_guard_rejects_oversized_jump() {
        let (_alice, _bob, mut a, mut b) = pair();
        // Get Bob onto the receiving chain.
        let m0 = a.encrypt(b"prime").unwrap();
        b.decrypt(&m0).unwrap();

        // Forge a header in the SAME chain (dh_pub = Alice's current dhs_pub) with n
        // beyond MAX_SKIP — Bob's skip_message_keys should refuse.
        let bogus = RatchetMessage {
            header: Header {
                dh_pub: a.dhs_pub(),
                pn: 0,
                n: MAX_SKIP + 5,
            },
            ciphertext: vec![0u8; 32],
        };
        let r = b.decrypt(&bogus);
        assert!(matches!(r, Err(Error::Ratchet(_))), "got {:?}", r);
    }

    // 6. Tamper: ciphertext byte and (separately) header byte → Err.
    #[test]
    fn tamper_ciphertext_and_header_fail() {
        let (_alice, _bob, mut a, mut b) = pair();
        let m = a.encrypt(b"integrity check").unwrap();

        // (a) flip a ciphertext byte
        {
            let mut tampered = m.clone();
            tampered.ciphertext[0] ^= 0xFF;
            let mut bob_clone = b.clone();
            assert!(bob_clone.decrypt(&tampered).is_err());
        }
        // (b) flip a header byte (n) — header is AEAD AD, so AEAD must reject.
        {
            let mut tampered = m.clone();
            tampered.header.n = tampered.header.n.wrapping_add(1);
            let mut bob_clone = b.clone();
            // Note: bumping n will cause skip_message_keys to derive a different mk,
            // and AEAD will fail to authenticate against the (now-mismatched) AD.
            assert!(bob_clone.decrypt(&tampered).is_err());
        }
        // The pristine message must still decrypt on the untouched Bob.
        assert_eq!(b.decrypt(&m).unwrap(), b"integrity check");
    }

    // 7. serde round-trip of a mid-conversation session.
    #[test]
    fn serde_roundtrip_resumes_conversation() {
        let (_alice, _bob, mut a, mut b) = pair();

        let m1 = a.encrypt(b"one").unwrap();
        b.decrypt(&m1).unwrap();
        let m2 = b.encrypt(b"two").unwrap();
        a.decrypt(&m2).unwrap();
        let m3 = a.encrypt(b"three").unwrap();
        b.decrypt(&m3).unwrap();

        // Snapshot Bob mid-conversation.
        let bytes = bincode::serialize(&b).expect("serialize");
        let mut b_restored: RatchetSession = bincode::deserialize(&bytes).expect("deserialize");

        // Conversation continues from restored state.
        let m4 = b_restored.encrypt(b"four").unwrap();
        assert_eq!(a.decrypt(&m4).unwrap(), b"four");

        let m5 = a.encrypt(b"five").unwrap();
        assert_eq!(b_restored.decrypt(&m5).unwrap(), b"five");
    }
}
