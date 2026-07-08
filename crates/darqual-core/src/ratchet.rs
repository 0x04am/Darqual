//! Signal Double Ratchet — header-encryption variant (Phase 2b).
//!
//! Upgrade-in-place of the Phase-2 ratchet: ratchet headers (`dh_pub`, `pn`, `n`) are now
//! AEAD-encrypted under per-chain header keys so a network observer / malicious relay sees
//! only opaque `enc_header || ciphertext` — no rotating pubkey, no counters, nothing to link
//! two messages of a conversation by header content.
//!
//! Algorithm: Signal Double Ratchet with header encryption (Perrin & Marlinspike,
//! "RatchetInitAliceHE / RatchetEncryptHE / RatchetDecryptHE"). Darqual choices pinned in
//! `notes/projects/anon-messenger-research/16-double-ratchet-header-encryption.md`:
//!
//! - x25519 for DH; blake3 XOF for `KDF_RK_HE` (96-byte output → rk' ‖ ck ‖ nhk);
//!   blake3 keyed_hash for `KDF_CK` (unchanged from Phase 2).
//! - ChaCha20-Poly1305 for both message AEAD (key = `mk`, AD = `enc_header`) and header
//!   AEAD (key = `hk`, random 12B nonce prepended, empty AD).
//! - Two shared header keys (`shared_hka`, `shared_nhkb`) derived deterministically from
//!   the Conversation SK — no extra round-trip at handshake.
//! - `MAX_SKIP` DoS bound + `MAX_SKIP_STORE` retention cap preserved. Skipped keys are
//!   stored under `(header_key, n)` now (header key identifies the chain — we can't see
//!   `dh_pub` until we decrypt the header).
//! - `HDEC` on a wrong key returns `Err`, never panics — trial-decryption depends on it.

use std::collections::BTreeMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::contact::ContactCard;
use crate::error::{Error, Result};
use crate::identity::Identity;

// ── domain-separation constants ──────────────────────────────────────────────
/// 96-byte root KDF for the header-encryption variant — DISTINCT from the Phase-2
/// 64-byte `DOMAIN_RK` so an upgrader can't accidentally cross the streams.
const DOMAIN_RK_HE: &[u8] = b"darqual ratchet :: root HE v1";
const DOMAIN_NONCE: &[u8] = b"darqual ratchet :: msg nonce v1";

/// blake3 derive_key contexts for the two shared header keys (spec §4).
const CTX_SHARED_HKA: &str = "darqual ratchet :: HE shared hka  v1";
const CTX_SHARED_NHKB: &str = "darqual ratchet :: HE shared nhkb v1";

// ── DoS bounds (spec §6) ─────────────────────────────────────────────────────
/// Maximum number of message keys that may be skipped in a single call (per chain).
pub const MAX_SKIP: u32 = 1000;
/// Maximum total skipped message keys retained across all chains; oldest evicted.
pub const MAX_SKIP_STORE: usize = 2000;

// ─────────────────────────────────────────────────────────────────────────────
//  Wire types
// ─────────────────────────────────────────────────────────────────────────────

/// Plaintext header. Never crosses the wire — gets serialized + encrypted into
/// `RatchetMessage::enc_header`. Kept `Serialize/Deserialize` so the header AEAD's
/// plaintext has a stable, deterministic layout.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub dh_pub: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl Header {
    /// Fixed-layout 40-byte serialization: dh_pub(32) ‖ pn(4 LE) ‖ n(4 LE).
    /// Used as the header-AEAD plaintext (NOT as message-AEAD AD anymore — that's
    /// `enc_header` now, which binds msg → its encrypted header).
    fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.dh_pub);
        out[32..36].copy_from_slice(&self.pn.to_le_bytes());
        out[36..40].copy_from_slice(&self.n.to_le_bytes());
        out
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 40 {
            return Err(Error::Ratchet(format!(
                "header decode: expected 40 bytes, got {}",
                b.len()
            )));
        }
        let mut dh_pub = [0u8; 32];
        dh_pub.copy_from_slice(&b[..32]);
        let mut pn_le = [0u8; 4];
        pn_le.copy_from_slice(&b[32..36]);
        let mut n_le = [0u8; 4];
        n_le.copy_from_slice(&b[36..40]);
        Ok(Header {
            dh_pub,
            pn: u32::from_le_bytes(pn_le),
            n: u32::from_le_bytes(n_le),
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RatchetMessage {
    /// `nonce(12) || ChaCha20Poly1305_seal(hk, nonce, serialize(header))`.
    pub enc_header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Session state (spec §2)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct RatchetSession {
    rk: [u8; 32],
    dhs_secret: [u8; 32],
    dhs_pub: [u8; 32],
    dhr: Option<[u8; 32]>,
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    // Header keys (spec §2): four total.
    hks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    nhks: [u8; 32],
    nhkr: [u8; 32],
    /// Out-of-order message keys: (header_key, n) -> mk.
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

/// `KDF_RK_HE(rk, dh_out) -> (rk', ck, nhk)` — blake3 XOF, 96 bytes split 32/32/32.
fn kdf_rk_he(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut hasher = blake3::Hasher::new_keyed(rk);
    hasher.update(DOMAIN_RK_HE);
    hasher.update(dh_out);
    let mut xof = hasher.finalize_xof();
    let mut out = [0u8; 96];
    xof.fill(&mut out);
    let mut rk_next = [0u8; 32];
    let mut ck = [0u8; 32];
    let mut nhk = [0u8; 32];
    rk_next.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..64]);
    nhk.copy_from_slice(&out[64..96]);
    (rk_next, ck, nhk)
}

/// `KDF_CK(ck) -> (ck', mk)` — unchanged from Phase 2.
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = blake3::keyed_hash(ck, &[0x01]);
    let ck_next = blake3::keyed_hash(ck, &[0x02]);
    (*ck_next.as_bytes(), *mk.as_bytes())
}

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

// ── Header AEAD (HENC/HDEC) ──────────────────────────────────────────────────
// Random 12B nonce prepended to ciphertext. Header key is reused across the chain's
// headers, so the per-message random nonce is what makes the AEAD safe. Empty AD.

fn henc(hk: &[u8; 32], header_bytes: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(hk));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: header_bytes,
                aad: &[],
            },
        )
        .map_err(|_| Error::Ratchet("header AEAD seal failed".to_string()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Returns `Err(Error::Decrypt)` on auth failure — caller treats this as "wrong key,
/// try next". MUST NOT panic; trial-decryption depends on it.
fn hdec(hk: &[u8; 32], enc: &[u8]) -> Result<Header> {
    if enc.len() < 12 + 16 {
        return Err(Error::Decrypt);
    }
    let (nonce, ct) = enc.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(hk));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &[] })
        .map_err(|_| Error::Decrypt)?;
    Header::from_bytes(&pt)
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

/// Spec §4: derive (shared_hka, shared_nhkb) deterministically from the Conversation SK.
fn shared_header_keys(sk: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hka = blake3::derive_key(CTX_SHARED_HKA, sk);
    let nhkb = blake3::derive_key(CTX_SHARED_NHKB, sk);
    (hka, nhkb)
}

// ─────────────────────────────────────────────────────────────────────────────
//  RatchetSession impl
// ─────────────────────────────────────────────────────────────────────────────

impl RatchetSession {
    /// Initiator (Alice). Spec §4 RatchetInitAliceHE.
    pub fn init_initiator(shared_secret: &[u8; 32], them: &ContactCard) -> Self {
        let (shared_hka, shared_nhkb) = shared_header_keys(shared_secret);
        let (dhs_secret, dhs_pub) = fresh_keypair();
        let dhr = them.x_pub;
        let dh_out = dh(&dhs_secret, &dhr);
        let (rk, cks, nhks) = kdf_rk_he(shared_secret, &dh_out);

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
            hks: Some(shared_hka),
            hkr: None,
            nhks,
            nhkr: shared_nhkb,
            skipped: BTreeMap::new(),
            skipped_order: Vec::new(),
        }
    }

    /// Responder (Bob). Spec §4 RatchetInitBobHE. Note the cross: his `nhkr = shared_hka`
    /// so his first inbound trial-decrypt succeeds against Alice's `hks = shared_hka`.
    pub fn init_responder(shared_secret: &[u8; 32], me: &Identity) -> Self {
        let (shared_hka, shared_nhkb) = shared_header_keys(shared_secret);
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
            hks: None,
            hkr: None,
            nhks: shared_nhkb,
            nhkr: shared_hka,
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
        let hks = self
            .hks
            .as_ref()
            .ok_or_else(|| Error::Ratchet("no sending header key".to_string()))?;
        let (cks_next, mk) = kdf_ck(cks);
        self.cks = Some(cks_next);

        let header = Header {
            dh_pub: self.dhs_pub,
            pn: self.pn,
            n: self.ns,
        };
        let enc_header = henc(hks, &header.to_bytes())?;
        self.ns += 1;

        let ct = aead_seal(&mk, &crate::padding::pad(plaintext), &enc_header)?;
        Ok(RatchetMessage {
            enc_header,
            ciphertext: ct,
        })
    }

    /// Decrypt. Handles DH ratchet, out-of-order, and skipped message keys.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        // 1. Skipped-keys fast path: trial-decrypt enc_header against each stored hk.
        if let Some(pt) = self.try_skipped_he(msg)? {
            return Ok(pt);
        }

        // 2. Clone-and-commit: run all state mutations on a trial copy so a failed
        //    AEAD (forged/corrupt message) can't permanently corrupt the session.
        let mut trial = self.clone();

        // Decrypt header (hkr → current chain; nhkr → DH-ratchet step).
        let (header, do_ratchet) = trial.decrypt_header(&msg.enc_header)?;

        if do_ratchet {
            trial.skip_message_keys(header.pn)?;
            trial.dh_ratchet_he(&header)?;
        }
        trial.skip_message_keys(header.n)?;

        let ckr = trial
            .ckr
            .as_ref()
            .ok_or_else(|| Error::Ratchet("no receiving chain".to_string()))?;
        let (ckr_next, mk) = kdf_ck(ckr);
        trial.ckr = Some(ckr_next);
        trial.nr += 1;

        let padded = aead_open(&mk, &msg.ciphertext, &msg.enc_header)?;
        let pt = crate::padding::unpad(&padded)?;

        // Commit only after AEAD + unpad both succeeded.
        *self = trial;
        Ok(pt)
    }

    // ── internals ─────────────────────────────────────────────────────────────

    fn decrypt_header(&self, enc_header: &[u8]) -> Result<(Header, bool)> {
        if let Some(hkr) = self.hkr.as_ref() {
            if let Ok(h) = hdec(hkr, enc_header) {
                return Ok((h, false));
            }
        }
        if let Ok(h) = hdec(&self.nhkr, enc_header) {
            return Ok((h, true));
        }
        Err(Error::Ratchet(
            "header decrypt failed: unknown header key".to_string(),
        ))
    }

    fn try_skipped_he(&mut self, msg: &RatchetMessage) -> Result<Option<Vec<u8>>> {
        // Find a (hk, n) entry whose hk decrypts the header AND whose n matches header.n.
        let mut hit: Option<SkippedKey> = None;
        for sk_key in self.skipped.keys() {
            let (hk, n) = sk_key;
            if let Ok(h) = hdec(hk, &msg.enc_header) {
                if h.n == *n {
                    hit = Some(*sk_key);
                    break;
                }
            }
        }
        if let Some(key) = hit {
            let mk = self
                .skipped
                .remove(&key)
                .expect("hit came from skipped iter");
            if let Some(pos) = self.skipped_order.iter().position(|k| k == &key) {
                self.skipped_order.remove(pos);
            }
            let padded = aead_open(&mk, &msg.ciphertext, &msg.enc_header)?;
            return Ok(Some(crate::padding::unpad(&padded)?));
        }
        Ok(None)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if self.ckr.is_none() {
            return Ok(());
        }
        if until > self.nr && until - self.nr > MAX_SKIP {
            return Err(Error::Ratchet(format!(
                "header demands {} skips, MAX_SKIP = {}",
                until - self.nr,
                MAX_SKIP
            )));
        }
        let hkr = self
            .hkr
            .ok_or_else(|| Error::Ratchet("skip without hkr".to_string()))?;
        let mut ckr = self.ckr.unwrap();
        while self.nr < until {
            let (ckr_next, mk) = kdf_ck(&ckr);
            let key: SkippedKey = (hkr, self.nr);
            self.skipped.insert(key, mk);
            self.skipped_order.push(key);
            while self.skipped_order.len() > MAX_SKIP_STORE {
                let oldest = self.skipped_order.remove(0);
                self.skipped.remove(&oldest);
            }
            ckr = ckr_next;
            self.nr += 1;
        }
        self.ckr = Some(ckr);
        Ok(())
    }

    /// DH ratchet step, header-encryption variant (spec §5).
    fn dh_ratchet_he(&mut self, header: &Header) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        // Promote next header keys to current.
        self.hks = Some(self.nhks);
        self.hkr = Some(self.nhkr);
        self.dhr = Some(header.dh_pub);

        let dh_out = dh(&self.dhs_secret, &header.dh_pub);
        let (rk_next, ckr, nhkr) = kdf_rk_he(&self.rk, &dh_out);
        self.rk = rk_next;
        self.ckr = Some(ckr);
        self.nhkr = nhkr;

        let (new_secret, new_pub) = fresh_keypair();
        self.dhs_secret = new_secret;
        self.dhs_pub = new_pub;

        let dh_out2 = dh(&self.dhs_secret, &header.dh_pub);
        let (rk_next2, cks, nhks) = kdf_rk_he(&self.rk, &dh_out2);
        self.rk = rk_next2;
        self.cks = Some(cks);
        self.nhks = nhks;
        Ok(())
    }

    /// My current ratchet public — exposed for test/inspection only.
    #[doc(hidden)]
    pub fn dhs_pub(&self) -> [u8; 32] {
        self.dhs_pub
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
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

    // 2. DH-ratchet self-heal: pubs rotate after round-trips.
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

    // 3. Out-of-order: msg #3 before #2 via skipped-key path.
    #[test]
    fn out_of_order_skipped_keys() {
        let (_alice, _bob, mut a, mut b) = pair();
        let m1 = a.encrypt(b"one").unwrap();
        let m2 = a.encrypt(b"two").unwrap();
        let m3 = a.encrypt(b"three").unwrap();

        assert_eq!(b.decrypt(&m1).unwrap(), b"one");
        assert_eq!(b.decrypt(&m3).unwrap(), b"three");
        assert_eq!(b.decrypt(&m2).unwrap(), b"two");
    }

    // 4. Forward secrecy.
    #[test]
    fn forward_secrecy_earlier_message_unrecoverable() {
        let (_alice, _bob, mut a, mut b) = pair();
        let m1 = a.encrypt(b"earlier secret").unwrap();
        let m2 = a.encrypt(b"later").unwrap();

        assert_eq!(b.decrypt(&m1).unwrap(), b"earlier secret");
        let bob_after_m1 = b.clone();
        assert_eq!(b.decrypt(&m2).unwrap(), b"later");

        let mut captured = bob_after_m1;
        assert!(
            captured.decrypt(&m1).is_err(),
            "captured later state must NOT decrypt earlier message — FS broken"
        );
    }

    // 5. MAX_SKIP guard. Forge a header in the same chain with n beyond the bound.
    #[test]
    fn max_skip_guard_rejects_oversized_jump() {
        let (_alice, _bob, mut a, mut b) = pair();
        // Prime: get Bob onto the receiving chain (hkr / ckr established).
        let m0 = a.encrypt(b"prime").unwrap();
        b.decrypt(&m0).unwrap();

        // Forge a same-chain message: re-use Alice's current hks to encrypt a header
        // with n past MAX_SKIP. (We can't reach into Alice's state cleanly, so just
        // re-encrypt under her sending chain — actually simpler: build a message via
        // Alice's encrypt then rewrite the inner header by swapping in a forged enc_header.
        // Easier: send MAX_SKIP+5 dummy messages from Alice, drop them, then Bob sees a
        // legit jump.) — concise approach: encrypt MAX_SKIP+5 msgs, only deliver the last.
        let mut last = None;
        for _ in 0..(MAX_SKIP + 5) {
            last = Some(a.encrypt(b"x").unwrap());
        }
        let bogus = last.unwrap();
        let r = b.decrypt(&bogus);
        assert!(matches!(r, Err(Error::Ratchet(_))), "got {:?}", r);
    }

    // 6. Tamper.
    #[test]
    fn tamper_ciphertext_and_header_fail() {
        let (_alice, _bob, mut a, mut b) = pair();
        let m = a.encrypt(b"integrity check").unwrap();

        {
            let mut tampered = m.clone();
            tampered.ciphertext[0] ^= 0xFF;
            let mut bob_clone = b.clone();
            assert!(bob_clone.decrypt(&tampered).is_err());
        }
        {
            // Flip a byte INSIDE enc_header — either the nonce (decrypt header fails) or
            // the AEAD tag/body (same). Either way decrypt must fail.
            let mut tampered = m.clone();
            let i = tampered.enc_header.len() - 1;
            tampered.enc_header[i] ^= 0xFF;
            let mut bob_clone = b.clone();
            assert!(bob_clone.decrypt(&tampered).is_err());
        }
        assert_eq!(b.decrypt(&m).unwrap(), b"integrity check");
    }

    // 7. serde round-trip mid-conversation.
    #[test]
    fn serde_roundtrip_resumes_conversation() {
        let (_alice, _bob, mut a, mut b) = pair();

        let m1 = a.encrypt(b"one").unwrap();
        b.decrypt(&m1).unwrap();
        let m2 = b.encrypt(b"two").unwrap();
        a.decrypt(&m2).unwrap();
        let m3 = a.encrypt(b"three").unwrap();
        b.decrypt(&m3).unwrap();

        let bytes = bincode::serialize(&b).expect("serialize");
        let mut b_restored: RatchetSession = bincode::deserialize(&bytes).expect("deserialize");

        let m4 = b_restored.encrypt(b"four").unwrap();
        assert_eq!(a.decrypt(&m4).unwrap(), b"four");

        let m5 = a.encrypt(b"five").unwrap();
        assert_eq!(b_restored.decrypt(&m5).unwrap(), b"five");
    }

    // 8. Header privacy (spec §9). An observer holding neither hkr nor nhkr cannot
    //    decrypt_header; consecutive messages have distinct enc_header bytes (random nonce).
    #[test]
    fn header_privacy_observer_cannot_decrypt_header() {
        let (_alice, _bob, mut a, mut b) = pair();
        let m1 = a.encrypt(b"one").unwrap();
        let m2 = a.encrypt(b"two").unwrap();

        // Two messages, same chain → different enc_header bytes (random nonce + counter).
        assert_ne!(m1.enc_header, m2.enc_header);

        // A third party with junk keys cannot decrypt the header.
        let junk = [0x77u8; 32];
        assert!(hdec(&junk, &m1.enc_header).is_err());
        assert!(hdec(&junk, &m2.enc_header).is_err());

        // Build a "fresh observer" session with random SK — neither hkr nor nhkr match.
        let eve = Identity::generate();
        let eve2 = Identity::generate();
        let sk_eve = *Conversation::new(&eve, &eve2.contact_card()).shared_secret();
        let observer = RatchetSession::init_initiator(&sk_eve, &eve2.contact_card());
        assert!(observer.decrypt_header(&m1.enc_header).is_err());

        // Bob can of course still decrypt.
        assert_eq!(b.decrypt(&m1).unwrap(), b"one");
        assert_eq!(b.decrypt(&m2).unwrap(), b"two");
    }

    // 9. Trial-decrypt ratchet path (spec §9). After a DH ratchet, the next inbound
    //    message decrypts via nhkr (do_ratchet=true) and yields correct plaintext.
    #[test]
    fn trial_decrypt_ratchet_path_via_nhkr() {
        let (_alice, _bob, mut a, mut b) = pair();

        // Round 1: A→B (Bob's first inbound — must use nhkr=shared_hka).
        let m1 = a.encrypt(b"hello").unwrap();
        // Probe decrypt_header BEFORE decrypt mutates state.
        {
            let (_h, do_ratchet) = b.decrypt_header(&m1.enc_header).unwrap();
            assert!(do_ratchet, "first inbound must trigger ratchet via nhkr");
        }
        assert_eq!(b.decrypt(&m1).unwrap(), b"hello");

        // Round 2: B→A (Alice's first inbound — must use nhkr=shared_nhkb).
        let r1 = b.encrypt(b"hi back").unwrap();
        {
            let (_h, do_ratchet) = a.decrypt_header(&r1.enc_header).unwrap();
            assert!(do_ratchet, "Alice's first inbound must trigger ratchet via nhkr");
        }
        assert_eq!(a.decrypt(&r1).unwrap(), b"hi back");

        // Round 3: A→B after another DH ratchet — should again be do_ratchet=true
        // (Alice rotated dhs on receiving r1, so her next send is a new chain for Bob).
        let m2 = a.encrypt(b"third").unwrap();
        {
            let (_h, do_ratchet) = b.decrypt_header(&m2.enc_header).unwrap();
            assert!(do_ratchet, "post-rotate inbound must trigger ratchet via nhkr");
        }
        assert_eq!(b.decrypt(&m2).unwrap(), b"third");

        // And a same-chain follow-up must NOT trigger ratchet (uses hkr).
        let m3 = a.encrypt(b"same chain").unwrap();
        {
            let (_h, do_ratchet) = b.decrypt_header(&m3.enc_header).unwrap();
            assert!(!do_ratchet, "same-chain inbound must use hkr, not nhkr");
        }
        assert_eq!(b.decrypt(&m3).unwrap(), b"same chain");
    }
}
