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

// ── version bytes ─────────────────────────────────────────────────────────────
const V1: u8 = 0x01;
const V2: u8 = 0x02;

// ── KDF context strings (domain separation) ───────────────────────────────────
const KDF_CONTEXT_V1: &str = "darqual lockbox v1 :: x25519-chacha20poly1305";
// k0: ephemeral-static DH  → encrypts sender's static pubkey
const KDF_CTX_ES: &str = "darqual lockbox v2 :: noise-IK es :: chacha20poly1305";
// k1: KDF(es || ss)        → encrypts the actual message
const KDF_CTX_ESS: &str = "darqual lockbox v2 :: noise-IK es+ss :: chacha20poly1305";

const BOX_PREFIX: &str = "dqbox1";

// ── v2 wire layout ────────────────────────────────────────────────────────────
//  [ver=2 1B][eph_pub 32B][nonce0 12B][enc_s 48B][nonce1 12B][enc_msg ...]
//
//  enc_s  = AEAD(k0, nonce0, alice_x_pub[32B])  → exactly 32+16 = 48 bytes
//  enc_msg= AEAD(k1, nonce1, msg)
//
// The sender static pubkey is hidden inside the first AEAD layer (k0 = f(es)),
// so the network only ever sees the ephemeral pubkey — identical shape to v1.

/// An encrypted lockbox.
///
/// - Version 1: anonymous (no sender identity, original behaviour).
/// - Version 2: authenticated + sender-hidden via Noise IK (e, es, s, ss).
#[derive(Debug, Clone)]
pub struct Lockbox {
    /// Wire-format envelope: `"dqbox1"` + BASE64(bytes)
    pub envelope: String,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn random_nonce() -> [u8; 12] {
    let mut b = [0u8; 12];
    OsRng.fill_bytes(&mut b);
    b
}

fn aead_encrypt(key_bytes: [u8; 32], nonce_bytes: [u8; 12], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(key_bytes));
    cipher
        .encrypt(&Nonce::from(nonce_bytes), plain)
        .map_err(|_| Error::Encoding("encryption failed".to_string()))
}

fn aead_decrypt(key_bytes: [u8; 32], nonce_bytes: [u8; 12], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(key_bytes));
    cipher
        .decrypt(&Nonce::from(nonce_bytes), ct)
        .map_err(|_| Error::Decrypt)
}

/// KDF(es || ss): concatenate the two DH outputs then derive.
fn kdf_ess(es: &[u8; 32], ss: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(es);
    input[32..].copy_from_slice(ss);
    blake3::derive_key(KDF_CTX_ESS, &input)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────────────────────

impl Lockbox {
    // ── v1: anonymous seal (unchanged behaviour) ─────────────────────────────

    /// Seal a message to a recipient's x25519 public key (anonymous, v1).
    pub fn seal(recipient_x_pub: &X25519PublicKey, msg: &[u8]) -> Result<Self> {
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_secret);

        let shared = eph_secret.diffie_hellman(recipient_x_pub);
        let key_bytes = blake3::derive_key(KDF_CONTEXT_V1, shared.as_bytes());
        let nonce_bytes = random_nonce();
        let padded = crate::padding::pad(msg);
        let ct = aead_encrypt(key_bytes, nonce_bytes, &padded)?;

        // Wire: [V1 1][eph_pub 32][nonce 12][ct ...]
        let mut wire = Vec::with_capacity(1 + 32 + 12 + ct.len());
        wire.push(V1);
        wire.extend_from_slice(eph_pub.as_bytes());
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ct);

        Ok(Lockbox {
            envelope: format!("{}{}", BOX_PREFIX, BASE64.encode(&wire)),
        })
    }

    /// Convenience: seal to a `ContactCard` (anonymous, v1).
    pub fn seal_to_card(card: &ContactCard, msg: &[u8]) -> Result<Self> {
        let x_pub = X25519PublicKey::from(card.x_pub);
        Self::seal(&x_pub, msg)
    }

    // ── v2: authenticated + sender-hidden seal (Noise IK) ────────────────────

    /// Seal a message with deniable sender authentication (v2, Noise IK).
    ///
    /// Noise IK pattern: `e, es, s, ss`
    /// - `es` term provides confidentiality + ephemeral forward secrecy.
    /// - Sender's static x_pub is encrypted under `k0 = KDF(es)` — hidden from the network.
    /// - `ss` term baked into `k1 = KDF(es || ss)` provides deniable authentication:
    ///   AEAD success proves the sender holds `alice_x_secret`, but Bob can also compute
    ///   `ss`, so he could have forged the box — making it deniable to third parties.
    pub fn seal_authenticated(
        sender: &Identity,
        recipient: &ContactCard,
        msg: &[u8],
    ) -> Result<Self> {
        let bob_x_pub = X25519PublicKey::from(recipient.x_pub);

        // e: ephemeral sender keypair
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_secret);

        // es: DH(eph, bob_x_pub)  →  k0
        let es = eph_secret.diffie_hellman(&bob_x_pub);
        let k0 = blake3::derive_key(KDF_CTX_ES, es.as_bytes());

        // s: encrypt Alice's static x_pub under k0
        let alice_x_pub_bytes: [u8; 32] = X25519PublicKey::from(&sender.x_secret).to_bytes();
        let nonce0 = random_nonce();
        let enc_s = aead_encrypt(k0, nonce0, &alice_x_pub_bytes)?;
        // enc_s is always 32 + 16 = 48 bytes (fixed-length, no prefix needed)
        debug_assert_eq!(enc_s.len(), 48);

        // ss: DH(alice_x_secret, bob_x_pub)  →  k1 = KDF(es || ss)
        let ss = sender.x_secret.diffie_hellman(&bob_x_pub);
        let k1 = kdf_ess(es.as_bytes(), ss.as_bytes());

        // msg: encrypt under k1 (padded to fixed bucket → no length leak).
        let nonce1 = random_nonce();
        let padded = crate::padding::pad(msg);
        let enc_msg = aead_encrypt(k1, nonce1, &padded)?;

        // Wire v2: [V2 1][eph_pub 32][nonce0 12][enc_s 48][nonce1 12][enc_msg ...]
        let mut wire = Vec::with_capacity(1 + 32 + 12 + 48 + 12 + enc_msg.len());
        wire.push(V2);
        wire.extend_from_slice(eph_pub.as_bytes());
        wire.extend_from_slice(&nonce0);
        wire.extend_from_slice(&enc_s);
        wire.extend_from_slice(&nonce1);
        wire.extend_from_slice(&enc_msg);

        Ok(Lockbox {
            envelope: format!("{}{}", BOX_PREFIX, BASE64.encode(&wire)),
        })
    }

    // ── open: plaintext-only (supports both v1 and v2) ───────────────────────

    /// Open a lockbox. Works for both v1 (anonymous) and v2 (authenticated) boxes.
    ///
    /// For v2, the sender x_pub is recovered and discarded — use
    /// [`open_authenticated`](Self::open_authenticated) if you need it.
    pub fn open(identity: &Identity, envelope: &str) -> Result<Vec<u8>> {
        Self::open_authenticated(identity, envelope).map(|(plain, _)| plain)
    }

    // ── open_authenticated: plaintext + optional sender x_pub ────────────────

    /// Open a lockbox and return `(plaintext, sender_x_pub)`.
    ///
    /// - v1 box → `sender_x_pub` is `None` (anonymous).
    /// - v2 box → `sender_x_pub` is `Some([u8; 32])` — the authenticated sender's
    ///   x25519 public key. Contact-matching is the caller's responsibility.
    pub fn open_authenticated(
        identity: &Identity,
        envelope: &str,
    ) -> Result<(Vec<u8>, Option<[u8; 32]>)> {
        let prefix = envelope
            .get(..BOX_PREFIX.len())
            .ok_or_else(|| Error::InvalidLockbox("too short".to_string()))?;
        if prefix != BOX_PREFIX {
            return Err(Error::InvalidLockbox(format!(
                "missing '{}' prefix",
                BOX_PREFIX
            )));
        }

        let wire = BASE64
            .decode(&envelope.as_bytes()[BOX_PREFIX.len()..])
            .map_err(|e| Error::InvalidLockbox(format!("base64: {}", e)))?;

        if wire.is_empty() {
            return Err(Error::InvalidLockbox("wire too short".to_string()));
        }

        match wire[0] {
            V1 => open_v1(identity, &wire),
            V2 => open_v2(identity, &wire),
            v => Err(Error::InvalidLockbox(format!("unknown version: {}", v))),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Version-specific open implementations
// ─────────────────────────────────────────────────────────────────────────────

fn open_v1(identity: &Identity, wire: &[u8]) -> Result<(Vec<u8>, Option<[u8; 32]>)> {
    // [V1 1][eph_pub 32][nonce 12][ct ...]
    const MIN: usize = 1 + 32 + 12 + 1;
    if wire.len() < MIN {
        return Err(Error::InvalidLockbox("v1 wire too short".to_string()));
    }

    let eph_pub_bytes: [u8; 32] = wire[1..33]
        .try_into()
        .map_err(|_| Error::InvalidLockbox("eph_pub slice".to_string()))?;
    let nonce_bytes: [u8; 12] = wire[33..45]
        .try_into()
        .map_err(|_| Error::InvalidLockbox("nonce slice".to_string()))?;
    let ct = &wire[45..];

    let eph_pub = X25519PublicKey::from(eph_pub_bytes);
    let shared = identity.x_secret.diffie_hellman(&eph_pub);
    let key_bytes = blake3::derive_key(KDF_CONTEXT_V1, shared.as_bytes());

    let plaintext = aead_decrypt(key_bytes, nonce_bytes, ct)?;
    let plaintext = crate::padding::unpad(&plaintext)?;
    Ok((plaintext, None))
}

fn open_v2(identity: &Identity, wire: &[u8]) -> Result<(Vec<u8>, Option<[u8; 32]>)> {
    // [V2 1][eph_pub 32][nonce0 12][enc_s 48][nonce1 12][enc_msg ...]
    const MIN: usize = 1 + 32 + 12 + 48 + 12 + 1;
    if wire.len() < MIN {
        return Err(Error::InvalidLockbox("v2 wire too short".to_string()));
    }

    let eph_pub_bytes: [u8; 32] = wire[1..33]
        .try_into()
        .map_err(|_| Error::InvalidLockbox("eph_pub slice".to_string()))?;
    let nonce0: [u8; 12] = wire[33..45]
        .try_into()
        .map_err(|_| Error::InvalidLockbox("nonce0 slice".to_string()))?;
    let enc_s = &wire[45..93]; // exactly 48 bytes
    let nonce1: [u8; 12] = wire[93..105]
        .try_into()
        .map_err(|_| Error::InvalidLockbox("nonce1 slice".to_string()))?;
    let enc_msg = &wire[105..];

    let eph_pub = X25519PublicKey::from(eph_pub_bytes);

    // es: DH(bob_x_secret, eph_pub)  →  k0
    let es = identity.x_secret.diffie_hellman(&eph_pub);
    let k0 = blake3::derive_key(KDF_CTX_ES, es.as_bytes());

    // Decrypt enc_s → recover alice_x_pub
    let alice_x_pub_bytes_vec = aead_decrypt(k0, nonce0, enc_s)?;
    let alice_x_pub_bytes: [u8; 32] = alice_x_pub_bytes_vec
        .try_into()
        .map_err(|_| Error::InvalidLockbox("sender x_pub wrong length".to_string()))?;
    let alice_x_pub = X25519PublicKey::from(alice_x_pub_bytes);

    // ss: DH(bob_x_secret, alice_x_pub)  →  k1
    let ss = identity.x_secret.diffie_hellman(&alice_x_pub);
    let k1 = kdf_ess(es.as_bytes(), ss.as_bytes());

    // Decrypt enc_msg — AEAD success IS the authentication
    let plaintext = aead_decrypt(k1, nonce1, enc_msg)?;
    let plaintext = crate::padding::unpad(&plaintext)?;
    Ok((plaintext, Some(alice_x_pub_bytes)))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use x25519_dalek::PublicKey as X25519PublicKey;

    // Helper: build a ContactCard from an Identity (the card the sender keeps for the recipient).
    fn card(id: &Identity) -> ContactCard {
        id.contact_card()
    }

    // ── 1. Authenticated round-trip ───────────────────────────────────────────

    #[test]
    fn test_v2_authenticated_roundtrip() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let msg = b"hello from alice";
        let lb = Lockbox::seal_authenticated(&alice, &card(&bob), msg)
            .expect("seal_authenticated failed");

        let (plain, sender_x_pub) =
            Lockbox::open_authenticated(&bob, &lb.envelope).expect("open_authenticated failed");

        assert_eq!(plain, msg);

        let recovered = sender_x_pub.expect("v2 must return sender x_pub");
        let alice_x_pub: [u8; 32] = X25519PublicKey::from(&alice.x_secret).to_bytes();
        assert_eq!(
            recovered, alice_x_pub,
            "recovered sender x_pub must match Alice's"
        );
    }

    // ── 2. Wrong recipient (Eve) cannot open Alice→Bob box ────────────────────

    #[test]
    fn test_v2_wrong_recipient_fails() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();

        let lb = Lockbox::seal_authenticated(&alice, &card(&bob), b"secret")
            .expect("seal failed");

        let result = Lockbox::open_authenticated(&eve, &lb.envelope);
        assert!(
            result.is_err(),
            "Eve must not be able to open a box sealed to Bob"
        );
    }

    // ── 3. Tampered envelope → open fails ─────────────────────────────────────

    #[test]
    fn test_v2_tamper_fails() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let lb = Lockbox::seal_authenticated(&alice, &card(&bob), b"integrity check")
            .expect("seal failed");

        // Flip a byte in the base64 body (deep in the ciphertext region).
        let prefix_len = BOX_PREFIX.len();
        let mut bytes = BASE64
            .decode(&lb.envelope.as_bytes()[prefix_len..])
            .unwrap();
        let flip_idx = bytes.len() - 5;
        bytes[flip_idx] ^= 0xFF;
        let tampered = format!("{}{}", BOX_PREFIX, BASE64.encode(&bytes));

        assert!(
            Lockbox::open_authenticated(&bob, &tampered).is_err(),
            "tampered box must fail"
        );
    }

    // ── 4. v1 back-compat ─────────────────────────────────────────────────────

    #[test]
    fn test_v1_backcompat() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let lb = Lockbox::seal_to_card(&card(&bob), b"old anon message").expect("seal failed");

        // open() must still work
        let plain = Lockbox::open(&bob, &lb.envelope).expect("v1 open() failed");
        assert_eq!(plain, b"old anon message");

        // open_authenticated() must also work, with sender == None
        let (plain2, sender) =
            Lockbox::open_authenticated(&bob, &lb.envelope).expect("v1 open_authenticated failed");
        assert_eq!(plain2, b"old anon message");
        assert!(sender.is_none(), "v1 box must return no sender");

        // alice's box must NOT open with alice's identity (different recipient)
        assert!(Lockbox::open(&alice, &lb.envelope).is_err());
    }

    // ── 5. Deniability: Bob can forge a "from-Alice" box ──────────────────────
    //
    // Because ss = DH(alice_sec, bob_pub) = DH(bob_sec, alice_pub), Bob holds
    // bob_x_secret and alice's ContactCard (= alice_x_pub).  He can compute the
    // exact same ss term as Alice would, build a valid v2 wire, and Bob's own
    // open_authenticated() call succeeds — i.e. the box is FORGEABLE by the
    // recipient, which means it's DENIABLE to third parties.
    //
    // This test demonstrates the symmetry by having Bob craft the box manually
    // using only (bob_x_secret, alice_x_pub, bob_x_pub, some_msg) — no
    // alice_x_secret — and showing that Bob can open it with the same result.
    #[test]
    fn test_v2_deniability_recipient_forgeable() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let alice_x_pub: [u8; 32] = X25519PublicKey::from(&alice.x_secret).to_bytes();
        let bob_x_pub_key = X25519PublicKey::from(&bob.x_secret);

        let msg = b"deniable message";

        // Bob forges a "from-Alice" box to himself:
        //   - He uses a fresh ephemeral
        //   - es = DH(eph, bob_x_pub)  — he can compute this because it's his own key
        //   - ss = DH(bob_x_secret, alice_x_pub)  — symmetric, no alice_x_secret needed
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph_secret);

        let es = eph_secret.diffie_hellman(&bob_x_pub_key);
        let k0 = blake3::derive_key(KDF_CTX_ES, es.as_bytes());

        let nonce0 = random_nonce();
        let enc_s = aead_encrypt(k0, nonce0, &alice_x_pub).expect("enc_s failed");

        let alice_x_pub_key = X25519PublicKey::from(alice_x_pub);
        let ss = bob.x_secret.diffie_hellman(&alice_x_pub_key); // DH(bob_sec, alice_pub)
        let k1 = kdf_ess(es.as_bytes(), ss.as_bytes());

        let nonce1 = random_nonce();
        let enc_msg = aead_encrypt(k1, nonce1, &crate::padding::pad(msg)).expect("enc_msg failed");

        let mut wire = Vec::new();
        wire.push(V2);
        wire.extend_from_slice(eph_pub.as_bytes());
        wire.extend_from_slice(&nonce0);
        wire.extend_from_slice(&enc_s);
        wire.extend_from_slice(&nonce1);
        wire.extend_from_slice(&enc_msg);

        let forged_envelope = format!("{}{}", BOX_PREFIX, BASE64.encode(&wire));

        // Bob opens his own forgery — it succeeds.
        let (plain, sender) =
            Lockbox::open_authenticated(&bob, &forged_envelope).expect("Bob's forgery failed");
        assert_eq!(plain, msg);
        assert_eq!(
            sender.unwrap(),
            alice_x_pub,
            "forged box claims to be from Alice"
        );
        // ∴ Bob could have sent any "from-Alice" message himself → deniable. ✓
    }

    // ── 6. open() (plaintext-only) works on v2 box ───────────────────────────

    #[test]
    fn test_v2_open_plaintext_only() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let lb = Lockbox::seal_authenticated(&alice, &card(&bob), b"plaintext-only path")
            .expect("seal failed");

        let plain = Lockbox::open(&bob, &lb.envelope).expect("open() on v2 box failed");
        assert_eq!(plain, b"plaintext-only path");
    }
}
