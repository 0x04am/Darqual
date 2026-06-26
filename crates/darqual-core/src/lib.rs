#![forbid(unsafe_code)]

pub mod address;
pub mod contact;
pub mod conversation;
pub mod error;
pub mod identity;
pub mod keywheel;
pub mod label;
pub mod lockbox;
pub mod pow;
pub mod ratchet;

pub use address::DarqualAddress;
pub use contact::ContactCard;
pub use conversation::Conversation;
pub use error::{Error, Result};
pub use identity::{verify_ed, Identity};
pub use keywheel::Keywheel;
pub use label::Label;
pub use lockbox::Lockbox;
pub use pow::{leading_zero_bits, mint as pow_mint, pow_hash, pow_valid, POW_DOMAIN};
pub use ratchet::{Header, RatchetMessage, RatchetSession, MAX_SKIP, MAX_SKIP_STORE};

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::PublicKey as X25519PublicKey;

    // ── Lockbox: seal → open roundtrip ──────────────────────────────────────

    #[test]
    fn lockbox_roundtrip() {
        let recipient = Identity::generate();
        let x_pub = X25519PublicKey::from(&recipient.x_secret);
        let msg = b"hello, anonymous world";

        let lb = Lockbox::seal(&x_pub, msg).expect("seal failed");
        let plaintext = Lockbox::open(&recipient, &lb.envelope).expect("open failed");
        assert_eq!(plaintext, msg);
    }

    // ── Lockbox: wrong recipient fails ───────────────────────────────────────

    #[test]
    fn lockbox_wrong_recipient() {
        let bob = Identity::generate();
        let alice = Identity::generate();
        let bob_x_pub = X25519PublicKey::from(&bob.x_secret);

        let lb = Lockbox::seal(&bob_x_pub, b"secret for bob").expect("seal failed");

        let result = Lockbox::open(&alice, &lb.envelope);
        assert!(
            matches!(result, Err(Error::Decrypt)),
            "expected Decrypt error, got: {:?}",
            result
        );
    }

    // ── Lockbox: tampered ciphertext ─────────────────────────────────────────

    #[test]
    fn lockbox_tamper_aead_reject() {
        let recipient = Identity::generate();
        let x_pub = X25519PublicKey::from(&recipient.x_secret);
        let lb = Lockbox::seal(&x_pub, b"tamper test").expect("seal failed");

        // Strip prefix, decode base64, flip a byte in ct, re-encode
        let prefix = "dqbox1";
        let b64 = &lb.envelope[prefix.len()..];
        let mut wire = data_encoding::BASE64.decode(b64.as_bytes()).unwrap();

        // Flip a byte in the ciphertext (after version[1] + eph_pub[32] + nonce[12] = 45)
        wire[50] ^= 0xFF;

        let tampered = format!("{}{}", prefix, data_encoding::BASE64.encode(&wire));
        let result = Lockbox::open(&recipient, &tampered);
        assert!(
            matches!(result, Err(Error::Decrypt)),
            "expected Decrypt on tamper, got: {:?}",
            result
        );
    }

    // ── Address: deterministic ───────────────────────────────────────────────

    #[test]
    fn address_deterministic() {
        let id = Identity::generate();
        let addr1 = id.address();
        let addr2 = id.address();
        assert_eq!(addr1, addr2);

        // Different identity → different address
        let id2 = Identity::generate();
        assert_ne!(id.address(), id2.address());
    }

    // ── ContactCard: verify() ────────────────────────────────────────────────

    #[test]
    fn contact_card_verify_pass() {
        let id = Identity::generate();
        let card = id.contact_card();
        assert!(card.verify(), "valid card should verify");
    }

    #[test]
    fn contact_card_verify_fail_swapped_ed_pub() {
        let id = Identity::generate();
        let id2 = Identity::generate();
        let mut card = id.contact_card();

        // Swap in a different ed_pub → address won't match
        card.ed_pub = id2.contact_card().ed_pub;
        assert!(!card.verify(), "tampered card should not verify");
    }

    #[test]
    fn contact_card_verify_fail_swapped_x_pub() {
        // Regression for the audit MITM finding: the address must bind the x25519
        // ENCRYPTION key too, so swapping x_pub (e.g. an attacker substituting their
        // own encryption key while keeping the victim's ed_pub) must fail verify().
        let id = Identity::generate();
        let attacker = Identity::generate();
        let mut card = id.contact_card();

        card.x_pub = attacker.contact_card().x_pub;
        assert!(
            !card.verify(),
            "card with a substituted encryption key must NOT verify (anti-MITM)"
        );
    }

    // ── ContactCard: encode → decode roundtrip ───────────────────────────────

    #[test]
    fn contact_card_roundtrip() {
        let id = Identity::generate();
        let card = id.contact_card();
        let encoded = card.to_string();

        let decoded = encoded.parse::<ContactCard>().expect("card parse failed");
        assert_eq!(decoded.address, card.address);
        assert_eq!(decoded.ed_pub, card.ed_pub);
        assert_eq!(decoded.x_pub, card.x_pub);
        assert!(decoded.verify());
    }

    // ── Identity: save → load roundtrip ─────────────────────────────────────

    #[test]
    fn identity_save_load_roundtrip() {
        let id = Identity::generate();
        let original_address = id.address();
        let original_ed_pub = id.signing_key.verifying_key().to_bytes();
        let original_x_pub = x25519_dalek::PublicKey::from(&id.x_secret).to_bytes();

        let tmp = std::env::temp_dir().join(format!(
            "darqual_test_{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));

        id.save(&tmp).expect("save failed");

        let loaded = Identity::load(&tmp).expect("load failed");
        assert_eq!(loaded.address(), original_address);
        assert_eq!(
            loaded.signing_key.verifying_key().to_bytes(),
            original_ed_pub
        );
        assert_eq!(
            x25519_dalek::PublicKey::from(&loaded.x_secret).to_bytes(),
            original_x_pub
        );

        // Cleanup
        let _ = std::fs::remove_file(&tmp);
    }

    // ── DarqualAddress: FromStr ──────────────────────────────────────────────

    #[test]
    fn address_from_str_valid() {
        let id = Identity::generate();
        let addr = id.address();
        let parsed: DarqualAddress = addr.as_str().parse().expect("parse failed");
        assert_eq!(addr, parsed);
    }

    #[test]
    fn address_from_str_invalid_prefix() {
        let result: Result<DarqualAddress> = "notdq1abc".parse();
        assert!(matches!(result, Err(Error::InvalidAddress(_))));
    }
}
