# Darqual v0.0.1

> Metadata-dark, asynchronous, peer-to-peer anonymous messenger.
> Cryptographic foundation — no network, no metadata, no bullshit.

## What it is

Darqual is an anonymous messenger built on a cryptographic foundation where the question *"who is talking to whom?"* is unanswerable to a global observer.

**v0.0.1** ships the cryptographic primitives:
- `Identity` — ed25519 (signing) + x25519 (encryption), stored at `~/.darqual/identity.toml`
- `DarqualAddress` — self-authenticating address: `dq1` + base32(BLAKE3(ed_pub)[..20])
- `ContactCard` — shareable public bundle (address + both pubkeys), self-verifying
- `Lockbox` — anonymous sealed box: ephemeral X25519 ECDH → BLAKE3-KDF → ChaCha20Poly1305. **Sender identity is NOT in the lockbox.**

## Quickstart

```sh
# Build
cargo build --release

# Generate your identity
darqual keygen
# Address: dq1abc...
# Contact card: dqcard1...

# Print your address + contact card
darqual address

# Seal a message to a recipient (use their contact card)
darqual seal --to dqcard1<their-card> --message "meet at the jazz club"
# dqbox1<base64-envelope>

# Open a lockbox sent to you
darqual open --lockbox dqbox1<envelope>
# meet at the jazz club

# Wrong recipient gets:
# not addressed to you
```

## Crypto design

```
Identity generation:
  ed_signing  = SigningKey::generate(&mut OsRng)        // ed25519
  x_secret    = StaticSecret::random_from_rng(OsRng)    // x25519

Address:
  dq1 + base32_nopad_lowercase(BLAKE3(ed_pub)[..20])

Lockbox.seal(recipient_x_pub, msg):
  eph         = EphemeralSecret::random_from_rng(OsRng)
  shared      = eph.diffie_hellman(recipient_x_pub)
  key         = BLAKE3::derive_key("darqual lockbox v1 :: x25519-chacha20poly1305", shared)
  nonce       = 12 random bytes
  ct          = ChaCha20Poly1305(key).encrypt(nonce, msg)
  wire        = [0x01][eph_pub 32B][nonce 12B][ct]
  envelope    = "dqbox1" + BASE64(wire)

Lockbox.open(identity, envelope):
  shared      = identity.x_secret.diffie_hellman(eph_pub)
  → same KDF → same key → decrypt
  wrong recipient or tampered → Err(Decrypt)
```

## Security properties

| Property | Status |
|---|---|
| Content confidentiality | ✓ ChaCha20Poly1305 AEAD |
| Sender anonymity | ✓ ephemeral key, no sender identity in lockbox |
| Recipient anonymity | ✓ no recipient identity in lockbox |
| AEAD integrity | ✓ any tamper → Err(Decrypt) |
| Secret key zeroization | ✓ `zeroize` on key bytes |
| Unsafe code | ✗ `#![forbid(unsafe_code)]` |

## Tests

```sh
cargo test
```

- `lockbox_roundtrip` — seal→open returns original plaintext
- `lockbox_wrong_recipient` — Alice can't open Bob's lockbox
- `lockbox_tamper_aead_reject` — flipped byte → AEAD error
- `address_deterministic` — same key → same address, different keys → different addresses
- `contact_card_verify_pass` — real card verifies
- `contact_card_verify_fail_swapped_ed_pub` — swapped pubkey doesn't verify
- `contact_card_roundtrip` — encode→decode preserves all fields
- `identity_save_load_roundtrip` — persisted identity reloads identically

## Workspace layout

```
darqual/
├── Cargo.toml                 # workspace
├── crates/
│   ├── darqual-core/          # Identity, DarqualAddress, ContactCard, Lockbox
│   └── darqual-cli/           # `darqual` binary
├── SPEC.md
├── ROADMAP.md
└── README.md
```

## Roadmap

See `ROADMAP.md`. Stage 1 adds onion transport via Arti (embedded Tor).
Next: v0.0.2 adds ed25519 signed contact cards, message padding, and property tests.
