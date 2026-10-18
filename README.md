# Darqual

> Research prototype of a metadata-private, asynchronous, peer-to-peer messenger.
> Signal-grade content crypto over live Tor onion services. Unaudited.

> ## ⚠️ SAFETY — READ BEFORE TRUSTING THIS WITH ANYTHING
> **Darqual is a RESEARCH PROTOTYPE. It is NOT audited. Do NOT use it to protect a real person.**
> - It is **anonymity research** (hide who-talks-to-whom from *mass/global* observation) — **not a
>   personal-safety tool for someone a state is hunting.**
> - It does **NOT** protect against: a compromised phone (Pegasus-grade spyware reads your screen),
>   device seizure, coercion/torture, **internet shutdowns** (it's Tor-only — dies when the net is
>   cut), or the fact that *using* it may itself be detectable.
> - **It does not yet even deliver contact-graph privacy in the running app** — the current node
>   does a *direct connection*; the dead-drop layer that hides who-talks-to-whom is unwired.
> - **If a government is hunting you specifically, this is not your shield.** Use [Briar](https://briarproject.org)
>   / Signal + operational security + physical safety, and get out with help.
>
> Full accounting: **[THREAT-MODEL.md](THREAT-MODEL.md)** · mission & anti-goals: **[SPEC.md §1/§3a](SPEC.md)**

## What it is

Darqual is an anonymity-research messenger whose *design goal* is to make the question
*"who is talking to whom?"* unanswerable to a global passive observer. **This is the target, not a
delivered guarantee** — see the safety banner above and THREAT-MODEL.md for what actually works today.

## Where it stands

Live status, with evidence for every line, is in **[STATUS.md](STATUS.md)**. In short:

- **Transport:** onion-to-onion over embedded Tor (Arti): live bootstrap, v3 onion service host and dial (`darqual-tor`, `darqual-tor-node`).
- **Content crypto:** ed25519/x25519 identities, anonymous sealed boxes (ChaCha20-Poly1305), a Double Ratchet with forward secrecy and post-compromise security, and Signal-style header encryption. The node uses persisted ratchet sessions over Tor.
- **Protocol stages 0–9 built and tested** (ledger, dead-drop addressing, PoW spam gate, erasure-coded storage, VRF committees, forward-secret discovery labels, cover traffic, light client), each tagged `v0.x.0`.
- **Not done:** the dead-drop layer that hides who-talks-to-whom is not wired into the running node, which still connects directly. Stage 10 (external audit, real beta users) is blocked on things an autonomous build can't do.

Built by Jawz, an AI agent, under Haseeb Khalid's direction.

The quickstart below covers the original Stage 0 CLI (identity, address, sealed box).

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
| Forward secrecy + post-compromise security | ✓ Double Ratchet (see STATUS.md) |
| Header privacy | ✓ encrypted headers, trial decryption |
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
│   ├── darqual-core/          # identity, address, contact card, lockbox, ratchet, sessions
│   ├── darqual-cli/           # `darqual` binary
│   ├── darqual-ledger/        # epochs, Merkle proofs, hash-linked chain
│   ├── darqual-storage/       # buckets, Reed-Solomon, data-availability sampling
│   ├── darqual-committee/     # VRF sortition
│   ├── darqual-cover/         # cover traffic, DP noise
│   ├── darqual-net/           # networking
│   ├── darqual-node/          # node
│   └── darqual-tor/           # Arti/Tor onion transport (outside the gated workspace)
├── STATUS.md
├── SPEC.md
├── ROADMAP.md
└── README.md
```

## Roadmap

See `ROADMAP.md` for the plan and `STATUS.md` for what's done. Next: wire the dead-drop layer into the running node, then hardening toward an external audit.
