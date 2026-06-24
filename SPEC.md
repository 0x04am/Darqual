# Darqual — Specification (v0)

> **Darqual** — a metadata-dark, asynchronous, peer-to-peer anonymous messenger.
> Turing's secure-comms dream rebuilt to beat the surveillance state.
> Codename locked S218 (2026-06-24). Lead: Jawz. Owner: Haseeb.

Full architecture rationale + the 7-paper synthesis live in
`~/Jawz/notes/projects/anon-messenger-research/`. This SPEC is the buildable contract.

---

## 1. What Darqual is (and is not)
- **Is:** a serverless, metadata-resistant comms network where messages are per-recipient
  encrypted "lockboxes," sends and receives are both unlinkable, and the question
  *"who is talking to whom?"* is unanswerable to a global observer.
- **Is not:** a real-time WhatsApp clone. Darqual is **async by nature** (the latency *is* the
  anonymity — Anonymity Trilemma, Das et al. S&P'18). Think: *email even a nation-state can't
  social-graph,* with an opt-in real-time channel for two online peers who accept the tradeoff.
- **Target user:** nation-state threat model — journalists, dissidents, sources, whistleblowers.

## 2. Security goals
| Property | Guarantee |
|---|---|
| Content confidentiality | E2E AEAD; only the recipient can read |
| Recipient anonymity | observer can't tell who a lockbox is for |
| Sender anonymity | observer can't tell who sent it |
| Contact-graph privacy | who-talks-to-whom is hidden |
| Integrity / tamper-evidence | AEAD + Merkle-linked ledger |
| Forward secrecy | per-epoch label rotation + ratchet (later stages) |
| Sybil/spam resistance | anonymous rate-limiting (RLN), no payment graph |
| Availability under churn | erasure coding + data-availability sampling |

**Non-goal (v0):** defeating a *global active* adversary that corrupts an entire epoch
committee. We make it economically/cryptographically hard, not impossible.

## 3. Threat model
- **Adversary:** global passive observer + dishonest *supermajority* of participants.
- **Trust:** **anytrust per epoch** — ≥1 honest member in each epoch's elected committee.
- **Transport:** Tor v3 onion services (location hiding + self-authenticating addresses),
  optional Loopix mix layer for global-passive resistance.

## 4. Core primitives (the vocabulary)
- **Identity:** ed25519 keypair (signing/identity) + X25519 keypair (encryption).
- **Darqual Address:** `dq1` + base32(BLAKE3(ed_pub || x_pub)[..20])` — self-authenticating, commits to BOTH signing + encryption keys.
- **Contact string:** address + both public keys, shareable out-of-band.
- **Lockbox:** an anonymous sealed-box — `ephemeral_x25519_pub || nonce || AEAD(msg)` —
  encrypted to a recipient's X25519 key. Sender identity is NOT in the lockbox (anonymous).
- **Dead-drop label (later):** per-epoch PRF(shared_secret, epoch) → the slot a lockbox lives in.
- **Epoch:** a fixed time window; unit of ledger commit, committee rotation, label rotation.
- **Block:** the set of lockboxes committed in an epoch; Merkle-rooted, hash-linked to prior.
- **Hot window:** recent epochs, fully replicated within a bucket (privacy).
- **Cold archive:** aged epochs, erasure-coded + DA-sampled (availability).

## 5. Architecture layers (maps to ROADMAP stages)
0. **Foundation** — identity, lockbox crypto, CLI, on-disk keystore.
1. **Transport** — Arti (embedded Rust Tor), onion-to-onion, both-online (Ricochet-level).
2. **Ledger** — epoch blocks, Merkle linking, hot-window replication, trial-decrypt.
3. **Addressing & notification** — PRF dead-drop labels (Pung), private notification (Talek).
4. **Write path** — DPF private writes (Riposte), epoch commit, RLN spam resistance.
5. **Storage scaling** — prefix buckets, Reed-Solomon erasure coding, DA sampling (Celestia-style).
6. **Committees** — VRF-elected per-epoch relay committees (the novel core).
7. **Discovery** — IBE contact bootstrap + keywheel ratchet (Alpenhorn).
8. **Metadata hardening** — mandatory cover traffic, DP dead-drop noise (Vuvuzela), Loopix mix.
9. **Clients** — mobile light-client (provider-pull) + opt-in real-time onion Layer-2.
10. **Hardening** — threat-model validation, fuzzing, external review, beta.

## 6. Crypto stack (Rust crates)
- Identity/signing: `ed25519-dalek`
- Encryption/ECDH: `x25519-dalek`
- AEAD: `chacha20poly1305`
- Hash/PRF: `blake3`
- Encoding: `bs58` or `base32`, `base64`
- Zeroization: `zeroize`
- Errors: `thiserror`
- CLI: `clap` (derive)
- Serialization: `serde` + `toml`/`serde_json`
- RNG: `rand_core` / `getrandom`
- Later: `arti-client` (Tor), `reed-solomon-erasure`, a DPF crate or hand-rolled, RLN/Semaphore.

## 7. Workspace layout (target)
```
darqual/
├── Cargo.toml                 # workspace
├── crates/
│   ├── darqual-core/          # types, identity, lockbox, errors  (lib)
│   ├── darqual-ledger/        # epochs, blocks, Merkle            (later)
│   ├── darqual-net/           # Arti transport, onion services    (later)
│   ├── darqual-node/          # the daemon                        (later)
│   └── darqual-cli/           # `darqual` binary                  (bin)
├── SPEC.md  ROADMAP.md  README.md
```

## 8. Versioning
- `v0.0.x` — Stage 0 (Foundation). No network.
- `v0.1.x` — Stage 1 (Transport / onion-to-onion).
- `v0.2.x`+ — one minor per stage thereafter.
- Pre-1.0 = no stability promises. 1.0 = audited, threat-model-validated.

## 9. v0.0.1 — DEFINITION OF DONE
**"Identity & Lockbox" — the cryptographic foundation, no network.**
- `cargo build` and `cargo test` both pass.
- `darqual-core` lib exposes: `Identity` (gen, save, load), `DarqualAddress`,
  `ContactCard`, `Lockbox` (`seal(recipient, msg) -> Lockbox`, `open(identity) -> Option<msg>`).
- CLI `darqual`:
  - `keygen` — generate identity, persist to `~/.darqual/identity.toml`, print address.
  - `address` — print your Darqual address + contact card.
  - `seal --to <contact|pubkey> --message <text>` — emit a base64 lockbox (no sender info).
  - `open --lockbox <b64>` — decrypt with stored identity; print plaintext or "not addressed to you".
- Tests: seal→open roundtrip; wrong recipient fails to open; tamper (flip a byte) → AEAD reject;
  address derivation deterministic; identity save/load roundtrip.
- README with quickstart.

**Explicitly OUT of v0.0.1:** networking, Tor, ledger, epochs, committees, RLN. Foundation only.
