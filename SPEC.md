# Darqual — Specification (v0)

> **Darqual** — a metadata-dark, asynchronous, peer-to-peer anonymous messenger.
> Turing's secure-comms dream rebuilt to beat the surveillance state.
> Codename locked S218 (2026-06-24). Lead: Jawz. Owner: Haseeb.

Full architecture rationale + the 7-paper synthesis live in
`~/Jawz/notes/projects/anon-messenger-research/`. This SPEC is the buildable contract.

---

## 1. Mission & what Darqual is (and is not)

> **MISSION (locked S222): Darqual is an anonymity *research* system.** Its single
> optimization target is **metadata-darkness against a global passive observer** — making
> *"who is talking to whom, and when?"* unanswerable to an adversary that watches all network
> traffic and controls a dishonest supermajority of participants (anytrust per epoch).
> Everything else is subordinate to that one goal.

- **Is:** a serverless, metadata-resistant comms network where messages are per-recipient
  encrypted "lockboxes," sends and receives are both unlinkable, and the question
  *"who is talking to whom?"* is unanswerable to a global observer.
- **Is not:** a real-time WhatsApp clone. Darqual is **async by nature** (the latency *is* the
  anonymity — Anonymity Trilemma, Das et al. S&P'18). Think: *email even a nation-state can't
  social-graph,* with an opt-in real-time channel for two online peers who accept the tradeoff.
- **Is NOT (mission boundary):** a **personal-safety tool for an individual a hostile state is
  hunting.** Darqual protects *the network's* metadata against *mass / global* observation; it
  does **not** protect *a marked person* against *targeted active attack.* See §3a (Anti-goals).
- **Target adversary:** the global passive observer + dishonest supermajority. Beneficiaries are
  populations whose *aggregate* communications metadata would otherwise be dragnet-harvested —
  not a specific dissident whose phone is already in the crosshairs of Pegasus-grade tooling.

## 3a. Anti-goals — who/what Darqual does NOT protect (read before trusting it)

Honesty is the first security property. Under Mission A, these are **explicitly out of scope**,
and no amount of crypto on the wire fixes them:

- **Endpoint compromise.** Targeted spyware (Pegasus-grade) reads plaintext on the screen
  before/after encryption. This defeats *all* message crypto — Darqual, Signal, anything. For a
  *targeted* user this is the dominant risk, and Darqual does not address it.
- **Targeted nation-state with physical access.** Device seizure, border search, raids — the
  identity, sessions, and contact cards live on the device.
- **Coercion / duress.** Rubber-hose key extraction. No panic-wipe, no duress password, no
  plausible-deniability hidden volume. Message *deniability* protects you from a courtroom — not
  from a regime that doesn't use courtrooms.
- **Internet shutdowns.** Darqual is Tor-only. When a state cuts or throttles the net (the common
  move during protests), Darqual is a brick. (Briar's Bluetooth/LAN mesh is the answer there —
  Darqual deliberately does not chase it.)
- **Tool-usage detectability.** Vanilla Tor is fingerprintable by a national firewall; Darqual
  has no pluggable transports. In regimes where *using* a circumvention tool is itself the crime,
  the encryption never gets a chance to matter.
- **Safe first contact under danger.** No anonymous discovery (IBE add-friend is research);
  bootstrapping a contact requires a pre-existing secure channel.

> **If a nation-state is hunting you specifically, Darqual is not your shield.** Get physically
> out, with help; use Briar/Signal + operational security + physical safety. Darqual is research
> into *mass* metadata-darkness, not a bodyguard for a marked individual.

## 2. Security goals
| Property | Guarantee |
|---|---|
| Content confidentiality | E2E AEAD; only the recipient can read |
| Recipient anonymity | observer can't tell who a lockbox is for |
| Sender anonymity (to network) | observer can't tell who sent it |
| Sender authentication (deniable) | recipient knows it's you; can't prove it to a third party (Noise IK, S222) |
| Contact-graph privacy | who-talks-to-whom is hidden |
| Integrity / tamper-evidence | AEAD + Merkle-linked ledger |
| Forward secrecy + post-compromise | per-msg message keys + DH ratchet self-heal (Double Ratchet, S222 ✅) |
| Header / metadata privacy | ratchet headers encrypted — no linkable pubkeys/counters on the wire (S222) |
| Sybil/spam resistance | anonymous rate-limiting (PoW now; RLN research), no payment graph |
| Availability under churn | erasure coding + data-availability sampling |

**Non-goal (v0):** defeating a *global active* adversary that corrupts an entire epoch
committee. We make it economically/cryptographically hard, not impossible.

## 3. Threat model
- **In scope (what we defend):** a **global passive observer** that watches all network traffic,
  plus a **dishonest supermajority** of participants (anytrust per epoch: ≥1 honest member in
  each epoch's elected committee). Goal: this adversary cannot answer *who-talks-to-whom-when*.
- **Out of scope (see §3a):** a global *active* adversary that corrupts an entire epoch's
  committee; **endpoint compromise**; a state mounting **targeted** physical/coercive/malware
  attacks on a specific person; **internet shutdowns**; detection that you're *using* the tool.
- **Trust:** **anytrust per epoch** — ≥1 honest member in each epoch's elected committee.
- **Transport:** Tor v3 onion services (location hiding + self-authenticating addresses) — **LIVE
  (S222)**. Optional Loopix mix layer for added global-passive resistance = research.

## 4. Core primitives (the vocabulary)
- **Identity:** ed25519 keypair (signing/identity) + X25519 keypair (encryption).
- **Darqual Address:** `dq1` + base32(BLAKE3(ed_pub || x_pub)[..20])` — self-authenticating, commits to BOTH signing + encryption keys.
- **Contact string:** address + both public keys, shareable out-of-band.
- **Lockbox:** the message envelope. **v1** = anonymous sealed box (`ephemeral_x25519 ‖ nonce ‖
  AEAD`), no sender identity. **v2 (S222)** = Noise IK — adds a static-static DH term for
  **deniable sender authentication** with the sender's identity encrypted *inside* the AEAD
  (authenticated to the recipient, hidden from the network). v2 is the session **bootstrap**.
- **Session (S222):** once bootstrapped, ongoing messages use a **Double Ratchet** (per-message
  forward secrecy + post-compromise security) with **encrypted headers**. Persisted per-peer.
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
