# Darqual — Roadmap (stages → tasks → subtasks)

Exhaustive build breakdown. Each **Stage** ships a version. Tasks are sequenced; subtasks are
the granular work. Mirrored into the synaps task system at the stage level (see S218 brief).

Legend: `[ ]` todo · `[~]` in progress · `[x]` done

---

## ⚠️ STATUS RECONCILIATION (S222, 2026-06-26) — read this first
This roadmap is the **original pre-build plan** (S218) and its granular `[ ]` boxes were never
ticked. **`STATUS.md` is the authoritative, evidence-based tracker.** Stage-level reality:

| Stage | Reality | Stage | Reality |
|---|---|---|---|
| 0 Foundation | ✅ done (v0.0.1) | 6 Committees | 🟡 VRF election only; anytrust+sybil = research |
| 1 Transport | ✅ **LIVE TOR** (S222) | 7 Discovery | 🟡 keywheel only; IBE add-friend = research |
| 2 Ledger | ✅ done | 8 Metadata harden | 🟡 cover+DP done; Loopix = research |
| 3 Addressing/notify | ✅ done (label-based) | 9 Clients | 🟡 light-client; UI/groups deferred |
| 4 Write path | 🟡 PoW spam (DPF = research) | 10 Hardening/audit | 🟡 partial; ext. audit = blocked |
| 5 Storage scaling | ✅ done (RS+DA) | **Content-crypto** | ✅ **S222, see bottom** |

Granular boxes below are NOT individually re-ticked — trust `STATUS.md` + the per-stage tags.

---

## STAGE 0 — Foundation (v0.0.x)  ✅ DONE (tag v0.0.1)
**Goal:** cryptographic identity + lockboxes + CLI. No network.

### 0.1 Workspace scaffold
- [ ] Cargo workspace + `crates/darqual-core` (lib) + `crates/darqual-cli` (bin)
- [ ] Shared lints, `rust-toolchain`, CI stub, `.gitignore`, MIT/AGPL license decision
- [ ] `thiserror` error enum, `Result` alias

### 0.2 Identity
- [ ] ed25519 keypair (identity/signing) via `ed25519-dalek`
- [ ] X25519 keypair (encryption) via `x25519-dalek`
- [ ] `Identity` struct: generate, serialize (toml), `zeroize` secrets on drop
- [ ] Keystore: save/load `~/.darqual/identity.toml`, 0600 perms
- [ ] `DarqualAddress` = `dq1` + base32(BLAKE3(ed_pub)[..20]); display/parse; checksum

### 0.3 Lockbox (anonymous sealed box)
- [ ] `seal(recipient_x_pub, msg)`: ephemeral X25519 → ECDH → BLAKE3-KDF → ChaCha20Poly1305
- [ ] Wire format: `version || ephemeral_pub || nonce || ciphertext`; base64 envelope
- [ ] `open(identity, lockbox)`: ECDH w/ stored secret → AEAD decrypt → `Option<msg>`
- [ ] Sender carries NO identity in the lockbox (anonymous-sender property)

### 0.4 Contact card
- [ ] `ContactCard` = address + ed_pub + x_pub; serialize to a shareable string
- [ ] Parse + verify address⇄pubkey consistency (self-authentication check)

### 0.5 CLI (`darqual`)
- [ ] `clap` derive; subcommands keygen / address / seal / open
- [ ] pretty output, error UX, `--json` flag

### 0.6 Tests + docs
- [ ] roundtrip, wrong-recipient, tamper/AEAD-reject, deterministic address, keystore roundtrip
- [ ] README quickstart; `cargo build` + `cargo test` green
- [ ] **TAG v0.0.1**

### 0.7 Foundation polish (v0.0.2+)
- [ ] ed25519 signing/verify API; signed contact cards
- [ ] message framing/length-padding to fixed buckets (size-metadata defense groundwork)
- [ ] property tests (proptest), fuzz target for lockbox parser

---

## STAGE 1 — Transport (v0.1.x)  ✅ DONE — LIVE TOR (S222)
**Goal:** onion-to-onion, both-online messaging (Ricochet-level).
- [x] `darqual-tor` crate; integrate `arti-client` (embedded Tor) — live bootstrap
- [x] publish a v3 onion service per node; host + dial over live Tor
- [x] dial a peer's onion address; framed wire protocol (`[sender_x_pub][bincode(RatchetMessage)]`)
- [x] E2E + forward secrecy over the circuit — done via **hand-rolled Noise IK + Double Ratchet**
      (NOT `snow`; see content-crypto track at bottom), not a circuit-level Noise handshake
- [x] send/receive between two online peers; manual address exchange; `darqual-tor-node` binary
- [~] connection mgmt, retries, timeouts — basic; daemon hardening deferred
- [~] integration test: session round-trip proven Tor-free in `darqual-core`; live 2-node Tor = manual

## STAGE 2 — Ledger (v0.2.x)
**Goal:** epoch blocks, hot-window replication, trial-decrypt.
- [ ] epoch clock; `Block` = ordered lockboxes; Merkle root; hash-link to prior
- [ ] hot-window store (sled/redb); prune aged epochs
- [ ] gossip/replication of recent blocks within a node set
- [ ] trial-decrypt sweep over the window; surface "my" messages
- [ ] block validation, header chain, checkpoints

## STAGE 3 — Addressing & Notification (v0.3.x)
**Goal:** dead-drop labels + "do I have mail?" cheaply.
- [ ] PRF dead-drop labels per conversation per epoch (Pung)
- [ ] label rotation; unlinkability across epochs
- [ ] Talek-style private notification DB + cheap PIR query
- [ ] conversation log abstraction (append-only per pair)

## STAGE 4 — Write path & spam resistance (v0.4.x)
**Goal:** private writes + un-floodable.
- [ ] DPF (distributed point function) private-write primitive (Riposte)
- [ ] epoch-boundary commit protocol; blind verifiable secret-sharing audit
- [ ] **RLN (Rate-Limiting Nullifiers)** membership + zk rate proof (Semaphore-style)
- [ ] slashing on rate-exceed; shielded registration stake (no payment graph)

## STAGE 5 — Storage scaling (v0.5.x)
**Goal:** beat the bandwidth wall.
- [ ] prefix-bucket sharding; bucket = privacy↔bandwidth dial
- [ ] Reed-Solomon erasure coding of cold blocks (`reed-solomon-erasure`)
- [ ] data-availability sampling (random ~30-chunk verify, Celestia-style)
- [ ] shard repair/healing under churn; replication factor mgmt

## STAGE 6 — Committees (v0.6.x)  ⟵ THE NOVEL CORE
**Goal:** replace "the server" with epoch committees.
- [ ] VRF (ECVRF) per-epoch committee election from participant set
- [ ] anytrust-per-epoch protocol for DPF commit + PIR notify + IBE PKG shares
- [ ] committee rotation, handoff, accountability
- [ ] sybil-resistant participant set (stake / PoW / proof-of-storage) — RESEARCH

## STAGE 7 — Discovery (v0.7.x)
**Goal:** add contacts without leaking the graph (Alpenhorn).
- [ ] IBE add-friend (identity-based encryption invite, threshold PKG)
- [ ] dialing protocol over mix/onion; keyword/keywheel ratchet
- [ ] contact-graph privacy end-to-end

## STAGE 8 — Metadata hardening (v0.8.x)
**Goal:** survive traffic analysis.
- [ ] mandatory cover traffic (every node sends every epoch)
- [ ] differential-privacy noise on dead-drop access counts (Vuvuzela); ε budget mgmt
- [ ] optional Loopix mix layer: Sphinx packets + Exp(μ) per-hop delay

## STAGE 9 — Clients (v0.9.x)
**Goal:** real usage surfaces.
- [ ] mobile light-client (provider-pull model, holds nothing)
- [ ] opt-in real-time onion Layer-2 channel (Ricochet mode, metadata tradeoff)
- [ ] desktop TUI/GUI; key backup/recovery UX
- [ ] group messaging (research-grade, defer hard parts)

## STAGE 10 — Hardening & beta (v1.0 track)
- [ ] threat-model validation doc; formal-ish argument per security goal
- [ ] fuzzing, property tests, constant-time review of crypto paths
- [ ] external security review / audit
- [ ] reproducible builds; signed releases; closed beta with real users

---

## Cross-cutting (every stage)
- [ ] no `unwrap` in lib paths; deny-warnings CI; `cargo audit`
- [ ] constant-time + zeroize discipline on all secret material
- [ ] benchmark each layer (latency/bandwidth/CPU) against the trilemma budget
- [ ] keep `SPEC.md` and the research notes in sync with reality

---

## CONTENT-CRYPTO TRACK (S222) — ✅ DONE, not in the original plan
The original roadmap assumed circuit-level `snow` Noise for E2E. S222 built a proper Signal-grade
content-crypto stack instead (design notes `14`–`17` in the research folder). All `[x]`,
verify.sh-green, independently re-verified, **not yet pushed**.

### CC.1 — Lockbox v2: deniable sender auth (Noise IK)  `ce5e699`
- [x] static-static DH (`ss`) MAC for sender auth; ephemeral (`es`) for confidentiality + FS
- [x] sender static encrypted inside the AEAD → authenticated to recipient, hidden from network
- [x] deniable (symmetric `ss` → recipient-forgeable); ed25519 NEVER signs content
- [x] v1 anonymous boxes preserved (version byte); 6 tests incl. deniability proof

### CC.2 — Double Ratchet: forward secrecy + post-compromise security  `9d46e25`
- [x] RK root chain + CKs/CKr symmetric chains; per-message message keys (FS)
- [x] DH ratchet (fresh x25519 per round-trip) → PCS / self-healing
- [x] out-of-order + skipped-key handling; `MAX_SKIP`/`MAX_SKIP_STORE` DoS bounds
- [x] serde-persistable; seeds from `Conversation` static-static SK; 7 tests incl. FS+PCS proofs

### CC.3 — Header encryption: metadata-dark headers (Signal HE variant)  `39f2047`
- [x] 4 header keys (HKs/HKr/NHKs/NHKr) ratcheted from the root chain
- [x] header trial-decryption (current vs next chain); `dh_pub`/`pn`/`n` all encrypted
- [x] observer/relay sees opaque `enc_header‖ciphertext`; 9 tests incl. header-privacy

### CC.4 — Session wiring: the node uses it  `b9edb80` (core) + `d2db642` (tor)
- [x] `SessionStore` — per-peer persisted sessions (`~/.darqual/sessions`, 0600, atomic writes)
- [x] initiator/responder bootstrap (send-first = initiator); `shared_secret_with` from raw x_pub
- [x] `darqual-tor-node` host/send rewired onto ratchet sessions over live Tor; 5 session tests
- [ ] **simultaneous-initiate race** → session-IDs / X3DH prekeys (deferred)
- [ ] **encrypt session files at rest** (deferred)
- [ ] **wire keywheel/dead-drop ledger into the node** (still direct onion dial; deferred)

### CC.5 — remaining content-crypto refinements (todo)
- [ ] fixed-bucket length padding (message-size metadata defense)
- [ ] drop the sender-tag for established sessions (trial-decrypt across sessions) to shrink metadata
- [ ] `git push` the S222 work + cut a release tag
