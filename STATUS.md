# Darqual — STATUS (living tracker)

Honest, evidence-based status. Updated as Jawz builds. Three buckets:
**✅ DONE+TESTED** · **🟡 SCAFFOLDED** · **🔬 OPEN-RESEARCH** (cannot be "finished" overnight by anyone).

Last update: 2026-07-19 — Tier-1 single-relay async path + nightly hardening.

---

## Tier-1 async dead-drop MVP (2026-07-19) — ✅ WIRED, single-relay scope

The direct-dial gap now has a working **single-relay async path** on branch
`feat/tier1-dead-drop-mvp`. `darqual-tor-node relay` hosts a persistent PoW-gated hot-window
ledger on a Tor v3 onion; `drop-send` submits labelled lockboxes to that relay; `drop-fetch`
retrieves public blocks and opens only the recipient's matching label. Alice and Bob never dial
each other in this mode. One live avante-relay / jade-client run observed offline delivery,
wrong-recipient rejection, and relay-restart persistence. Deterministic automated tests now cover
Alice→relay→Bob, Eve rejection, sender exit, restart persistence, plaintext absence, malformed
request recovery, replay rejection, bounded snapshots, and one-epoch clock skew. See
`docs/TIER1-LIVE-VERIFICATION.md`.

**Compatibility:** the explicit `LedgerPage { blocks, truncated }` response introduced at
`fe9b5ca` is not wire-compatible with earlier feature-branch relay/client binaries. Rebuild both
ends from the same feature revision.

**Scope boundary:** this closes the *application wiring* gap for an async MVP, not the research
mission. One relay still observes write/read timing; there is no DPF private write, PIR private
read, mandatory cover schedule, or multi-relay anytrust protocol. Therefore full contact-graph
privacy against a global passive observer remains **NOT delivered**.

Commands:

```bash
# Relay
darqual-tor-node relay --state ~/.darqual/relay-ledger.bin --window 60 --pow-difficulty 12

# Alice (only the relay onion is supplied; there is no Bob onion argument)
darqual-tor-node drop-send --relay <relay>.onion --to dqcard1... --message "hello"

# Bob, later/offline-safe
darqual-tor-node drop-fetch --relay <relay>.onion --from dqcard1...
```

---

## Verification policy
Nothing is marked ✅ without `scripts/verify.sh` GREEN (cargo build + cargo test +
clippy -D warnings + live messaging demo) and a git commit. Agent reports are verified
independently before any claim.

---

## Stage status

| Stage | Version | Status | Evidence |
|---|---|---|---|
| 0 — Foundation (identity, lockbox, CLI) | v0.0.1 | ✅ DONE+TESTED | tag v0.0.1; 10 tests; verify.sh green; live Alice→Bob→Eve demo |
| 1 — Transport (onion-to-onion) | v0.1.x | ✅ DONE+TESTED (LIVE TOR) | TCP→**Arti/Tor onion** complete (S222). `darqual-tor` crate: live bootstrap, v3 onion service host + dial. `darqual-tor-node` binary (`host`/`send`). The IP-leak gap is CLOSED. |
| 2 — Ledger (epochs, hot-window) | v0.2.0 | ✅ DONE+TESTED | tag v0.2.0; 22 ledger tests; Merkle+proofs, hash-linked chain, trial-decrypt sweep verified |
| 3 — Addressing & notification | v0.3.0 | ✅ DONE+TESTED | tag v0.3.0; +8 tests; dead-drop labels (symmetric, per-epoch, unlinkable) + notify + fetch_open |
| 4 — Write path + RLN spam | v0.4.0 | ✅ DONE+TESTED (PoW) | tag v0.4.0; +PoW tests; difficulty-enforced spam gate. RLN/DPF = documented research path |
| 5 — Storage scaling (buckets, erasure, DA) | v0.5.0 | ✅ DONE+TESTED | tag v0.5.0; 16 tests; buckets + Reed-Solomon + DA sampling + repair |
| 6 — Committees (VRF) [NOVEL CORE] | v0.6.0 | ✅ DONE+TESTED (election) | tag v0.6.0; 12 tests; VRF sortition. anytrust protocol + sybil = documented research |
| 7 — Discovery (Alpenhorn IBE) | v0.7.0 | ✅ DONE+TESTED (keywheel) | tag v0.7.0; 6 tests; forward-secret labels. IBE add-friend = pairing crypto, documented research |
| 8 — Metadata hardening (cover/DP/Loopix) | v0.8.0 | ✅ DONE+TESTED | tag v0.8.0; 10 tests; cover traffic + DP noise. Loopix/Sphinx = documented research |
| 9 — Clients (mobile light + L2 realtime) | v0.9.0 | ✅ DONE+TESTED (light-client) | tag v0.9.0; 3 integration tests + live demo; block transport + fetch-by-label. Realtime-L2/UI/groups = deferred/research |
| 10 — Hardening + audit + beta | v1.0 | 🟡 PARTIAL → 🔬 BLOCKED | threat-model doc + property/fuzz tests = tractable (doing); external audit + real beta users = genuine blocker, not autonomously possible |

---

## Content-crypto layer (S222, 2026-06-26) — ✅ NEW, the Signal-grade messaging stack

The S218 build sealed messages as **anonymous static-key sealed boxes** (no sender auth, no
forward secrecy). S222 replaced that with the full Signal-grade content-crypto stack and wired
it into the live node. All hand-rolled on existing x25519 + blake3 + chacha20poly1305 (no new
runtime deps except `bincode` for session persistence). Every phase: design note → build →
independently re-verified → `verify.sh` green + clippy `-D warnings` clean.

| Phase | What | Property | Evidence |
|---|---|---|---|
| 1 — Lockbox v2 | Noise IK (e, es, s, ss); sender static encrypted inside the AEAD | confidentiality + **deniable sender auth** + sender-hidden-from-network | commit `ce5e699`; 6 tests incl. a real deniability/forgeability proof |
| 2 — Double Ratchet | RK/CK chains + DH ratchet, MAX_SKIP DoS bound | per-message **forward secrecy** + **post-compromise security** | commit `9d46e25`; 7 tests incl. genuine FS + PCS proofs |
| 2b — Header encryption | Signal HE variant; 4 header keys, trial-decryption | **metadata-dark headers** (no linkable pubkeys/counters on the wire) | commit `39f2047`; 9 tests incl. header-privacy + trial-decrypt-path |
| Wiring | `SessionStore` (persisted per-peer) + node rewire | the **node actually uses** the ratchet over Tor | commits `b9edb80` (core) + `d2db642` (tor); 5 session tests |

Design notes: `~/Jawz/notes/projects/anon-messenger-research/{14,15,16,17}-*.md`.
Closes SPEC §11.3 (forward-secrecy-vs-static-lockboxes). **NOT pushed** as of S222.

---

## What v0.0.1 actually does (try it)
```
cargo build
BIN=target/debug/darqual
HOME=/tmp/a $BIN keygen            # Alice identity + address + contact card
HOME=/tmp/b $BIN keygen            # Bob
CARD=$(HOME=/tmp/b $BIN address | grep -o 'dqcard1[a-z0-9]*')
BOX=$(HOME=/tmp/a $BIN seal --to "$CARD" --message "hello bob" | grep -o 'dqbox1[A-Za-z0-9+/=]*')
HOME=/tmp/b $BIN open --lockbox "$BOX"     # -> "hello bob"
HOME=/tmp/c $BIN keygen; HOME=/tmp/c $BIN open --lockbox "$BOX"   # -> "not addressed to you"
```

## Honest frontier note (read before judging completeness)
Stages 6 & 10 are flagged research/external on purpose. VRF-committee anytrust with
Pung-strength in a serverless setting is an **open research question** (stated in SPEC §1).
Stage 10 requires an **external security audit + real beta users**. No autonomous overnight
run finishes those "for good." Everything below that line will be built, tested, and committed
as far as it verifiably holds together — truth over theater.

---

## Build log
- **S222 (2026-06-26): content-crypto layer + live Tor + session wiring.** 6 commits (NOT
  pushed). (1) committed the stranded `darqual-tor-node` CLI (`29919b1`) — host/send over live
  v3 onion services; (2) Lockbox v2 deniable auth `ce5e699`; (3) Double Ratchet FS+PCS
  `9d46e25`; (4) header encryption `39f2047`; (5+6) `SessionStore` + node rewire `b9edb80`,
  `d2db642`. The node now uses persisted ratchet sessions over Tor. ~50+ new tests across the
  phases; every phase verify.sh-green + independently re-verified. The IP-leak gap and the
  forward-secrecy gap are both CLOSED.
- S218 overnight→day (2026-06-24): Stages 0–9 shipped + Stage 10 partial. 11 tags
  (v0.0.1 → v0.10.0). **164 tests, all green.** verify.sh gate run before every commit;
  every subagent's work verified independently (caught a recursive-trait bug, clippy nits,
  flawed test assumptions). Whole pipeline demoed live end-to-end over the network.
  - v0.0.1 Foundation · v0.1.0 Transport(TCP) · v0.2.0 Ledger · v0.3.0 Dead-drop labels
  - v0.4.0 PoW spam · v0.5.0 Storage(buckets+erasure+DA) · v0.6.0 VRF committees
  - v0.7.0 Keywheel(forward-secret) · v0.8.0 Cover+DP · v0.9.0 E2E light-client
  - v0.10.0 Threat model + property/fuzz tests
- 🧱 HIT THE WALL (honest): Stage 10's external audit + real beta users = not autonomously
  possible. Also documented-not-built (research/deferred): PIR retrieval, full RLN/DPF, IBE
  add-friend (pairings), Loopix/Sphinx mix, the full anytrust committee protocol + sybil-
  resistant set. (Tor/Arti transport swap and content forward-secrecy/Double-Ratchet were on
  this list at S218 — both DONE at S222.) See THREAT-MODEL.md for the complete honest accounting.
- RESUME POINTS (highest value first): (1) **simultaneous-initiate race** — two peers sending
  first at once diverge; needs session-IDs / X3DH prekeys. (2) **harden the Tier-1 dead-drop path**
  — keywheel persistence, receiver-side chain validation, fetch pagination/rate limits, and
  repeatable live smoke automation. (3) **encrypt session files at rest**
  (`~/.darqual/sessions` holds secrets). (4) PIR retrieval. (5) external audit.

---

## How to run the spine (end-to-end, today)
```bash
cd ~/Projects/darqual && cargo build
DQ=target/debug/darqual; NODE=target/debug/darqual-node

# 1. two identities
HOME=/tmp/a $DQ keygen ; HOME=/tmp/b $DQ keygen
BCARD=$(HOME=/tmp/b $DQ address | grep -o 'dqcard1[a-z0-9]*')

# 2. OFFLINE lockbox (Stage 0): seal -> open
BOX=$(HOME=/tmp/a $DQ seal --to "$BCARD" --message "hi bob" | grep -o 'dqbox1[A-Za-z0-9+/=]*')
HOME=/tmp/b $DQ open --lockbox "$BOX"                 # -> "hi bob"

# 3. OVER LIVE TOR with ratchet sessions (Stage 1 + content-crypto, S222):
#    build the Tor node standalone (excluded from root workspace — ~2min Arti compile):
cd crates/darqual-tor && cargo build && cd ../..
TORNODE=crates/darqual-tor/target/debug/darqual-tor-node
#    Bob hosts an onion service (prints his .onion); Alice sends to it.
HOME=/tmp/b $TORNODE host                                  # in one terminal → prints <bob>.onion
HOME=/tmp/a $TORNODE send --onion <bob>.onion --to "$BCARD" --message "over live tor"
#   Bob prints: [recv] over live tor   — forward-secret, post-compromise-secure, encrypted header.
#   Sessions persist in ~/.darqual/sessions/ and advance per message.

# 4. THE LEDGER (Stage 2): see crates/darqual-ledger tests — build a block of
#    lockboxes, Merkle-root it, trial-decrypt to surface only your messages.
```
Regression gate (run after ANY change): `./scripts/verify.sh`

## What's NOT done (honest)
- The **direct ratcheted mode** still dials a peer onion and requires both peers online. The
  separate **Tier-1 dead-drop mode** is wired and async through one relay, but uses static
  per-epoch conversation labels rather than persisted forward-secret keywheel state. One relay
  still sees write/read timing, and reads/writes are not PIR/DPF-private.
- **Simultaneous-initiate race** unsolved (needs session-IDs / X3DH prekeys).
- **Session files not encrypted at rest** (`~/.darqual/sessions`, 0600 but plaintext secrets).
- Message **length** still observable — fixed-bucket padding not yet enforced at transport.
- Stages 6 & 10 contain open-research + external-audit work that cannot be finished
  autonomously. Content crypto (auth/FS/PCS/header-privacy) and Tor transport are DONE (S222);
  this is now a working metadata-dark messenger spine, not yet the finished anonymity system.

