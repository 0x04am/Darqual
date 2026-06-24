# Darqual — STATUS (living tracker)

Honest, evidence-based status. Updated as Jawz builds. Three buckets:
**✅ DONE+TESTED** · **🟡 SCAFFOLDED** · **🔬 OPEN-RESEARCH** (cannot be "finished" overnight by anyone).

Last update: S218 overnight build (2026-06-24).

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
| 1 — Transport (onion-to-onion) | v0.1.0 | ✅ DONE+TESTED (TCP) | tag v0.1.0; 2 net integration tests; verify.sh green; live two-daemon TCP demo (Alice→Bob recv, Eve rejected). Tor/Arti = v0.1.x next |
| 2 — Ledger (epochs, hot-window) | v0.2.0 | ✅ DONE+TESTED | tag v0.2.0; 22 ledger tests; Merkle+proofs, hash-linked chain, trial-decrypt sweep verified |
| 3 — Addressing & notification | v0.3.0 | ✅ DONE+TESTED | tag v0.3.0; +8 tests; dead-drop labels (symmetric, per-epoch, unlinkable) + notify + fetch_open |
| 4 — Write path + RLN spam | v0.4.0 | ✅ DONE+TESTED (PoW) | tag v0.4.0; +PoW tests; difficulty-enforced spam gate. RLN/DPF = documented research path |
| 5 — Storage scaling (buckets, erasure, DA) | v0.5.0 | ✅ DONE+TESTED | tag v0.5.0; 16 tests; buckets + Reed-Solomon + DA sampling + repair |
| 6 — Committees (VRF) [NOVEL CORE] | v0.6.0 | ✅ DONE+TESTED (election) | tag v0.6.0; 12 tests; VRF sortition. anytrust protocol + sybil = documented research |
| 7 — Discovery (Alpenhorn IBE) | v0.7.0 | ✅ DONE+TESTED (keywheel) | tag v0.7.0; 6 tests; forward-secret labels. IBE add-friend = pairing crypto, documented research |
| 8 — Metadata hardening (cover/DP/Loopix) | v0.8.x | ⏳ NEXT | cover traffic + DP dead-drop noise (tractable) building; Loopix/Sphinx = documented research |
| 9 — Clients (mobile light + L2 realtime) | v0.9.x | ⬜ todo | — |
| 10 — Hardening + audit + beta | v1.0 | 🔬 external | needs real audit + real beta users — NOT autonomously completable |

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
- S218 overnight (2026-06-24): Stages 0–2 shipped, tested, tagged.
  - v0.0.1 Foundation — identity, lockboxes, CLI (10 tests)
  - v0.1.0 Transport — TCP node-to-node + daemon (2 integration tests)
  - v0.2.0 Ledger — epochs, Merkle, hot-window, trial-decrypt (22 tests)
  - **34 tests total, all green.** verify.sh gate established + run before every commit.
  - 11-stage task ladder (#144–#153, epic #146); research corpus in
    ~/Jawz/notes/projects/anon-messenger-research/.
- RESUME POINT: Stage 3 (#147) — dead-drop PRF labels (Pung) + Talek private notification.

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

# 3. OVER THE NETWORK (Stage 1): Bob listens, Alice sends
HOME=/tmp/b $NODE listen --addr 127.0.0.1:19939 &     # in one terminal
HOME=/tmp/a $NODE send --peer 127.0.0.1:19939 --to "$BCARD" --message "over the wire"
#   Bob's listener prints:  [recv] over the wire

# 4. THE LEDGER (Stage 2): see crates/darqual-ledger tests — build a block of
#    lockboxes, Merkle-root it, trial-decrypt to surface only your messages.
```
Regression gate (run after ANY change): `./scripts/verify.sh`

## What's NOT done (honest)
- Stage 1 is TCP, not yet Tor — Arti/onion is the next transport increment (v0.1.x).
- No anonymity-network properties yet (cover traffic, mixing, dead-drops, committees).
  Stages 3–10 deliver those; 6 & 10 contain open-research + external-audit work that
  cannot be finished autonomously. This is the SPINE, not the finished anonymity system.

