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
| 1 — Transport (onion-to-onion) | v0.1.x | ⏳ NEXT | — |
| 2 — Ledger (epochs, hot-window) | v0.2.x | ⬜ todo | — |
| 3 — Addressing & notification | v0.3.x | ⬜ todo | — |
| 4 — Write path + RLN spam | v0.4.x | ⬜ todo | — |
| 5 — Storage scaling (buckets, erasure, DA) | v0.5.x | ⬜ todo | — |
| 6 — Committees (VRF) [NOVEL CORE] | v0.6.x | 🔬 research | unpublished question — will scaffold + document, not fake |
| 7 — Discovery (Alpenhorn IBE) | v0.7.x | ⬜ todo | — |
| 8 — Metadata hardening (cover/DP/Loopix) | v0.8.x | ⬜ todo | — |
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
- S218: Stage 0 shipped (v0.0.1). 11-stage task ladder created (#144–#153, epic #146).
  Research corpus: ~/Jawz/notes/projects/anon-messenger-research/. verify.sh gate established.
