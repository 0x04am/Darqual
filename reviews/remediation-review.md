# Remediation Design — Review (Wave-1 review of remediation-design.md)

**Verdict: FLAWED** — tier structure + finding coverage are right, but 2 load-bearing
design errors sit on the critical path. Do NOT execute remediation-design.md as written;
amend B1 + B2 first. (fable-5 review, S238; the doc was NOT yet amended — opus-4-8 flaked
twice on the amendment pass. THIS review is the amendment spec.)

---

## BLOCKERS (must fix in the design before building)

**B1 — Single-chain LedgerService can't host the multi-node mesh the doc builds.**
§3.3/§3.6/§3.8 vs `darqual-ledger/src/ledger.rs:54-70`. Every node builds+ingests its own
block every epoch (§3.8), pulls every peer's blocks into ONE LedgerService with one tip_hash
(§3.6), Fork=reject (§3.3). With N nodes, forking is the NORMAL case → chain-link validation
rejects all peer blocks, receive pipeline never sees peers' entries. R5's "single-publisher"
contradicts §3.8.
→ FIX: per-publisher chains — map<publisher → Ledger>, each validated independently,
ReceivePipeline trial-decrypts across ALL publishers' recent blocks. Decide before Phase 1.

**B2 — §4.3 keywheel convergence claim is FALSE for async first-derivation.**
§4.3 vs `keywheel.rs:100-107`. `from_seed(seed, start_epoch)` sets state IDENTICALLY
regardless of start_epoch — label at E depends on advances-since-seeding, not E. Alice
seeds@100→105 ≠ Bob first seeds@105 → permanent desync. Async diff-epoch first-derivation is
the COMMON case; symmetry test hides it (only seeds both at 0, `keywheel.rs:159-169`).
→ FIX: canonical wheel state = `ratchet^E(seed)` from a fixed genesis epoch (≈29M blake3 for
unix/60 = sub-second, cache per contact), OR exchange conversation-start epoch in ContactCard.
Add asymmetric-seed-epoch test.

## MAJORS

- **M1 — Symmetric labels link the two endpoints on the public ledger** (§4.3;
  `conversation.rs:69-79`, `keywheel.rs:17-18`). Both peers sending in epoch E emit the SAME
  16-byte label → observer links them = the exact F-4 leak the plan claims to close.
  → FIX: domain-separate labels per direction (ordered (sender_pub, receiver_pub) in the KDF).
- **M2 — Bootstrap→Ratchet tag switch gated on wrong condition** (§4.2; `session.rs:86-110`).
  LockboxV2 emitted only when "no local session" → if receiver missed bootstrap (offline >
  hot-window W=8, §3.2 tolerates), all Ratchet flights undecryptable forever. No simultaneous-
  init rule. → FIX: emit LockboxV2 until first inbound reply (reuse received_from_peer());
  role-conflict tie-break (lower x_pub = initiator).
- **M3 — §3.4 "byte-identical wire" + §3.9 golden test CONTRADICT §5.1 DP noise**
  (`dp.rs:109-118`). Constant min_entries already hides demand; layering noisy_cover_count adds
  a RANDOM per-epoch count → golden test's "identical counts" fails by construction.
  → FIX: pick constant-rate (drop per-epoch DLap at emission) OR DP-noised variable rate w/
  distribution-level test; reconcile §3.4/§3.9/§5.1.
- **M4 — "unfixable without runtime" overstated → over-serializes critical path** (§9).
  Envelope/KeywheelStore/atrest/F-12-list() are pure darqual-core, testable standalone; only
  F-3/F-4 wiring + F-5 shape-acceptance need the runtime. Phase 1 sketches even IMPORT Phase 2
  artifacts → Phase 1 can't compile alone. → FIX: move F-20/F-8-store/atrest/F-12 to Phase 0 /
  parallel; keep trunk thesis for F-3/F-4/F-5 only.
- **M5 — Risk register misses top risks** (§10): (a) fork-is-normal (B1), (b) inter-node clock
  skew (epoch alignment is wall-clock, §3.2 — add skew-tolerance window), (c) AsyncAnonymous
  cost wall (B≈45 DP cover × network-PoW per epoch per node → mode unusable on real hardware
  unless opt-in + cost-gated).

## MINORS (fold if cheap)
m1 F-6+F-12 = ONE atomic migration (§4.5/§4.6 — file_key keyed on filename_nonce which F-12
sets → else double re-encrypt). m2 §4.3 expected_labels signature inconsistent (label_at(now-1)
returns None post-advance). m3 F-12 leaves count/mtime metadata. m4 §8.6 Arti PT optimism.
m5 srk-from-DH-scalar + no at-rest re-key on identity rotation (§4.5). m6 F-29 merkle
domain-sep changes every root (consensus break, list w/ F-24). m7 catch-up burst = timing FP.

## WHAT'S SOLID
Finding coverage COMPLETE (all F-3/4/5/6/8/10/11/12/13/15/16/18/20/21/23/24/29 + 6 research
stubs; F-2/F-12 list() coupling handled right). Crypto plumbing correct where checked
(Envelope tags leave Merkle/PoW untouched `block.rs:35-48`; F-3 reuses seal_authenticated/
clone-and-commit; F-11 CKS sampler + F-5 tag×bucket×work parity right; F-15 sound). Line
citations verified accurate throughout. Honest scoping (audit/beta excluded, committee/sybil
held out of the artifact line, "no new primitives" rule).
