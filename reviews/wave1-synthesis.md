# Darqual Wave 1 Review — Synthesis
## Date: 2026-07-08, S238

Four independent reviewers examined the entire codebase (~7.5K LOC, 8 crates). This document synthesizes their findings into a unified improvement plan.

---

## Cross-Review Convergence (findings confirmed by 2+ reviewers)

### CRITICAL — Fix Immediately

| ID | Finding | Confirmed By | Fix |
|---|---|---|---|
| **F-1** | **Non-transactional `decrypt()` — replay causes permanent chain desync** | Protocol, Security | Clone-and-commit: `let mut trial = self.clone(); ... *self = trial;` only after AEAD succeeds. `ratchet.rs:342-367` |
| **F-2** | **Tor wire frame leaks sender's static x_pub in cleartext** — defeats header encryption | Architecture, Security, Protocol | Remove `sender_x_pub` from frame; use header trial-decrypt (already built in `hdec`) or lockbox v2 outer envelope for first flight. `darqual-tor/src/main.rs:12,99-101,154` |

### HIGH — Fix Before Next Release

| ID | Finding | Confirmed By | Fix |
|---|---|---|---|
| **F-3** | **Async path uses Lockbox v1 (no FS/PCS/auth)** — publish path has weakest crypto | Architecture, Security | Wire ratchet-over-dead-drops or at minimum use v2. `darqual-node/src/main.rs:213` |
| **F-4** | **Publish uses static PRF label, not keywheel** — forward-secret metadata claim is void for running code | Architecture, Security | Switch to keywheel labels. `darqual-node/src/main.rs:208` |
| **F-5** | **Cover traffic distinguishable from real** — PoW=0, v1-only envelopes, single bucket | Architecture, Security, Code Quality | Parameterize difficulty, match real envelope shape, distribute across buckets. `cover.rs:47-78` |
| **F-6** | **Sessions stored in cleartext** — device seizure exposes all session secrets | Security, Architecture | AEAD-wrap sessions at rest with identity-derived key. `session.rs:68-82` |
| **F-7** | **No zeroization on RatchetSession/Keywheel/Conversation** | Security, Code Quality | Derive `ZeroizeOnDrop`. Already a dependency. `ratchet.rs:111-131` |
| **F-8** | **Keywheel forward-secrecy voided by re-derivation from static secret** | Architecture | Persist keywheel state; derive once, then advance-only. `conversation.rs:88-90` |
| **F-9** | **ContactCard.verify() skipped on Tor send path** | Security, Code Quality | Move verify into `decode` or enforce at parse. `darqual-tor/src/main.rs:136` |
| **F-10** | **Transport trait unusable for Arti (tokio bound vs futures-io)** and has zero call sites | Architecture, Code Quality | Delete current trait; build message-level trait with address enum. `transport/mod.rs:14-23` |
| **F-11** | **DP mechanism broken** — float sampling + asymmetric clamping breaks ε | Security | Integer-arithmetic DLap (Canonne et al. 2020), raise base to avoid clamping. `dp.rs:71-118` |

### MEDIUM — Address During This Cycle

| ID | Finding | Confirmed By | Fix |
|---|---|---|---|
| **F-12** | **Session filenames are the contact graph** — `hex(peer_x_pub)` as filename | Architecture, Security | Hash or encrypt filenames. `session.rs:52` |
| **F-13** | **Serial accept loops** — one slow peer stalls everything | Architecture, Code Quality | `tokio::spawn` per connection. `net/src/lib.rs:63-73`, `block_transport.rs:57-76` |
| **F-14** | **x25519 zero-check missing** on DH outputs | Security | Reject all-zeros shared secret. `lockbox.rs:90` et al. |
| **F-15** | **160-bit address → 80-bit collision resistance** | Security | Widen to 32 bytes or document explicitly. `address.rs:26` |
| **F-16** | **No CI** — verify.sh only, darqual-tor completely excluded | Code Quality | GitHub Actions + separate tor check workflow |
| **F-17** | **Stale error message** — "1 MiB" vs actual 16 MiB | Code Quality | Fix `error.rs:9` |
| **F-18** | **Identity fields pub** — raw secret material accessible | Code Quality | Privatize. `identity.rs:25-28` |
| **F-19** | **TOCTOU on identity.toml permissions** | Security | `OpenOptions::create_new(true).mode(0o600)` |
| **F-20** | **Ledger entry envelope assumes Lockbox string** — can't carry ratchet messages | Architecture | Versioned `Envelope` enum. `block.rs:11-12`, `notify.rs`, `sweep.rs` |

### LOW / STRUCTURAL

| ID | Finding | Fix |
|---|---|---|
| **F-21** | No `[workspace.dependencies]` — 7 duplicated dep versions | Unify |
| **F-22** | `skipped_order: Vec` with `remove(0)` — O(n) | Use `VecDeque` |
| **F-23** | No tests for darqual-cli, darqual-node, darqual-tor binaries | Add smoke/integration tests |
| **F-24** | `bincode 1` for persisted session state — no versioning | Pin or migrate |
| **F-25** | STATUS.md says 132 tests; reality is 164 | Update |
| **F-26** | No `cargo fmt --check` in verify.sh | Add |
| **F-27** | `DarqualAddress::from_str` doesn't validate length | Check 32 base32 chars |
| **F-28** | Dead `Error::IdentityExists` variant | Delete or use |
| **F-29** | Missing proptests for pad/unpad roundtrip, merkle proof | Add |
| **F-30** | `Ledger` invariant fields are pub | Privatize |

---

## Architecture — The Big Three

The four reviews converge on three architectural truths:

1. **The composition layer doesn't exist.** Eight library crates and two demo binaries. No daemon, no epoch loop, no persistent ledger, no control plane. The "wiring" gap is understated — it's not glue, it requires reworking `LedgerEntry` to carry ratchet messages (F-20).

2. **Two incompatible crypto stacks.** Tor path (ratchet, FS/PCS, encrypted headers) vs async path (Lockbox v1, no auth, no FS). The async path is the *mission* path and has the weakest crypto.

3. **Mission C docs never landed on disk.** SPEC, THREAT-MODEL, README still declare Mission A. The decision from S223 lives only in notes.

---

## Implementation Plan — Iteration 1

### Phase 1: Critical Security Fixes (no new features, pure hardening)
1. F-1: Non-transactional decrypt fix (clone-and-commit)
2. F-2: Remove sender_x_pub from Tor frame
3. F-7: ZeroizeOnDrop on RatchetSession, Keywheel, Conversation
4. F-9: ContactCard.verify() enforcement
5. F-14: x25519 zero-check
6. F-17: Stale error message fix
7. F-19: TOCTOU identity.toml fix

### Phase 2: Integrity Fixes (correctness of existing claims)
8. F-5: Cover traffic parity (difficulty param + bucket distribution)
9. F-11: DP mechanism fix (integer DLap + base raise)
10. F-18: Privatize Identity fields
11. F-22: VecDeque for skipped_order
12. F-13: Concurrent accept loops
13. F-25-F-30: Housekeeping batch

### Phase 3: Architecture (composition layer foundation)
14. F-20: Versioned Envelope enum in darqual-core
15. F-10: Message-level transport trait
16. F-8: Persist keywheel state
17. F-12: Encrypted session filenames
18. F-6: AEAD-wrapped sessions at rest
19. F-21: Workspace dependency unification

### Phase 4: Doc Re-aim (Mission C)
20. SPEC.md → Mission C
21. THREAT-MODEL.md → two-adversary model + modes
22. README safety banner update
23. CLIENT-OBLIGATIONS.md (new)
24. STATUS.md update (test count, stage honest-labeling)
