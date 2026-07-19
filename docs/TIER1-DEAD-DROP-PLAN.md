# Tier-1 Dead-Drop MVP — Implementation Plan

## Dependency graph

Relay state + persistence
  -> typed request/response protocol
    -> Tor reply-capable stream handling
      -> relay CLI
      -> drop-send CLI
      -> drop-fetch CLI
        -> deterministic E2E
          -> jade/avante live Tor smoke

## Task 1 — Relay state machine and persistence (M)

**Acceptance:** PoW-gated submit, epoch-linked blocks, pruning, atomic snapshot/reload; invalid input leaves state unchanged.  
**Verification:** ledger RED→GREEN unit tests; workspace build/test/clippy.  
**Files:** `darqual-ledger/src/{relay,lib}.rs`, ledger Cargo if needed.

## Task 2 — Bounded relay protocol and duplex transport (M)

**Acceptance:** typed Submit/Fetch and Accepted/Ledger/Rejected round-trip; request and response frames bounded; malformed payload rejected.  
**Verification:** standalone Tor pure unit tests (no Tor bootstrap), clippy.  
**Files:** `darqual-tor/src/{relay,lib}.rs`, Tor Cargo.

### Checkpoint A

Both foundations green and independently committed. No CLI behavior changed yet.

## Task 3 — Relay CLI vertical slice (M)

**Acceptance:** relay onion accepts submit/fetch, persists accepted state, returns explicit rejection, continues after malformed request.  
**Verification:** local state-machine integration test + standalone Tor tests/build/clippy.  
**Files:** `darqual-tor/src/main.rs`, optionally module tests.

## Task 4 — drop-send vertical slice (S/M)

**Acceptance:** derives current label, seals, mints configured PoW, submits to relay, requires acceptance; no recipient onion argument.  
**Verification:** protocol test plus local/mock integration.

## Task 5 — drop-fetch vertical slice (M)

**Acceptance:** fetches retained blocks, derives label(s) with sender card, decrypts only matching lockboxes, handles no-message and duplicate-poll semantics.  
**Verification:** Alice/Bob/Eve E2E; offline retrieval.

### Checkpoint B

Full async single-relay behavior works deterministically without live Tor. Run full `verify.sh` and standalone Tor gates.

## Task 6 — Cross-host live Tor smoke (M)

**Acceptance:** avante relay onion; jade sends then Bob fetches after sender exits; Eve rejects; no direct Alice→Bob dial. Save sanitized transcript.  
**Verification:** `scripts/tier1-two-host-smoke.sh` or manual transcript under docs.

## Task 7 — Status/docs and final review (S)

**Acceptance:** README/STATUS/THREAT-MODEL distinguish Tier-1 single-relay guarantee from full mission; commands accurate; no overclaim.  
**Verification:** code review, full gates, clean working tree, local commit log.
