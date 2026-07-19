# Tier-1.5 Committee Fan-out — Implementation Plan

## Task 1: Canonical entry identity

**Description:** Put the cross-relay logical write ID on `LedgerEntry` and make Tier-1 replay checks use it.

**Acceptance criteria:**
- identical entries have identical IDs;
- any label/envelope/nonce change changes the ID;
- relay duplicate behavior remains unchanged.

**Verification:** Avante ledger tests, workspace gate.
**Files:** `darqual-ledger/src/{block,relay}.rs`
**Scope:** S

## Task 2: Static committee manifest

**Description:** Add transport-neutral ordered member/config validation without Tor dependencies.

**Acceptance criteria:**
- valid manifests round-trip and sort deterministically;
- empty/duplicate/bad-threshold manifests fail with typed errors;
- onion endpoint syntax can be enforced by the CLI edge.

**Verification:** Avante committee tests, workspace gate.
**Files:** `darqual-committee/src/{manifest,lib}.rs`, Cargo manifest
**Scope:** M

## Checkpoint A

- workspace tests/clippy green;
- spec + entry ID + manifest independently committed/pushed.

## Task 3: Structured idempotent relay outcomes

**Description:** Replace brittle duplicate-string matching with stable rejection codes.

**Acceptance criteria:**
- duplicate response round-trips;
- invalid PoW/capacity/persistence errors map to stable codes;
- old single-relay behavior remains explicit and tested.

**Verification:** standalone Tor tests/clippy.
**Files:** `darqual-tor/src/{relay,main}.rs`
**Scope:** M

## Task 4: Pure committee aggregation

**Description:** Add reusable outcome and fetch-union logic independent of live Tor dialing.

**Acceptance criteria:**
- threshold accounting treats accepted/duplicate as stored;
- fetched pages validate and malformed members are isolated;
- entries deduplicate by ID while retaining source provenance.

**Verification:** standalone Tor pure tests.
**Files:** new `darqual-tor/src/committee.rs`, `lib.rs`
**Scope:** M

## Task 5: Multi-relay CLI vertical slice

**Description:** Add committee send/fetch commands or manifest options that bootstrap Arti once and fan out/fan in.

**Acceptance criteria:**
- seal/mint once, submit same entry to all;
- threshold controls exit result and all outcomes are reported;
- fetch union emits Bob plaintext once, Eve none;
- legacy commands remain.

**Verification:** handler/mock tests; standalone Tor gate on Avante.
**Files:** `darqual-tor/src/{main,committee}.rs`, Tor Cargo/lock
**Scope:** M

## Checkpoint B

- deterministic 3-relay happy/outage/malformed/Eve tests green;
- workspace + Tor gates green;
- feature branch pushed, never merged.

## Task 6: Simulator and documentation closure

**Description:** If time remains, model threshold replication availability and update status/threat docs with shipped limits.

**Acceptance criteria:**
- simulator distinguishes write threshold from BFT finality;
- docs add no contact-graph/privacy claim;
- exact commands and known limitations are current.

**Verification:** sim tests + text audit + final gates.
**Files:** `darqual-sim`, README/STATUS/THREAT-MODEL, Tier-1.5 docs
**Scope:** M
