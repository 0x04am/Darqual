# Tier-1.6 Committee Simulator — Specification

**Status:** implementation contract
**Branch:** `feat/committee-dead-drop-sim`
**Baseline:** static manifest + canonical entry IDs + checked election at `8895209`

## Objective

Build a deterministic, transport-neutral simulator for replicated committee dead-drops before
adding multi-relay Tor CLI fan-out. The simulator models one logical write replicated to a static
committee, threshold acknowledgement, per-relay omission/corruption, validated union reads,
canonical entry deduplication, and equivocation evidence.

This slice improves availability and integrity reasoning. It does **not** provide private writes,
private reads, consensus, BFT finality, anytrust privacy, Sybil resistance, or global-observer
contact-graph privacy.

## Model

- Committee membership comes from a validated `CommitteeManifest`.
- Every logical write has one canonical `LedgerEntry::id()`.
- Each relay independently stores the same entry or fails/omits it.
- A write is acknowledged when stored outcomes meet `write_threshold`.
- Fetch validates every page independently, isolates malformed relays, unions entries by ID, and
  records source provenance.
- Relays do not merge hash chains. Agreement on an entry is replication evidence, not consensus.
- Two valid but conflicting commitments from the same relay/epoch constitute equivocation evidence.

## Security games represented

### Availability game

Given a write accepted by at least the configured threshold, remove or corrupt up to a declared
number of relay responses. The message is recoverable if at least one honest reachable accepting
relay still serves the entry.

### Omission game

One relay may omit an accepted entry. Union read must recover it from another valid relay and report
which relays served or omitted it.

### Equivocation game

A relay presents two different valid block commitments for the same epoch. The simulator must emit
an evidence record containing the relay identity, epoch, and both hashes. It must not call either
history finalized.

### Privacy non-game

Static fan-out exposes the same write to more relays and provides no write/read privacy. The
simulator records this as an explicit leakage fact. It does not emit `privacy_safe = true` for this
mode.

## Project structure

- `darqual-sim/src/committee.rs`: deterministic replicated-write/read model and evidence types.
- `darqual-sim/src/lib.rs`: exports only; preserve the older research event simulator.
- `darqual-sim/Cargo.toml`: depend on committee + ledger crates, no Tor/Arti.

## TDD order

1. Three relays, threshold two: all store; one logical entry recovered once with three-source provenance.
2. One relay unavailable: write threshold still succeeds and read recovers.
3. Two relays unavailable: threshold fails explicitly; partial writes remain visible in outcomes.
4. One relay omits on read: union recovers and omission is reported.
5. Malformed page: isolate relay; valid peers remain useful.
6. Replayed replicated entry: dedupe by `LedgerEntry::id()`.
7. Two conflicting same-epoch commitments from one relay: emit equivocation evidence.
8. Global-view leakage flag remains explicit; no anonymity claim.

## Boundaries

- All build/test/clippy runs happen on Avante.
- Push only green, independently revertible commits to this branch.
- No Tor wiring until the deterministic model is green and reviewed.
- No "anytrust", "BFT", "finality", or privacy claim from fan-out.
- Do not merge to `main` without separate integration review.
