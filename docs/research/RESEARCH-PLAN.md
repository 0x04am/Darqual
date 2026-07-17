# Darqual Research Plan

## Phase 0: Artifact preservation

- [x] Create annotated freeze tag `research-prototype-2026-07-17` at `033dba5`.
- [x] Create and verify a complete Git bundle under `~/Jawz/backups/darqual-research-reset-2026-07-17/`.
- [x] Preserve the pre-reset uncommitted remediation amendment as a patch.
- [x] Start branch `research/rotating-committees` from the frozen commit.
- [ ] Push the existing 12 local security commits and freeze tag after explicit release review.
- [ ] Add an independent verification gate for the excluded `darqual-tor` workspace.

## Phase 1: Research constitution

- [x] Draft primary question and falsification criteria.
- [x] Draft system model and leakage boundary.
- [x] Draft security definitions.
- [x] Draft protocol sketch.
- [x] Draft novelty matrix.
- [x] Convert informal security properties into draft game-based definitions.
- [x] Review the constitution against the SoK taxonomy and citation-closure systems.

## Phase 2: Literature closure

- [x] Fully annotate PingPong, Stadium, Karaoke, Express, Groove, XRD, RPM, and available modern sources; Talek/Trellis/YOSO require final verified full-text annotation.
- [x] Add Groove, XRD, Clarion, Trellis, Echomix, and recent 2025–2026 work to the comparison map.
- [x] Produce an initial primitive-by-primitive trust and leakage comparison.
- [ ] Complete formal citation-graph closure and search citing works for equivalent rotating-service constructions.
- [ ] Seek an external academic novelty check before implementation expansion.

## Phase 3: Protocol analysis

- [x] Choose the fixed-committee threshold model (`n=4`, `f=1`, quorum 3).
- [x] Specify baseline and candidate private write, notification, and retrieval primitives.
- [x] Specify participant-set commitment and privacy-safe exclusion behavior.
- [x] Specify handoff state, overlap assumptions, and erasure requirements.
- [x] Produce an initial mobile-corruption attack analysis; formal proof or impossibility result remains open.
- [x] Decide provisionally that the public log uses threshold-certified commitments; generic consensus is not required for the first artifact.

## Phase 4: Deterministic simulator

- [x] Build a separate simulation crate with deterministic clock/event ordering and network-event vocabulary.
- [ ] Model clients, committees, epochs, message demand, and cover schedules.
- [x] Add initial delay/drop vocabulary, exclusion, corruption, finalization, handoff, and erasure events.
- [ ] Compare constant-rate and optimistic-indistinguishability traffic.
- [ ] Measure anonymity-set size, leakage events, delivery, bandwidth, and recovery.

## Phase 5: Fixed-committee vertical slice

- [ ] Implement one private-write primitive with malicious-client validation.
- [ ] Implement one private-notification primitive.
- [ ] Implement full-window retrieval baseline.
- [ ] Integrate versioned ratchet envelopes and directional addressing.
- [ ] Demonstrate send while recipient is offline, later private notify and retrieve.

## Phase 6: Rotation and handoff

- [ ] Implement authenticated configured-registry committee rotation.
- [ ] Implement proactive refresh or state migration.
- [ ] Add certified epoch commitments and equivocation evidence.
- [ ] Test mobile corruption and old-member post-service compromise.
- [ ] Measure handoff latency, bandwidth, and availability.

## Phase 7: Retrieval and storage evaluation

- [ ] Integrate one PIR baseline and compare with full download.
- [ ] Evaluate shuffle-model PIR under fixed epoch traffic.
- [ ] Integrate erasure-coded immutable epoch storage if supported by the model.
- [ ] Define retention and recovery under storage churn.

## Phase 8: Network evaluation

- [ ] Run the protocol over direct authenticated TCP.
- [ ] Integrate Arti as an IP-hiding underlay.
- [ ] Evaluate a delayed mix transport for global-observer mode.
- [ ] Train traffic classifiers against packet traces and report inference accuracy.

## Phase 9: External review and publication

- [ ] Reproducible experiments and public artifact.
- [ ] Cryptography and distributed-systems review.
- [ ] Independent security audit only after protocol stability.
- [ ] Draft for PoPETs/PETS, with NDSS/USENIX Security as alternatives depending on result.

## Stop conditions

Stop or pivot if novelty is preempted, assumptions become less realistic than PingPong's TEE model, committee handoff leaks state ownership, or measured costs fail to improve a meaningful point in the prior-art tradeoff space.
