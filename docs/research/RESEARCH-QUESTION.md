# Darqual Research Question

**Status:** Draft research constitution, pre-protocol
**Branch:** `research/rotating-committees`
**Date:** 2026-07-17

## Assumptions

This research track proceeds under the following explicit assumptions until evidence forces a revision:

1. Darqual targets **asynchronous end-to-end messaging with communication unobservability**, not merely sender anonymity or encrypted delivery.
2. Initial contact establishment is out of band. Private discovery is important but not the primary contribution.
3. The first research artifact uses a registered participant set. Permissionless Sybil resistance is deferred and must not be implied.
4. At least one service member in the active committee remains honest during each protected operation. The exact cross-epoch corruption condition remains to be defined.
5. The network adversary can observe all links and can delay, drop, replay, and inject traffic.
6. Endpoints are honest for the challenged conversation. Live endpoint compromise is outside the protocol claim.
7. Tor, mixnets, Double Ratchet, DPF/FSS, PIR, Merkle commitments, threshold signatures, and proactive secret sharing are ingredients, not claimed inventions.

## Primary question

> Can an asynchronous, communication-unobservable messaging service replace trusted enclaves and permanent non-colluding servers with unpredictable, proactively refreshed committees, while preserving private notification, private message retrieval, availability, and anonymity-set integrity across committee churn?

## Working hypothesis

A notify-before-retrieval service can be operated by ephemeral committees without TEEs if:

- clients maintain an activity-independent epoch schedule;
- write destinations are hidden through function secret sharing or an equivalent private-write primitive;
- notification and retrieval are hidden through PIR, oblivious aggregation, or a secure shuffle;
- service state is proactively refreshed during committee handoff;
- each epoch commits to its participant set and service state;
- clients detect exclusion, equivocation, withholding, and unsafe anonymity-set shrinkage;
- secrets from expired committees are erased before later corruption.

This is a hypothesis, not a current guarantee.

## Candidate contribution

Darqual will investigate a protocol that combines:

1. **Cryptographic notify-before-retrieval:** PingPong-style asynchronous usability without enclave trust.
2. **Rotating committee service:** private write, notification, retrieval, and retention state operated under an explicit anytrust or threshold assumption.
3. **Privacy-preserving handoff:** proactive state refresh across unpredictable committees without exposing mailbox ownership or communication relationships.
4. **Anonymity-set integrity:** committed participation, exclusion evidence, and privacy-preserving abort behavior under malicious servers.
5. **Forward-secure conversations:** directional dead-drop addressing and Double Ratchet content sessions integrated with asynchronous service epochs.
6. **Accountability commitments:** a hash-linked sequence of certified state roots, not necessarily a public ledger containing every ciphertext.

## Non-contributions

Darqual does not claim to invent or solve:

- end-to-end encryption or Double Ratchet;
- Tor or mix routing;
- PIR, DPF/FSS, MPC, threshold signatures, or proactive secret sharing;
- generic Byzantine consensus;
- permissionless Sybil resistance;
- endpoint security against spyware or coercion;
- private user discovery;
- abuse moderation;
- production-safe anonymous messaging before external audit.

## Falsification criteria

The primary hypothesis should be rejected or narrowed if any of the following holds:

1. Prior work already provides equivalent asynchronous private notification and retrieval across rotating committees under equal or weaker assumptions.
2. Committee handoff requires revealing a stable mailbox or recipient identifier to the incoming committee.
3. Adaptive corruption across practical committee lifetimes accumulates enough shares to recover protected state despite refresh and erasure.
4. Maintaining communication unobservability requires client bandwidth or server work that is noncompetitive with relevant baselines at the intended scale.
5. Malicious participation control can shrink an honest user's effective anonymity set without detection.
6. Availability under churn cannot be achieved without a fixed trusted provider that invalidates the research premise.

## Success criteria for the research artifact

A successful first artifact must include:

- a precise system and leakage model;
- formal privacy games for communication traces, write destinations, reads, and handoff;
- a protocol specification with explicit setup, epoch, send, notify, retrieve, handoff, and recovery steps;
- a deterministic simulator with malicious-node, churn, delay, exclusion, and withholding experiments;
- a fixed-committee prototype before committee rotation;
- a rotating-committee prototype or a defensible impossibility/negative result;
- comparison against PingPong, Stadium, Karaoke, Express, Talek/PIR baselines, and modern MPC/mix systems;
- reproducible measurements for latency, bandwidth, throughput, storage, churn recovery, and privacy degradation;
- an honest limitations section and independent research review before strong claims.
