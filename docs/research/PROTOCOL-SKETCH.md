# Darqual Protocol Sketch

**Status:** Candidate architecture for analysis, not an implementation contract

## Design principle

Darqual separates the private messaging service into two logical functions:

1. **Notify:** privately indicate that a client may have unread mail.
2. **Retrieve:** privately store and return asynchronous encrypted messages.

Both are operated by a committee whose state is refreshed across epochs. A public hash-linked log commits to state transitions and accountability evidence. It does not need to publish all ciphertexts.

## Setup

1. Establish a registered service-member set and public keys.
2. Generate or refresh committee threshold material.
3. Publish protocol parameters: epoch length, traffic schedule, capacities, retention, corruption threshold, and commitment format.
4. Clients establish contacts out of band and derive directional conversation roots.
5. Clients initialize content-ratchet and directional-addressing state.

## Directional addressing

For peers A and B, derive separate roots for A→B and B→A by domain-separating ordered public keys. Epoch labels derive from a persisted one-way state anchored to a canonical conversation epoch. Initialization at different wall-clock epochs must converge when supplied the same conversation-start metadata.

## Client epoch schedule

Each participating client emits fixed-size protocol actions according to mode, regardless of real demand. The strongest mode includes:

- one write action or cover equivalent;
- one notification action or cover equivalent;
- one retrieval action or cover equivalent;
- deterministic failure behavior that does not depend on message presence.

Karaoke-style optimistic leakage handling is an alternative experiment, not assumed secure by default.

## Sending

1. Dequeue plaintext only at emission time.
2. Advance the Double Ratchet exactly once and persist atomically.
3. Encode either an authenticated bootstrap envelope or established-session envelope.
4. Derive the directional epoch label.
5. Create private-write shares targeting a logical message-store slot and notification state.
6. Submit fixed-size shares through the anonymous transport to committee members.
7. Retain a private receipt sufficient for retry or omission evidence without reusing a ratchet key.

## Committee processing

1. Commit to the epoch participant set before processing challenge traffic.
2. Validate write authorization and shape without learning the destination.
3. Combine private-write shares into oblivious notification and message-store state.
4. Reject malformed or over-capacity writes without corrupting unrelated state.
5. Generate cover or shuffle material required by the traffic model.
6. Commit to the resulting state and availability encoding.
7. Produce a threshold certificate over the epoch commitment.

## Notification

A client learns whether retrieval may be useful without exposing which contacts or labels it monitors. Candidate constructions to evaluate:

- committee PIR over a compact notification table;
- private Bloom-filter query with quantified false positives;
- secret-shared notification aggregation;
- PingPong-style oblivious aggregation without TEEs.

False-positive notifications are acceptable if their distribution is activity-independent and budgeted.

## Retrieval

Candidate baselines, in order:

1. Full epoch/window download.
2. Prefix-bucket download.
3. Single-server computational PIR such as FrodoPIR.
4. Multi-server or committee PIR.
5. Shuffle-model PIR using epoch concurrency.

The first prototype implements at least full download and one PIR baseline to establish a crossover point.

## Receiving

1. Retrieve candidate encrypted envelopes privately.
2. Match directional labels locally where applicable.
3. Decode versioned envelope.
4. For bootstrap, recover authenticated sender identity inside the AEAD and initialize responder state.
5. For established traffic, decrypt transactionally against the expected session.
6. Persist advanced ratchet and addressing state only after successful authentication.
7. Deduplicate by a cryptographic message identifier that does not become a public cross-epoch link.

## Committee handoff

At E→E+1:

1. Finalize E and publish its certified commitment.
2. Select and authenticate the next committee.
3. Secret-share or proactively refresh retained notification, message, authorization, and service-key state.
4. Transfer availability material with verifiable completeness.
5. New members verify the predecessor certificate and handoff transcript.
6. Old members erase epoch secrets.
7. Publish a handoff-complete certificate or abort safely.

Open question: whether message-store state should be transferred, remain with storage providers under refreshed access keys, or be represented by immutable encrypted epoch segments.

## Public commitment log

Each record should commit to, at minimum:

- protocol and parameter version;
- epoch and predecessor commitment;
- participant-set commitment;
- notification-state root;
- message-store root;
- availability root;
- handoff transcript root;
- committee identifier and threshold certificate.

## Failure behavior

- Unsafe participant-set shrinkage: abort with uniform client behavior.
- Missing committee threshold: do not finalize.
- Withheld predecessor state: expose handoff failure, retain privacy, and enter recovery.
- Invalid shares: isolate without revealing target slot.
- Network loss: mark epoch degraded and apply the selected leakage policy.
- Capacity overflow: queue independently of destination and preserve fixed traffic shape.

## Protocol forks to resolve through simulation and proof

1. One-honest anytrust versus honest-majority MPC.
2. Full-download versus committee PIR retrieval.
3. Immutable epoch segments versus mutable oblivious store.
4. Constant-rate traffic versus Karaoke-style optimistic leakage.
5. Committee-certified global state versus per-provider commitments.
6. Storage integrated into committee versus separate erasure-coded providers.
