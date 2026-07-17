# Protocol Primitives and Handoff State

**Status:** Selection contract for simulation and prototype work

## Functional split

Darqual adopts four independent logical services:

1. `Write`: hide the target slot of an encrypted envelope.
2. `Notify`: tell a client that retrieval may be useful without exposing its contact.
3. `Retrieve`: return an encrypted record without exposing the chosen record.
4. `Handoff`: transfer retained service state to the next committee without exposing ownership.

Each service has an explicit baseline and one research candidate.

## Write

### Baseline

Full-board fixed-position shares in a deterministic simulator. Clients secret-share a point write across four members. The baseline is inefficient but exposes the correct threshold and malformed-write behavior.

### Candidate

DPF/FSS private writes with a validity proof or SNIP-like audit derived from Express/Riposte literature. The proof must bind authorization, size bucket, epoch, and retry identifier without revealing the slot.

## Notify

### Baseline

A fixed-size notification bitmap downloaded in full each epoch. It provides read privacy and establishes bandwidth truth.

### Candidate

A compact private notification table queried through committee PIR or oblivious aggregation. False positives are permitted if their distribution is independent of real demand and included in the leakage model.

## Retrieve

### Baselines

1. Full immutable epoch-segment download.
2. Prefix-bucket download with explicitly reduced anonymity set.

### Candidates

1. FrodoPIR over immutable epoch segments or a stable notification database.
2. Multi-server PIR over threshold committee replicas.
3. Shuffle-model PIR if fixed epoch traffic supplies sufficient concurrent queries.

The project chooses by measured crossover, not elegance.

## Message envelope

The asynchronous store carries a versioned typed envelope:

- `Bootstrap`: authenticated Lockbox v2 containing a serialized ratchet message;
- `Session`: established Double Ratchet message with encrypted header;
- `Cover`: syntactically and computationally indistinguishable from the relevant real variant.

Every variant uses fixed size buckets, equal validation work, and a domain-separated message identifier.

## Directional labels

For public keys ordered as sender and receiver, derive separate directional roots. The state is anchored at an explicit conversation-start epoch and advanced one way. State includes:

- current epoch;
- current directional secret;
- bounded pending-window secrets needed for tolerated skew;
- last accepted message identifiers;
- expiry metadata.

The current prototype keywheel is not reused unchanged because its `start_epoch` counter does not alter initial state and peers initialized at different epochs diverge.

## Retained committee state

State is partitioned into:

### Public

- protocol version;
- epoch and predecessor hash;
- participant-set commitment;
- committee registry identifier;
- notification root;
- message-store root;
- availability root;
- expiry histogram commitment;
- threshold certificate.

### Secret-shared

- private-write accumulator state;
- private notification contents;
- retrieval service keys or shares;
- authorization accumulator state;
- unexpired message-store access state;
- anti-replay and capacity state.

### Client-only

- contact graph;
- Double Ratchet sessions;
- directional label state;
- plaintext outbox and inbox;
- mapping from contacts to private notification/retrieval tokens.

The committee must never receive the client-only mapping in plaintext.

## Handoff transcript

The transcript contains:

1. predecessor certificate;
2. old and new committee identifiers;
3. verifiable resharing commitments;
4. encrypted state fragments addressed to new members;
5. availability proof or shard manifest commitments;
6. completion or abort certificate;
7. no plaintext mailbox index, directional label, contact key, or per-client message count.

## Crash consistency

Client encryption occurs at emission time. Ratchet advancement, outbox state, and retry receipt are committed atomically. A crash must not cause key reuse or silent message loss.

Committee state uses write-ahead epoch staging:

1. accept shares into epoch staging;
2. compute candidate state;
3. certify candidate root;
4. atomically mark finalized;
5. expose retrieval state;
6. begin handoff.

## Deferred primitives

- permissionless committee membership;
- RLN or anonymous credentials for abuse control;
- private human-readable discovery;
- mix packet design;
- production threshold signature choice;
- cold archival beyond the tested retention window.
