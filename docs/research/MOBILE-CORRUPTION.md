# Mobile and Adaptive Corruption Analysis

## Core result

Committee rotation does not by itself improve privacy. Without proactive refresh and secure erasure, a mobile adversary can corrupt different members over time, accumulate enough old shares, and reconstruct protected service state.

## Baseline model

- Each epoch uses `n=4`, `f=1` for active security.
- The adversary may corrupt one active member per epoch.
- At handoff, secret state is reshared with fresh randomness into the next committee.
- Old shares and temporary resharing material are erased after a certified transition.
- The adversary retains everything learned from corrupted members.

## Necessary invariant

For every protected secret generation `g`, the adversary must obtain fewer than the reconstruction threshold of shares from that same generation. Shares from different refreshed generations must be information-theoretically or computationally unlinkable for reconstruction.

Rotation only helps if this invariant holds.

## Attack without refresh

1. State secret `s` is shared among members A, B, C, D.
2. Epoch 1: corrupt A and retain `share_A(s)`.
3. Epoch 2: rotate labels but keep underlying shares; corrupt B.
4. Epoch 3: corrupt C.
5. The adversary reconstructs `s` from accumulated shares.

No simultaneous threshold corruption was needed. This is a mandatory negative-control simulation.

## Attack without erasure

Even with refresh, if honest old members retain prior shares, post-service corruption recovers old generations. Forward security therefore depends on operational erasure. Software cannot prove physical erasure; the claim must be conditional and deployment guidance must use isolated ephemeral execution where possible.

## Handoff exposure window

During resharing, old members hold old shares while new members receive new shares. An adaptive adversary may target both committees during this overlap. The protocol must define one of:

- a bound on total corruptions across the overlap;
- non-interactive encrypted resharing with erasure before new activation;
- YOSO-style ephemeral members whose identities are unpredictable until action;
- proactive security under a mobile-adversary time-window assumption.

“Up to one corrupt member per committee” is insufficient if it permits one old plus one new corruption that jointly breaks the handoff construction.

## State classes and corruption impact

| State | If reconstructed | Required mitigation |
|---|---|---|
| Private-write accumulator | Reveals target distribution or corrupts board | Refresh and verifiable transition |
| Notification table | Reveals who may have mail | Secret-sharing/PIR state refresh |
| Retrieval keys | Reveals queried records or store plaintext | Key rotation and immutable encrypted segments |
| Authorization state | Enables spam or mailbox targeting | Anonymous credential refresh |
| Availability metadata | May reveal occupancy or expiry | Aggregate commitments and padding |
| Client ratchets | Reveals endpoint history/future depending state | Client-side erasure and Double Ratchet |

## Cumulative committee failure

If a randomly selected committee is fully unsafe with probability `q`, then over `T` independent epochs the probability of at least one unsafe epoch is `1 - (1-q)^T`. Long-lived messaging magnifies even small per-epoch failure probabilities. The paper must report cumulative risk over realistic lifetimes, not only per-epoch security.

## Anonymity-set manipulation under corruption

A corrupt scheduler can exclude honest clients and fill a round with Sybils. Participant commitments and client-visible inclusion are necessary but not sufficient: clients must behave uniformly on exclusion, otherwise abort behavior itself links correspondents.

## Recovery tradeoff

Keeping old label or retrieval state aids offline recovery but weakens forward-secure metadata. Darqual must choose and publish a retention window. State older than the window is erased; messages beyond it are unavailable or require a separately analyzed archive.

## Claims allowed after a successful prototype

Only conditional claims:

> Privacy holds against a mobile adversary that corrupts at most one active member per four-party committee within each refresh window, does not exceed the handoff overlap bound, and cannot recover securely erased shares after transition.

Anything stronger requires a different proof and likely a different protocol.

## Simulator experiments

1. Refresh plus erasure: sequential corruptions do not reconstruct one generation.
2. No refresh: sequential corruptions accumulate and breach threshold.
3. Refresh without erasure: post-service corruptions recover prior generations.
4. Handoff-overlap violation: old/new corruption breaches the modeled bound.
5. Committee selection: estimate cumulative unsafe-epoch probability.
6. Exclusion: detect anonymity-set shrink and abort without recipient-dependent behavior.
