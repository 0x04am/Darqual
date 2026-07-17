# Darqual External Novelty Review Packet

## Request

We are seeking an early research critique, not endorsement or a security audit. Please identify prior work, false assumptions, impossible goals, and the smallest publishable question.

## One-sentence proposal

Darqual investigates whether a cryptographic notify-before-retrieval messaging service can preserve communication unobservability, retained unread messages, and anonymity-set integrity while its untrusted service committee changes and proactively refreshes state.

## Why this might matter

The 2024 SoK on metadata-protecting communication identifies a shortage of systems combining asynchrony, low latency, horizontal scalability, robustness, and anonymity-set protection. PingPong provides flexible asynchronous notify-before-retrieval using TEEs. Groove provides offline flexibility through untrusted delegation and a DP mixnet. Express/Talek provide private write/read components under fixed-server assumptions. YOSO work provides generic ephemeral threshold services.

The proposed seam is the privacy of **messaging-specific state handoff** across committees without TEEs or permanent non-colluding servers.

## Current research question

Can an asynchronous communication-unobservable service replace trusted enclaves and permanent servers with proactively refreshed committees while preserving:

- private writes;
- private notification;
- private retrieval;
- unread-message retention;
- anonymity-set integrity;
- privacy against mobile/adaptive corruption?

## Baseline model

- Four-member configured committee, at most one Byzantine member.
- Three signatures finalize state.
- Global active network observer.
- Out-of-band contact establishment.
- Activity-independent client epoch schedule in strongest mode.
- Conditional secure erasure.
- No permissionless Sybil-resistance claim.

## Candidate novelty

1. A handoff-privacy game for asynchronous message service state.
2. A protocol for verifiable proactive migration of notification, retrieval, authorization, and retention state without exposing ownership.
3. Integration with directional forward-secure labels and content ratchets.
4. Anonymity-set commitments and privacy-safe abort under exclusion.
5. Evaluation against fixed TEE and fixed-server baselines.

## Prior art most likely to preempt us

- PingPong, Groove, Talek, Express;
- Stadium, Karaoke, XRD;
- Trellis, Clarion, RPM, Blinder;
- YOSO threshold cryptography, dynamic proactive secret sharing;
- any work combining private messaging with dynamic committees or proactive ORAM/PIR state.

## Questions for reviewer

1. Is committee handoff privacy already formalized under another name?
2. Is a four-party `f=1` model too weak to justify the complexity over TEEs?
3. Should the service be modeled as MPC, ORAM/PIR, anonymous broadcast, or proactive secret sharing?
4. Does a public commitment log add security, or merely blockchain-shaped overhead?
5. Which state should remain immutable at storage providers rather than migrate?
6. Can communication unobservability coexist with bounded offline clients without trusted delegation?
7. What is the strongest realistic mobile-corruption model?
8. Which venue and artifact scope would be credible?

## Falsification criteria

We will pivot if equivalent prior work exists, handoff exposes ownership, mobile corruption defeats practical refresh, anonymity-set integrity cannot be enforced, or measured overhead has no defensible tradeoff point against PingPong/Groove/Talek.

## Repository evidence

Current prototype: Rust identity, Lockbox v2, Double Ratchet, encrypted headers, Tor/Arti transport, epoch/Merkle ledger primitives, cover primitives, storage coding, and committee-election sketch. These are prototype ingredients, not evidence for the proposed protocol.

Research branch documents:

- `RESEARCH-QUESTION.md`
- `SYSTEM-MODEL.md`
- `SECURITY-GAMES.md`
- `THRESHOLD-DECISION.md`
- `PROTOCOL-PRIMITIVES.md`
- `MOBILE-CORRUPTION.md`
- `NOVELTY-MATRIX.md`
- `LITERATURE-REVIEW.md`
