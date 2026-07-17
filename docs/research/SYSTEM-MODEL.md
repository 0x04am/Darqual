# Darqual System Model

**Status:** Draft, pre-proof

## Entities

### Clients

Clients maintain identities, contacts, content-ratchet state, directional addressing state, an encrypted outbound queue, and a retrieval cursor. A client may disconnect for bounded periods. A client emits protocol traffic according to its selected privacy mode, not according to real message demand.

### Epoch committees

A committee performs one epoch's private notification, write processing, message-store operation, retrieval service, and handoff preparation. The initial artifact uses a configured registry. Later work may select committees unpredictably from that registry using a standard VRF or YOSO-like mechanism.

### Storage providers

Storage providers retain authenticated or erasure-coded epoch data. They are not trusted for confidentiality. Their exact role is deferred until the fixed-committee service state is defined.

### Public commitment log

The log contains threshold-certified commitments to epoch state. It provides rollback and equivocation evidence. It is not assumed to carry plaintext, contact identifiers, or necessarily every message ciphertext.

### Transport network

The transport hides client IP addresses and supports fixed-size messages. Initial simulation uses an ideal authenticated transport. Deployment experiments compare direct TCP, Tor/Arti, and a delayed mix underlay.

## Time and synchrony

- Time is divided into numbered epochs.
- Clients and committees have bounded clock skew in the baseline model.
- The network is partially synchronous for liveness: messages may be delayed or dropped, but eventual delivery is required during healthy periods.
- Safety and privacy claims must specify whether they survive indefinite delay.

## Adversary

The adversary may:

- observe all network links, packet timings, sizes, and participation;
- corrupt clients outside the challenged relationship;
- corrupt committee and storage members subject to the active threshold;
- adaptively choose corruptions based on observations;
- delay, drop, reorder, replay, inject, or selectively deliver traffic;
- create malformed writes and queries;
- attempt Sybil participation within the configured-registry boundary;
- exclude honest clients or committee members from an epoch;
- withhold state during committee transition;
- cause crashes and restarts.

The adversary may not:

- break standard cryptographic assumptions;
- read an uncompromised client's live memory;
- compromise both challenged endpoints during the challenge;
- violate the explicit honest-member or threshold assumption for the property being claimed.

## Corruption models to compare

1. **Static:** corruptions fixed before setup.
2. **Epoch-adaptive:** corruptions chosen during an epoch, bounded below the threshold.
3. **Mobile:** the adversary corrupts different members across epochs.
4. **Post-service:** expired members may be corrupted after erasure.

The research must not collapse these models into the phrase “anytrust.”

## Network views and leakage

The intended public leakage function may include:

- protocol version and mode;
- epoch number and duration;
- registered participant count;
- committee public identities;
- fixed packet and block sizes;
- public state commitments;
- declared retention window;
- whether an epoch safely finalized or aborted.

It must not include, for honest challenged users:

- whether they exchanged a real message;
- sender-recipient relationships;
- mailbox or dead-drop ownership;
- which notification or message was retrieved;
- message contents or precise plaintext length;
- prior directional labels after forward-secure state advancement.

## Trust assumptions

The first prototype uses a small fixed committee and explicitly compares:

- one-honest-member anytrust;
- honest majority;
- threshold assumptions required by selected MPC/PIR primitives.

A protocol component is not allowed to inherit a stronger trust assumption silently. Every component must state its threshold and collusion model.

## Availability and safety

Darqual distinguishes:

- **privacy safety:** attacks may stop service but do not reveal the challenged relationship;
- **integrity safety:** finalized commitments do not fork or accept malformed transitions;
- **liveness:** honest messages are eventually accepted and retrievable;
- **retention:** unread messages remain available for the advertised lifetime;
- **censorship evidence:** excluded or withheld inputs produce client-verifiable evidence when possible.

Privacy-preserving abort is preferred to continuing with an unsafe anonymity set.

## Out of scope for the first artifact

- permissionless membership and economic incentives;
- live endpoint compromise;
- coercion and physical seizure while unlocked;
- private human-readable discovery;
- groups;
- moderation and lawful traceability;
- internet shutdown resistance;
- production deployment claims.
