# Darqual Literature Review

**Search date:** 2026-07-17
**Method:** OpenAlex searches through `jawz-scholar`, followed by full-text inspection where accessible. This is a research map, not yet a systematic review.

## Executive synthesis

The broad territory is mature. Distributed metadata-private messaging, dead drops, DPF private writes, PIR reads, verifiable mixnets, differential-privacy cover, robust MPC broadcast, private discovery, and ephemeral committee selection all have substantial prior art.

The unresolved combination most relevant to Darqual is:

> asynchronous communication-unobservable messaging with private notification and retrieval, no TEE trust, robust anonymity-set protection, and privacy-preserving service continuity across mobile or ephemeral committees.

The 2024 MPCS SoK independently identifies asynchrony, robustness, anonymity-set manipulation, and practical trust distribution as open concerns. PingPong addresses asynchronous notify-before-retrieval with TEEs. YOSO threshold-service work addresses ephemeral committees generically. Darqual's plausible research seam is their cryptographic composition, provided equivalent work is not found in citation closure.

## Taxonomy adopted from the SoK

Darqual must distinguish:

- **SUMS:** sender-message unlinkability;
- **RUMS:** receiver-message unlinkability;
- **RUS:** sender-recipient relationship unobservability among active users;
- **CUS:** communication unobservability, including hiding whether a relationship is active.

The intended strongest asynchronous mode is CUS. This requires activity-independent traffic, not merely encryption, Tor, or secret labels.

The SoK identifies three practical messaging properties that rarely coexist:

1. low latency;
2. asynchronous operation;
3. horizontal scalability.

It also highlights server churn, anonymity-set protection, private asynchronous storage, and misleading manytrust assumptions as research gaps.

## Core systems

### PingPong: Metadata-private Messaging without Coordination (2025)

**Contribution:** Replaces dial-before-converse with notify-before-retrieval. `Ping` privately aggregates notifications; `Pong` is an oblivious asynchronous message store. Supports parallel conversations and communication-trace indistinguishability under uniform traffic.

**Trust:** Secure enclaves, implemented with Intel SGX, plus oblivious algorithms to hide access patterns.

**Reported scale:** 32 eight-core enclave servers; Ping 99th-percentile latency of 0.934 seconds for 50,000 concurrent clients; Pong around 20,000 fetches/s in the reported setup.

**Limitations relevant to Darqual:** Enclave integrity/confidentiality and attestation are assumed; enclave compromise and broader side-channel concerns are outside the abstract guarantee. Initial add-friend remains required.

**Use:** Adopt the functional decomposition. Investigate a no-TEE committee realization rather than reinventing async workflow.

### Stadium (2017)

**Contribution:** Distributed, horizontally scalable metadata-private messaging through parallel verifiable mixchains, dead drops, and differential-privacy noise.

**Trust:** At least one honest server in every relevant mixchain. Global active network observer allowed. Users send and receive exactly one item per round.

**Reported scale:** 100-server EC2 deployment; projected tens of millions of users with minute-scale rounds.

**Limitations:** Synchronous, separate dialing protocol, broad DoS can halt service, evaluated prototype simulated client input and lacked full fault tolerance/verifiable decryption.

**Use:** Baseline for distributed trust, parallel mixing, and manytrust failure analysis. Darqual cannot claim distributed metadata-private messaging as novel.

### Karaoke (2018)

**Contribution:** Optimistic indistinguishability. In healthy rounds, traffic transformations reveal no relationship information; DP noise protects rounds with loss or active interference. Bloom filters verify that server noise was not removed.

**Trust:** Global observer, active interference, fraction-honest server assumption. Users are visibly Karaoke participants.

**Reported scale:** Approximately 6.8 seconds for two million users; horizontal scaling by adding servers.

**Limitations:** Synchronous conversation rounds, separate dialing, DP composition under loss, no hiding of tool usage.

**Use:** Replace naive cover-count reasoning with explicit clean-round invariants, detectable degraded rounds, and measured privacy composition.

### Express (2019)

**Contribution:** Efficient DPF private writes to locked mailboxes. Secure against arbitrary malicious clients and one malicious server in a two-server deployment. Includes validation against malformed client writes.

**Privacy:** Cryptographic write privacy. The adversary sees that a client wrote and when, but not the target mailbox.

**Limitations:** Reads are not private; either server can deny service; blocking one server stops service; mailbox overwrite and polling behavior require care; limited horizontal scalability.

**Use:** Candidate private-write component. Darqual's work would be notification, private read, robust rotation, and handoff, not DPF invention.

### FrodoPIR (2023)

**Contribution:** Simple stateful single-server LWE PIR with client-independent server preprocessing and low online response overhead.

**Reported scale:** One million 1KB records, server responses below one second, response expansion below roughly 3.6x.

**Costs:** Multi-megabyte queries at large database sizes, client preprocessing/storage, server preprocessing, global query budget before parameter refresh, and dynamic-database friction.

**Use:** Candidate for stable notification tables or immutable epoch segments. Must be benchmarked against full-window retrieval; not assumed suitable for a continuously mutable store.

### Shuffle-model PIR (2024)

**Contribution:** Information-theoretic single-server PIR with sublinear client cost when many clients submit anonymous concurrent queries through a shuffle.

**Trust/cost:** Requires a shuffle abstraction and sufficient concurrent clients; security and efficiency depend on crowd volume.

**Use:** Darqual's fixed epoch traffic may create the required query crowd. This is a concrete experiment connecting cover traffic and retrieval rather than treating them independently.

### RPM (2023)

**Contribution:** Robust scalable anonymous broadcast using secret-shared random permutation matrices, with efficient offline/online MPC and variants for malicious security and two-way communication.

**Limitations:** Broadcast/mixing substrate rather than asynchronous private notification and storage; content confidentiality is not its core goal.

**Use:** Candidate robust server-side shuffle/MPC machinery. Suggests modeling Darqual's service as MPC, not assuming blockchain consensus.

### Trellis (2023)

**Contribution:** Robust scalable mixnet anonymous broadcast under full network surveillance, with verifiable random paths, blame, and changing-network robustness.

**Use:** Robustness and malicious-server accountability baseline. Full-text analysis remains to be completed from a verified source.

### Pudding (2024)

**Contribution:** Private human-readable user discovery with hidden registration status and contact relationships, Byzantine fault tolerance, intermittent clients, and a Nym prototype.

**Use:** Discovery integration/reference. Darqual should not spend its primary novelty budget on new contact discovery.

### Threshold Cryptography as a Service / YOSO (2022)

**Contribution:** Threshold cryptographic services under unpredictable, changing, ephemeral committees; proactive maintenance of system-wide keys; multi-secret multi-dealer VSS.

**Use:** Foundation for committee selection, adaptive-targeting resistance, and proactive key continuity. Full paper annotation remains required. Darqual's delta would concern messaging-specific private state and leakage during handoff.

## Design implications

### 1. Separate service functions

Darqual should model private notification and private retrieval independently, then prove their composition. A monolithic public ciphertext ledger is not automatically the best service design.

### 2. Narrow the ledger

Use a hash-linked public log for state roots, participant commitments, availability commitments, handoff transcripts, and threshold certificates. Publishing every ciphertext is optional and must be justified by privacy, availability, and bandwidth analysis.

### 3. Treat anytrust composition explicitly

“One honest member” is not a universal property. Every chain, committee, PIR replica, shuffle path, and handoff may have a different collusion threshold. Cross-epoch corruption compounds.

### 4. Make asynchrony first-class

Model offline duration, delegated cover, reconnect behavior, retention, expiry, missed notification, forced exclusion, and committee transition. Asynchrony is not equivalent to adding disk storage.

### 5. Protect the anonymity set

Commit participant sets, detect exclusion, define safe abort, and test `n-1`/Sybil attacks. Correct cryptography on an attacker-selected crowd can still deanonymize users.

### 6. Benchmark retrieval choices

Compare full download, buckets, computational PIR, multi-server PIR, and shuffle PIR. Choose based on measured database update rate, client volume, bandwidth, and trust assumptions.

### 7. Analyze traffic over time

Compare strict constant-rate schedules against optimistic indistinguishability. Report cumulative DP loss and behavior under drop, delay, and partition.

## Mandatory reading queue

1. SoK: Metadata-Protecting Communication Systems.
2. PingPong full protocol and security appendix.
3. Stadium and Karaoke.
4. Express and Talek.
5. YOSO threshold service, hbACSS, and dynamic proactive secret sharing.
6. RPM, Trellis, Blinder, Clarion, XRD, Groove.
7. FrodoPIR and shuffle-model PIR.
8. Pudding and Alpenhorn.
9. Latest citing works from 2025–2026, including Metadata-private Messaging without Coordination successors and accountable anonymous broadcast.

## References

- S. Sasy and I. Goldberg, “SoK: Metadata-Protecting Communication Systems,” PoPETs 2024(1), 509–524. https://doi.org/10.56553/popets-2024-0030
- P. Jiang et al., “Metadata-private Messaging without Coordination,” arXiv:2504.19566, 2025. https://arxiv.org/abs/2504.19566
- N. Tyagi et al., “Stadium: A Distributed Metadata-Private Messaging System,” SOSP 2017. https://doi.org/10.1145/3132747.3132783
- D. Lazar, Y. Gilad, and N. Zeldovich, “Karaoke: Distributed Private Messaging Immune to Passive Traffic Analysis,” OSDI 2018. https://www.usenix.org/system/files/osdi18-lazar.pdf
- S. Eskandarian et al., “Express: Lowering the Cost of Metadata-hiding Communication with Cryptographic Privacy,” arXiv:1911.09215. https://arxiv.org/abs/1911.09215
- R. Cheng et al., “Talek: Private Group Messaging with Hidden Access Patterns,” ACSAC 2020. https://doi.org/10.1145/3427228.3427231
- A. Davidson, G. Pestana, and S. Celi, “FrodoPIR,” PoPETs 2023(1), 365–383. https://doi.org/10.56553/popets-2023-0022
- Y. Ishai et al., “Information-Theoretic Single-Server PIR in the Shuffle Model,” ITC 2024. https://arxiv.org/abs/2001.03618
- D. Lu and A. Kate, “RPM: Robust Anonymity at Scale,” PoPETs 2023. https://doi.org/10.56553/popets-2023-0057
- S. Langowski, S. Servan-Schreiber, and S. Devadas, “Trellis,” NDSS 2023. https://doi.org/10.14722/ndss.2023.23088
- C. Kocaoğullar et al., “Pudding: Private User Discovery in Anonymity Networks,” IEEE S&P 2024. https://doi.org/10.1109/sp54263.2024.00167
- F. Benhamouda et al., “Threshold Cryptography as a Service (in the Multiserver and YOSO Models),” CCS 2022. https://doi.org/10.1145/3548606.3559397
