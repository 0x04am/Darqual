# Darqual Novelty Matrix

**Status:** Working literature map. “Darqual delta” is a hypothesis until the cited system is fully compared at protocol level.

| System | Established contribution | Trust / privacy shape | Limitation relevant to Darqual | Candidate Darqual delta |
|---|---|---|---|---|
| SoK MPCS (2024) | Taxonomy of 31 metadata-protecting systems | Global-network-adversary focus | Identifies asynchrony, robustness, anonymity-set integrity, and trust distribution gaps | Use its definitions and evaluate the combined gap, not invent terminology |
| PingPong (2025) | Notify-before-retrieval, async concurrent messaging | TEE-backed cryptographic communication unobservability | Hardware trust, enclave side-channel and availability assumptions | Cryptographic committee realization without TEEs, including handoff |
| Stadium (2017) | Horizontally distributed verifiable mixchains | DP privacy; one honest server per chain | Synchronous, separate dialing, minute-scale latency, incomplete fault tolerance | Async retention and notification with churn-safe service state |
| Karaoke (2018) | Optimistic indistinguishability and efficient noise verification | Computational DP; synchronous rounds | Separate dialing, loss-driven privacy degradation, users visible | Apply loss-aware traffic reasoning to asynchronous committee service |
| Express (2019) | Efficient DPF private writes to mailboxes | Two-server, one malicious; write privacy | Reads exposed, either server can deny service, poor horizontal scaling | Private notify/read plus rotating distributed trust and state continuity |
| Talek (2020) | Hidden-access-pattern group messaging and private notification | Untrusted server set with private reads | Fixed service assumptions, TTL loss, not committee-rotated | Handoff-safe notification and retention across ephemeral committees |
| FrodoPIR (2023) | Practical stateful single-server PIR | LWE computational security | Large queries/preprocessing; dynamic DB integration | Evaluate as notification/read primitive, not invention |
| Shuffle PIR (2024) | Information-theoretic PIR from anonymous concurrent queries | Shuffle and crowd assumptions | Requires concurrent client volume and shuffle service | Use fixed epoch traffic to supply query crowd; evaluate feasibility |
| MCMix (2017) | Dialing and conversation via MPC | MPC trust model | Coordination and synchronous workflow | Notify-before-retrieval and committee churn |
| RPM (2023) | Robust scalable MPC anonymous broadcast | Honest-threshold MPC | Broadcast substrate, no async mailbox semantics | Reuse robust shuffle/MPC techniques inside service |
| Trellis (2023) | Robust scalable metadata-private anonymous broadcast | Fraction of malicious mix servers | Broadcast, rigid participation, substantial latency | Messaging-specific async state and handoff; use robustness ideas |
| Pudding (2024) | Private human-readable discovery over anonymity networks | BFT fixed discovery nodes | Discovery only | Integration target; not Darqual novelty |
| YOSO threshold service (2022) | Threshold cryptography with ephemeral committees | YOSO/adaptive setting | Generic threshold service, not metadata-private messaging state | Messaging-specific private notification/store handoff and leakage analysis |
| Algorand/YOSO literature | Unpredictable ephemeral committee selection | Registered/stake participant assumptions | Consensus focus; selection alone does not transfer private state | Use committee machinery, do not claim generic selection novelty |

## Novelty claims currently allowed

Only as hypotheses:

1. Privacy-preserving transition of asynchronous notification and message-store state across ephemeral committees.
2. Communication-trace privacy under mobile/adaptive committee corruption and bounded offline clients.
3. Anonymity-set integrity integrated with asynchronous private messaging.
4. A practical no-TEE notify-before-retrieval construction that is horizontally scalable.

## Claims currently forbidden

- first distributed metadata-private messenger;
- first asynchronous metadata-private messenger;
- first dead-drop messenger;
- first DPF/PIR messenger;
- first rotating committee or VRF service;
- first blockchain messenger;
- global-observer resistance merely because Tor, cover entries, or a ledger is present.
