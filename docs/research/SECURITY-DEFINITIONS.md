# Darqual Security Definitions

**Status:** Informal-to-formal bridge. These definitions must become games before implementation claims.

## 1. Content confidentiality

An adversary without a challenged endpoint's current session secrets cannot distinguish equal-length challenged plaintexts from ledger, committee, storage, or transport observations.

## 2. Sender-message unlinkability

Given two eligible honest senders and one equal-length encrypted message, the adversary cannot determine which sender submitted that message beyond the declared leakage.

## 3. Receiver-message unlinkability

Given two eligible honest receivers and one stored message, the adversary cannot determine which receiver privately retrieved it beyond the declared leakage.

## 4. Relationship unobservability

For two communication traces with identical public leakage and participation schedules but different honest sender-recipient pairings, the adversary cannot distinguish the traces with more than negligible advantage, or more than an explicitly bounded differential-privacy advantage for a DP mode.

## 5. Communication unobservability

For two traces with identical public leakage where an honest pair exchanges real messages in one trace and only cover traffic in the other, the adversary cannot distinguish the traces beyond the protocol's stated bound.

This requires traffic schedules independent of real demand. Encryption alone cannot satisfy it.

## 6. Write privacy

Committee views of a valid write reveal neither the logical destination nor payload, except to the final authorized receiver. The game must account for malicious clients and all-but-threshold committee collusion.

## 7. Query privacy

Committee and storage views of retrieval reveal neither the requested notification nor message-store index. Query timing and fixed schedule are handled separately by communication unobservability.

## 8. Handoff privacy

For two valid committee-transition histories with identical public commitments but permuted honest mailbox ownership and communication relationships, old and new committee views remain indistinguishable, including under allowed cross-epoch corruptions.

This is the candidate novel definition.

## 9. Forward-secure metadata

After a client advances and erases directional addressing state through epoch E, compromise at E+1 does not reveal labels used before E+1, subject to retained transcripts and declared endpoint state.

## 10. Post-compromise content recovery

Following a temporary endpoint compromise, a later uncompromised DH ratchet step restores future message confidentiality under the existing Double Ratchet assumptions.

## 11. Anonymity-set integrity

A malicious service cannot make an honest client believe it participated in an epoch with anonymity set A while the actual challenge set was a strict attacker-controlled subset, without detection or failure to finalize.

Required subproperties:

- participant-set commitment;
- input-inclusion or exclusion evidence;
- uniform client behavior on exclusion;
- safe abort below a configured threshold;
- no privacy claim for silently partitioned views.

## 12. Robustness

The service preserves privacy and integrity when up to the modeled threshold behaves maliciously. Liveness is evaluated separately under crash, churn, and network partition.

## 13. Availability and retention

A message accepted and committed in epoch E remains reconstructible and privately retrievable until its advertised expiry if the stated number of storage or committee members remains available.

## 14. Censorship evidence

If a valid client submission is acknowledged but omitted from finalized state, the client can produce evidence of omission without revealing its destination or plaintext. Whether this is achievable without harming write privacy is an open design question.

## 15. Equivocation resistance

An epoch committee cannot produce two conflicting certified state commitments without publicly attributable evidence, assuming fewer than the certificate threshold collude.

## 16. Leakage accounting

Every protocol variant must publish one leakage function covering:

- timing;
- sizes and buckets;
- participation;
- failures and retries;
- mode transitions;
- message expiry;
- committee membership;
- public commitments;
- client disconnection and reconnection.

No use of “metadata-private” is valid without this accounting.
