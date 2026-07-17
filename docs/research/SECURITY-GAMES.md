# Darqual Security Games

**Status:** Draft game suite for protocol selection

## Common experiment

Let `Setup(1^lambda)` create public parameters, a registered service-member set, client identities, and initial committee state. The adversary controls the network and schedules all delivery. It may corrupt parties according to the corruption model declared by each game.

A trace contains client epoch actions, committee messages, public commitments, failures, reconnects, and retrievals. `Leak(trace)` returns only the leakage explicitly allowed by `SYSTEM-MODEL.md`.

A challenge is valid only when both worlds have equal public leakage, equal message-size buckets, equal honest participation schedules, and equal declared failures. This prevents the game from hiding information the protocol intentionally publishes.

## G-CU: communication unobservability

1. The adversary chooses honest clients `(S0, R0)` and `(S1, R1)`, equal-length plaintexts, and two valid traces.
2. In world 0, the first pair exchanges real messages and the second emits cover.
3. In world 1, the roles are reversed.
4. The challenger samples `b`, executes world `b`, and gives the adversary the global network view, corrupted-party state, and public log.
5. The adversary outputs `b'`.

Advantage is `|Pr[b'=b] - 1/2|`. Cryptographic mode requires negligible advantage. A DP mode must publish an explicit `(epsilon, delta, T)` bound over `T` epochs.

## G-REL: relationship unobservability

The adversary selects two equal-leakage matchings over the same set of active honest senders and receivers. The challenger executes one matching. The adversary wins by identifying it. This isolates relationship privacy from the stronger question of whether communication occurred.

## G-WRITE: private-write destination

1. The adversary chooses two authorized logical slots and one equal-size encrypted envelope.
2. The challenger creates write shares for one slot.
3. The adversary receives the views of up to the declared corrupt threshold, all network traffic, and the resulting public commitment.
4. It guesses the slot.

The game must include malformed concurrent writes, retries, and committee handoff. A write primitive only passes if its authorization proof does not identify the slot.

## G-READ: private retrieval

The adversary chooses two existing equal-size records or notifications. The challenger privately retrieves one under an identical client schedule. The adversary receives server views, traffic, and public commitments and guesses the index.

For full-window download this game is trivial but bandwidth is linear. For PIR variants, the proof must state preprocessing, collusion, and query-count assumptions.

## G-HANDOFF: private committee transition

1. The adversary chooses two valid service states with identical public roots, capacities, expiry distribution, and message sizes, but permuted honest mailbox ownership and relationships.
2. The challenger runs `Handoff(C_e, C_{e+1}, state_b)`.
3. The adversary may corrupt allowed members before, during, and after handoff, receiving their full retained state.
4. Expired honest members execute the specified erasure operation.
5. The adversary sees the handoff transcript and guesses `b`.

Security requires negligible advantage under the declared mobile-corruption schedule. If erasure is omitted, the game is expected to fail and should be used as a negative control.

## G-AS: anonymity-set integrity

1. The challenger commits to eligible participant set `P_e` before challenge inputs.
2. The adversary controls delivery and attempts to present an honest client with a view containing a strict attacker-selected subset `P'_e`.
3. The client either finalizes, aborts, or outputs exclusion evidence.

The adversary wins if the client finalizes while believing the anonymity set meets policy but the effective set is below policy, without detectable commitment inconsistency.

## G-RET: retention and private recovery

The challenger accepts a message in epoch `e`, rotates committees, induces allowed crashes and shard withholding, then retrieves before expiry. The adversary wins if either the message is unavailable under the stated availability threshold or the retrieval violates G-READ.

## G-EQUIV: certified-state equivocation

The adversary wins by producing two distinct valid threshold-certified commitments for the same epoch and predecessor without publicly attributable threshold violation evidence.

## G-FSM: forward-secure metadata

The challenger runs directional label state through epoch `e`, erases prior states, and compromises the client at `e+1`. Given transcripts and current state, the adversary must distinguish a real prior label from random. This game excludes labels still retained for unread-message recovery; that retention must appear in leakage.

## G-PCS: post-compromise content recovery

Use the standard Double Ratchet recovery experiment. Darqual claims only composition: asynchronous transport and committee processing must not prevent a later honest DH ratchet step from restoring future confidentiality.

## Composition obligations

Passing components independently is insufficient. The protocol proof must address:

- schedule leakage across G-WRITE and G-READ;
- participant exclusion before G-CU;
- state retained for G-RET weakening G-HANDOFF or G-FSM;
- retries creating cross-epoch identifiers;
- mode changes altering public leakage;
- cumulative corruption across committees;
- malicious friends causing distinguishable notification or retrieval behavior.

## Required negative controls

The simulator and prototype must demonstrate game failure when:

1. clients emit only on real demand;
2. read indices are requested in plaintext;
3. old committee shares are not erased or refreshed;
4. participant commitments are omitted;
5. cover and real envelopes use different sizes or validation work;
6. the adversary can isolate a target with Sybil clients.
