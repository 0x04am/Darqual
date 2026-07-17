# Fixed-Committee Threshold Decision

**Decision:** The first active-security prototype uses `n = 4` committee members and tolerates `f = 1` Byzantine member.

## Why this model

A four-member committee with at most one Byzantine member gives an honest supermajority and a conventional `n >= 3f + 1` basis for authenticated state-machine agreement, robust secret sharing, and deterministic finalization. It is small enough for exhaustive simulation and localhost experiments, while strong enough to model active faults rather than semi-honest non-collusion.

This does **not** satisfy the aspirational “one honest member among arbitrarily many corrupt members” service model. Darqual separates two properties:

- **privacy of additive or FSS shares** may survive while at least one required share-holder remains honest and erases state;
- **integrity and liveness of the composed service** initially require at most one Byzantine member out of four.

The distinction must remain visible in every claim.

## Roles

The committee is one four-party service, not two permanent named servers. For primitives requiring two non-colluding logical databases, each logical role is instantiated by a threshold subprotocol over the same four registered members with domain-separated keys. A design that reveals both logical-role states to one corrupt member is rejected.

## Finalization

An epoch commitment requires at least three valid committee signatures. Two conflicting certificates would require at least two honest members to sign conflicting state under `f = 1`, which the protocol forbids.

## Handoff

State transfer from committee `C_e` to `C_{e+1}` requires:

- a finalized predecessor certificate;
- verifiable resharing or refresh into the new committee;
- at least three responsive old members for liveness in the baseline;
- erasure acknowledgements as audit evidence, not proof of physical erasure;
- no stable plaintext mailbox ownership in the transcript.

## Safety and liveness boundaries

| Fault state | Privacy | Integrity | Liveness |
|---|---|---|---|
| 0 Byzantine | target | target | target |
| 1 Byzantine | target | target | target under eventual delivery |
| 2 Byzantine | primitive-dependent, not claimed globally | may fail to finalize | not guaranteed |
| 3 Byzantine | only components proven one-honest may survive | not guaranteed | not guaranteed |
| 4 Byzantine | none | none | none |

The node must abort rather than silently downgrade when it cannot assemble a three-member certificate.

## Alternative models retained for experiments

1. `n=3, f=1`: lower cost, unsuitable for standard active BFT finalization without stronger assumptions.
2. `n=7, f=2`: same threshold ratio, useful for scaling experiments.
3. One-honest anytrust with privacy-preserving abort: research target after the four-party artifact.
4. TEE-assisted single or replicated service: PingPong performance baseline, not Darqual's target.

## Decision consequences

- Current Ed25519-based “poor man's VRF” is not used for security claims.
- Initial committees come from a configured authenticated registry.
- Selection randomness and permissionless Sybil resistance are deferred.
- Threshold signatures, VSS, and resharing should use established libraries or research implementations; no hand-rolled production cryptography.
- Simulator defaults must encode `n=4`, `f=1`, quorum `3`.
