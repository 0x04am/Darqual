# Tier-1.5 Committee Fan-out — Specification

**Status:** one-day implementation contract
**Branch:** `feat/tier15-committee-fanout`
**Baseline:** Tier-1 single-relay dead-drop at `600a95b`

## 1. Objective

Replace Tier-1's single relay as a storage/availability point with a static, authenticated
multi-relay committee. Clients seal and PoW-mint one `LedgerEntry`, replicate the identical entry
to every configured relay over Tor, require a write-acceptance threshold, fetch from every reachable
relay, validate every relay page, deduplicate entries locally, and trial-open the union.

This is a vertical availability/integrity slice. It is **not** a consensus protocol, threshold
cryptography, write privacy, read privacy, or global-observer contact-graph privacy.

## 2. Honest security delta

| Property | Tier-1 | Tier-1.5 | Claim |
|---|---|---|---|
| One-relay crash | total outage | message survives if any accepting relay remains reachable | real availability gain |
| One-relay omission | message absent | union read recovers from another accepting relay | real availability gain |
| One-relay malformed/forged page | client may consume it | page is validated and isolated; other relays remain usable | real integrity gain |
| Replay of one paid PoW stamp | relay-local rejection | stable entry ID deduplicates across relays | real replay/storage gain |
| Equivocation/common history | no cert | still no cert; chains remain independent | not solved |
| Contact-graph privacy vs GPA | not delivered | not delivered; fan-out increases observation points | no gain |
| Sybil resistance | configured relay | authenticated static manifest | no permissionless claim |

**Allowed wording:** "replicated multi-relay store-and-forward with threshold write acceptance."

**Forbidden wording:** "anytrust", "BFT finalized", "global-observer resistant", "private write",
"private read", or "rotating committee" until those mechanisms actually exist.

## 3. Trust and configuration

1. The committee is a static out-of-band manifest for this slice.
2. Every member has a unique name and unique `host:port` endpoint.
3. The manifest is local configuration, not discovered over the relay protocol.
4. `1 <= write_threshold <= members.len()`.
5. Committee membership is deterministically ordered.
6. Relays remain independent Tier-1 state machines and maintain independent hash chains.

The manifest is TOML:

```toml
version = 1
write_threshold = 2

[[members]]
name = "relay-a"
onion = "aaaaaaaa...aaaa.onion"
port = 9999
```

For deterministic tests, endpoints are opaque validated strings; the Tor CLI additionally validates
that production endpoints end in `.onion`.

## 4. Protocol behavior

### 4.1 Canonical entry ID

`LedgerEntry::id()` is BLAKE3 over a domain separator and its existing canonical bytes
`label || envelope || nonce`. Relay-local free-PoW replay rejection and cross-relay client
deduplication use the same definition.

### 4.2 Submit

1. Build one `Conversation` label and one encrypted envelope.
2. Mint PoW once.
3. Submit the exact same `LedgerEntry` to all members using one bootstrapped Tor client.
4. Wait for all member calls up to a per-member timeout.
5. Count `Accepted` and structured `Duplicate` as stored acknowledgements.
6. Exit success iff acknowledgements meet `write_threshold`.
7. Report every member outcome. Threshold failure is explicit; partial writes are not rolled back.

### 4.3 Fetch

1. Fetch public pages from all reachable members.
2. Reject a relay page if decoding fails, it is truncated, any block fails Merkle or expected-PoW
   validation, or returned epochs regress.
3. Do not merge relay block chains. Flatten valid blocks to entries with source/epoch provenance.
4. Deduplicate by `LedgerEntry::id()`.
5. Trial-open each unique entry against the block epoch and adjacent epochs.
6. Emit each unique plaintext once.
7. Report relay failures and whether history completeness is unknown.

A read quorum is not required for recovery: a message held by one honest reachable relay is useful.
The number of agreeing sources is reported as provenance, not BFT confidence.

## 5. Failure behavior

- zero reachable relays: explicit error;
- acknowledgements below threshold: explicit partial-write error;
- duplicate at relay: idempotent stored result;
- malformed relay page: isolate that relay;
- one relay omits an entry: union recovers from another;
- all relays omit an entry: unavailable, no false success;
- truncated page: relay rejected for complete-history fetch;
- divergent independent chains: permitted; entries are unioned only after page validation;
- replayed identical entry across relays: one logical message after deduplication;
- restart: each relay uses existing Tier-1 durable snapshot rules.

## 6. Project structure

- `darqual-ledger/src/block.rs`: canonical `LedgerEntry::id()`.
- `darqual-committee/src/manifest.rs`: transport-neutral manifest types and validation.
- `darqual-tor/src/committee.rs`: multi-relay outcomes, page validation, union/dedup helpers.
- `darqual-tor/src/main.rs`: committee CLI orchestration using one Arti client.
- `darqual-tor/src/relay.rs`: structured rejection code for idempotent retry.
- `darqual-sim`: optional deterministic availability model if time remains.

Do not add Arti dependencies to `darqual-committee` or `darqual-sim`.

## 7. Testing strategy

TDD in vertical slices, all builds/tests on Avante:

1. Entry-ID stability/change/replay tests.
2. Manifest validation: empty, duplicate endpoint/name, threshold bounds, deterministic ordering.
3. Structured duplicate response mapping and round-trip.
4. Pure committee aggregation tests:
   - 3 members / threshold 2 happy path;
   - 1 unavailable and success;
   - 2 unavailable and explicit threshold failure;
   - duplicate counts as stored;
   - valid entry deduped across 3 pages;
   - one malformed page isolated;
   - Eve opens nothing.
5. Handler durability regression tests.
6. Workspace gate plus standalone Tor gate.

No live cross-host Tor run is required for this slice. Existing single-relay commands remain.

## 8. Boundaries

### Always
- spec before code;
- one thin slice per commit;
- tests first;
- verify and build only on Avante;
- push green, revertible commits to the feature branch;
- preserve explicit per-relay outcomes and incomplete-history warnings.

### Ask before
- adding a production crypto primitive;
- changing identity/contact-card wire formats;
- merging to `main`;
- opening the configured participant registry.

### Never
- claim committee consensus or anytrust privacy from client fan-out;
- merge independent relay hash chains;
- silently treat partial writes as full success;
- accept unvalidated relay blocks;
- rebuild or test on Jade;
- commit onion private keys or relay state.

## 9. Success criteria

- one entry is sealed/minted once and submitted to all configured relays;
- `write_threshold` determines CLI success;
- one failed/omitting relay does not prevent recovery from another;
- Bob decrypts one plaintext from replicated pages; Eve decrypts none;
- identical replicated entries print once;
- malformed/truncated relay responses are isolated and surfaced;
- legacy one-relay Tier-1 commands remain functional;
- workspace `verify.sh` and standalone `verify-tier1-tor.sh` are green on Avante;
- docs state availability/integrity gains and explicitly deny new privacy claims.

## 10. Explicitly deferred

Threshold signatures/certificates, relay gossip, common-log consensus, equivocation evidence,
VRF-elected rotation, endpoint-key binding, DPF/FSS writes, PIR reads, mandatory cover schedule,
independent circuit policy, RLN/anonymous credentials, handoff/proactive resharing, and Sybil
resistance.
