# Tier-1 Dead-Drop MVP — Specification

**Status:** autonomous overnight implementation contract  
**Branch:** `feat/tier1-dead-drop-mvp`  
**Scope:** single-relay, async, store-and-forward messaging over Tor. This closes the direct peer-to-peer routing gap for the MVP; it does **not** claim global-observer resistance.

## Assumptions

1. One designated relay onion service is acceptable for Tier 1. It is infrastructure, not a trusted plaintext party: it receives PoW-gated opaque `LedgerEntry` values and exposes committed `Block` values.
2. The relay address is shared out-of-band. Sender and receiver never dial each other in dead-drop mode.
3. Recipient contact cards are already exchanged out-of-band. Anonymous first-contact discovery remains out of scope.
4. Existing `Conversation` labels and lockboxes are the compatibility foundation. The first vertical slice uses static per-epoch labels; forward-secret keywheel persistence is a follow-up after the async path is proven.
5. Epoch duration remains the existing 60 seconds. The relay may expose an in-progress current-epoch snapshot so messages need not wait a full epoch.
6. Existing direct `host`/`send` commands remain available and are explicitly identified as direct mode.
7. No push. Commits remain local on this feature branch.

## Objective

Deliver a working end-to-end path in which:

- a relay hosts one Tor onion service;
- Alice seals and labels a message for Bob, mints PoW, and submits it to the relay;
- Bob independently dials only the relay, fetches the hot-window ledger, matches his per-epoch label, and decrypts the message;
- Alice and Bob never establish a direct network connection;
- a wrong recipient cannot decrypt Bob's message;
- messages survive sender disconnect and are retrievable later;
- relay state survives restart using an atomic local snapshot.

## Protocol and commands

Wire protocol is length-framed by `darqual-tor`, then serialized as bounded bincode:

```rust
enum RelayRequest {
    Submit(LedgerEntry),
    Fetch { since_epoch: Option<u64> },
}
enum RelayResponse {
    Accepted { epoch: u64, entries: u32 },
    Ledger(Vec<Block>),
    Rejected(String),
}
```

Commands:

```text
darqual-tor-node relay --nickname <name> --port 9999 \
  --state ~/.darqual/relay-ledger.bin --window 60 --pow-difficulty <n>

darqual-tor-node drop-send --relay <relay.onion> --to dqcard1... \
  --message "..." --port 9999 --pow-difficulty <n>

darqual-tor-node drop-fetch --relay <relay.onion> --from dqcard1... \
  --port 9999 [--since-epoch <n>]
```

`drop-send` derives `Conversation::label(epoch_now())`, seals a lockbox to the recipient, mints a `LedgerEntry`, submits it, and waits for relay acceptance. `drop-fetch` fetches public blocks, derives labels for the current and retained epochs using the sender card, and calls `fetch_open`.

## Project structure

- `crates/darqual-ledger/src/relay.rs` — transport-neutral relay state machine, epoch rollover, persistence DTO.
- `crates/darqual-ledger/src/lib.rs` — relay API exports.
- `crates/darqual-tor/src/lib.rs` — request/response framing with reply support.
- `crates/darqual-tor/src/relay.rs` — protocol DTO and bincode bounds.
- `crates/darqual-tor/src/main.rs` — CLI glue only.
- `crates/darqual-sim/` or ledger integration tests — deterministic Alice→relay→Bob→Eve scenario.
- `scripts/tier1-two-host-smoke.sh` — jade/avante Tor smoke test.

## Code style

Straight-line typed state transitions; no generic service framework:

```rust
pub fn submit(&mut self, now_epoch: Epoch, entry: LedgerEntry) -> Result<Block, RelayError> {
    entry.verify_pow(self.pow_difficulty)?;
    self.rotate_to(now_epoch)?;
    self.pending.push(entry);
    self.snapshot_current()
}
```

All inbound lengths and collection counts are bounded before allocation. Errors are typed in libraries and contextualized with `anyhow` only at the CLI edge. `#![forbid(unsafe_code)]` remains.

## Testing strategy

TDD, in this order:

1. Relay state unit tests: submit, PoW rejection, epoch rotation/linking, hot-window pruning, restart round-trip, malformed snapshot rejection.
2. Protocol tests over in-memory futures I/O: request/reply, oversized-frame rejection, malformed bincode rejection.
3. End-to-end deterministic test: Alice submits; Bob fetches/decrypts; Eve fails; Alice and Bob need only relay coordinates.
4. Local process smoke test without Tor if possible.
5. Live cross-host Tor smoke: relay on avante, sender/receiver commands from jade (and vice versa if time permits).
6. Full `./scripts/verify.sh`, standalone Tor `cargo test`, `cargo clippy --all-targets -- -D warnings`.

## Boundaries

### Always
- Tests fail before implementation (RED), then pass (GREEN).
- Atomic state persistence (temp file + rename, no partial snapshots).
- Bound frame size, entry size, fetched block count, and response size.
- Verify PoW at relay ingress; relay chooses effective epoch.
- Preserve direct mode and existing wire protocol.
- Be explicit in CLI/docs that this is single-relay Tier 1, not full metadata-darkness.

### Allowed autonomously
- Add serde/bincode dependencies already present elsewhere in the workspace.
- Add new modules, commands, tests, and local scripts.
- Make local commits after each green vertical slice.

### Never
- Push or merge.
- Claim global passive observer resistance.
- Implement committee consensus, RLN/DPF, PIR, or full cover-traffic scheduling in Tier 1.
- Store plaintext messages at relay.
- Remove or weaken existing tests.

## Success criteria

- `drop-send` and `drop-fetch` communicate exclusively with the relay onion.
- Bob decrypts a message submitted while Bob was offline.
- Eve receives the same public blocks but cannot decrypt the message.
- Invalid PoW and oversized/malformed requests are rejected without state mutation.
- Restarting relay reloads a valid linked hot window.
- Existing direct mode remains functional.
- Workspace and standalone Tor test/build/clippy gates are green.
- At least one live jade↔avante Tor dead-drop scenario is recorded in verification output.

## Explicitly deferred

Forward-secret keywheel state persistence, simultaneous first-initiation with X3DH/prekeys, multi-relay committees, private writes (DPF), PIR retrieval, mandatory cover schedule, and external audit.
