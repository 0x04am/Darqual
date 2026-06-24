# Code Review — `darqual-node` & `darqual-cli` binaries
**Reviewer:** Spike (subagent)  
**Scope:** `crates/darqual-node/src/main.rs`, `crates/darqual-cli/src/main.rs`  
**Reference docs:** `SPEC.md`, `THREAT-MODEL.md`  
**Date:** 2025-06-24

---

## Summary

Both binaries are clean and well-structured for a prototype. Error messages are human-readable, no `unwrap`/`expect` in production paths, and identity loading has appropriate context. The serious issues are concentrated in the epoch-alignment logic (a correctness/reliability bug that can cause silent message loss) and two security-hygiene concerns (non-atomic overwrite under `--force`, private-key material lingering in heap strings). Everything else is medium-to-nit territory.

---

## Findings

---

### [HIGH] `darqual-node` — Fetcher ignores `block.header.epoch`; only tries `[epoch_now, epoch_now-1]` — silent message miss when clocks diverge by ≥2 epochs

**File:** `crates/darqual-node/src/main.rs:272–289`

**Problem:**  
`cmd_fetch` fetches a block over the wire, then derives labels using the *fetcher's local clock* (`epoch_now()`) rather than the epoch baked into the block header. It tries two values:
```rust
for epoch in [epoch_now, epoch_now.saturating_sub(1)] {
```
The publisher sealed the label using `epoch_now()` *at publish time* (`main.rs:204`). If the publisher's clock is ahead of the fetcher's clock by ≥2 minutes (i.e., ≥2 epochs), the fetcher derives labels for epochs `[N-1, N-2]` while the block holds entries labelled for epoch `N`. No label match, no error, no warning — `[fetch] no messages for me this epoch` is printed and the message is silently dropped.

The fix is trivially available: `block.header.epoch` is already in the received block. The fetcher should use it *directly* as the primary epoch for label derivation instead of trusting its own clock to guess what the publisher used:

```rust
// Use the epoch the publisher committed to, fall back to local clock only
// as a last-resort cover-traffic epoch.
let block_epoch = block.header.epoch;
let epoch_now = epoch_now();
// Try: block's own epoch first, then ±1 for any residual skew.
let candidates = [block_epoch, block_epoch.saturating_sub(1), block_epoch + 1];
```

With this approach the fetcher's clock is irrelevant — it decrypts relative to what the publisher actually committed. The current two-value window is asymmetric (handles fetcher-late but not fetcher-early) and only protects against a single-epoch skew in one direction.

**Why it matters:** In a real deployment, nodes will have NTP drift, intentional clock skew for traffic-analysis resistance, or simply be fetching a cached/replayed block from a prior epoch. Silent message loss in a metadata-dark messenger is a serious reliability failure; users have no indication the message existed at all.

---

### [HIGH] `darqual-node` — No read/connect timeout on `fetch_block` or `serve_block`; `cmd_fetch` hangs indefinitely on a stalled publisher

**File:** `crates/darqual-net/src/frame.rs:27–36`, `crates/darqual-node/src/main.rs:261`

**Problem:**  
`fetch_block` calls `tokio::net::TcpStream::connect` and then `frame::read_frame`. Neither has a timeout. A malicious or crashed publisher that accepts the TCP connection but sends nothing (or sends 3 bytes of the 4-byte length prefix and stalls) will hang `cmd_fetch` forever, holding the process open. There is no `tokio::time::timeout` wrapper anywhere in the net layer.

The `serve_block` accept loop (`block_transport.rs:58`) similarly spawns no per-connection timeout — a connecting client that never reads will pin the cloned block in memory.

**Fix:**
```rust
// fetch side
let block = tokio::time::timeout(
    Duration::from_secs(30),
    fetch_block(peer)
).await
.context("fetch timed out")?
.context("failed to fetch block from peer")?;
```
Add a symmetric per-connection write timeout on the serve side.

---

### [MEDIUM] `darqual-node` `cmd_send` — Identity loaded but unused (`_identity`); contact card self-authentication check absent

**File:** `crates/darqual-node/src/main.rs:171–188`

**Problem (part 1):**  
`cmd_send` loads the caller's identity but immediately stores it as `_identity` (suppressing the unused-variable warning) and never uses it. The lockbox is sealed without the sender's private key — that is correct by design (anonymous sends). But loading the identity and then not using it is dead code: the load could fail (e.g., no identity file), aborting a send operation that doesn't require the sender's key at all. Either use the identity (e.g., future authenticated sends or rate-limiting) or remove the load.

**Problem (part 2):**  
`cmd_seal` in `darqual-cli` (`cli/main.rs:93`) calls `card.verify()` to confirm the address is derived from the ed25519 pubkey before sealing. `cmd_send` in `darqual-node` does not (`node/main.rs:176–181`). A corrupted or maliciously crafted contact card with a mismatched address would be silently accepted. Consistent behavior across both binaries is warranted, especially since the node is the network-facing component.

**Fix:**
- If the sender identity is not needed, remove lines 171–174.
- Add `if !card.verify() { anyhow::bail!(...) }` after parsing the `to` card (mirror `cmd_seal`).

---

### [MEDIUM] `darqual-node` `cmd_publish` — Also missing contact card self-authentication check

**File:** `crates/darqual-node/src/main.rs:201–202`

**Problem:**  
Same as the above finding for `cmd_send`. The `recipient` card parsed at line 201 is used directly in `Conversation::new` and `Lockbox::seal` without calling `card.verify()`. An address/pubkey mismatch in the input would produce a block with a label and ciphertext that can never be matched or decrypted by the intended recipient.

**Fix:** Add `if !recipient.verify() { anyhow::bail!(...) }` after line 202.

---

### [MEDIUM] `darqual-cli` `cmd_keygen --force` — Non-atomic overwrite; crash between truncate and write destroys identity with no backup

**File:** `crates/darqual-core/src/identity.rs:80` (called from `crates/darqual-cli/src/main.rs:65`)

**Problem:**  
`Identity::save` uses `fs::write(path, ...)` which on most Unix kernels truncates the existing file and writes new content in-place. If the process is killed, panics, or the disk fills between truncate and write completion, the previous identity is destroyed and the new identity is partially written. After `--force` the user has lost their keypair and thus their Darqual address forever.

`fs::write` is not atomic. Atomic overwrite requires write-to-tempfile + `rename`:
```rust
let tmp = path.with_extension("tmp");
fs::write(&tmp, toml_str.as_bytes())?;
fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
fs::rename(&tmp, path)?;
```
`rename` is atomic on POSIX when source and destination are on the same filesystem (which `path.with_extension("tmp")` guarantees).

Additionally, there is no backup of the old identity before overwrite. A `--force` on an accidentally typo'd path silently destroys a real identity. A named backup (e.g., `identity.toml.bak`) would give a recovery window.

---

### [MEDIUM] `darqual-core` `Identity::save` / `load` — Private-key bytes linger in heap-allocated `String` / `IdentityFile` fields; `zeroize` gap

**File:** `crates/darqual-core/src/identity.rs:68–80`, `crates/darqual-core/src/identity.rs:91–101`

**Problem:**  
In `save()`:
```rust
let mut ed_seed = self.signing_key.to_bytes();   // [u8;32] on stack
let mut x_seed  = self.x_secret.to_bytes();      // [u8;32] on stack
let file = IdentityFile {
    ed_seed: hex::encode(ed_seed),   // String — heap alloc with private key hex
    x_seed:  hex::encode(x_seed),   // String — heap alloc with private key hex
};
ed_seed.zeroize();   // ✓ stack bytes zeroed
x_seed.zeroize();    // ✓ stack bytes zeroed
let toml_str = toml::to_string(&file)?;   // another heap String with private keys
// file and toml_str are dropped here — memory freed but NOT zeroed
```
The `ed_seed` and `x_seed` `String` fields inside `IdentityFile`, and `toml_str`, all hold hex-encoded private key material on the heap. They are not zeroized before drop. A memory dump, core file, or use-after-free could expose the keys.

Same issue in `load()`: `content` (the whole TOML file contents), `file.ed_seed`, and `file.x_seed` are all heap `String`s holding private key material, none zeroized.

**Fix:**  
Derive `zeroize::Zeroize` on `IdentityFile` and call `file.zeroize()` before drop (or use `ZeroizeOnDrop`). Zeroize `toml_str` and `content` similarly — or use a `Zeroizing<String>` wrapper.

```rust
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct IdentityFile {
    ed_seed: String,
    x_seed: String,
}
```

This does not fully close the channel (OS swap, compiler optimizations on `String::drop`) but it is meaningfully better than the current state and is the expected mitigation.

---

### [MEDIUM] `darqual-node` — `label` printed to stdout in `cmd_publish`; dead-drop label is sensitive metadata

**File:** `crates/darqual-node/src/main.rs:230`

```rust
println!(
    "[publish] label={} — serving on {} (Ctrl-C to stop)",
    label, bind
);
```

**Problem:**  
The dead-drop label is derived from the static-static ECDH shared secret of a specific conversation. It is the *only* piece of information that links a block entry to two communicating parties. Printing it to stdout violates the metadata-dark model: any process reading stdout (logger, terminal emulator, screen capture, CI logs) sees the label. An observer who knows the label can trivially confirm which conversation slot is active, undoing the contact-graph privacy guarantee.

**Fix:** Remove the label from the user-facing print. The address it's serving on and the entry count are sufficient operational feedback. If label visibility is needed for debugging, gate it behind a `--debug` flag or `tracing::debug!`:

```rust
tracing::debug!(label = %label, "dead-drop label derived");
println!(
    "[publish] epoch={} entries={} (1 real + {} cover) addr={}",
    block.header.epoch, block.entries.len(), block.entries.len() - 1, bind
);
```

---

### [LOW] `darqual-node` — `cmd_publish` always uses `difficulty = 0` for PoW; spam gate is entirely absent at the network entry point

**File:** `crates/darqual-node/src/main.rs:216`

```rust
let entry = LedgerEntry::mint(label, envelope_bytes, 0);
```

**Problem:**  
PoW difficulty is hardcoded to 0, meaning no work is required to publish a block. The SPEC and THREAT-MODEL document PoW as the current spam/Sybil gate (Stage 4). Using difficulty 0 in the network daemon — the component that actually accepts and serves blocks — means that protection is completely absent in practice, even though the mechanism exists in `darqual-core`. Cover entries added by `pad_block` also use difficulty 0.

This is acceptable for a prototype but should be a named constant (`DEFAULT_PUBLISH_DIFFICULTY`) with a `// TODO: raise to ≥8 for production` comment, or exposed as a `--difficulty` flag.

---

### [LOW] `darqual-node` — `cmd_fetch` epoch window is asymmetric; only handles fetcher-behind, not fetcher-ahead

**File:** `crates/darqual-node/src/main.rs:277`

```rust
for epoch in [epoch_now, epoch_now.saturating_sub(1)] {
```

**Problem:**  
This handles the case where the publisher's clock is ahead of the fetcher (fetcher tries `epoch_now - 1` and matches the publisher's earlier epoch). It does *not* handle the reverse: if the fetcher's clock is ahead (e.g., fetcher on UTC+0 while publisher is NTP-drifted slow), the window never tries `epoch_now + 1`. 

This is a secondary concern if the primary fix (use `block.header.epoch` as the basis) from the HIGH finding is applied — but if the current window approach is kept, it should be symmetric:
```rust
for epoch in [epoch_now, epoch_now.saturating_sub(1), epoch_now + 1] {
```

---

### [LOW] `darqual-cli` — No tracing / logging setup; library crates that use `tracing` macros silently discard spans

**File:** `crates/darqual-cli/src/main.rs` (entire file)

**Problem:**  
`darqual-cli` does not initialize any `tracing` subscriber. `darqual-core` and its dependencies use `tracing` internally. Without a subscriber, all spans and events are silently dropped. Users running `darqual --help` or `darqual open` see nothing diagnostic even if they set `RUST_LOG=debug`. This creates a poor debugging experience and means any future `tracing::warn!` or `tracing::error!` calls in core will be invisible to CLI users.

**Fix:** Add a minimal subscriber init to `main()`, gated on `RUST_LOG` (defaulting to warnings):
```rust
fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    // ...
}
```
Add `tracing` and `tracing-subscriber` to `darqual-cli/Cargo.toml`.

---

### [LOW] `darqual-node` — `cmd_listen` error path for non-decrypt errors uses `error!()` tracing but listener loop error still terminates serve future

**File:** `crates/darqual-node/src/main.rs:152`, `crates/darqual-net/src/lib.rs:65–69`

**Problem:**  
In `cmd_listen`, the callback passed to `serve` calls `error!("open error: {}", e)` for unexpected `Lockbox::open` errors. This is fine. However, in `serve_listener` (net/lib.rs:63–69), a `frame::read_frame` error on any *single* connection produces `warn!` and the loop continues — that's correct. But a `listener.accept()` error at line 64 *returns* the error, which propagates up to `serve_fut` in the `tokio::select!`. A momentary accept error (e.g., `EMFILE`) would terminate the entire listener rather than being retried. This is a resilience gap rather than a security issue, but worth noting.

**Fix:** Wrap `listener.accept().await?` in a retry/backoff loop for transient errors.

---

### [NIT] `darqual-node` `cmd_send` — Confirmation message says `bytes` but counts envelope length, not wire bytes

**File:** `crates/darqual-node/src/main.rs:183–188`

```rust
let bytes = lockbox.envelope.len();   // length of the base64-encoded string
send_lockbox(peer, &lockbox.envelope).await...;
println!("[sent] {} bytes to {}", bytes, peer);
```

`lockbox.envelope.len()` is the length of the `dqbox1<base64>` string in characters, not the actual wire bytes sent (which include the 4-byte length prefix and are encoded differently on the wire). Minor but misleading.

---

### [NIT] `darqual-core` `contact.rs:48` — `expect` in library code (non-test path)

**File:** `crates/darqual-core/src/contact.rs:48`

```rust
let toml_str = toml::to_string(&wire).expect("ContactCard serialization is infallible");
```

`toml::to_string` on a struct of plain `String` fields is indeed infallible in practice, but `expect` in library code (reachable from the CLI binary via `id.contact_card().to_string()`) is an unconditional panic if the assumption is ever violated. Should return `Result` or use `unwrap_or_else` with a meaningful fallback. Not a present risk, but inconsistent with the no-panics-in-binaries policy.

---

### [NIT] `darqual-node` — `cmd_fetch` "no messages for me this epoch" is ambiguous

**File:** `crates/darqual-node/src/main.rs:294–296`

If `notified` is false for all epochs tried, the message says "no messages for me this epoch." If `notified` is true but `fetch_open` returns no decryptable messages (unexpected), the same message is printed. The two cases have different implications (no entry in block vs. entry present but not decryptable). Differentiating them — e.g., "no entry in block for my label" vs. "label present but no messages decrypted" — aids debugging without leaking sensitive information.

---

## Counts

| Severity  | Count |
|-----------|-------|
| CRITICAL  | 0     |
| HIGH      | 2     |
| MEDIUM    | 5     |
| LOW       | 4     |
| NIT       | 3     |
| **Total** | **14** |
