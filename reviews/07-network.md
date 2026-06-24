# Darqual Network Layer — Security Review
**Reviewer:** Silverhand (red-team subagent)  
**Date:** 2025-07-12  
**Scope:** `crates/darqual-net/src/frame.rs`, `transport/mod.rs`, `transport/tcp.rs`,
`block_transport.rs`, `lib.rs` (including `serve_listener` / `serve_block_listener`),
and `crates/darqual-node/src/main.rs` as caller surface.  
**Reference docs:** `SPEC.md` (v0, Stage 1 + Stage 9), `THREAT-MODEL.md`.

---

## Executive summary

The framing layer is structurally sound for a prototype: the `u32` length-prefix is read
into a fixed-size buffer, the cap comparison is done before allocation, and `read_exact`
prevents partial-read confusion. No integer overflow in the length path under normal
32-bit arithmetic on a 64-bit host.

However, an attacker that can open a TCP connection — trivial in the current plaintext TCP
model — has **four concrete DoS/resource-exhaustion levers**, the server loops are
**completely unbounded in connections and hang time**, and there is **zero authentication
on who can fetch or publish**. The JSON deserialisation of a 16 MiB attacker-controlled
`Block` introduces a bounded-but-real parser-amplification path. None of these are
panics in the Rust sense, but several are availability kills.

The THREAT-MODEL already flags "no Tor yet / IP-level privacy absent". These findings
are the *next layer down*: assuming the node is reachable on TCP, what can an attacker do?

---

## Findings

---

### [HIGH] `frame.rs:20` — Silent truncation: oversized payload accepted by `write_frame`, then causes framing desync on the read side

**File/line:** `frame.rs:20`

```rust
let len = data.len() as u32;   // ← silent truncation if data.len() > u32::MAX
```

**Problem:**  
`write_frame` casts `data.len() as u32` without bounds-checking. On a 64-bit host,
`usize` is 64 bits. If the caller ever supplies a slice ≥ 4 GiB (theoretically possible
with a future streaming path or a bug in a caller that builds an unbounded buffer),
the length field is silently truncated, the written length prefix is wrong, and the
remote `read_frame` will block or fail with a confusing I/O error rather than a clean
protocol error.

This is latent now — no current caller builds a payload > 4 GiB — but the invariant
is not enforced at write time, only at read time. There is asymmetry: the reader
enforces `MAX_FRAME`; the writer enforces nothing.

**Exploit path:**  
Not directly reachable today, but a future refactor or caller bug that passes a large
accumulated buffer will silently corrupt the frame stream, potentially causing a remote
listener to hang in `read_exact` waiting for bytes that will never arrive.

**Fix:**
```rust
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| Error::FrameTooLarge(u32::MAX))?;
    if len > MAX_FRAME {
        return Err(Error::FrameTooLarge(len));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}
```
This closes the asymmetry and enforces the cap on *both* sides of the wire.

---

### [HIGH] `lib.rs:63` / `block_transport.rs:58` — Unbounded concurrent connections + no per-connection timeout (Slowloris / connection exhaustion)

**Files/lines:** `lib.rs:63–71` (`serve_listener`), `block_transport.rs:58–73` (`serve_block_listener`)

```rust
loop {
    let (mut stream, peer) = listener.accept().await?;
    // ← no timeout, no semaphore, no rate-limit
    match frame::read_frame(&mut stream).await {   // blocks indefinitely
        ...
    }
}
```

**Problem:**  
Both accept loops process each connection **synchronously in the accept loop itself** —
they await the full `read_frame` / `write_frame` before calling `accept()` again.
This is a classic single-threaded listener mistake.

An attacker connects, then sends only 2 of the 4 length-prefix bytes and stops. The
daemon blocks in `read_exact` waiting for the remaining 2 bytes. During this time, no
other connection is accepted. One connection is enough to completely deny service to
all legitimate peers. This is a trivially-mounted Slowloris-style DoS.

Even without intentional stalling: on a real network, slow peers will pile up and the
server will appear hung from everyone else's perspective.

**Exploit path:**  
```
# Attacker: send partial length prefix then idle
python3 -c "
import socket, time
s = socket.create_connection(('target', 9939))
s.send(b'\x00\x00')   # only 2 of 4 length bytes
time.sleep(9999)
"
# Daemon is now completely frozen — no other connection accepted
```

**Fix:**  
Spawn each connection into its own task with a deadline:
```rust
loop {
    let (mut stream, peer) = listener.accept().await?;
    let handler = async move {
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            frame::read_frame(&mut stream),
        ).await {
            Ok(Ok(bytes)) => { /* process */ }
            Ok(Err(e))    => warn!(?peer, "frame error: {}", e),
            Err(_elapsed) => warn!(?peer, "read timeout"),
        }
    };
    tokio::spawn(handler);
}
```
For `serve_block_listener`, the same pattern applies to the write side. Also add a
global connection semaphore (e.g. `tokio::sync::Semaphore`) to cap total concurrent
connections.

---

### [HIGH] `block_transport.rs:58` — Unbounded concurrent block-serve tasks (memory/FD exhaustion)

**File/line:** `block_transport.rs:58–73`

**Problem:**  
Even after spawning per-connection tasks (fixing the Slowloris issue above), without a
concurrency cap an attacker can open thousands of simultaneous connections, each holding
a file descriptor and a task allocation. On Linux, the default per-process FD limit is
1024. Hitting it causes `accept()` to return `EMFILE`, which propagates as an `Err` from
`listener.accept()`, which returns from `serve_block_listener` with an error, **killing
the entire server**.

The current synchronous loop accidentally limits to 1 connection at a time, which
masks this problem — fixing Slowloris exposes the FD/memory exhaustion.

**Exploit path:**  
```
# Attacker: open 1025 connections simultaneously, send nothing
# FD table fills → accept() → EMFILE → serve_block_listener returns Err → daemon dies
```

**Fix:**  
Wrap `listener.accept()` to handle `EMFILE` / `ECONNABORTED` gracefully (log + continue),
and bound concurrent in-flight connections with a semaphore:
```rust
let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)); // e.g. 256
loop {
    let permit = semaphore.clone().acquire_owned().await.unwrap();
    match listener.accept().await {
        Ok((stream, peer)) => {
            tokio::spawn(async move {
                let _permit = permit; // holds until task completes
                // handle stream...
            });
        }
        Err(e) if is_transient_accept_error(&e) => {
            warn!("transient accept error: {}", e);
            drop(permit);
            continue;
        }
        Err(e) => return Err(e.into()),
    }
}
```

---

### [HIGH] `block_transport.rs:84–86` — `serde_json::from_slice` on 16 MiB of attacker-controlled bytes — no recursion/depth limit, parser amplification

**File/line:** `block_transport.rs:84–86`

```rust
let data = frame::read_frame(&mut stream).await?;        // up to 16 MiB
let block: Block = serde_json::from_slice(&data)          // ← no depth limit
    .map_err(|e| Error::Encoding(...))?;
```

**Problem:**  
`serde_json` in its default configuration has no maximum recursion depth or object-count
limit. The `Block` type contains `Vec<LedgerEntry>` where each `LedgerEntry` contains
`Vec<u8>` (envelope). A malicious peer can craft a legal-looking JSON payload up to
16 MiB that:

1. **Recursion / stack overflow** — JSON is not deeply recursive for these flat types,
   so stack overflow is not the primary concern here. However:
2. **Entry count amplification** — each `LedgerEntry` is small (label 16 bytes, nonce
   8 bytes, tiny envelope). An attacker can pack thousands of entries into 16 MiB of
   JSON. The Merkle root recomputation in `Block::validate()` hashes all of them.
   Downstream callers that run `block.validate()` or `sweep_window()` / `trial_decrypt()`
   will spend CPU proportional to the number of entries, each of which requires a
   BLAKE3 hash.
3. **`n_messages` mismatch as a confused-deputy trap** — if `block.header.n_messages`
   is set to `u32::MAX` but `entries` has only 1 entry, `Block::validate()` returns
   `false` cleanly, but code that trusts `header.n_messages` without calling `validate()`
   first will be confused.

**Severity context:** `fetch_block` is the *client* side; the server trusts itself.
But in any future model where a node can receive a `serve_block`-style push from a
peer, this path is fully attacker-controlled.

**Fix:**
- After deserialisation, **always call `block.validate()`** before touching the block.
  Add this to `fetch_block` immediately:
  ```rust
  if !block.validate() {
      return Err(Error::Encoding("block Merkle root invalid".into()));
  }
  ```
- Add an entry-count cap before spending CPU:
  ```rust
  const MAX_BLOCK_ENTRIES: usize = 100_000; // tune to realistic max
  if block.entries.len() > MAX_BLOCK_ENTRIES {
      return Err(Error::Encoding("block entry count exceeds cap".into()));
  }
  ```
- Consider `serde_json` with `recursion_limit` or switching to a structured binary
  format (bincode / CBOR) that natively bounds sizes.

---

### [HIGH] `lib.rs:66–70` — `serve_listener` processes each connection synchronously in the accept loop — same Slowloris root cause

**File/line:** `lib.rs:66–70`

This is the Stage-1 `serve_listener` (lockbox receiver), not just the block server.
The same sequential-accept-loop pattern described in finding #2 applies here identically.
A single stalling connection blocks all lockbox delivery. See #2 for full exploit path
and fix.

---

### [MEDIUM] `frame.rs:31–34` — 16 MiB `vec![0u8; len]` allocation on unverified attacker-declared length — allocation DoS

**File/line:** `frame.rs:31–34`

```rust
if len > MAX_FRAME {
    return Err(Error::FrameTooLarge(len));
}
let mut buf = vec![0u8; len as usize];   // ← 16 MiB zero-allocation
```

**Problem:**  
The cap check is present and correct — the allocation does not happen for `len > MAX_FRAME`.
However, for any `len ≤ MAX_FRAME`, a **16 MiB zero-allocation is performed immediately
upon receiving the length prefix**, before a single body byte is read. Since connections
are (currently) sequential in the accept loop, this is bounded to one in-flight 16 MiB
allocation at a time. But:

- Once connections are spawned concurrently (the fix for #2), each concurrent connection
  can independently trigger a 16 MiB allocation. With 100 concurrent connections, that
  is 1.6 GiB of RSS just from length-prefix lies, before any body bytes are read.
- The attacker payload is just 4 bytes: `\xFF\xFF\xFF\xFF` (well, `\x01\x00\x00\x00` for
  1 byte = fast path, but `\x00\xFF\xFF\xFF` = 16 MiB − 1 per connection costs nothing
  to send).

**OWASP:** CWE-400 (Uncontrolled Resource Consumption), related to CWE-789.

**Fix:**  
Two complementary mitigations:
1. Lower `MAX_FRAME` to the realistic maximum legitimate payload size. 16 MiB is
   extremely generous; individual lockboxes are ~300 bytes; even large blocks with
   cover traffic should be well under 1 MiB. Keep 16 MiB only for the block-transport
   path and use a separate, tighter cap (e.g. 64 KiB) for the lockbox path.
2. After the cap check, perform a **speculative probe** — read (say) the first 4 KiB
   of the body before committing to the full allocation. This makes stalling
   allocations require actual data:
   ```rust
   // Don't allocate full len upfront; use BufReader or streaming read
   // For correctness + safety, at minimum add per-connection concurrency limits
   // so aggregate allocation is bounded (see #3).
   ```

---

### [MEDIUM] `error.rs:8` — Error message says "1 MiB" but actual limit is 16 MiB

**File/line:** `error.rs:8`

```rust
#[error("Frame too large: {0} bytes (max 1 MiB)")]
FrameTooLarge(u32),
```

**Problem:**  
`MAX_FRAME` was raised to 16 MiB in Stage 9 (`frame.rs:16`), but the error message was
not updated. It still says "max 1 MiB". This is a documentation/correctness mismatch
that will mislead any operator or attacker reading error logs.

More importantly: the discrepancy means someone **reading only the error message** will
set the client's `MAX_FRAME` to 1 MiB and wonder why large block frames are being
rejected by the remote — or vice versa. Frame cap mismatches cause hard-to-diagnose
protocol failures.

**Fix:**
```rust
#[error("Frame too large: {0} bytes (max {} bytes)", MAX_FRAME)]
```
Or, simpler, hardcode the correct value:
```rust
#[error("Frame too large: {0} bytes (max 16 MiB)")]
```

---

### [MEDIUM] `block_transport.rs:46–73` + `lib.rs:38–44` — No authentication: any TCP peer can trigger serve/fetch

**File/line:** `block_transport.rs:46`, `lib.rs:38`

**Problem:**  
Both `serve_block` and `serve` (lockbox listener) bind a TCP socket and respond to
**any connecting peer** with no authentication, no allowlist, no HMAC handshake.
For the block server: any peer that can TCP-connect receives the full block contents
(all entries, including real lockboxes with their labels and encrypted envelopes).
For the lockbox server: any peer can inject an arbitrary lockbox envelope into the
node's `on_envelope` callback.

The THREAT-MODEL acknowledges "no Tor yet — IP location privacy absent" but does not
call out the fact that unauthenticated serve means **the block contents are trivially
scraped by anyone on the network**. Even if content is encrypted, metadata about which
epochs have how many entries at what cadence is leaked.

**Severity:** MEDIUM in the current prototype context. The THREAT-MODEL explicitly
scopes this as "known gap" (no anonymity network yet). But this should be called out
as a blocking item before any real-data deployment.

**Fix (near-term):**  
- Add an IP allowlist / bind to loopback-only in the default config.
- Document that `--addr 0.0.0.0:9940` is insecure without Tor.

**Fix (production):**  
Mutual authentication via the node's ed25519 identity keys in a handshake before
any data flows. Tor onion services solve this at the transport layer (the onion address
*is* the public key), which is the planned path per SPEC §3.

---

### [MEDIUM] `block_transport.rs:61` — `serde_json::to_vec(&block)` inside the accept loop — serialization on hot path, no caching

**File/line:** `block_transport.rs:61–66`

```rust
let serialised = match serde_json::to_vec(&block) {
    Ok(b) => b,
    Err(e) => { warn!(...); continue; }
};
```

**Problem:**  
The block is re-serialised **for every connecting client**, inside the accept loop.
For a block with many entries (cover traffic), this is O(entries) CPU and O(block_size)
allocation on every connection. An attacker that connects 1000 times forces 1000
re-serialisations of potentially a multi-megabyte block.

This is less severe than the allocation DoS in #5 (serialisation is bounded by the
block size which is bounded by the server's own `pad_block` call), but it compounds
the CPU amplification of #3 — each connection costs both a serialise and an allocate.

**Fix:**  
Serialise once before the accept loop and clone/share the `Arc<Bytes>`:
```rust
let serialised = Arc::new(serde_json::to_vec(&block)?);
loop {
    let (mut stream, peer) = listener.accept().await?;
    let data = serialised.clone();
    tokio::spawn(async move {
        if let Err(e) = frame::write_frame(&mut stream, &data).await {
            warn!(?peer, "frame write error: {}", e);
        }
    });
}
```

---

### [LOW] `lib.rs:138–139` — `accept()` failure kills the entire server loop permanently

**File/line:** `lib.rs:63–64` (and `block_transport.rs:59`)

```rust
let (mut stream, peer) = listener.accept().await?;  // ← ? propagates up
```

**Problem:**  
Transient `accept()` errors (e.g. `EMFILE`, `ECONNABORTED`, `ENFILE`, a temporary
resource shortage) cause the `?` to propagate an `Err` all the way out of
`serve_listener` / `serve_block_listener`, terminating the loop permanently. The
daemon then either crashes or returns to `cmd_listen`'s `tokio::select!` which
exits gracefully — either way, the listener is **gone** after one transient OS error.

An attacker that can briefly exhaust the FD table (see #3) can permanently kill
the listening service.

**Fix:**
```rust
match listener.accept().await {
    Ok((stream, peer)) => { /* spawn handler */ }
    Err(e) if is_transient(&e) => {
        warn!("transient accept error (continuing): {}", e);
        tokio::time::sleep(Duration::from_millis(10)).await;
        continue;
    }
    Err(e) => return Err(e.into()), // real error: bind gone, etc.
}

fn is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(e.kind(), ConnectionAborted | ConnectionReset | TimedOut)
    || e.raw_os_error().map_or(false, |n| n == libc::EMFILE || n == libc::ENFILE)
}
```

---

### [LOW] `lib.rs:67–69` — UTF-8 decode of frame bytes allocates a new `String`; `from_utf8_lossy` would be safer for logging

**File/line:** `lib.rs:67–69`

```rust
Ok(bytes) => match String::from_utf8(bytes) {
    Ok(envelope) => on_envelope(envelope),
    Err(e) => warn!(?peer, "non-UTF8 frame: {}", e),
},
```

**Problem:**  
`String::from_utf8(bytes)` consumes the byte vector and returns it in the error if it
fails (via `FromUtf8Error::into_bytes`). This is correct and memory-safe. However, the
warning message `"non-UTF8 frame"` doesn't log the offending peer's bytes or the
offset of the invalid sequence, making it harder to distinguish a protocol error from
a legitimate lockbox send from a different implementation. Not a security flaw, but
it degrades incident observability.

More noteworthy: the `envelope` is passed to `on_envelope` as a `String` and the
`on_envelope` callback in `cmd_listen` immediately passes it to `Lockbox::open`. If a
future `on_envelope` implementation does anything expensive or blocking with the
envelope, it will stall the accept loop (since `on_envelope` is called inline, not
spawned). This is a latent design trap.

**Fix:**  
Make `on_envelope` async or move its invocation into a spawned task.

---

### [LOW] `block_transport.rs:89` — `block.entries.len()` logged but `block.validate()` not called in `fetch_block`

**File/line:** `block_transport.rs:84–92`

```rust
let block: Block = serde_json::from_slice(&data)...?;
debug!(peer = peer_addr, entries = block.entries.len(), "block fetched");
Ok(block)
```

**Problem:**  
`fetch_block` returns the deserialized `Block` to the caller without calling
`block.validate()`. The caller (`cmd_fetch` in `darqual-node`) also does not call
`validate()` before passing the block to `notify()` and `fetch_open()`. If a malicious
server sends a block with a forged Merkle root and crafted entries, downstream code
will operate on unvalidated data.

`notify()` only checks label equality (no validation needed). `fetch_open()` calls
`Lockbox::open()` which handles AEAD failures gracefully. So this is not
directly exploitable today (AEAD will reject tampered ciphertexts). However, the
absence of structural validation creates a brittle trust assumption.

**Fix:**  
Add to `fetch_block`:
```rust
if !block.validate() {
    return Err(Error::Encoding("block Merkle validation failed".into()));
}
```

---

### [LOW] `darqual-node/src/main.rs:216` — PoW difficulty hardcoded to 0 on publish path

**File/line:** `darqual-node/src/main.rs:216`

```rust
let entry = LedgerEntry::mint(label, envelope_bytes, 0);  // difficulty = 0
```

**Problem:**  
The published block has PoW difficulty 0 — any entry is accepted with zero work. The
THREAT-MODEL notes this as a known gap ("PoW is a blunt instrument… RLN = research").
However, difficulty 0 means an attacker who can serve a block can pack it with
arbitrarily many entries at zero cost, compounding the parser-amplification issues
described in #4. A non-zero default difficulty would at least add a minimal work gate.

This is listed LOW because the THREAT-MODEL is already honest about it, and the fix
(RLN) is acknowledged as future work. But it should be explicitly called out in the
context of the block-transport DoS surface.

**Fix:** Set a non-zero default difficulty (even `difficulty = 1`) for the published
entry in `cmd_publish` to add a trivial work gate:
```rust
const DEFAULT_POW_DIFFICULTY: u32 = 16; // tune to ~1ms of work
let entry = LedgerEntry::mint(label, envelope_bytes, DEFAULT_POW_DIFFICULTY);
```

---

### [NIT] `transport/tcp.rs` — `TcpTransport` is a zero-byte marker with no behaviour; the `impl Transport` lives in `mod.rs`

**File/line:** `transport/tcp.rs` (entire file), `transport/mod.rs:25–37`

The `TcpTransport` struct is defined in `tcp.rs` but the actual `impl Transport for
TcpTransport` lives in `mod.rs`. This split is confusing: a future contributor looking
at `tcp.rs` to understand the TCP implementation finds nothing and must know to look
in `mod.rs`. Move the `impl Transport for TcpTransport` block into `tcp.rs` or add a
`// See transport/mod.rs for the impl` doc comment.

---

### [NIT] `frame.rs:16` — `MAX_FRAME` is a `u32` but `data.len()` returns `usize`; the comparison `len > MAX_FRAME` works but the types require an implicit `as u32` cast

**File/line:** `frame.rs:31`

`let len = u32::from_be_bytes(len_buf)` — this is correct, `len` is already `u32`,
comparison to `MAX_FRAME: u32` is type-safe. No issue here, just note that the
`read_frame` side is clean whereas the `write_frame` side (the `as u32` cast flagged
in finding #1) is the asymmetry.

---

### [NIT] `lib.rs:38` — `on_envelope: impl FnMut(String)` takes ownership of each String; consider `&str` or `Bytes` to avoid gratuitous clone in callers

Minor ergonomic point. Not a security issue.

---

## Attack scenario walkthrough — "I just found this node on the network"

1. **Reconnaissance:** `nmap -p 9939,9940 <target>` — two open TCP ports.
2. **Stage 1 listener DoS (HIGH #2):** `nc target 9939` + send 2 bytes + idle.
   Server frozen. No lockboxes delivered to legitimate peers. Cost: one TCP connection.
3. **Block scrape (MEDIUM #6):** `fetch_block("target:9940")` — receive full epoch block,
   all entry labels and encrypted envelopes. Even without decryption, label patterns
   reveal communication cadence, entry counts, epoch timing.
4. **Inject garbage lockbox (MEDIUM #6):** Connect to port 9939, send a well-framed
   but garbage envelope. The `on_envelope` callback sees it, calls `Lockbox::open`,
   gets `Err(Decrypt)`, logs it. Harmless per-connection, but this confirms the
   framing protocol and reveals how errors surface.
5. **Allocation flood (MEDIUM #5):** Once the sequential-accept limitation is removed,
   open 100 connections to port 9939/9940, each sending `\x00\xFF\xFF\xFF` (16 MiB − 1
   length prefix). Daemon allocates ~1.6 GiB of zero buffers. OOM or severe swapping.
6. **JSON bomb (HIGH #4):** Serve a crafted "block" with 500,000 `LedgerEntry` objects
   totalling ~15 MiB of JSON. A light-client calling `fetch_block` from this node
   deserialises it, then `sweep_window` / `trial_decrypt` hash 500,000 entries with
   BLAKE3. CPU spike until timeout or crash.

---

## Summary table

| # | Severity | File | Issue |
|---|----------|------|-------|
| 1 | HIGH     | `frame.rs:20` | `write_frame` silently truncates `data.len() as u32`; no cap on write side |
| 2 | HIGH     | `lib.rs:63`, `block_transport.rs:58` | Sequential accept loops; one stalling connection freezes the server (Slowloris) |
| 3 | HIGH     | `block_transport.rs:58` | No concurrency cap; FD exhaustion after Slowloris fix kills server via `EMFILE` |
| 4 | HIGH     | `block_transport.rs:84` | `serde_json::from_slice` on 16 MiB attacker bytes; no entry-count cap; no post-parse `validate()` |
| 5 | MEDIUM   | `frame.rs:31` | 16 MiB allocation on declared length before body bytes arrive; amplified by concurrent connections |
| 6 | MEDIUM   | `error.rs:8` | Error message says "max 1 MiB" but actual cap is 16 MiB (stale after Stage 9 raise) |
| 7 | MEDIUM   | `block_transport.rs:46`, `lib.rs:38` | No authentication; any TCP peer can fetch blocks or inject envelopes |
| 8 | MEDIUM   | `block_transport.rs:61` | Block re-serialised per connection inside accept loop; no pre-serialised cache |
| 9 | LOW      | `lib.rs:63`, `block_transport.rs:59` | `accept()` failure (transient) propagates `?` and kills server loop permanently |
| 10 | LOW     | `lib.rs:67` | `on_envelope` called inline in accept loop; blocking envelope handlers will stall |
| 11 | LOW     | `block_transport.rs:89` | `fetch_block` returns unvalidated block; no `block.validate()` call |
| 12 | LOW     | `darqual-node/main.rs:216` | PoW difficulty = 0 on publish; zero work gate compounds entry-count DoS |
| 13 | NIT     | `transport/tcp.rs` | `TcpTransport` marker struct split from its `impl Transport` in `mod.rs` |
| 14 | NIT     | `frame.rs:20` | `write_frame` cast asymmetry (no cap) noted separately from truncation |

**Counts: CRITICAL 0 · HIGH 4 · MEDIUM 4 · LOW 4 · NIT 2**

---

*Review performed without modifications to source. All file:line references are to the
codebase as of v0.9.0 / current HEAD.*
