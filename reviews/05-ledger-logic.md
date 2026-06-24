# Code Review — Ledger Logic
**Scope:** `crates/darqual-ledger/src/ledger.rs`, `sweep.rs`, `notify.rs`
**Reviewer:** Joestar (subagent)
**Reference docs:** `SPEC.md`, `THREAT-MODEL.md`

---

## [CRITICAL] `ledger.rs` — Post-prune anchor block trusts caller-supplied `prev_hash` without chain evidence

**Location:** `ledger.rs`, `append()` (the branch that fires when `self.blocks.is_empty()` after a prune has occurred, i.e. `self.base_seq > 0`)

**Problem:**
`append()` distinguishes a true genesis block (seq == 0, prev_hash must be `[0u8; 32]`) from every other block by checking `self.blocks.is_empty()`. After `prune()` drains the window, `self.blocks` is again empty, yet `self.base_seq > 0`. In that state the code falls through to the *genesis* path and enforces only `seq == self.base_seq + window` — it does **not** verify `prev_hash` against anything, because no prior block exists in memory to compare against. A caller who controls block construction can supply an arbitrary `prev_hash` on the first post-prune block, permanently breaking the hash chain without the ledger noticing.

**Why it matters:**
The entire integrity guarantee of the ledger rests on the unbroken `prev_hash` chain. An adversary with write access (or a bug in the ingestion path) can silently inject a forged block immediately after any prune boundary. `validate_chain()` will pass because it only validates what is currently in `self.blocks`, and the anchor for the new sub-chain is never verified against anything persistent.

**Fix:**
Persist the `prev_hash` of the last pruned block (a single `[u8; 32]` field, e.g. `self.prune_tail_hash`). On the first `append()` after a prune, enforce `block.prev_hash == self.prune_tail_hash` instead of skipping the check. The genesis special-case should be gated on `self.base_seq == 0 && self.prune_tail_hash == [0u8; 32]`.

---

## [CRITICAL] `ledger.rs` — `validate_chain()` silently succeeds on an empty pruned window

**Location:** `ledger.rs`, `validate_chain()`

**Problem:**
`validate_chain()` iterates over `self.blocks` with a fold/zip pattern. When the window has been pruned to empty, the iterator is empty, the loop body never executes, and the function returns `Ok(())`. This means that immediately after any `prune()` call, `validate_chain()` is vacuously valid regardless of ledger state — including a ledger that has had its prune-tail tampered with (see CRITICAL-1 above).

**Why it matters:**
Any monitoring or audit path that calls `validate_chain()` post-prune will receive a clean bill of health even when the chain is broken. The function gives a false sense of integrity at precisely the moment the chain is most vulnerable (the post-prune re-anchor window).

**Fix:**
When `self.blocks.is_empty() && self.base_seq > 0`, `validate_chain()` should verify that `self.prune_tail_hash` is non-zero (i.e. a prune has actually been committed) and return an explicit error or a qualified `Ok` with a documented caveat. Alternatively, require at least one block to be present before the window may be considered validated.

---

## [HIGH] `ledger.rs` — Genesis block accepts any `prev_hash`; `[0u8;32]` enforcement is one-sided

**Location:** `ledger.rs`, `append()` genesis branch

**Problem:**
The genesis branch checks `seq == 0` and enforces `prev_hash == [0u8; 32]`. However, it does **not** check that `self.base_seq == 0`. If somehow `base_seq` is non-zero (e.g. after a serialization round-trip bug or manual construction) and `blocks` is empty, a block with `seq == 0` would be accepted as genesis even though the ledger has existing history. This is a secondary effect of the missing `prune_tail_hash` field but deserves its own call-out because it can be triggered independently through deserialization or test fixtures.

**Why it matters:**
An attacker who can reset `base_seq` (e.g. via a corrupt snapshot) can replay or substitute the genesis block, resetting the entire chain's root of trust.

**Fix:**
The genesis branch should assert `self.base_seq == 0` and `self.blocks.is_empty()` together. Any other combination should be rejected with a distinct error variant.

---

## [HIGH] `sweep.rs` — `trial_decrypt` panic on malformed envelope (short ciphertext)

**Location:** `sweep.rs`, `trial_decrypt()` (calls into lockbox decrypt)

**Problem:**
`lockbox::decrypt` (per `lockbox.rs`) performs an index operation to split the ciphertext into nonce || ciphertext. If the stored `LockboxEnvelope.ciphertext` field is shorter than `NONCE_LEN` bytes (24 bytes for XChaCha20), the slice operation panics with an out-of-bounds index rather than returning an `Err`. Because `sweep_window` calls `trial_decrypt` for every entry in the window, a single malformed envelope causes the entire sweep to abort with a panic rather than gracefully skipping the bad entry.

**Why it matters:**
An adversary who can append a ledger entry with a short `ciphertext` field (even an empty `Vec`) can trigger a process-level panic on any node that subsequently runs `sweep_window`. This is a remote-crash / availability vulnerability. THREAT-MODEL.md explicitly calls out availability as in-scope.

**Fix:**
In `lockbox::decrypt`, guard the split with a length check and return `Err(LockboxError::Malformed)` (or equivalent) before indexing. In `sweep.rs`, treat any `Err` from `trial_decrypt` as "not our envelope" and `continue` to the next entry — which is likely the current intent, but the panic bypasses it.

---

## [HIGH] `notify.rs` — Timing side-channel leaks label presence

**Location:** `notify.rs`, `notify()` and `fetch_open()`

**Problem:**
Both functions iterate over stored entries and compare labels using a standard `==` on `&str` / `String`. String equality in Rust short-circuits on the first mismatching byte. An adversary capable of submitting label strings and measuring response latency (or instruction-count via a shared cache) can binary-search the label space to determine whether a given label has any entries, how many entries it has, and approximate label lengths — all without holding the decryption key. THREAT-MODEL.md classifies label content as sensitive metadata.

**Why it matters:**
Even though the payload is encrypted, label leakage reveals *who is communicating with whom* in a one-sided-pseudonymous system. This is a metadata-confidentiality failure that partially defeats the point of encrypting payloads.

**Fix:**
Replace plaintext label comparison with constant-time comparison (e.g. using the `subtle` crate's `ConstantTimeEq` on the raw bytes of the label). Ensure the number of iterations is not short-circuited — always scan the full list rather than returning early on the first match if the list length itself is sensitive.

---

## [HIGH] `notify.rs` — `fetch_open()` returns only the *first* matching entry; silently drops collisions

**Location:** `notify.rs`, `fetch_open()`, return type is `Option<Envelope>` (single value)

**Problem:**
`fetch_open()` uses `.find()` (or equivalent first-match logic) over the open-notification list. When multiple entries exist under the same label — a valid scenario under the SPEC's multi-sender model — all entries after the first are silently ignored. The caller receives one entry and has no indication that others exist. Depending on how the application layer consumes this, notifications are permanently lost: they are neither returned nor re-queued.

**Why it matters:**
In the multi-sender scenario a label collision causes message loss. This is both a correctness bug and a potential denial-of-service: a malicious sender can flood a label with dummy entries, burying the legitimate entry under junk that `fetch_open` will never surface (since the dummy is returned first).

**Fix:**
Change `fetch_open()` to return `Vec<Envelope>` (or an iterator) and collect all matching entries. Callers that genuinely want only one can take the first element themselves, but the default should not silently discard data.

---

## [MEDIUM] `ledger.rs` — `prune()` off-by-one: window boundary is inclusive on both ends

**Location:** `ledger.rs`, `prune()`, the `retain` / drain predicate

**Problem:**
The prune window is defined as `[base_seq, base_seq + window_size)` (half-open, per SPEC §4). The drain predicate in `prune()` uses `block.seq <= self.base_seq + self.window` (note: `<=`, not `<`). This retains one fewer block than the spec window — the block at `base_seq + window` is pruned rather than kept. On a perfectly full window of size `N`, `N` blocks should remain after prune of the oldest; instead `N-1` remain.

**Why it matters:**
This progressively shrinks the available validation window with every prune cycle. On a long-running node the effective window collapses toward zero, eventually making `validate_chain()` trivially vacuous even without any adversarial action.

**Fix:**
Change the drain predicate to `block.seq < self.base_seq + self.window` (strict less-than) to match the half-open interval in the SPEC.

---

## [MEDIUM] `sweep.rs` — `sweep_window` does not bound iteration; unbounded linear scan on large ledger

**Location:** `sweep.rs`, `sweep_window()`

**Problem:**
`sweep_window` iterates the entire current window of blocks and, for each block, iterates all entries, calling `trial_decrypt` on each. There is no early-exit once the caller's expected number of entries is found, and there is no cap on the number of trial decryptions per call. On a ledger with a large window and many entries per block, this is an O(window × entries_per_block) operation that executes synchronously. A single caller sweep can monopolize the thread for a significant period.

**Why it matters:**
If `sweep_window` is called in a latency-sensitive path (e.g. per-request in an async context without a dedicated thread), it becomes a self-inflicted DoS. Combined with HIGH-3 (panic on malformed envelope), an attacker can amplify the impact by padding the ledger with many malformed entries before the panic terminates the sweep.

**Fix:**
Add a configurable `max_trials` parameter and return an error / partial result if the limit is reached. Consider moving sweep to a background task or thread pool. At minimum document the complexity and call-site constraints.

---

## [MEDIUM] `ledger.rs` — Merkle root of a single-entry block is the raw entry hash (no domain separation)

**Location:** `ledger.rs`, `append()` → `merkle_root()` call; `merkle.rs`

**Problem:**
`merkle_root` with a single leaf returns the leaf hash directly (no parent-level hashing). The leaf hash is computed as `H(entry_bytes)`. This means for a single-entry block, the block's `merkle_root` field equals the entry hash — the same value that would be stored as a direct commitment to the entry. If the application ever uses the `merkle_root` as an opaque commitment (e.g. for proofs or cross-chain anchoring), a single-leaf block's root is indistinguishable from a raw entry hash, enabling proof forgery (second-preimage at the commitment layer).

**Why it matters:**
Second-preimage resistance at the tree level requires domain separation between leaf nodes and internal nodes. Without it, a single-entry block's Merkle root can be presented as either a tree root or a leaf hash in any context that doesn't track depth — a classic Merkle tree vulnerability (CVE class: Bitcoin-style Merkle bug).

**Fix:**
Prefix leaf hashing with a domain separator byte (e.g. `0x00 || entry_bytes`) and internal node hashing with `0x01 || left || right`. This matches RFC 6962 (Certificate Transparency) and closes the second-preimage class.

---

## [LOW] `ledger.rs` — `validate_chain()` does not verify `merkle_root` against re-computed root

**Location:** `ledger.rs`, `validate_chain()`

**Problem:**
`validate_chain()` verifies `prev_hash` linkage between blocks but does not re-compute each block's `merkle_root` from its entries and compare it to `block.merkle_root`. A block with a valid `prev_hash` link but corrupted or swapped entries will pass `validate_chain()` cleanly.

**Why it matters:**
The Merkle root exists precisely to detect entry-level tampering within a block. Not checking it in `validate_chain()` means the primary integrity function ignores half of what it should protect.

**Fix:**
Inside the `validate_chain()` loop, compute `merkle_root(&block.entries)` and assert it equals `block.merkle_root`, returning an error on mismatch.

---

## [LOW] `notify.rs` — Open notifications are stored in plaintext; no expiry or capacity bound

**Location:** `notify.rs`, the `open_notifications` store

**Problem:**
Entries placed via `notify()` accumulate indefinitely with no TTL, no maximum list size, and no eviction policy. An unauthenticated caller (if `notify()` lacks auth — which the current code does not enforce) can fill the notification store without bound, consuming memory until OOM.

**Why it matters:**
Even with authentication, a legitimate but misbehaving sender can cause unbounded memory growth. Combined with the label-timing issue (HIGH-2), a full store also degrades the constant-time property since more iterations are needed.

**Fix:**
Enforce a capacity cap per label (e.g. configurable `max_pending_per_label`). Add a TTL field and a background reaper, or at minimum evict on `fetch_open()`.

---

## [LOW] `sweep.rs` — Decrypted entry content is kept in heap memory without zeroing on drop

**Location:** `sweep.rs`, `trial_decrypt()` return path; any `Vec<u8>` holding plaintext

**Problem:**
Successfully decrypted plaintext is returned as `Vec<u8>` and lives on the heap until the caller drops it. Rust does not zero memory on `drop` for standard types. If the process is swapped, core-dumped, or its heap inspected (e.g. via `/proc/self/mem`), decrypted message content is recoverable.

**Why it matters:**
THREAT-MODEL.md lists host memory as a partial trust boundary. For a privacy-focused ledger, decrypted payloads should have minimal lifetime on the heap.

**Fix:**
Wrap decrypted output in a `Zeroizing<Vec<u8>>` (from the `zeroize` crate), which zeroes on drop. Propagate this type through the sweep return path so callers don't casually clone the plaintext.

---

## [NIT] `ledger.rs:append()` — Error variant for duplicate seq is misleading

**Location:** `ledger.rs`, `append()` duplicate-sequence check

**Problem:**
When a block with an already-seen `seq` is rejected, the returned error variant is (based on the pattern) `LedgerError::InvalidBlock` or similar generic variant. There is no dedicated `DuplicateSequence` variant. Callers cannot distinguish "this block is structurally invalid" from "this block is a replay" without string-matching the error message.

**Fix:**
Add a `DuplicateSequence(u64)` error variant. Useful for logging, metrics, and replay-detection logic upstream.

---

## [NIT] `sweep.rs` — `sweep_window` returns `Vec<Vec<u8>>`; no type alias, no doc comment

**Location:** `sweep.rs`, `pub fn sweep_window`

**Problem:**
The return type `Vec<Vec<u8>>` gives no indication of what the inner `Vec<u8>` represents (decrypted envelope bytes? entry IDs? raw ciphertext on failure?). No doc comment exists.

**Fix:**
Add a type alias (`type PlaintextEntries = Vec<Vec<u8>>`) or wrap in a named struct. Add a doc comment clarifying what is returned and in what order.

---

## [NIT] `notify.rs` — `fetch_open()` consuming vs. peeking behavior is undocumented

**Location:** `notify.rs`, `fetch_open()`

**Problem:**
It is unclear (no doc comment, no test) whether `fetch_open()` removes the returned entry from the store (consume semantics) or leaves it (peek semantics). This ambiguity will cause double-delivery or missed-delivery bugs at integration time.

**Fix:**
Document the semantics explicitly. Implement whichever is correct, and add a test that calls `fetch_open()` twice on the same label to pin the behavior.

---

## Counts

| Severity  | Count |
|-----------|-------|
| CRITICAL  | 2     |
| HIGH      | 4     |
| MEDIUM    | 3     |
| LOW       | 3     |
| NIT       | 3     |
| **TOTAL** | **15** |
