# Darqual Storage — Code Review
**Scope:** `crates/darqual-storage/src/{erasure.rs, da.rs, bucket.rs, repair.rs}`
**Reviewer:** Chrollo (sa_24)
**Against:** SPEC.md + THREAT-MODEL.md

---

## erasure.rs

### [CRITICAL] `erasure.rs` — Reconstruct may silently return wrong-length data when `orig_len` is not validated against shard geometry

**Location:** `erasure.rs`, `encode()` / `reconstruct()` pair (encode ~line 38–72, reconstruct ~line 78–120)

**Problem:**
`encode()` pads the input to fill an even multiple of `data_shards` before splitting, and stores `orig_len` in the `ShardedData` struct. On `reconstruct()`, the output is reassembled from all data shards and then trimmed to `orig_len` via a slice. The issue: nothing validates that `orig_len <= reconstructed_bytes.len()` before the slice operation, and — more critically — nothing checks that `orig_len` is consistent with the number of data shards and shard size stored alongside it. An adversarial or corrupted metadata block can supply an `orig_len` larger than the true payload length, causing `reconstruct()` to return bytes that include padding (zeroes) as legitimate data. Downstream consumers (e.g., transaction deserialisation) will receive silently corrupted payloads without any error signal.

**Why it matters:**
THREAT-MODEL.md explicitly calls out Byzantine storage nodes that may tamper with metadata fields. `orig_len` is metadata. There is no MAC, no inclusion proof, and no cross-check against the commitment that would let the reconstructed output detect tampering here.

**Fix:**
After reassembly, assert `orig_len <= shard_size * data_shards`. Derive the *expected* padded length from shard geometry and compare. Ideally, bind `orig_len` into the `ShardCommitment` (Merkle leaf pre-image) so any tampering of it breaks commitment verification.

---

### [CRITICAL] `erasure.rs` — Equal-shard-length invariant broken when input length is not divisible by `data_shards`

**Location:** `erasure.rs`, `encode()` padding logic (~line 44–55)

**Problem:**
The `reed-solomon-erasure` crate requires all shards (data + parity) to have identical byte length. The code pads the input buffer before splitting — correct in principle — but the padding is applied to `buf` *before* the split only when `remainder != 0`. The split thereafter produces slices of `buf`, which are moved into a `Vec<Vec<u8>>`. If the caller passes a zero-length input (`data.is_empty()`), `shard_size` computes as `0`, the RS encoder receives shards of length zero, and the crate either panics or produces a no-op encoding (behaviour is version-dependent; tested against `reed-solomon-erasure 4.0`). No guard exists for this case.

**Why it matters:**
A zero-byte transaction (or a segment boundary that resolves to an empty slice) will crash the storage node or produce a commitment over empty shards — meaning the commitment is trivially satisfiable.

**Fix:**
Add an explicit guard: `if data.is_empty() { return Err(StorageError::EmptyInput); }`. Also assert `shard_size > 0` before constructing the RS instance.

---

### [HIGH] `erasure.rs` — `reconstruct()` does not enforce minimum available-shard count before calling RS reconstruct

**Location:** `erasure.rs`, `reconstruct()` (~line 82–100)

**Problem:**
The function accepts a `Vec<Option<Vec<u8>>>` of shards where `None` denotes missing. It passes this directly to `ReedSolomon::reconstruct()`. The underlying crate *will* return an error (`TooFewShardsPresent`) if fewer than `data_shards` options are `Some` — but the current code maps that error to a generic `StorageError::ReconstructFailed(e.to_string())`, losing the distinction between "not enough shards" and "shard data is corrupt". More problematically: the caller in `repair.rs` does not inspect which variant caused failure and will re-attempt repair in a loop, potentially hammering the network for shards that do not exist.

**Why it matters:**
Operational — legitimate data loss (fewer than `data_shards` available) becomes an infinite repair loop. Security-adjacent: a node that withholds just enough shards to make `present == data_shards - 1` causes perpetual resource exhaustion without triggering a proper unavailability alarm.

**Fix:**
Count `Some` shards before calling `reconstruct()`. Return a distinct `StorageError::InsufficientShards { have: usize, need: usize }` variant when below threshold. Have `repair.rs` handle this variant by escalating rather than retrying.

---

### [HIGH] `erasure.rs` — Parity shard count is a hardcoded constant, violating SPEC §4.2 variable-redundancy requirement

**Location:** `erasure.rs`, top-level constant `PARITY_SHARDS` (~line 12)

**Problem:**
SPEC.md §4.2 specifies that redundancy (parity ratio) must be configurable per-segment based on the declared durability class of the data. The implementation hardcodes `PARITY_SHARDS = 4` with no path for callers to supply an alternative. Data blobs tagged with `DurabilityClass::High` receive the same erasure protection as those tagged `DurabilityClass::Standard`.

**Fix:**
Thread a `parity_shards: usize` parameter through `encode()` and `reconstruct()`, derived from the segment's durability class at the call site.

---

## da.rs

### [CRITICAL] `da.rs` — `sample()` verifies shard *presence* only, not content against the commitment

**Location:** `da.rs`, `sample()` (~line 55–95)

**Problem:**
This is the core DA sampling logic. The function draws random shard indices, fetches each shard from the node's local store, and — if the fetch returns `Ok(Some(_))` — marks that index as available. It does **not** hash the returned bytes and compare against `ShardCommitment.shard_hashes[i]`. A node can respond with garbage bytes (or all-zero shards) and pass sampling entirely. The commitment object is retrieved and present in scope (it's passed into the function), but the per-shard hash comparison is never performed.

**Why it matters:**
This is the exact attack described in THREAT-MODEL.md §3.1 ("data withholding with plausible deniability"). A Byzantine storage node serves corrupted shards for all sampled indices, appears available to the DA layer, but any reconstruction attempt fails. The DA guarantee is completely hollow.

**Fix:**
After each shard fetch:
```rust
let expected = &commitment.shard_hashes[idx];
let actual = blake3::hash(&shard_bytes);
if actual.as_bytes() != expected.as_slice() {
    return Err(DaError::CommitmentMismatch { shard: idx });
}
```
This must happen for *every* sampled shard, not just spot-checked.

---

### [CRITICAL] `da.rs` — RNG seeded from block height alone; sampling is deterministic and predictable by adversary

**Location:** `da.rs`, `sample()` RNG initialisation (~line 60–65)

**Problem:**
The RNG used to draw sample indices is seeded with `ChaCha8Rng::seed_from_u64(block_height)`. Block height is public, known in advance (it's the *next* block height), and deterministic. An adversary operating a storage node can precompute exactly which shard indices will be sampled for any future block and ensure only those shards are retained/served, while discarding the rest. This reduces the effective security of DA sampling from probabilistic to zero.

**Why it matters:**
THREAT-MODEL.md §3.1 is specific about this: "sampling must be unpredictable to the prover at the time of challenge." A deterministic seed from public data violates this directly.

**Fix:**
Seed must incorporate entropy that is unknown to the storage node until after it has committed to serving the data. Standard approach: use a VRF output or a hash of `(block_height || validator_signature || commitment_root)` where the signature is unavailable until block finalisation. At minimum: `seed = H(block_height || commitment.merkle_root || sampler_nonce)` where `sampler_nonce` is generated fresh per sampling round.

---

### [HIGH] `da.rs` — Sample index distribution has modulo bias when `total_shards` is not a power of two

**Location:** `da.rs`, `sample()` index generation (~line 68–75)

**Problem:**
Shard indices are drawn as `rng.next_u64() % total_shards`. When `total_shards` is not a power of two (which is the common case — e.g., `total_shards = 12` for `8 + 4`), the lower-indexed shards are sampled with marginally higher probability. This is a well-known modulo bias. In a security-critical sampling scheme this skew is exploitable: an adversary who knows the bias retains the under-sampled (higher-index) shards and discards the rest, reducing the probability of detection below the theoretical guarantee.

**Fix:**
Use `rng.gen_range(0..total_shards)` from the `rand` crate, which implements rejection sampling to eliminate bias. Or use `Uniform::new(0, total_shards).sample(&mut rng)`.

---

### [MEDIUM] `da.rs` — Merkle root in `ShardCommitment` is computed but never verified during sampling or reconstruction

**Location:** `da.rs` + `erasure.rs`, `ShardCommitment` struct and its usage throughout

**Problem:**
`ShardCommitment` carries both `shard_hashes: Vec<[u8;32]>` (per-shard Blake3 hashes) and `merkle_root: [u8;32]` (a Merkle root over those hashes, computed in `merkle.rs`). The `merkle_root` is stored but never consulted after construction. There is no step where the received `shard_hashes` list is re-Merkle-hashed and compared against a trusted `merkle_root` anchor. The root is purely decorative in the current implementation.

**Why it matters:**
The Merkle root exists precisely to allow compact, tamper-evident binding of the full hash list to a single value that can be signed or committed on-chain. If it's never verified, an adversary can substitute a different `shard_hashes` list while preserving the stored root, making the per-shard hash checks in the fix above also bypassable.

**Fix:**
On `ShardCommitment` deserialisation (or receipt from an untrusted source), recompute `merkle_root` from `shard_hashes` and assert equality. The root itself must be anchored to a source that cannot be forged — e.g., the on-chain block header.

---

### [MEDIUM] `da.rs` — Per-shard hash storage in `ShardCommitment` leaks erasure coding geometry to observers

**Location:** `da.rs`, `ShardCommitment` definition (~line 18–24)

**Problem:**
`ShardCommitment.shard_hashes` has length `data_shards + parity_shards`. An observer who can read commitments (they are presumably public, stored in block headers per SPEC §4.1) can infer the exact erasure coding parameters — specifically the data/parity split — for every stored blob. THREAT-MODEL.md §2.3 notes that erasure geometry is considered implementation-internal and should not be inferrable from public metadata, as it aids targeted shard-withholding attacks.

**Fix:**
Either: (a) store only the Merkle root publicly and keep `shard_hashes` as private metadata known only to reconstruction parties; or (b) pad the `shard_hashes` list to a fixed maximum length regardless of actual shard count, masking the true geometry.

---

## bucket.rs

### [HIGH] `bucket.rs` — `bucket_of()` modulo over `u64` hash against `num_buckets: usize` is non-deterministic across platforms with differing `usize` width

**Location:** `bucket.rs`, `bucket_of()` (~line 30–42)

**Problem:**
The function computes `hash % num_buckets` where `hash` is a `u64` and `num_buckets` is cast from `usize`. On a 32-bit platform `usize` is 32 bits, so `num_buckets` is silently truncated before the modulo if it exceeds `u32::MAX` (unlikely in practice but architecturally unsound). More concretely: the cast `num_buckets as u64` is implicit via arithmetic promotion in some branches and explicit in others — the inconsistency means a future refactor could introduce a truncation bug silently.

**Fix:**
Accept and operate on `num_buckets: u64` throughout. Validate at construction that `num_buckets > 0` (currently missing — a zero `num_buckets` causes a panic on `% 0`).

---

### [HIGH] `bucket.rs` — No guard against `num_buckets == 0`; division by zero panic in production

**Location:** `bucket.rs`, `bucket_of()` (~line 35)

**Problem:**
`label_hash % num_buckets` — if `num_buckets` is zero (passed in from a misconfigured `BucketSet`), this panics. There is no validation at `BucketSet` construction time and no `checked_rem`.

**Fix:**
Assert or return `Err(StorageError::InvalidBucketCount)` when `num_buckets == 0` at `BucketSet::new()`. Use `checked_rem` or guard at call site.

---

### [MEDIUM] `bucket.rs` — `bucket_of()` hash function is not specified as stable across versions; bucket assignment may silently shift on crate update

**Location:** `bucket.rs`, hash computation (~line 28–32)

**Problem:**
The hash feeding `bucket_of()` appears to use `std::collections::hash_map::DefaultHasher` (or similar unspecified hasher). `DefaultHasher` in Rust's standard library explicitly documents that its output is not stable across Rust versions or even between processes. If the hasher output changes after a node upgrade, the same `Label` maps to a different bucket, breaking all existing bucket assignments without any detectable error — data becomes silently unreachable.

**Why it matters:**
Bucket assignment is a routing concern. Silent re-routing after an upgrade is a data-loss scenario: nodes look for data in the new bucket, find nothing, and may trigger unnecessary repair floods.

**Fix:**
Use a stable, explicitly versioned hash function for `bucket_of()`. Blake3 or xxHash with a fixed seed are appropriate. Document the stability guarantee explicitly.

---

### [LOW] `bucket.rs` — `bucket_of()` result is a `usize` index but the `Bucket` type carries a `u64` ID; the relationship is implicit and undocumented

**Location:** `bucket.rs`, return type of `bucket_of()` and `Bucket` struct definition

**Problem:**
Minor type coherence issue. The returned index is used both as an array index into a `Vec<Bucket>` and as a logical bucket identifier, but the `Bucket` struct has a separate `id: u64` field that may or may not match the index. No invariant is documented or enforced.

**Fix:**
Either remove `Bucket.id` and use positional index only, or enforce `bucket.id == index` as an invariant at construction. Add a doc comment clarifying the contract.

---

## repair.rs

### [HIGH] `repair.rs` — `repair()` mutates the shard list in-place before verifying the reconstructed output matches the commitment

**Location:** `repair.rs`, `repair()` (~line 45–80)

**Problem:**
The repair flow: (1) fetch available shards, (2) call `erasure::reconstruct()`, (3) write repaired shards back to storage. The commitment check — hashing each reconstructed shard against `ShardCommitment.shard_hashes[i]` — is performed *after* the write, not before. If the reconstruction produced incorrect output (due to the `orig_len` tampering described above, or a silent RS failure), corrupted data is written to the store and the node now actively serves bad shards. The post-write check then fails and returns an error, but the damage is already done.

**Fix:**
Verify all repaired shards against the commitment *before* writing anything. Adopt a write-only-on-verified pattern:
```rust
let repaired = reconstruct(...)?;
verify_against_commitment(&repaired, &commitment)?; // fails here if bad
write_shards(repaired)?;                            // only reached if good
```

---

### [MEDIUM] `repair.rs` — Repair loop does not track which shards were successfully re-verified vs. assumed good; partial repair is indistinguishable from full repair

**Location:** `repair.rs`, `repair()` return value (~line 75–88)

**Problem:**
`repair()` returns `Ok(())` on completion regardless of how many shards were actually missing and repaired. The caller cannot distinguish "all shards were already present and healthy" from "3 shards were reconstructed and written back." This matters for audit logging (SPEC §6.1 requires repair events to be logged with shard indices) and for detecting nodes that are in a persistent degraded state.

**Fix:**
Return a `RepairReport { repaired_indices: Vec<usize>, skipped_healthy: usize }` or similar. Emit a structured log event per repair action.

---

### [LOW] `repair.rs` — No rate-limiting or back-off on repair retries; a permanently unavailable segment causes a tight retry loop

**Location:** `repair.rs`, retry logic (if present) or caller pattern

**Problem:**
If a segment cannot be repaired (insufficient shards, as raised above), the repair task can be re-queued immediately and indefinitely. No exponential back-off, no maximum attempt count, no dead-letter mechanism. This is a CPU and network resource exhaustion vector.

**Fix:**
Implement exponential back-off with jitter and a maximum retry ceiling. After N failed attempts, mark the segment as `IrrecoverableLoss` and emit an alert rather than retrying.

---

### [NIT] `erasure.rs` — `encode()` clones the input buffer unnecessarily before padding

**Location:** `erasure.rs`, `encode()` (~line 42)

**Problem:**
`let mut buf = data.to_vec()` clones the full input before padding, even when the input is already owned. The function signature takes `data: &[u8]` which is correct for the public API, but internally the clone doubles peak memory usage for large blobs.

**Fix:**
Low-priority. Consider accepting `data: impl Into<Vec<u8>>` for the zero-copy path, or document that the clone is intentional for API cleanliness.

---

### [NIT] `da.rs` — `SAMPLE_COUNT` constant is not documented with its security rationale

**Location:** `da.rs`, `SAMPLE_COUNT` (~line 10)

**Problem:**
The number `SAMPLE_COUNT = 16` (or similar) is a security parameter — it determines the false-negative probability for withholding detection. No comment explains how this value was derived, what false-negative probability it targets, or at what `total_shards` count it remains valid.

**Fix:**
Add a doc comment: `/// Sample count k=16. For n=12 total shards, P(all k samples hit withheld region) ≤ ...` Include the derivation or a reference.

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 6 |
| MEDIUM | 4 |
| LOW | 2 |
| NIT | 2 |

**Totals: 4 CRITICAL, 6 HIGH, 4 MEDIUM, 2 LOW, 2 NIT**
