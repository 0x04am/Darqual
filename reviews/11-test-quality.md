# Test Quality Review — Darqual
**Pass:** 11 — Test Quality  
**Scope:** All 132 tests across 8 crates (darqual-committee, darqual-core, darqual-cover, darqual-ledger, darqual-storage, darqual-net, darqual-node, darqual-cli)  
**Command:** `cargo test --workspace --no-fail-fast`  
**Result at time of review:** 131 passed, **1 FAILED** (`prop_pow_tampered_envelope_fails`)

---

## GENUINE TEST FAILURE — Read This First

### [CRITICAL] `prop_pow_tampered_envelope_fails` fails deterministically on every run

**File:** `crates/darqual-core/tests/property_tests.rs:123–163`  
**Crate:** `darqual-core` (integration test binary `property_tests`)

**Exact reproduction command:**
```bash
cargo test prop_pow_tampered_envelope_fails -p darqual-core --test property_tests
```
Fails **every single run** — not intermittent. The shrunk counterexample is saved and replayed:
```
label_bytes = [14, 205, 80, 95, 57, 0, 92, 124, 160, 197, 212, 72, 39, 106, 158, 102]
envelope    = [37, 38, 44, 227, 14, 244, 229, 229, 187, 75, 147, 177, 108, 92, 171, 30]
difficulty  = 8
```

**Root cause — false-positive collision, not a real security flaw:**

The test asserts that `pow_valid(label, tampered_envelope, nonce, difficulty)` returns `false`, where `nonce` was minted for the *original* envelope. At `difficulty=8`, a random hash satisfies the stamp with probability `1/256 ≈ 0.39%`. The test runs 64 proptest cases, so the expected number of false-positive collisions per run is:

```
P(at least one failure) = 1 - (1 - 1/256)^64 ≈ 22%
```

The test comment even says _"< 0.4% total"_ — this is the per-case rate, not the per-run rate. Over 64 cases, the suite fails roughly **1 in 5 runs**. Proptest shrinks and saves the failing case, so after the first failure the shrunk input is replayed on every subsequent run, making it appear deterministic.

**Why this matters (beyond CI noise):** The test is trying to verify a real security property — that PoW stamps are envelope-bound. That property IS correctly implemented in the code (see `pow::tests::tampered_envelope_invalidates_pow` which uses fixed inputs and passes). The property-based version just has a broken probability model in the assertion condition.

**Fix:** Either raise difficulty so collision probability is negligible over 64 cases (difficulty ≥ 20 gives `1/2^20 * 64 ≈ 0.006%`), or — better — add a `prop_assume` that verifies the minted nonce does NOT accidentally satisfy the tampered envelope before asserting it doesn't, OR use a deterministic "definitely different" check (e.g., also verify `pow_valid(label, tampered, nonce, difficulty+16)` where the extra headroom kills any coincidence). Most pragmatically: delete the proptest version and expand the unit test `tampered_envelope_invalidates_pow` with more fixed vectors. The unit test at `pow.rs:164` already correctly tests this property.

**Also:** `proptest: FileFailurePersistence::SourceParallel set, but failed to find lib.rs or main.rs` — proptest cannot write its failure database because the test is in `tests/property_tests.rs` (an integration test binary, not a lib). This causes proptest to fall back silently and means failure cases may not be persisted reliably across runs on a clean workspace. Not blocking, but noisy.

---

## Findings by Severity

---

### [HIGH] `prop_address_different_keys_differ` assumes BLAKE3/160-bit has no collisions for arbitrary 32-byte inputs

**File:** `crates/darqual-core/tests/property_tests.rs:73–81`

```rust
fn prop_address_different_keys_differ(
    k1 in prop::array::uniform32(any::<u8>()),
    k2 in prop::array::uniform32(any::<u8>()),
) {
    prop_assume!(k1 != k2);
    let a1 = DarqualAddress::from_ed_pubkey(&k1);
    let a2 = DarqualAddress::from_ed_pubkey(&k2);
    prop_assert_ne!(a1, a2);
}
```

This property is not provably true for arbitrary 32-byte inputs — it asserts the address function is collision-free over the entire 2^256 input space, which is unprovable by testing. For inputs that are valid ed25519 public keys the collision probability is negligible, but the generator (`uniform32(any::<u8>())`) generates invalid-key garbage and the property could theoretically fire. More importantly, this test would PASS even if `from_ed_pubkey` returned a constant — because the test only checks two random inputs, not the actual derivation logic.

**What's missing:** A test that asserts `from_ed_pubkey` actually changes its output when the input changes by a single bit — i.e., the address function is sensitive to each bit of the public key. The current test is more of a "doesn't obviously collapse" check.

**Fix:** Add a fixed-vector test deriving addresses from known ed25519 keypairs and checking the expected BLAKE3-truncated hex. That pins the derivation algorithm and catches silent regressions.

---

### [HIGH] `identity_save_load_roundtrip` uses `subsec_nanos()` for uniqueness — race-prone in parallel test runs

**File:** `crates/darqual-core/src/lib.rs:143–167`

```rust
let tmp = std::env::temp_dir().join(format!(
    "darqual_test_{}.toml",
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
));
```

`subsec_nanos()` wraps at 10^9 and is not unique — two test threads started within the same nanosecond (common on fast hardware) share the same path. If tests ever run in parallel (`cargo test` runs unit tests in parallel by default), two instances of this test could collide on the same temp file, leading to one test reading another's keypair or a write-then-delete race.

**Additionally:** The cleanup `let _ = std::fs::remove_file(&tmp)` is silent — if the test panics before cleanup, the file leaks. On the next run the stale file will be read by a different test iteration.

**Fix:** Use `tempfile::NamedTempFile` (already a transitive dep). It generates truly unique paths and cleans up on drop, even on panic.

---

### [HIGH] `epoch_now_is_reasonable` is a timing-dependent wall-clock test with a hardcoded floor

**File:** `crates/darqual-ledger/src/lib.rs:57–61`

```rust
fn epoch_now_is_reasonable() {
    let e = epoch_now();
    assert!(e > 28_000_000, "epoch_now seems too low: {}", e);
}
```

`28_000_000` epochs of 60 seconds = ~53 years from Unix epoch = year 2023. This test:
1. Has no upper bound — would pass if `epoch_now()` returned `u64::MAX` (clock running backward or wrapping)
2. Will start failing in ~year 2023 if the epoch constant changes
3. Cannot be run in a deterministic time-mocked environment
4. Provides zero confidence that `epoch_at()` correctly converts seconds → epochs (that's what should be tested)

**What's actually missing:** A test that `epoch_at(0) == 0`, `epoch_at(EPOCH_SECONDS - 1) == 0`, `epoch_at(EPOCH_SECONDS) == 1`, `epoch_at(EPOCH_SECONDS * k) == k`. The boundary tests at lines 50–54 DO test this for some values — but `epoch_now_is_reasonable` adds nothing beyond verifying the process isn't running in 1970.

**Fix:** Delete or shrink this test to just assert `epoch_now() > 0`. The boundary arithmetic is what needs testing, and it already has coverage.

---

### [HIGH] `elect_rotation_yields_different_committees` can legitimately fail with probability ~1/56

**File:** `crates/darqual-committee/src/election.rs` (test `elect_rotation_yields_different_committees`)

```rust
// They *could* be the same by cosmic coincidence (1/56 at n=8,k=3) but won't be
// with randomly generated keys — assert and re-run if it ever fires.
assert_ne!(
    committee_a, committee_b,
    "different epoch seeds must generally produce different committees"
);
```

The comment says "1/56 at n=8,k=3" and instructs developers to "re-run if it ever fires". This is not a test — it's a hope. `P(committees identical) = C(8,3)^{-1} * ... ` is nonzero and not negligible enough. In a CI pipeline with thousands of runs this fires eventually and breaks the build. The comment instructs humans to manually rerun, which does not scale.

**Fix:** Use a fixed seed for `Identity::generate()` (requires seeded key generation API), or use a larger candidate pool (n=50 reduces coincidence to ~10^{-9}), or reformulate the assertion: instead of checking committees are different, check that at least some members differ (`!committee_a.iter().all(|m| committee_b.contains(m))`).

---

### [MEDIUM] `prop_lockbox_wrong_recipient_is_err` tests isolation but not the error type

**File:** `crates/darqual-core/tests/property_tests.rs:43–52`

```rust
let result = Lockbox::open(&other, &lb.envelope);
prop_assert!(result.is_err(), "wrong recipient must be Err");
```

This correctly tests the security property (wrong key → failure) but doesn't assert the error variant is `Error::Decrypt`. If a future refactor returns `Error::InvalidLockbox` for some truncation reason, or `Error::Utf8`, this test stays green while masking a regression in the error classification. The unit test `lockbox_wrong_recipient` in `src/lib.rs:47` does check `matches!(result, Err(Error::Decrypt))` — but the property-based version is weaker.

**Fix:** `prop_assert!(matches!(result, Err(darqual_core::Error::Decrypt)), ...)`.

---

### [MEDIUM] `cover_entries_decrypt_for_nobody` only tries 3 identities — insufficient for "nobody"

**File:** `crates/darqual-cover/src/cover.rs:188–203`

The test generates 10 cover entries and trial-decrypts with 3 random identities. This verifies "3 specific identities can't read it", not "nobody can". The security claim is that cover entries are structurally invalid lockboxes. The test should instead verify the structural invariant directly — e.g., that the base64 body, when decoded and parsed, does NOT have a valid AEAD tag — rather than relying on the probability that 3 random keys don't happen to be the right one.

**Fix:** Add an assertion that `Lockbox::open` returns specifically `Err(Error::Decrypt)` (not `Err(Error::InvalidLockbox)` and not `Ok`), and do so for ALL 10 entries, not just sampling.

---

### [MEDIUM] `nonce_zero_fails_nontrivial_difficulty` asserts over 20 inputs but conflates the assertion

**File:** `crates/darqual-core/src/pow.rs:170–189`

```rust
let mut any_pass = false;
for i in 0u8..20 {
    // ...
    if pow_valid(&label, &envelope, 0, difficulty) {
        any_pass = true;
    }
}
assert!(!any_pass, "nonce=0 should almost never satisfy...");
```

This is correct in spirit but the comment says "probability all 20 happen to pass ≈ 10^{-60}". The math is `(1/1024)^20` — correct. However, this test will fail if even ONE of the 20 inputs happens to have `pow_hash(label, env, 0)` with 10 leading zero bits. That's a 1-in-1024 event per input, so ~2% of runs will see at least one `any_pass = true`. In practice `difficulty=10` at nonce=0 is likely fine because these are fixed inputs (same on every run), but if someone changes the `test_label()` or the inputs to hit a lucky hash, the test will spuriously fail.

**Fix:** Hard-code the assertion to a specific known-bad nonce=0 hash for a fixed label and envelope, verified by hand. This removes the statistical argument entirely.

---

### [MEDIUM] `real_message_survives_cover_mixing` uses `difficulty=0` for cover entries — differs from production

**File:** `crates/darqual-cover/src/cover.rs:216–243`

The test correctly recovers Bob's message but the real entry is also minted with `difficulty=0`:
```rust
let real_entry = LedgerEntry::mint(label, lockbox.envelope.into_bytes(), 0);
```

The module docstring explicitly calls out that production cover entries MUST carry the same PoW difficulty as real entries, or an adversary can distinguish them. This test gives no coverage of the parity requirement — it would pass equally well in a broken world where cover entries have `difficulty=0` and real entries have `difficulty=16`. The test is validating the message recovery path, not the indistinguishability property it's named after.

**Fix:** Run the mixing test with `difficulty ≥ 1` for both real and cover entries. Add a separate test that explicitly asserts cover and real entries in the same block have equal nonce difficulty (or that `cover_entry()` accepts a difficulty parameter and uses it).

---

### [MEDIUM] No test for `Keywheel` at epoch boundaries — epoch 0, epoch `u64::MAX`, large advance counts

**File:** `crates/darqual-core/src/keywheel.rs`

The keywheel tests cover: symmetry, rotation (1 advance), backward prevention, forward determinism (10 advances), cross-conversation isolation, and forward-secrecy state-is-one-way. What's missing:

- **Epoch 0 initialization:** `conv.keywheel(0)` is tested but `keywheel(u64::MAX - 1)` and `keywheel(u64::MAX)` are not. If the internal KDF uses epoch as a counter with wrapping arithmetic, boundary epochs could produce unexpected collisions.
- **Large advance:** `wheel.advance()` called 1000 times — does it stay deterministic? Does it match a freshly-constructed `keywheel(start + 1000)`?
- **Label uniqueness across epochs:** The test checks that label changes on advance, but doesn't assert labels across 100 epochs are all distinct (possible if the KDF has a short cycle).

**Fix:** Add boundary epoch tests and a uniqueness sweep over N epochs.

---

### [MEDIUM] `fuzz_lockbox_open_arbitrary_bytes` uses `from_utf8_lossy` — mutates input before fuzzing

**File:** `crates/darqual-core/tests/property_tests.rs:200–210`

```rust
fn fuzz_lockbox_open_arbitrary_bytes(raw in prop::collection::vec(any::<u8>(), 0..512)) {
    let id = Identity::generate();
    let s = String::from_utf8_lossy(&raw).into_owned();
    let _ = Lockbox::open(&id, &s);
}
```

`from_utf8_lossy` replaces invalid UTF-8 sequences with `U+FFFD`. This means the actual bytes reaching `Lockbox::open` are not the arbitrary bytes generated by proptest — they're a transformed version. Invalid multi-byte sequences become 3-byte `\xEF\xBF\xBD` sequences. The fuzz surface is smaller than intended and some invalid-UTF-8 paths are never explored.

**Fix:** Since `Lockbox::open` takes `&str`, arbitrary raw bytes with invalid UTF-8 cannot be passed through a `String` without mutation. The test should document this limitation or — better — also test `Lockbox::open` with a `Vec<u8>` path if one exists, or verify the open function correctly handles the UTF-8 boundary before calling the base64 decoder.

---

### [MEDIUM] No test for `darqual-storage` erasure with a data shard (not parity shard) missing — reconstruction path untested asymmetrically

**File:** `crates/darqual-storage/src/erasure.rs:165–178`

`reconstruct_with_data_shards_missing_within_parity_budget` drops shards 0 and 2 (two data shards). But the repair tests drop only parity shards. The combination — one data shard plus one parity shard missing — is untested. Reed-Solomon codes handle this, but the integration between `repair()` and `reconstruct()` in that mixed-loss scenario is not covered.

**Fix:** Add `repair_with_mixed_data_and_parity_loss` dropping shard 1 (data) and shard 5 (parity), verifying full recovery.

---

### [LOW] `vrf_output_fully_determined_by_key_and_seed` asserts inequality but not magnitude

**File:** `crates/darqual-committee/src/vrf.rs`

```rust
assert_ne!(out_a, out_b, "different seeds must yield different outputs");
```

This tests that the VRF output changes with the seed, but not that it changes *sufficiently* — a bad VRF that only changes the last byte would still pass. No test verifies that the VRF output distribution is approximately uniform (e.g., that outputs are spread across the full 32-byte space). This is a statistical property that's hard to test in a unit context, but a basic sanity check — asserting the Hamming distance between `out_a` and `out_b` is not suspiciously small — would catch obvious degeneracy.

---

### [LOW] `fuzz_contact_card_truncated` only cuts to 200 chars but valid cards can be longer

**File:** `crates/darqual-core/tests/property_tests.rs:238–245`

```rust
fn fuzz_contact_card_truncated(cut_len in 0usize..200usize) {
    let id = Identity::generate();
    let card_str = id.contact_card().to_string();
    let truncated: String = card_str.chars().take(cut_len).collect();
    let _: Result<darqual_core::ContactCard, _> = truncated.parse();
}
```

The ceiling of 200 chars may not cover all truncation points if a valid `ContactCard` encodes to more than 200 characters. Truncation at exactly the bech32 checksum boundary or mid-field is then never tested.

**Fix:** Use `0..card_str.len()` as the range, computed inside the test from the actual card length.

---

### [LOW] `bucket_of_is_deterministic` — weak assertion, tests a trivial property

**File:** `crates/darqual-storage/src/bucket.rs:54–60`

```rust
let b1 = bucket_of(&label, 8);
let b2 = bucket_of(&label, 8);
assert_eq!(b1, b2);
assert!(b1 < 8);
```

Calling a pure function twice with the same input and asserting equal output is tautological unless there's hidden mutable state. The valuable test here is that `bucket_of` is actually a deterministic hash-based assignment — the test should verify the specific bucket value for a known label, not just that it's stable.

**Fix:** Precompute the expected bucket for `Label([0xAB, 0xCD, 0xEF, 0x01, ...])` with 8 buckets (it's `u32::from_be_bytes([0xAB, 0xCD, 0xEF, 0x01]) % 8 == some_known_value`) and assert that exact value.

---

### [LOW] `merkle_proof` tests do not cover unbalanced trees with power-of-2 + 1 elements

**File:** `crates/darqual-ledger/src/lib.rs:102–128`

The Merkle proof tests use a single leaf and 4 leaves (power of 2). The boundary case of 3, 5, 6, 7 elements (non-power-of-two that exercise the "odd node duplicated" or "promote" logic) is not tested. Merkle tree implementations frequently have off-by-one errors at these boundaries.

**Fix:** Add a 3-leaf and 5-leaf proof test verifying all leaf indices.

---

### [NIT] `seeded_rng()` is copy-pasted across `darqual-cover` test modules

**Files:** `crates/darqual-cover/src/cover.rs:132`, `crates/darqual-cover/src/dp.rs:152`

Both define `fn seeded_rng() -> ChaCha8Rng { ChaCha8Rng::seed_from_u64(0xDEAD_BEEF) }` identically. Not a correctness issue, but if the seed changes in one place and not the other, test behavior diverges silently.

---

### [NIT] `prop_contact_card_roundtrip` uses `_seed in 0u8..=255u8` as a fake randomization handle

**File:** `crates/darqual-core/tests/property_tests.rs:95–112`

The `_seed` parameter is unused — `Identity::generate()` always calls `OsRng`. Proptest generates 128 different seeds but they all result in 128 calls to `Identity::generate()` with the OS RNG. The property IS being tested correctly (128 random identities are generated), but the test scaffolding is misleading — it looks like `_seed` drives the generation when it doesn't.

**Fix:** Either use `_seed` to actually seed the identity generation (requires seeded Identity generation API), or simplify to `fn prop_contact_card_roundtrip()` with no proptest input (just `(0..128).for_each(|_| { ... })` in a regular test loop).

---

## Security-Critical Coverage Assessment

| Property | Tested? | How | Sufficient? |
|---|---|---|---|
| Wrong recipient → Err | ✅ | Unit + proptest | ✅ Yes |
| AEAD tamper → Err::Decrypt | ✅ | Unit (wire byte flip) | ✅ Yes |
| PoW bound to envelope | ✅ (but flaky) | Unit (fixed) + proptest (BROKEN) | ⚠️ Unit only, proptest FAILS |
| PoW bound to label | ✅ | Unit | ✅ Yes |
| Forward secrecy (state one-way) | ✅ | Keywheel unit | ⚠️ Conceptual only — doesn't verify old key is gone from memory |
| VRF tamper detection | ✅ | Committee unit | ✅ Yes |
| Cover indistinguishable from real | ⚠️ | Length test + `cover_entries_decrypt_for_nobody` | ❌ No PoW parity test |
| Erasure recovery under loss | ✅ | Multiple storage unit tests | ⚠️ Mixed-loss scenario untested |
| ContactCard self-authentication | ✅ | `contact_card_verify_fail_swapped_ed_pub` | ✅ Yes |
| Ledger chain integrity | ✅ | `ledger_wrong_prev_hash_errors`, `validate_chain` | ✅ Yes |

---

## Coverage Gaps (Important Behavior With No Tests)

1. **PoW difficulty enforcement at the ledger boundary** — `LedgerEntry::mint` sets the PoW nonce, but there's no test that a ledger rejects entries whose nonce doesn't satisfy the current epoch difficulty.
2. **`Identity::save` path collision / permission errors** — no test for what happens when the save path is unwritable or exists as a directory.
3. **`DarqualAddress` from_str with valid bech32 but wrong HRP** — prefix check tested (`notdq1abc`), but a bech32-valid string with HRP `"dq2"` (close but wrong) is not.
4. **`seed_for_epoch` with epoch=0** — the boundary epoch (genesis) is not tested.
5. **`partition` with a single bucket** — `n_buckets=1` should put all entries in bucket 0; untested.
6. **`Ledger::get` when ledger has been pruned** — accessing an epoch that's been pruned should return `None`; not tested.
7. **`repair()` + `reconstruct()` round-trip** — repair is tested in isolation, reconstruction is tested in isolation, but the full `encode → drop shards → repair → reconstruct` pipeline is not tested end-to-end.

---

## Counts

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 4 |
| MEDIUM | 7 |
| LOW | 4 |
| NIT | 2 |
| **Total findings** | **18** |
| Tests audited | 132 |
| Tests currently failing | 1 (`prop_pow_tampered_envelope_fails`) |
