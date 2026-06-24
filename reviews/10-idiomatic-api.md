# Review 10 — Idiomatic Rust & API Hygiene
**Scope:** workspace-wide  
**Focus:** error handling, panic paths, Display/FromStr, allocations, `&str`/`String`, `#[must_use]`, Debug derives, pub API surface, doc coverage, `Vec<u8>`/`&[u8]` ergonomics, truncating `as` casts  
**Verdict:** genuinely solid library-quality code with a short list of fixable issues — no architectural rot, but several real correctness hazards and a pile of missing ergonomic annotations

---

## CRITICAL

### [CRITICAL] `darqual-net/src/frame.rs:20` — silent truncation in `write_frame`
```rust
let len = data.len() as u32;
```
`data.len()` is `usize` (64-bit on 64-bit hosts). If a caller passes a slice larger than `u32::MAX` (~4 GiB) the cast silently wraps, the wire prefix lies about the payload length, and the remote peer's framing parser will either hang waiting for more bytes or corrupt the connection. The function contract says max frame is 16 MiB (enforced on read), but nothing enforces it on write. This is a correctness bug that becomes reachable as block sizes grow.

**Fix:**
```rust
let len = u32::try_from(data.len())
    .map_err(|_| Error::FrameTooLarge(u32::MAX))?;
if len > MAX_FRAME {
    return Err(Error::FrameTooLarge(len));
}
```
Enforce the same cap on both sides, symmetrically.

---

### [CRITICAL] `darqual-ledger/src/merkle.rs:4–9` — `EMPTY_ROOT` is SHA-256("") not BLAKE3("")
```rust
pub const EMPTY_ROOT: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14 …
];
```
This byte sequence is the SHA-256 hash of the empty string (confirmed: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). The tree itself uses BLAKE3. Any node computing the canonical empty root via `merkle_root(&[])` returns this constant; any node that independently derives it by actually hashing with BLAKE3 will get a different value. This is a latent consensus split bug — the moment any code path *derives* rather than *reads* the empty root, it diverges silently.

**Fix:** Replace the constant with the correct BLAKE3 value, or better, remove the hardcoded constant entirely and let `merkle_root` return the hash of the empty input under the same BLAKE3 construction:
```rust
pub fn merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    if leaves.is_empty() {
        // BLAKE3 of zero bytes under the leaf domain: deterministic, no magic constant
        return hash_leaf(&[]);
    }
    // …
}
```
Update the doc comment and the test `merkle_empty_is_empty_root` accordingly.

---

## HIGH

### [HIGH] `darqual-core/src/contact.rs:48` — `expect` in library (non-test) code
```rust
let toml_str = toml::to_string(&wire).expect("ContactCard serialization is infallible");
```
This panics the caller's thread if TOML serialization ever fails (e.g., future refactor introduces a non-serialisable field). Library code must not panic — it must propagate errors. The comment "infallible" is an assertion, not a proof.

**Fix:**
```rust
let toml_str = toml::to_string(&wire)
    .map_err(|e| Error::InvalidContactCard(format!("serialization: {e}")))?;
```
Change `encode` to `fn encode(&self) -> Result<String>` and update `Display::fmt` to write a placeholder on error or propagate via `write!` returning `fmt::Error`.

---

### [HIGH] `darqual-ledger/src/block.rs:75` — unchecked `usize as u32` cast for `n_messages`
```rust
let n = entries.len() as u32;
```
A block with more than `u32::MAX` entries would silently truncate `n_messages`, making `validate()` (which checks `self.entries.len() as u32 == self.header.n_messages`) pass incorrectly for a corrupted block. In practice this won't happen in v0.x, but the function should fail loudly on overflow rather than silently lie.

**Fix:**
```rust
let n = u32::try_from(entries.len())
    .expect("block entry count overflows u32"); // or return Result
```
Given `Block::new` is infallible by design, the `expect` is acceptable here since the invariant is genuinely unreachable in practice; but add a debug_assert at minimum.

### [HIGH] `darqual-ledger/src/ledger.rs:62–63` — `{:x?}` debug format for hash in error message
```rust
expected: format!("{:x?}", expected_prev),
got:      format!("{:x?}", block.header.prev_hash),
```
`{:x?}` on a `[u8; 32]` produces `[0xde, 0xad, …]` — a 192-character array-with-brackets. Any log line or user-facing error message containing a `BrokenChain` error is unreadable. The codebase already uses `hex` everywhere else.

**Fix:**
```rust
expected: hex::encode(expected_prev),
got:      hex::encode(block.header.prev_hash),
```

### [HIGH] `darqual-core/src/lockbox.rs:22` — `pub envelope: String` leaks internals
`Lockbox.envelope` is the raw wire-format string. Exposing it as a public field lets callers mutate it after construction, breaking the invariant that `envelope` is always a validly-encoded lockbox. It also creates an awkward API: callers should use `lockbox.to_string()` / `Display`, not `lockbox.envelope`.

**Fix:** Make the field private (`envelope: String`), impl `Display` to expose it as a `&str`/`String`, and add `pub fn as_str(&self) -> &str`. `Lockbox::open` already takes `&str`, so callers can just `&lb.to_string()`.

### [HIGH] `darqual-core/src/conversation.rs:67` — `Conversation::seal` returns `Vec<u8>` for a UTF-8 string
```rust
Ok((lbl, lockbox.envelope.into_bytes()))
```
`Lockbox::envelope` is a `String`; `into_bytes()` converts it to `Vec<u8>`. The return type of `seal` is `Result<(Label, Vec<u8>)>`. Callers then need `std::str::from_utf8(&envelope)` to use it — as seen in `notify.rs` and `sweep.rs`. This `String → Vec<u8> → &str` round-trip is pointless friction.

**Fix:** Return `Result<(Label, String)>` or `Result<(Label, Lockbox)>` and let callers call `.as_str()` directly.

---

## MEDIUM

### [MEDIUM] `darqual-core/src/contact.rs:11` — `ContactCard` missing `PartialEq`
`ContactCard` derives `Debug, Clone, Serialize, Deserialize` but not `PartialEq`. Equality comparison between cards (e.g., "have I seen this contact before?") requires manual field-by-field comparison. The derived impl would be correct and safe because all fields (`DarqualAddress`, `[u8; 32]`, `[u8; 32]`) already implement `PartialEq`/`Eq`.

**Fix:** `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]`

### [MEDIUM] `darqual-ledger/src/block.rs`, `darqual-ledger/src/ledger.rs` — missing `#[must_use]` on pure query methods
The following functions return computed values that are silently discardable:
- `Block::validate(&self) -> bool` (block.rs:105)
- `Block::validate_pow(&self, ..) -> bool` (block.rs:115)
- `Block::hash(&self) -> [u8; 32]` (block.rs:94)
- `Ledger::validate_chain(&self) -> bool` (ledger.rs:111)
- `Ledger::tip_hash(&self) -> [u8; 32]` (ledger.rs:83)
- `ContactCard::verify(&self) -> bool` (contact.rs:36)
- `Keywheel::label(&self) -> Label` (keywheel.rs:107)
- `Keywheel::label_at(&self, ..) -> Option<Label>` (keywheel.rs:115)

Calling `block.validate()` without inspecting the return value is a logic bug that Rust can catch for free.

**Fix:** Add `#[must_use]` to each of these. For the bool-returning ones a message hint helps:
```rust
#[must_use = "validation result must be checked"]
pub fn validate(&self) -> bool { … }
```

### [MEDIUM] `darqual-core/src/label.rs:8` — `Label(pub [u8; 16])` exposes inner bytes directly
The public tuple field allows callers to construct arbitrary `Label` values without going through any derivation path (`Label([0x00; 16])`, etc.). This is acceptable for a value type but inconsistent with the rest of the codebase's encapsulation style. It also prevents adding validation later.

**Fix:** Make the inner field private, add `pub fn as_bytes(&self) -> &[u8; 16]` and a `pub fn from_bytes(b: [u8; 16]) -> Self` constructor. The existing `label.0` accesses across the codebase are mechanical to update.

### [MEDIUM] `darqual-ledger/src/block.rs:22` — `LedgerEntry::mint` takes `envelope: Vec<u8>` by value
```rust
pub fn mint(label: Label, envelope: Vec<u8>, difficulty: u32) -> Self {
```
The function stores the `Vec<u8>` directly, which is fine for owned usage. But many callers convert a `String` or `&[u8]` just to pass it here. Accepting `impl Into<Vec<u8>>` or keeping `Vec<u8>` is reasonable, but the companion `canonical_bytes` and `pow_valid` internally slice `&self.envelope` — there's no need for the *constructor* to take ownership if callers have a `&[u8]`. Since this is a minting function that grinds a nonce, taking owned `Vec<u8>` is correct; the real fix is to document it explicitly. **Minor** but should have a doc note about ownership transfer.

### [MEDIUM] `darqual-committee/src/election.rs:30` — `seed_for_epoch` returns `Vec<u8>` unnecessarily
```rust
pub fn seed_for_epoch(epoch: u64, prev_root: &[u8; 32]) -> Vec<u8>
```
The result is only ever passed to `elect(candidates, seed, size)` which takes `&[u8]`. There is no reason to heap-allocate; a fixed-size array would do. Since the seed length is fixed at `PREFIX.len() + 8 + 32`, this could return a stack `[u8; N]` or at minimum be documented as "returns a heap-allocated seed". Currently the function forces an allocation on every epoch transition.

**Fix:**
```rust
const SEED_LEN: usize = b"darqual-epoch-seed-v1".len() + 8 + 32; // = 61
pub fn seed_for_epoch(epoch: u64, prev_root: &[u8; 32]) -> [u8; SEED_LEN] { … }
```
Or keep `Vec<u8>` but add `#[must_use]`.

### [MEDIUM] `darqual-cover/src/dp.rs:92` — float-to-int cast in `sample_geo` without NaN/Inf guard
```rust
(u.ln() / q.ln()).floor() as i64
```
`f64 as i64` in Rust is a *saturating* cast: if the float is `+inf`, `-inf`, or `NaN`, the result is `i64::MAX`, `i64::MIN`, or `0` respectively (platform-dependent in older Rust, defined since Rust 1.45 as saturating). For `epsilon` very close to 0, `q = exp(-epsilon) → 1.0`, making `q.ln() → 0.0`, and the division produces `±inf`. The assert guards `epsilon > 0` but not `epsilon < SOME_MIN`. Extremely small epsilon values are invalid for DP but not explicitly rejected.

**Fix:** Add a minimum epsilon guard and use `f64::to_int_unchecked` only after asserting finiteness, or use `.clamp`:
```rust
assert!(epsilon >= 1e-6, "epsilon too small for stable geometric sampling");
let raw = (u.ln() / q.ln()).floor();
assert!(raw.is_finite(), "geometric sample produced non-finite value");
raw as i64
```

---

## LOW

### [LOW] `darqual-core/src/keywheel.rs:50` — `Keywheel::epoch` is `pub` without `#[must_use]`-level encapsulation concern
The `epoch` field is public, which means external code can read it freely (fine) but also that someone could construct `Keywheel { epoch: 0, state: … }` if `state` were public. The `state` field is private (good), but `epoch` being mutable via pattern is a footgun. Since `Keywheel` is only constructable via `Conversation::keywheel`, this is contained for now. Consider `pub fn epoch(&self) -> u64` and making `epoch` private.

### [LOW] `darqual-core/src/identity.rs` — missing `#[must_use]` on pure methods
- `Identity::address(&self) -> DarqualAddress` — pure derivation, should be `#[must_use]`
- `Identity::ed_pub(&self) -> [u8; 32]` — same
- `Identity::sign(&self, msg: &[u8]) -> [u8; 64]` — silently discarding a signature is almost certainly a bug

### [LOW] `darqual-ledger/src/block.rs:76–79` — `SystemTime::now()` in `Block::new` makes blocks non-deterministic and non-testable
```rust
let created_unix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs();
```
`Block::new` takes epoch and prev_hash but injects a live wall-clock timestamp. This makes the same inputs produce different `Block::hash()` values across calls (different `created_unix`), which is fine for production but breaks deterministic testing. Tests that build a block and then compare its hash have a race condition if the timestamp ticks between calls. Adding a `Block::new_with_timestamp(…, created_unix: u64)` constructor and making `Block::new` call it with `SystemTime` would separate the concerns cleanly.

### [LOW] `darqual-core/src/address.rs` — `DarqualAddress::as_str` and `Display` both exist
Both `as_str(&self) -> &str` and `impl Display` do essentially the same thing. By Rust convention, `Display` is the canonical "give me the string representation" path; `as_str` is for when you need a `&str` borrow specifically. The duplication isn't wrong, but `as_str` should be documented as "prefer `to_string()` or `Display` unless you need a `&str` lifetime."

### [LOW] `darqual-storage/src/erasure.rs:99` / `darqual-storage/src/repair.rs:44` — redundant `s.clone()` inside `Option` mapping
```rust
.map(|(s, &p)| if p { Some(s.clone()) } else { None })
```
The RS library (`reed_solomon_erasure`) requires `Option<Vec<u8>>` where `None` means "erased". This clone is forced by the API. However, the pattern can be made clearer with:
```rust
.map(|(s, &p)| p.then(|| s.clone()))
```
Minor readability improvement; the allocation is unavoidable given the library's design.

### [LOW] `darqual-core/src/pow.rs` — `pub const POW_DOMAIN` is exported but callers don't need it
`POW_DOMAIN` is re-exported from `darqual-core`'s `lib.rs`. Nothing in the public API surface should require callers to construct raw BLAKE3 hashes with this domain — it's an implementation detail of `pow_hash`. Keeping it `pub(crate)` would be cleaner; exporting it invites callers to roll their own PoW outside the provided API.

---

## NIT

### [NIT] `darqual-core/src/lockbox.rs:51` — encryption error uses `Error::Encoding`, not a dedicated variant
```rust
.map_err(|_| Error::Encoding("encryption failed".to_string()))?;
```
`Error::Encoding` is documented as "encoding error" (serialisation context). Using it for AEAD encryption failure conflates two distinct failure modes. `Error::Decrypt` exists for decryption failure; consider `Error::Encrypt` for the encryption side, or at minimum document the dual use.

### [NIT] `darqual-ledger/src/ledger.rs:18` — `Ledger::window` and `Ledger::pow_difficulty` are `pub` fields
Both are mutable from outside the crate: `ledger.window = 0` would silently disable pruning; `ledger.pow_difficulty = 0` would silently disable PoW. These should be private with setter methods (or at least `pub(crate)`) to preserve invariants. A `window` of 0 with no guard causes `drain_count = len - 0 = len` on every append, dropping all blocks.

### [NIT] `darqual-core/src/contact.rs` — `ContactCard::new` is public but doesn't call `verify()`
Callers can construct a `ContactCard` with a mismatched `address`/`ed_pub` via `ContactCard::new`. Only `verify()` checks consistency. This is fine architecturally (the type is data, not a capability), but a doc note on `new` saying "call `verify()` before trusting a card from an untrusted source" would prevent misuse.

### [NIT] `darqual-ledger/src/merkle.rs` — `merkle_root` takes `&[Vec<u8>]`, not `&[impl AsRef<[u8]>]`
```rust
pub fn merkle_root(leaves: &[Vec<u8>]) -> [u8; 32]
```
Callers must heap-allocate `Vec<u8>` for each leaf even when they have `&[u8]` slices. Changing to `&[impl AsRef<[u8]>]` or making it generic over `T: AsRef<[u8]>` would eliminate the allocation overhead in, e.g., `canonical_bytes` calls.

### [NIT] `darqual-committee/src/election.rs:65` — `is_member` does a linear scan
```rust
committee.contains(ed_pub)
```
Fine for small committees (typ. 3–7 members). If committee sizes grow, this should use a `HashSet`. Document the O(n) complexity or add a note about expected committee size bounds.

### [NIT] `darqual-core/src/keywheel.rs` — `ratchet_state` allocates a `Vec` for each step
```rust
let mut input = Vec::with_capacity(RATCHET_DOMAIN.len() + 32);
input.extend_from_slice(RATCHET_DOMAIN);
input.extend_from_slice(&state);
*blake3::hash(&input).as_bytes()
```
BLAKE3's `Hasher` API allows incremental updates without allocating. Replace with:
```rust
*blake3::Hasher::new()
    .update(RATCHET_DOMAIN)
    .update(&state)
    .finalize()
    .as_bytes()
```
This eliminates one heap allocation per ratchet step — meaningful in tight loops.

### [NIT] `darqual-cover/src/cover.rs` — `debug_assert_eq!` is the only guard on `COVER_ENVELOPE_LEN` correctness
```rust
debug_assert_eq!(envelope.len(), COVER_ENVELOPE_LEN);
```
Debug asserts are stripped in release builds. The `cover_envelope_len_matches_real_lockbox` test provides the canonical check. Fine for now, but worth noting: if `COVER_ENVELOPE_LEN` drifts from reality in release, the size-indistinguishability property silently breaks.

### [NIT] `darqual-core/src/identity.rs` — `IdentityFile` and helper `decode_hex_32` are private but undocumented
Private types don't need doc comments, but `decode_hex_32` is duplicated between `identity.rs` and `contact.rs`. Extract to a shared `crate::util::decode_hex_32` to avoid drift.

---

## Summary

| Severity  | Count |
|-----------|-------|
| CRITICAL  | 2     |
| HIGH      | 5     |
| MEDIUM    | 6     |
| LOW       | 6     |
| NIT       | 8     |
| **Total** | **27** |
