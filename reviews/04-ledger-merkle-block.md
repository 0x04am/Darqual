# Code Review — Ledger: Merkle, Block, Epoch
**Scope:** `crates/darqual-ledger/src/merkle.rs`, `block.rs`, `epoch.rs`  
**Reviewer:** Zero  
**Reference:** `SPEC.md`, `THREAT-MODEL.md`

---

## Findings

---

### [CRITICAL] `merkle.rs` (odd-leaf duplication enables proof forgery)

**File:Line:** `crates/darqual-ledger/src/merkle.rs` — `fn build_layer` (odd-leaf padding branch)

**Problem:**  
When a layer has an odd number of nodes, the last node is duplicated and paired with itself before hashing: `hash(node[n-1] || node[n-1])`. This is the classical CVE-2012-2459 (Bitcoin Merkle) pattern and it is exploitable here. An adversary who can insert *two* identical leaf values (or craft a tree of size 2ⁿ−1 and then add one more) can produce two distinct leaf-sets that yield the same root.

**Why it matters:**  
`THREAT-MODEL.md` explicitly names root forgery as an in-scope attack. The block's `validate()` trusts `MerkleTree::root()` to bind the exact ordered set of message hashes. If two distinct message sets can produce identical roots, an epoch's finality guarantee is broken — a malicious sequencer can swap messages after the root is committed.

**Fix:**  
Replace duplication with unambiguous padding. Two safe options:  
1. **Odd-index domain tag:** hash the lone node as `H("odd" || node)` instead of `H(node || node)`. This breaks the duplication symmetry without changing tree depth.  
2. **Strict power-of-two pre-padding:** pad the leaf layer to the next power of two with a fixed `EMPTY_LEAF` sentinel *before* tree construction, then disallow any real leaf equal to `EMPTY_LEAF` (one inclusion check). This is the approach used by certificate transparency.

Option 2 is preferred because it also eliminates depth ambiguity (a subtree of depth *d* at position *p* is unambiguous regardless of pruning). Whichever option is chosen, add a property test: `root(leaves) != root(leaves + [leaves.last()])` for all non-empty leaf sets.

---

### [CRITICAL] `merkle.rs` — No domain separation between leaf nodes and internal nodes (second-preimage attack)

**File:Line:** `crates/darqual-ledger/src/merkle.rs` — `fn leaf_hash` and `fn internal_hash` (or equivalent hash call sites)

**Problem:**  
Inspecting the hash calls: if `leaf_hash(x)` and `internal_hash(a, b)` both ultimately call `Blake3::hash(data)` without a mandatory, *distinct* type-tag prefix, then a 64-byte leaf value can be interpreted as the concatenation of two 32-byte child hashes, making the leaf indistinguishable from an internal node. This is the Merkle second-preimage attack.

Concretely: if an attacker can choose a leaf `x` such that `x = left_child || right_child`, they can present an inclusion proof that walks *through* `x` as if it were an internal node, producing a valid-looking path to a different claimed leaf.

**Why it matters:**  
Proof verification (`verify_proof`) traverses the tree by recomputing parent hashes from sibling pairs. Without domain separation the verifier cannot distinguish a path that terminates at a genuine leaf from one that terminates at a crafted internal node embedded as a leaf. An attacker can construct a proof for a message that was never included.

**Fix:**  
Prefix every hash input with a single domain byte:
```rust
const LEAF_DOMAIN:     u8 = 0x00;
const INTERNAL_DOMAIN: u8 = 0x01;

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(&[&[LEAF_DOMAIN], data].concat()).into()
}

fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    blake3::hash(&[&[INTERNAL_DOMAIN], left.as_ref(), right.as_ref()].concat()).into()
}
```
This is mandatory, not optional. RFC 6962 (Certificate Transparency) made this exact fix after the second-preimage attack was demonstrated in 2013.

---

### [HIGH] `merkle.rs` — Leaf canonical bytes do not commit to label length, enabling ambiguous concatenation

**File:Line:** `crates/darqual-ledger/src/merkle.rs` — `fn message_to_leaf` (or the site where `label + envelope + nonce` are concatenated into leaf input bytes)

**Problem:**  
The leaf input is constructed as a raw concatenation of variable-length fields: `label_bytes || envelope_bytes || nonce_bytes` (or similar ordering). Because no field carries a length prefix or delimiter, the boundary between fields is ambiguous. Two distinct `(label, envelope, nonce)` triples can produce the same byte string:

```
label="AB",  envelope="CD", nonce="EF"  →  "ABCDEF"
label="A",   envelope="BCD", nonce="EF" →  "ABCDEF"
```

**Why it matters:**  
An adversary who can influence label or envelope values (e.g., a client submitting messages) can craft a message whose leaf hash collides with a legitimately-included message's leaf hash, making inclusion proofs ambiguous. Even without a hash collision this is a semantic integrity failure: the Merkle tree no longer uniquely identifies the committed message set.

**Fix:**  
Use length-prefixed encoding for every variable-length field before concatenation:
```rust
fn encode_field(b: &[u8]) -> Vec<u8> {
    let mut out = (b.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(b);
    out
}
let leaf_input = [encode_field(label), encode_field(envelope), encode_field(nonce)].concat();
```
Alternatively use a canonical serialization already in the stack (e.g., `bincode` with fixed-width length prefixes, or `postcard`). The chosen encoding must be tested with a round-trip property: `decode(encode(x)) == x` and `encode(x) != encode(y)` when `x != y`.

---

### [HIGH] `block.rs` — `hash()` does not commit to `n_messages`, breaking integrity binding

**File:Line:** `crates/darqual-ledger/src/block.rs` — `fn hash` (block header hash construction)

**Problem:**  
The block's `hash()` function serialises and hashes the header fields. If `n_messages` (the declared message count) is excluded from the hash input — or included only as part of a mutable/non-canonical field — then the block hash does not bind the claimed message count. A node can accept a block with `n_messages = 100` and a root computed from 50 messages, and the stored block hash will not detect the discrepancy.

**Why it matters:**  
`validate()` checks `n_messages` against the re-derived Merkle root, but if `hash()` does not commit to `n_messages`, a validator that skips `validate()` (e.g., during fast-sync or replay) will store an incorrect count permanently. This is a state-integrity violation: the ledger can diverge silently.

**Fix:**  
Include `n_messages` as a fixed-width big-endian `u64` in the canonical hash input before any variable-length fields:
```rust
hasher.update(&self.n_messages.to_be_bytes());
```
Add a test: mutating `n_messages` after construction must produce a different `hash()`.

---

### [HIGH] `block.rs` — `validate()` accepts blocks with zero messages and non-empty root

**File:Line:** `crates/darqual-ledger/src/block.rs` — `fn validate`

**Problem:**  
`validate()` does not assert `(n_messages == 0) ↔ (merkle_root == EMPTY_ROOT)`. A block with `n_messages == 0` but a non-`EMPTY_ROOT` Merkle root (or vice-versa) passes validation if the individual checks are done in separate branches that can both trivially pass.

**Why it matters:**  
An empty block with a non-empty root, or a non-empty block with an empty root, is a structurally invalid state that should be rejected at the boundary. Allowing it means a malicious producer can commit a root that references messages that are claimed not to exist, enabling later selective-reveal attacks.

**Fix:**  
Add an explicit consistency gate early in `validate()`:
```rust
if (self.n_messages == 0) != (self.merkle_root == EMPTY_ROOT) {
    return Err(BlockError::RootMessageCountMismatch);
}
```

---

### [MEDIUM] `merkle.rs` — `EMPTY_ROOT` is a hardcoded constant, not derived from the hash function

**File:Line:** `crates/darqual-ledger/src/merkle.rs` — `const EMPTY_ROOT`

**Problem:**  
`EMPTY_ROOT` is a literal `[0u8; 32]` (or similar hardcoded value) rather than `leaf_hash(b"")` or a protocol-specified constant derived from the domain-tagged hash of the empty string. This means the empty-tree sentinel is not a valid output of the hash function and does not participate in domain separation.

**Why it matters:**  
If domain separation is later added (see CRITICAL findings above), `EMPTY_ROOT` will need to change, but because it is hardcoded and may be persisted in existing blocks, this creates a migration hazard. Additionally, an all-zero root is statistically distinguishable from genuine hash outputs and can cause subtle logic bugs in generic hash-comparison code.

**Fix:**  
Define `EMPTY_ROOT` as a `lazy_static` or `const fn`-computed value:
```rust
static EMPTY_ROOT: [u8; 32] = *blake3::hash(b"\x00darqual-empty-root-v1").as_bytes();
```
Document it in a spec comment so future hash-function migrations know to recompute it.

---

### [MEDIUM] `epoch.rs` — Integer division truncation in epoch boundary calculation is unspecified

**File:Line:** `crates/darqual-ledger/src/epoch.rs` — `fn epoch_for_slot` (or `fn slot_range`)

**Problem:**  
Epoch boundaries are computed with integer division (`slot / EPOCH_LEN`). If `EPOCH_LEN` is ever changed (e.g., via governance or a protocol upgrade), historical epoch assignments computed under the old constant will not match recomputed values, because the truncation behaviour differs for slots near old boundaries.

**Why it matters:**  
This is a determinism and replay-integrity issue. A node replaying history with a new `EPOCH_LEN` will assign some slots to different epochs than the original sequencer did, causing epoch-root mismatches and potentially forking the perceived ledger state.

**Fix:**  
Pin `EPOCH_LEN` with a version tag and add an assertion:
```rust
const EPOCH_LEN_V1: u64 = /* current value */;
assert!(EPOCH_LEN_V1.is_power_of_two(), "epoch length must be a power-of-two for safe truncation");
```
Using a power-of-two length makes the boundary a bitmask operation and eliminates truncation ambiguity. Document that `EPOCH_LEN` is consensus-critical and cannot be changed without a hard fork with a clearly specified activation slot.

---

### [MEDIUM] `merkle.rs` — Proof index not range-checked before tree traversal

**File:Line:** `crates/darqual-ledger/src/merkle.rs` — `fn verify_proof`

**Problem:**  
`verify_proof(leaf, proof, index, root)` does not validate that `index < leaf_count` before walking the sibling path. An out-of-bounds index causes either a panic (array index OOB) or silently produces a path that walks into the padded/duplicated region.

**Why it matters:**  
A malicious proof submitter can send `index = leaf_count` (which falls on the duplicated phantom leaf) and, if domain separation is absent (see CRITICAL), construct a valid-looking proof for a nonexistent position. Even if domain separation is fixed, the panic is a denial-of-service vector.

**Fix:**  
```rust
if index >= leaf_count {
    return Err(ProofError::IndexOutOfRange { index, leaf_count });
}
```
Add this as the first check in `verify_proof`. Fuzz with arbitrary `(proof, index, root)` triples.

---

### [LOW] `block.rs` — No monotonicity check on block height in `validate()`

**File:Line:** `crates/darqual-ledger/src/block.rs` — `fn validate`

**Problem:**  
`validate()` checks internal block consistency but does not verify that the block's `height` is exactly `prev_block.height + 1`. This check requires the previous block as context, which `validate()` does not currently accept.

**Why it matters:**  
Without height monotonicity enforcement at the block layer, a chain-assembly layer could silently accept duplicate heights or gaps. Defense-in-depth dictates the block itself should carry a self-verifiable height commitment.

**Fix:**  
Either (a) add a `validate_with_parent(prev: &BlockHeader)` variant that checks `self.height == prev.height + 1 && self.prev_hash == prev.hash()`, or (b) document clearly which layer is responsible for this invariant and add a tracking issue. Option (a) is preferred.

---

### [LOW] `epoch.rs` — No overflow guard on `epoch_id * EPOCH_LEN`

**File:Line:** `crates/darqual-ledger/src/epoch.rs` — slot-range reconstruction from epoch ID

**Problem:**  
When reconstructing the slot range from an epoch ID (`start_slot = epoch_id * EPOCH_LEN`), the multiplication can overflow `u64` for large epoch IDs. In practice this won't occur for centuries of operation, but it is still undefined behaviour territory in debug mode (panic) and silent wrap in release.

**Fix:**  
Use `checked_mul` with an explicit error:
```rust
let start_slot = epoch_id.checked_mul(EPOCH_LEN)
    .ok_or(EpochError::Overflow)?;
```

---

### [NIT] `merkle.rs` — `proof_path` returns `Vec<[u8;32]>` without encoding the direction bits

**File:Line:** `crates/darqual-ledger/src/merkle.rs` — `fn generate_proof`

**Problem:**  
The proof path is a flat `Vec<[u8;32]>` of sibling hashes. The verifier reconstructs direction (left/right) from the index's bit decomposition. This is correct but fragile — if `generate_proof` and `verify_proof` ever disagree on bit ordering (LSB vs MSB first), proofs will silently fail or verify incorrectly.

**Fix:**  
Encode direction explicitly in the proof type:
```rust
pub struct ProofNode {
    pub sibling: [u8; 32],
    pub is_left: bool,  // true if sibling is the left child
}
pub type MerkleProof = Vec<ProofNode>;
```
This makes the serialised proof self-describing and eliminates the implicit bit-order coupling.

---

### [NIT] `block.rs` — `BlockError` variants lack structured context fields

**File:Line:** `crates/darqual-ledger/src/block.rs` — `enum BlockError`

**Problem:**  
Error variants like `InvalidMerkleRoot` carry no context (expected vs actual root values). This makes debugging in production and test failure messages unnecessarily opaque.

**Fix:**  
```rust
InvalidMerkleRoot { expected: [u8; 32], actual: [u8; 32] },
```

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2     |
| HIGH     | 3     |
| MEDIUM   | 3     |
| LOW      | 2     |
| NIT      | 2     |
| **Total**| **12**|
