# Darqual — Code Review 03: Proof-of-Work & VRF
**Scope:** `crates/darqual-core/src/pow.rs`, `crates/darqual-committee/src/vrf.rs`, `crates/darqual-committee/src/election.rs`
**Reference:** `SPEC.md`, `THREAT-MODEL.md`, `crates/darqual-core/src/identity.rs`, `crates/darqual-core/src/label.rs`
**Reviewed by:** Chrollo (subagent, handle sa_19)

---

## I. Proof-of-Work (`crates/darqual-core/src/pow.rs`)

---

### [HIGH] PoW nonce is NOT bound to the envelope payload — replay / cross-entry reuse possible
**File:** `pow.rs` (the `solve` / `verify` functions, nonce construction site)

**Problem:**
The PoW hash input is constructed as `blake3(label_bytes || nonce_bytes)`. The `label` here is the entry label (epoch + author pubkey), but the **envelope body** (the actual content being committed to) is absent from the hash preimage. This means:

1. A valid `(nonce, hash)` pair computed for label `L` is valid for *any* envelope carrying the same label.
2. An adversary who has previously solved PoW for an earlier entry under the same label can replay the nonce without re-grinding — valid solutions accumulate and are reusable.
3. In a system where labels are predictable (epoch is public, pubkey is stable), an adversary can pre-grind PoW solutions *before* an epoch opens and submit instantly at epoch start.

**Why it matters:**
PoW is the primary anti-spam / anti-Sybil gate for entry submission. If solutions can be precomputed or replayed, the rate-limiting property is nullified. An adversary pre-grinds offline, then floods at epoch boundary.

**Fix:**
Bind the nonce to the full envelope: `blake3(label_bytes || envelope_hash || nonce_bytes)` where `envelope_hash` is a commitment to the payload (e.g., `blake3(envelope_bytes)`). This makes every valid solution specific to one (label, content) pair, preventing both replay and precomputation.

---

### [MEDIUM] `leading_zero_bits` is correct for the common case but has an undocumented edge-case at all-zero hash output
**File:** `pow.rs`, `leading_zero_bits` function

**Problem:**
The function counts leading zero bits across the 32-byte Blake3 output by iterating bytes and returning early on the first non-zero byte. When the hash is all-zero (probability 2⁻²⁵⁶, cosmologically negligible) the function returns `256`. Any difficulty target `d < 256` would be satisfied, but a target of exactly `256` would pass a `>= d` check — this is fine. However, if downstream code ever does `(1u64 << leading_zero_bits())` or similar shifts on the result, a value of `256` causes **undefined behavior / panic** in Rust (shift overflow on u64/u128 bounded to 63/127 bits).

More practically: the function is not documented as returning values in `[0, 256]`, and no caller is shown to guard against the `256` case. If a difficulty-scaling formula uses the return value as a shift exponent, this is a latent panic path on legitimate (if astronomically rare) inputs.

**Fix:**
Clamp return value to `min(count, 255)` or document the `[0, 256]` range explicitly and audit all callers for shift operations.

---

### [MEDIUM] PoW difficulty is a fixed constant — no adaptive rate-limiting, grinding DoS possible
**File:** `pow.rs`, `DIFFICULTY` / `MIN_DIFFICULTY` constant

**Problem:**
The difficulty target is a compile-time constant (or at most an epoch-level static). There is no adaptive adjustment based on observed submission rate. An adversary with GPU/ASIC resources can grind far below the expected time budget, submitting valid PoW solutions orders of magnitude faster than a legitimate CPU participant. The THREAT-MODEL acknowledges grinding but assumes difficulty is "set high enough" — this is not verifiable without a feedback loop.

Additionally, because nonces are not bound to envelope content (see [HIGH] above), grinding effort is amortized across all future submissions under the same label, making the effective cost even lower.

**Fix:**
At minimum, implement epoch-level difficulty adjustment based on observed solution submission latency (similar to Bitcoin's 2-week window). Short-term: bind nonce to content to eliminate amortization.

---

### [LOW] No upper bound on nonce search iterations — `solve` can run forever
**File:** `pow.rs`, `solve` loop

**Problem:**
The `solve` function iterates nonces until a valid solution is found, with no iteration cap or timeout. For a misconfigured or accidentally elevated difficulty, this produces a function that never returns — hanging the caller thread indefinitely with no cancellation mechanism.

**Fix:**
Accept a `max_iters: u64` parameter (or a `CancellationToken`) and return `Err(PowError::Exhausted)` when the limit is reached. Callers can then handle the case or retry with adjusted parameters.

---

### [NIT] Nonce is a `u64` — wraps silently at 2⁶⁴ without detection
**File:** `pow.rs`, nonce increment

**Problem:**
The nonce counter wraps at `u64::MAX` to `0` in release builds (Rust wrapping arithmetic on overflow in release mode, panic in debug). If the nonce space is exhausted (should not happen for reasonable difficulty, but possible with a bug), the function silently re-explores already-checked nonces rather than reporting failure.

**Fix:**
Use `nonce.checked_add(1).ok_or(PowError::NonceExhausted)?` to surface exhaustion explicitly.

---

## II. VRF Construction (`crates/darqual-committee/src/vrf.rs`)

---

### [CRITICAL] `verify_ed` uses `verify` (non-strict) — small-order R malleability not caught, VRF uniqueness broken
**File:** `crates/darqual-core/src/identity.rs` (the `verify_ed` function called by vrf.rs), dalek `ed25519-dalek` internals

**Problem:**
The VRF is constructed as:

```
vrf_output = blake3(ed25519_sign(sk, vrf_input))
```

The security of this construction as a VRF rests on two properties:
1. **Uniqueness / determinism:** For a fixed `(sk, vrf_input)`, exactly one signature — and therefore exactly one output — is valid.
2. **Verifiability:** A verifier can confirm that `blake3(sig)` is the correct output for `(pk, vrf_input)`.

**The flaw:** `verify_ed` calls `vk.verify(msg, &sig)` (non-strict ed25519). The non-strict `verify` path in `ed25519-dalek` does **not** call `is_small_order()` on the `R` component of the signature. As documented in dalek's own security notes (and the [Ristretto/cofactor attack literature](https://hdevalence.ca/blog/2020-10-04-its-25519-pt1)):

- Ed25519 with cofactor 8 admits **eight valid `R` points** for a given `(s, msg, pk)` combination when the key or nonce lands on a small-order subgroup point.
- A malicious signer can produce **up to 8 distinct signatures** `(R_i, s)` that all pass non-strict `verify` for the same message.
- Each such signature produces a **different** `blake3(sig)` output.
- Therefore the VRF is **not unique**: a participant can choose among up to 8 valid outputs and submit whichever is most favorable to them (i.e., whichever gives them committee membership).

This is **not theoretical** — the dalek library split `verify` vs `verify_strict` precisely to expose this class of attack. The THREAT-MODEL section on VRF grinding/biasing does not account for this vector.

**Impact:**
A participant with a key that produces a small-order `R` can selectively bias their VRF output by choosing among valid signature variants. With 8 choices, they gain log₂(8) = 3 bits of effective entropy advantage — enough to meaningfully inflate committee inclusion probability depending on committee size and threshold.

**Fix:**
Replace `vk.verify(msg, &sig)` with `vk.verify_strict(msg, &sig)` in `verify_ed` (identity.rs). This enforces `is_small_order(R) == false` and `is_small_order(pk) == false`, collapsing the valid signature set to exactly one per `(sk, msg)` pair and restoring VRF uniqueness. Additionally, during key registration, reject any public key `pk` where `is_small_order(pk) == true` to close the subgroup-cofactor key attack surface entirely.

---

### [HIGH] `blake3(ed25519_sig)` is not a formally proven VRF — it is a heuristic construction with unproven binding
**File:** `vrf.rs`, `vrf_output` derivation

**Problem:**
A VRF requires three properties: **pseudorandomness** (output indistinguishable from random to non-key-holders), **uniqueness** (one valid output per input), and **verifiability** (verifier can check correctness). The construction `blake3(sign(sk, input))` achieves verifiability trivially (verifier re-verifies the signature then hashes), and achieves uniqueness *only if* the signature scheme is truly deterministic and non-malleable (see [CRITICAL] above). The pseudorandomness argument holds under ROM + the assumption that the ed25519 signing function behaves as a PRF — which requires **determinism of the nonce `r`** in the signing process.

For `ed25519-dalek`, nonce derivation is `r = blake2b(sk_expanded || msg)` (RFC 8032 deterministic). This is sound **for the canonical dalek signer**. However:

1. If the signing path is ever replaced by an HSM, hardware key, or alternative signer implementation, determinism is **not guaranteed by the trait interface** — `Signer::sign` in the `signature` crate makes no determinism promise. The VRF would silently degrade to a non-deterministic scheme.
2. There is no documentation in `vrf.rs` asserting the determinism assumption or binding it to a specific implementation.

**Fix:**
Annotate the VRF construction prominently with the determinism assumption. Consider replacing with a formally specified VRF (e.g., ECVRF per IETF draft-irtf-cfrg-vrf, or a hash-to-curve based construction) which makes the uniqueness and pseudorandomness properties unconditional and auditable. At minimum, add a compile-time assertion or type-level constraint that restricts the `Signer` to `SigningKey` (the concrete dalek type) rather than a generic `Signer<ed25519::Signature>`.

---

### [MEDIUM] VRF input does not include the epoch number — outputs reusable across epochs
**File:** `vrf.rs`, vrf_input construction

**Problem:**
The VRF input is constructed from the `label` (which includes author pubkey) and the `vrf_nonce` / round seed, but does **not** explicitly embed the epoch number as a separate domain-separated field. If the epoch seed happens to repeat (or if an adversary can influence seed selection), VRF outputs from a prior epoch are valid in the current epoch for the same participant.

More importantly: the domain separation between "VRF for committee election in epoch N" and "VRF for any other protocol use" is implicit. A future protocol extension reusing VRF outputs in a different context could produce cross-context collisions.

**Fix:**
Construct vrf_input as `blake3(DOMAIN_SEP || epoch_number_le_bytes || round_seed || author_pubkey)` with an explicit domain separator constant. This binds each VRF output irrevocably to a single epoch and use-case.

---

### [LOW] VRF proof is the raw ed25519 signature bytes — 64 bytes, no binding to vrf_output
**File:** `vrf.rs`, `VrfProof` type

**Problem:**
The "proof" transmitted is the raw `ed25519::Signature` (64 bytes). A verifier who receives `(vrf_output, proof, pk, msg)` must:
1. Verify `proof` is a valid ed25519 sig over `msg` by `pk`.
2. Recompute `blake3(proof)` and compare to `vrf_output`.

Step 2 is a byte-equality check on the hash — this is sound. However, the `VrfProof` struct carries no explicit binding between the proof bytes and the claimed output; the binding is enforced only by the verifier's logic. If a code path ever verifies the signature but skips the hash recomputation, the VRF output is unverified. This is a defense-in-depth gap.

**Fix:**
Make `VrfProof` a struct that carries both `signature: ed25519::Signature` and `output: blake3::Hash`, computed and stored together at proof creation time. The `verify` method on `VrfProof` checks both in one call, preventing partial verification.

---

## III. Election Logic (`crates/darqual-committee/src/election.rs`)

---

### [HIGH] Invalid VRF proofs are silently excluded rather than causing election failure — equivocation vector
**File:** `election.rs`, candidate filtering loop

**Problem:**
The election logic filters candidates by collecting only those whose VRF proof verifies successfully, discarding invalid proofs silently. This means:

1. An adversary can submit an entry with a deliberately invalid VRF proof, knowing it will be excluded. This is a **free action** — no cost for the adversary (they already paid PoW), but it consumes verifier CPU.
2. More critically: if **signature malleability** (see [CRITICAL] in VRF section) is exploited, an adversary can submit two entries — one with the "bad" VRF output (which loses the election) and one with the favorable one — and the bad one is silently dropped. The favorable one is retained. This is precisely the grinding/bias attack enabled by the non-strict verify.
3. Nodes may reach different filtered candidate sets if they process entries in different orders or have different views of submitted proofs, creating **consensus split** potential.

**Fix:**
Define and enforce a rule: each participant identity may submit exactly one VRF proof per epoch. If multiple are received, apply a deterministic tiebreak (e.g., first-seen by slot timestamp, or lowest hash) and record the chosen one. Submission of an invalid VRF proof by a known participant should be a slashable offense (invalidating all their submissions for the epoch), not a silent skip.

---

### [MEDIUM] Sort stability and tie-breaking rely on VRF output ordering — not explicitly documented as deterministic across platforms
**File:** `election.rs`, candidate sort

**Problem:**
Candidates are sorted by `vrf_output` (the blake3 hash, treated as a 32-byte big-endian integer). This is correct and deterministic for fixed inputs. However:

1. There is no assertion or comment that blake3 output is compared as raw bytes (big-endian) rather than as a Rust `[u8; 32]` lexicographic comparison — these happen to be equivalent, but the equivalence is undocumented and a future refactor could break it.
2. If two candidates produce identical VRF outputs (negligible probability, ~2⁻²⁵⁶, but possible in theory for adversarially chosen keys), the sort is unstable and committee membership becomes non-deterministic across nodes.

**Fix:**
Document the sort key explicitly as "32-byte big-endian integer comparison of blake3 output." Add a secondary tiebreak on `author_pubkey` bytes to guarantee strict total order even in the astronomically unlikely collision case.

---

### [MEDIUM] Committee size edge case: threshold computation underflows when fewer valid candidates than `MIN_COMMITTEE_SIZE`
**File:** `election.rs`, committee assembly

**Problem:**
If the number of valid candidates after PoW + VRF filtering is less than `MIN_COMMITTEE_SIZE`, the code either panics (slice index out of bounds) or returns a committee smaller than the minimum, depending on how the size is computed. Neither outcome is explicitly handled or documented. In a low-participation epoch, this is not a theoretical edge case.

**Fix:**
Explicitly check `valid_candidates.len() >= MIN_COMMITTEE_SIZE` before slicing. If below threshold, either:
- Abort the epoch (return `Err(ElectionError::InsufficientCandidates)`) and trigger a re-roll or epoch extension per SPEC, or
- Document that sub-minimum committees are permitted and specify the security implications.

---

### [LOW] PoW verification is not re-executed during election — stale valid proofs accepted
**File:** `election.rs`, entry validation path

**Problem:**
During election, the code verifies VRF proofs but does not re-verify PoW for each candidate entry. PoW validity is presumably checked at entry submission time, but if the election accepts a cached / persisted entry set, a scenario exists where PoW was valid at submission time under a previous difficulty setting and is now accepted under a stricter setting. The election does not enforce current-epoch difficulty.

**Fix:**
Re-verify PoW against the current epoch's difficulty constant during election candidate validation, not just at submission ingress.

---

### [NIT] `election.rs` imports `identity::verify_ed` transitively through `vrf.rs` — coupling is invisible at the call site
**File:** `election.rs`

The call to `candidate.verify_vrf()` dispatches through `vrf.rs` → `identity.rs` → `verify_ed`. There is no documentation at the election layer that the non-strict verify issue propagates here. When `verify_ed` is fixed to use `verify_strict`, the election layer gets the fix for free — but the dependency chain should be documented so future maintainers don't inadvertently reintroduce a non-strict path.

---

## IV. Summary Table

| ID | Severity | Component | Title |
|----|----------|-----------|-------|
| 01 | **CRITICAL** | vrf.rs / identity.rs | `verify` (non-strict) allows small-order R malleability — VRF uniqueness broken |
| 02 | **HIGH** | pow.rs | PoW nonce not bound to envelope — replay and precomputation possible |
| 03 | **HIGH** | vrf.rs | `blake3(sign())` VRF construction not formally proven; determinism implicit |
| 04 | **HIGH** | election.rs | Invalid VRF proofs silently excluded — equivocation and bias vector |
| 05 | **MEDIUM** | pow.rs | Fixed difficulty — no adaptive rate-limiting, grinding DoS possible |
| 06 | **MEDIUM** | vrf.rs | VRF input excludes epoch number — cross-epoch reuse and weak domain separation |
| 07 | **MEDIUM** | vrf.rs | `VrfProof` carries no binding between signature and output — partial verify risk |
| 08 | **MEDIUM** | election.rs | Sort stability undocumented; no strict tiebreak on pubkey for collision case |
| 09 | **MEDIUM** | election.rs | Committee size underflow when candidates < MIN_COMMITTEE_SIZE |
| 10 | **LOW** | pow.rs | `solve` has no iteration cap — can hang indefinitely |
| 11 | **LOW** | pow.rs | Nonce wraps silently at u64::MAX |
| 12 | **LOW** | election.rs | PoW not re-verified at election time — stale difficulty accepted |
| 13 | **NIT** | pow.rs | `leading_zero_bits` returns 256 on all-zero hash; callers may shift on it |
| 14 | **NIT** | election.rs | Non-strict verify chain undocumented across election → vrf → identity |

---

**Counts: CRITICAL 1 · HIGH 3 · MEDIUM 5 · LOW 3 · NIT 2**
