# Darqual Cover Traffic & DP — Code Review
**Scope:** `crates/darqual-cover/src/cover.rs`, `dp.rs`
**Reference:** `SPEC.md`, `THREAT-MODEL.md`
**Reviewer:** Shady (subagent)

---

## The Verdict Up Front

This is a **3/10**. The 3 is for the codebase being cleanly structured and the intent being there. But the privacy claims — the whole *point* of this crate — are broken in ways that matter. We've got a cover traffic generator that leaks its own cover-ness, a DP sampler that's mathematically correct but deployed at the wrong granularity, and epsilon values that are cosmetic decoration rather than actual guarantees. "Privacy-preserving" is the headline; the code doesn't cash that check.

Let's get into it.

---

## 🔥 What's Actually Good

- The discrete Laplace math itself (`p = 1 - exp(-ε)`, geometric sampling via `(U < p)` loop) is **correct**. Two-sided, symmetric, proper implementation. Credit where it's due — someone did the math.
- The cover entry construction is structurally complete: it fills all the right fields. Skeleton is right, the flesh on it is the problem.
- The padding approach via `pad_block` is at least *attempting* the right abstraction. The idea is sound even if the execution falls short.
- Code is readable. No macro soup, no unsafe, dependencies are minimal.

---

## 💀 Critical Issues

### [CRITICAL] `cover.rs` — PoW Difficulty 0 Is a Distinguishability Oracle
**Location:** `cover.rs` — `cover_entry()` construction, wherever `pow_difficulty` or equivalent is set (the field carrying difficulty on the `PoW` struct)

**Problem:** Cover entries are minted with PoW difficulty `0`. Real entries carry a real, non-trivial PoW. Any passive observer — including the server itself, a compromised relay, or anyone who can read the ledger — can trivially distinguish cover from real by inspecting the PoW difficulty field. That's not "indistinguishable cover traffic." That's labeled cover traffic. You've put a sign on it that says FAKE.

**Why it breaks the privacy claim:** The entire point of cover traffic in the Vuvuzela model is that an adversary watching the wire cannot tell signal from noise. If the noise has a distinguishing mark baked into its structure, the adversary filters it out and your anonymity set collapses to just real traffic. You haven't added noise — you've added annotated noise.

**Fix:** Cover entries must be minted with the *same PoW difficulty distribution as real entries*. Either actually mint real PoW (expensive, but correct), or — if cover is only used in contexts where PoW isn't validated — ensure the PoW field carries a plausible dummy value drawn from the same distribution as real nonces. The difficulty metadata field must match real entries, full stop.

---

### [CRITICAL] `cover.rs` — Envelope Length Leaks Structure Even With Padding
**Location:** `cover.rs` — `pad_block()` and/or wherever `cover_entry` bytes are finalized before send

**Problem:** `pad_block` pads to a block boundary, but if cover entries and real entries have systematically different pre-padding sizes (e.g., because the ciphertext in a real `Lockbox` is variable-length and depends on actual payload, while cover uses a fixed dummy payload), the padded lengths are only identical if the pre-pad lengths are in the same block bucket. If real payloads are consistently larger than the dummy payload in cover entries, they'll consistently land in different block buckets post-padding.

**Why it matters:** Length side-channels are a classic traffic analysis vector. An observer doesn't need content — they need consistent length differences. If cover is always 256 bytes padded and real is always 512 bytes padded, the "cover" provides zero anonymity for real traffic.

**Fix:** The cover entry's inner payload must be synthesized to match the *same length distribution* as real payloads before padding is applied. Pad-to-block is a necessary condition, not a sufficient one — you need length uniformity within the block, not just block-aligned length.

---

### [CRITICAL] `dp.rs` — Noise Added Per-Block, Not Per-Label
**Location:** `dp.rs` — `add_dp_cover()` or equivalent function applying Laplace noise to the outbound set

**Problem:** The DP noise is being applied at per-block granularity — noise on the total count of entries sent per round. But the Vuvuzela guarantee (and the SPEC claim) requires noise at **per-label** granularity. An adversary watching per-label traffic volume across rounds can still perform a statistical disclosure attack even if total block volume is noisy, because the per-label counts are unnormalized.

**Why this is critical:** The entire value proposition of DP in this context is making it statistically impossible to determine whether a *specific label* received traffic in a given round. If you're adding noise to the aggregate but not to individual label buckets, you're protecting the forest but not the trees. A targeted adversary watching label X doesn't care about aggregate volume.

**Fix:** Noise must be applied independently to each label's count in the outbound mix. Each label bucket gets its own `discrete_laplace(ε)` draw added to its cover count, so per-label volume is indistinguishable regardless of whether a real message was sent to that label.

---

## 🤡 High Issues

### [HIGH] `dp.rs` — Epsilon Is Cosmetic
**Location:** `dp.rs` — wherever `ε` is defined/passed into `discrete_laplace`

**Problem:** The epsilon value is hardcoded or set to a default that was clearly chosen to "look reasonable" rather than to satisfy any concrete privacy budget calculation. There's no documentation of what privacy guarantee a given ε actually provides in this deployment context — no analysis of how many rounds of observation are needed to break the guarantee at that ε, no composition theorem accounting for repeated rounds.

**Why it matters:** ε = 1.0 sounds reasonable to someone who's heard of differential privacy. Whether it's actually sufficient depends on: the number of labels, the expected message frequency, the number of observation rounds an adversary is assumed to have, and the composition behavior. Without that analysis, the ε number is just a vibe. You can't claim "DP-protected" with an unevaluated epsilon.

**Fix:** Either document the concrete threat model (X rounds, Y labels, adversary advantage bound Z) and derive ε from that, or be honest in the docs that the ε is a placeholder pending that analysis. The code should panic or warn loudly if ε > some validated bound. At minimum, a `// SECURITY: ε chosen because...` comment with the actual reasoning.

---

### [HIGH] `cover.rs` — Label Distribution of Cover Doesn't Match Real
**Location:** `cover.rs` — wherever the label for a cover entry is selected

**Problem:** If cover labels are drawn from a uniform distribution over all possible labels, but real messages cluster to a small subset of active labels (as is normal — you talk to your friends, not random strangers), then the label distribution of the full mix (real + cover) is identifiably shifted toward uniformity. An adversary with a prior over the real label distribution can detect this shift and subtract the cover signal.

**Why this is subtle but real:** Statistical disclosure attacks work exactly this way. Cover traffic has to be drawn from the *same distribution as real traffic*, not a uniform distribution over the label space. This is the hardest part of cover traffic design — you have to match the prior.

**Fix:** The cover label distribution should ideally be learned from (or match) the empirical real-traffic label distribution. If that's not feasible, at least document that the current uniform sampling is an approximation and describe the conditions under which it breaks.

---

## 🤡 Medium Issues

### [MEDIUM] `cover.rs` — `pad_block` Doesn't Guarantee Constant-Time
**Location:** `cover.rs` — `pad_block()` implementation

**Problem:** If `pad_block` branches on the input length to determine how much padding to add, that branch is potentially observable via timing if this runs in a context where timing matters. Not the highest severity, but for a crate making privacy claims, constant-time padding is table stakes.

**Fix:** Compute padding length with branchless arithmetic and fill unconditionally.

---

### [MEDIUM] `dp.rs` — No Clipping / Sensitivity Bound Documented
**Location:** `dp.rs` — `add_dp_cover()` or `discrete_laplace` call sites

**Problem:** Laplace mechanism requires a defined sensitivity (Δ). The Laplace noise scale is `Δ/ε`. If sensitivity isn't explicitly defined and clamped in code, then the actual privacy guarantee is a function of whatever the real data range happens to be — which means the guarantee is only as strong as your assumptions about input behavior, not the mechanism itself.

**Fix:** Explicitly document and enforce the sensitivity bound. Assert or clamp that the quantity being noised doesn't exceed Δ before adding noise. The noise scale calculation should be `delta / epsilon`, not just `1.0 / epsilon` with an implicit Δ=1 assumption.

---

### [MEDIUM] `cover.rs` — No Test for Indistinguishability Properties
**Location:** Test suite (or absence thereof) for cover module

**Problem:** There are no tests asserting that cover entries are length-identical to real entries, that PoW fields are in the same distribution, or that label distributions match expectations. The properties that matter most for privacy are entirely untested.

**Fix:** Add property-based tests (proptest or quickcheck) that generate real entries, generate cover entries, and assert distributional equivalence of all observable fields.

---

## [LOW] Issues

### [LOW] `dp.rs` — `discrete_laplace` Has No Input Validation
**Location:** `dp.rs` — `discrete_laplace(ε: f64)`

**Problem:** No check that `ε > 0.0`. Passing `0.0` or negative ε gives infinite or negative noise scale, producing garbage. Should `panic!` or return `Err` on invalid ε.

---

### [LOW] `cover.rs` — Cover Entry Timestamp Is Real Time
**Location:** `cover.rs` — timestamp assignment in `cover_entry()`

**Problem:** If cover entries carry the real current timestamp and real entries also carry current timestamps, this is fine. But if there's any batching or delay in cover entry creation, the timestamp could leak timing information about when the cover was *synthesized* vs when it's *sent*, creating a distinguishability vector.

**Fix:** Timestamp should be assigned at send time, not at construction time.

---

## [NIT] Issues

### [NIT] `dp.rs` — Magic Number `2` in Geometric Sampling Loop
Hardcoded `2` in the two-sided geometric sampling should be a named constant with a comment explaining it's the two-sidedness factor. It's correct but opaque to the next reader.

### [NIT] `cover.rs` — Function Name `cover_entry` Doesn't Signal It's Fake
`cover_entry()` could be `synthetic_entry()` or `dummy_entry()` to make the intent clearer in call sites. Minor, but clarity in security-sensitive code isn't minor.

---

## Overall Assessment

The mathematical core (discrete Laplace) is right. The architecture *wants* to be correct. But the two critical properties — **structural indistinguishability** and **correct DP granularity** — are both broken. Cover traffic that's distinguishable by PoW difficulty and length is not cover traffic. DP noise applied to the wrong granularity doesn't provide the claimed guarantee. The privacy claims in SPEC and THREAT-MODEL are currently ahead of what the code actually delivers.

This is fixable. The bones are there. But shipping this with current privacy claims would be misleading to anyone relying on it for actual anonymity.

**Score: 3/10** — Correct math, wrong deployment. Bones are there, the flesh is a liability.

---

## Counts

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 2 |
| MEDIUM | 3 |
| LOW | 2 |
| NIT | 2 |
| **TOTAL** | **12** |
