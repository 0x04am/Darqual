//! Differential-privacy noise on dead-drop access counts — Vuvuzela mechanism.
//!
//! # Background
//!
//! In Vuvuzela (Van Den Hooff et al., 2015) the core privacy guarantee is:
//! a global adversary observing which dead-drop slots are accessed cannot
//! determine whether two parties are communicating, provided enough noise is
//! added to access counts.  The mechanism is **ε-differential privacy** on
//! the per-slot access-count histogram.
//!
//! ## Discrete Laplace construction
//!
//! The **discrete Laplace** (two-sided geometric) distribution is the canonical
//! DP mechanism for integer-valued queries (Ghosh et al., 2012).
//!
//! For sensitivity Δ = 1 and privacy budget ε, sample:
//! ```text
//! p = 1 - exp(-ε)
//! X ~ Geometric(p)   (# of failures before first success, support {0,1,2,...})
//! Y ~ Geometric(p)   (independent copy)
//! noise = X - Y      (two-sided; mean 0, tails decay as exp(-ε·|k|))
//! ```
//!
//! This is equivalent to sampling from the discrete Laplace distribution
//! `DLap(1/ε)` directly.  The construction is described in:
//!   * Ghosh, A., Roughgarden, T., Sundararajan, M. — "Universally Utility-
//!     Maximizing Privacy Mechanisms" (STOC 2009 / JACM 2012).
//!   * Canonne, C. L., Kamath, G., Steinke, T. — "The Discrete Gaussian for
//!     Differential Privacy" (NeurIPS 2020), §2 background.
//!
//! ## Vuvuzela budget note
//!
//! Each epoch consumes ε privacy budget.  Over T epochs the *total* budget
//! (by basic composition) is T·ε.  Use advanced composition (Dwork et al.)
//! or Rényi DP (Mironov) to get tighter bounds.  Budget management across
//! epochs is the caller's responsibility; this module exposes the per-call
//! primitive.
//!
//! ## What is NOT built here
//!
//! **PIR (Private Information Retrieval)** on the dead-drop *read* path is the
//! complementary defence: a reader fetches their slot without the server
//! learning which slot they read.  Talek-style PIR (Chan et al., 2020) or
//! DPF-based (Boyle et al.) approaches are in ROADMAP Stage 3 and require
//! significant infrastructure (multi-server XOR-PIR or homomorphic ops).
//! DP noise on write-side counts is the tractable Stage 8 increment.

use rand::Rng;

use crate::cover::cover_entry;
use darqual_ledger::LedgerEntry;

/// Sample from the discrete Laplace (two-sided geometric) distribution.
///
/// Privacy parameter `epsilon > 0`.  Returns a signed integer noise value
/// with mean 0 and tails decaying as `exp(-epsilon * |k|)`.
///
/// # Construction
/// ```text
/// p     = 1 - exp(-epsilon)
/// X, Y  ~ Geometric(p)  (independent)
/// noise = X - Y
/// ```
/// Geometric(p) here is the number-of-failures-before-first-success variant
/// (support {0, 1, 2, …}) sampled via the inverse-CDF:
/// `k = floor(log(U) / log(1-p))` for U ~ Uniform(0,1), equivalently
/// `k = floor(log(U) / log(q))` where `q = 1-p = exp(-epsilon)`.
///
/// # Panics
/// Panics if `epsilon <= 0` (invalid DP parameter).
pub fn discrete_laplace(epsilon: f64, rng: &mut impl Rng) -> i64 {
    assert!(epsilon > 0.0, "epsilon must be > 0 for DP noise");

    // q = exp(-epsilon); p = 1 - q
    let q = (-epsilon).exp(); // in (0, 1)

    // Sample Geometric(p) via inverse CDF.
    // Geometric(p): P(X=k) = (1-p)^k * p = q^k * (1-q)
    // CDF inversion: k = floor(log(U) / log(q)), U ~ Uniform(0,1)
    // We need U > 0; rand's gen_range(0.0..1.0) is [0,1) so add eps guard.
    let sample_geo = |rng: &mut dyn rand::RngCore| -> i64 {
        let u: f64 = {
            let mut v = rng.gen::<f64>();
            // Guard against exactly 0 (log(0) = -inf)
            while v == 0.0 {
                v = rng.gen::<f64>();
            }
            v
        };
        // k = floor(ln(u) / ln(q))
        // ln(q) = -epsilon < 0; ln(u) <= 0 for u in (0,1] => k >= 0
        (u.ln() / q.ln()).floor() as i64
    };

    let x = sample_geo(rng);
    let y = sample_geo(rng);
    x - y
}

/// Return the number of extra cover entries to inject this epoch for DP noise.
///
/// Adds `discrete_laplace(epsilon, rng)` to a small base count, clamped to
/// `>= 0`.  The base count (1) ensures at least some cover is injected even
/// at low noise, which helps mask whether any real activity occurred.
///
/// In Vuvuzela terms this is the per-slot injection count:  for each monitored
/// dead-drop slot the server (or committee) injects this many fake accesses so
/// the histogram is DP-noised.
pub fn noisy_cover_count(epsilon: f64, rng: &mut impl Rng) -> usize {
    let base: i64 = 1;
    let noise = discrete_laplace(epsilon, rng);
    let raw = base + noise;
    if raw < 0 {
        0
    } else {
        raw as usize
    }
}

/// Inject differentially-private cover entries into `entries`.
///
/// Appends `noisy_cover_count(epsilon, rng)` cover entries drawn from
/// `cover_entry`.  The caller should shuffle the combined slice before
/// publishing to avoid the cover entries being identifiable by position.
///
/// `epsilon` is the per-epoch DP budget for dead-drop access-count noise.
/// Smaller ε → more noise → stronger privacy, but higher bandwidth overhead.
/// Vuvuzela uses ε ≈ 1.0–2.0 in practice.
pub fn add_dp_cover(entries: &mut Vec<LedgerEntry>, epsilon: f64, rng: &mut impl Rng) {
    let count = noisy_cover_count(epsilon, rng);
    for _ in 0..count {
        entries.push(cover_entry(rng));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cover::COVER_ENVELOPE_LEN;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn seeded_rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(0xCAFE_BABE)
    }

    // ── discrete_laplace: sign distribution ──────────────────────────────

    /// Over many samples the noise should be both positive and negative,
    /// and have mean close to 0.
    #[test]
    fn discrete_laplace_both_signs_and_mean_zero() {
        let mut rng = seeded_rng();
        let n = 10_000usize;
        let epsilon = 1.0_f64;

        let mut positives = 0usize;
        let mut negatives = 0usize;
        let mut sum: i64 = 0;

        for _ in 0..n {
            let v = discrete_laplace(epsilon, &mut rng);
            sum += v;
            if v > 0 {
                positives += 1;
            } else if v < 0 {
                negatives += 1;
            }
        }

        assert!(
            positives > n / 5,
            "expected many positive samples, got {}/{}",
            positives,
            n
        );
        assert!(
            negatives > n / 5,
            "expected many negative samples, got {}/{}",
            negatives,
            n
        );

        // Mean should be within ±0.1 of 0 (very loose)
        let mean = sum as f64 / n as f64;
        assert!(
            mean.abs() < 0.1,
            "mean discrete_laplace should be ≈ 0, got {}",
            mean
        );
    }

    /// Larger epsilon → tighter distribution (smaller |noise| on average).
    #[test]
    fn discrete_laplace_tighter_with_larger_epsilon() {
        let mut rng = seeded_rng();
        let n = 5_000usize;

        let avg_abs = |eps: f64, rng: &mut ChaCha8Rng| -> f64 {
            (0..n)
                .map(|_| discrete_laplace(eps, rng).unsigned_abs() as f64)
                .sum::<f64>()
                / n as f64
        };

        let small_eps = avg_abs(0.1, &mut rng); // wide tails
        let large_eps = avg_abs(5.0, &mut rng); // tight tails

        assert!(
            large_eps < small_eps,
            "larger epsilon should give smaller mean |noise|: small_eps_avg={}, large_eps_avg={}",
            small_eps,
            large_eps
        );
    }

    // ── noisy_cover_count is always >= 0 ─────────────────────────────────

    #[test]
    fn noisy_cover_count_non_negative() {
        let mut rng = seeded_rng();
        for _ in 0..1_000 {
            let c = noisy_cover_count(1.0, &mut rng);
            assert!(c < usize::MAX, "should be a valid usize (non-negative)");
        }
    }

    // ── add_dp_cover increases entry count ───────────────────────────────

    /// add_dp_cover should add >= 0 entries; over many calls the count
    /// almost always increases (base = 1 means at least 1 on average).
    #[test]
    fn add_dp_cover_increases_count() {
        let mut rng = seeded_rng();
        let mut any_increased = false;

        for _ in 0..50 {
            let mut entries: Vec<LedgerEntry> = vec![];
            let before = entries.len();
            add_dp_cover(&mut entries, 1.0, &mut rng);
            if entries.len() > before {
                any_increased = true;
            }
            // Count is always non-negative (can't go below 0 entries)
            assert!(
                entries.len() >= before,
                "add_dp_cover must not remove entries"
            );
        }

        assert!(
            any_increased,
            "add_dp_cover should increase count in at least one trial"
        );
    }

    /// Check the added entries have the canonical cover envelope size.
    #[test]
    fn add_dp_cover_entries_have_canonical_size() {
        let mut rng = seeded_rng();
        let mut entries: Vec<LedgerEntry> = vec![];
        // Force at least a few entries by calling multiple times
        for _ in 0..10 {
            add_dp_cover(&mut entries, 2.0, &mut rng);
        }
        // Every injected entry should have canonical cover envelope length
        for e in &entries {
            assert_eq!(
                e.envelope.len(),
                COVER_ENVELOPE_LEN,
                "DP cover entry envelope length must be canonical ({})",
                COVER_ENVELOPE_LEN
            );
        }
    }
}
