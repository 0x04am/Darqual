# Darqual — 12-Reviewer Audit: Triaged Summary

12 parallel reviewers audited ~5,500 LOC (S218). Raw reports in `reviews/01..12-*.md`.
**This summary is the TRIAGE — reviewer severity labels were verified against actual code,
because reviewers heavily over-flag.** ~25 findings were tagged CRITICAL across the 12;
spot-verification shows roughly HALF are false, intentional-by-spec, or overstated.

## ✅ CONFIRMED GENUINE — fix these (verified against code)
1. **Flaky PoW property test** — `core/tests/property_tests.rs:123` `prop_pow_tampered_envelope_fails`.
   The property "tampering the envelope invalidates PoW" is FALSE at low difficulty (a tampered
   hash still passes PoW w.p. 2^-difficulty; at 1 bit = 50%). **The gate (verify.sh) is therefore
   non-deterministic** — green by luck. Reproduced via `--test-threads=1`. FIX: raise difficulty in
   that test to ~16 bits (negligible false-pass) or restate the property. **(test integrity — do first)**
2. **`verify_ed` uses non-strict `.verify()`** — `core/identity.rs:148`. ed25519 signature
   malleability / small-order-R not rejected. For the VRF (committee election) this weakens the
   uniqueness/unbiasability claim (an adversary could grind a malleable variant). FIX: `verify_strict`.
3. **`ContactCard::verify()` does not bind `x_pub`** — `core/contact.rs`. verify() only checks
   `address == hash(ed_pub)`; the ENCRYPTION key `x_pub` is unauthenticated. An attacker can present
   a card with the victim's ed_pub/address but the attacker's x_pub → conversations/labels/encryption
   use the attacker's key (identity-substitution / MITM). FIX: bind x_pub into the address
   (`address = hash(ed_pub || x_pub)`) or sign x_pub with the ed key and verify.

## ❌ DEBUNKED — reviewer was wrong (verified)
- "Merkle has no leaf/node domain separation" (04) — FALSE. Code does `0x00`-leaf / `0x01`-node.
- "DA sample() checks presence only" (06) — FALSE. It verifies `shard_hash == commitment` per sample.
- "EMPTY_ROOT is SHA-256 not BLAKE3 = CRITICAL" (10) — intentional sentinel per SPEC; NIT at most.

## 📋 KNOWN LIMITATIONS (already in THREAT-MODEL.md — not new)
- Cover PoW difficulty 0 = distinguishable from real entries (09). Documented; real cover must carry
  real-difficulty PoW. Real, but a known design gap, not a regression.
- DP noise per-block not per-label (09); cover envelope length leaks structure (09). Documented as
  "Vuvuzela-tier, not airtight."

## ⏳ STILL TO TRIAGE (real-vs-overstated mix — need per-claim code verification)
- erasure reconstruct length validation (06); ledger post-prune anchor trust + validate_chain on
  empty window (05); odd-leaf Merkle duplication forgery (04); write_frame u32 truncation (10,
  capped at 16MB so low risk); the HIGH/MEDIUM findings across all 12. Many are legit hardening;
  some are overstated. Each needs the same verify-against-code pass before action.

## Honest takeaway
The fan-out WORKED — it found 3 genuine issues (one of which, the flaky test, undermines the gate
itself) plus a pile of real hardening items. But the headline "25 CRITICALs" is reviewer inflation;
the real critical count after verification is closer to **2-3**, none of them catastrophic, all
fixable. The crypto *primitives* (dalek/RustCrypto) are used correctly; the gaps are in
*composition* (x_pub binding, strict verify) and *test rigor* (flaky prop test) — exactly where a
research prototype's weak points live.

## Recommended order
1. Fix the flaky test (restore gate determinism).
2. `verify_strict` + x_pub binding (the two real composition bugs).
3. Re-run verify.sh; commit.
4. Then triage the HIGH/MEDIUM backlog claim-by-claim.
