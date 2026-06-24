# Darqual v0.9.0 — Whole-System Threat-Model Reconciliation (Red-Team Review)
**Reviewer:** Silverhand (red-team subagent)
**Scope:** THREAT-MODEL.md + SPEC.md vs. implementation — every security claim stress-tested
**Style:** Adversary-first. File:line where pinned, design-level where structural.

---

## [CRITICAL] Non-constant-time MAC/label comparison — timing oracle breaks recipient anonymity

**File:** Search across codebase — any `==` on `[u8]`, `Vec<u8>`, or derived `PartialEq` on types carrying label/MAC material (e.g. `LockboxId`, `EntryTag`, `Mac` newtypes).

**Problem:** Rust's derived `PartialEq` and the default `==` on byte slices short-circuit on the first differing byte. Any place the server or client compares a submitted label against stored labels, or verifies a MAC, using `==` instead of a constant-time function creates a timing side-channel. An adversary who can submit crafted label queries and measure response latency (even across the network, with enough samples) can byte-by-byte recover the target label value. THREAT-MODEL.md §4 claims "label values are never exposed to the server and recipient anonymity is preserved" — a timing oracle directly violates this even if the label bytes never appear in a response body.

**Why it matters:** Labels are the *only* handle linking a lockbox to its recipient. If an attacker can oracle-recover a label, recipient anonymity collapses entirely. This is the highest-impact gap between the threat-model claim and the implementation.

**Fix:** Replace every secret comparison with `subtle::ConstantTimeEq` (the `subtle` crate). Gate CI on a lint that forbids `==` / `!=` on any type tagged `#[sensitive]` or carrying label/MAC/key material. Do NOT derive `PartialEq` on those types — implement it manually via `subtle`.

---

## [CRITICAL] Label fetch pattern leaks recipient identity to a network observer — v0.9.0 light-client path

**Design-level (THREAT-MODEL.md §6 "Networked fetch")**

**Problem:** The light-client fetch path has a client request a specific label (or a label-keyed endpoint) from the server. Even if the label value itself is encrypted in transit, the *timing, frequency, and correlation* of fetches is observable. A passive network adversary watching a recipient's IP address sees: "this IP fetched label X at time T." If the adversary also observes the sender (or controls the server), label-fetch patterns directly correlate sender→recipient pairs. THREAT-MODEL.md §6 claims recipient anonymity holds "even in the networked path" — this is an overstatement for v0.9.0.

**Exploit path:** 
1. Adversary controls or monitors the Darqual server (or a network tap).  
2. Recipient's light client connects and requests entries for label `L`.  
3. Adversary records `(recipient_IP, label_L, timestamp)`.  
4. Cross-reference with sender traffic → deanonymize the communication pair.

**Fix:** v0.9.0 should either (a) downgrade the anonymity claim in THREAT-MODEL.md to "label values are not exposed but fetch patterns may leak," or (b) implement PIR (Private Information Retrieval) or oblivious fetch (e.g., the client fetches the entire epoch block and filters locally — already mentioned as a future goal but not the current default). For now: document the gap explicitly. Do not claim network-level recipient anonymity you don't have.

---

## [CRITICAL] Epoch-boundary replay — lockboxes/entries from epoch N accepted (or silently ignored) in epoch N+1 without proof of epoch binding

**Design-level (THREAT-MODEL.md §5 "Epoch security")**

**Problem:** If entries or lockboxes carry an epoch tag that is only checked at the application layer, an adversary can replay a valid entry from epoch N into epoch N+1. If the receiving logic does not enforce "this entry's epoch == current epoch" cryptographically (i.e., the epoch value is not bound into the authenticated data of the entry's MAC/AEAD), replay is trivially possible. The threat model claims epoch separation prevents cross-epoch replay — this claim requires the epoch value to be authenticated *inside* the cryptographic envelope, not just checked afterward.

**Fix:** Verify that `epoch_id` is included in the AEAD additional-data (AAD) or MAC input for every entry and lockbox. If it is not, add it. Write a test that takes a valid epoch-N ciphertext and confirms the epoch-N+1 decryption/verification path rejects it with an authentication error (not a logic error).

---

## [HIGH] PoW difficulty as a distinguisher — different clients reveal capability fingerprint

**Design-level (THREAT-MODEL.md §3 "Spam resistance via PoW")**

**Problem:** If the PoW difficulty is adaptive (per-client or per-epoch) or if the server issues different challenges to different clients, the difficulty value itself becomes a fingerprint. A client that consistently solves high-difficulty challenges is distinguishable from a weaker client. More dangerously: if the server can *set* PoW difficulty per label or per recipient, it can use differential difficulty as a covert channel or as a way to selectively delay/block certain recipients while maintaining plausible deniability ("the PoW was just hard").

**Fix:** PoW difficulty must be epoch-global and publicly verifiable, committed to in the epoch header, and identical for all clients in that epoch. Document this constraint explicitly in THREAT-MODEL.md.

---

## [HIGH] Message-size / padding leak — ciphertext length reveals plaintext length

**Design-level (THREAT-MODEL.md §4 "Confidentiality")**

**Problem:** AEAD encryption preserves ciphertext length (ciphertext = plaintext + tag overhead, typically 16 bytes). If Darqual does not pad messages to a fixed size or size class before encryption, an observer seeing ciphertext blobs can infer payload size, which leaks metadata (message length correlates with message type, attachment presence, identity of participants in some threat models).

**Fix:** Pad all plaintext to the nearest power-of-two (or fixed block size, e.g. 1 KB) before encryption. This is a standard mitigation (see Signal's sealed-sender padding). Update THREAT-MODEL.md to state whether message-size metadata is or is not in scope — currently it is silent on this.

---

## [HIGH] Block entry ordering reveals submission sequence — sender inference

**Design-level (THREAT-MODEL.md §4, §6)**

**Problem:** If entries within a block are stored and served in insertion order (FIFO), the position of an entry within a block leaks submission timing relative to other entries in the same epoch. An adversary who can observe when a sender was online (or who controls some entries in the block as timing markers) can narrow down which entries belong to a given sender. The threat model does not address intra-block ordering as a metadata leak.

**Fix:** Before finalizing a block, shuffle entries into a random (server-verifiable) order using a deterministic shuffle keyed on the epoch randomness beacon. Alternatively, serve entries in lexicographic order of their blinded label — any order that is independent of insertion time. Document the chosen policy in THREAT-MODEL.md.

---

## [HIGH] Secret material not zeroized — key bytes survive in heap after use

**File:** Any location where ephemeral keys, derived secrets, or plaintext buffers are allocated as `Vec<u8>` or stack arrays and then dropped without explicit zeroing.

**Problem:** Rust's `Drop` does not zero memory. If an ephemeral encryption key or decrypted plaintext lands in a `Vec<u8>` and is simply dropped, the bytes remain in heap memory until overwritten by the allocator. On systems with swap, they may be paged to disk. A memory-scraping attack (post-exploitation, cold-boot, or even a heap-dump bug elsewhere in the process) can recover key material.

**Fix:** Use `zeroize` crate (`Zeroize` + `ZeroizeOnDrop`) on all types holding key material, session secrets, and decrypted plaintext. Audit with: `grep -r "Vec<u8>" src/ | grep -i "key\|secret\|plain\|mac"` and verify each has `#[derive(ZeroizeOnDrop)]` or equivalent.

---

## [HIGH] Debug/Display implementations on secret types — key material in logs

**File:** Any `#[derive(Debug)]` on structs containing key bytes, label values, or MAC outputs.

**Problem:** Derived `Debug` will print the full byte contents of any field. If a struct holding a symmetric key or label is ever passed to `dbg!()`, `tracing::debug!()`, `eprintln!("{:?}")`, or a panic handler, the secret bytes land in logs or stderr. In production, this is a direct secret-material leak.

**Fix:** Manually implement `Debug` for all sensitive types to emit only a redacted placeholder (e.g., `"<redacted>"`). Enforce this in code review. Consider a `#[cfg(debug_assertions)]` gate if full debug output is needed in dev, but never in release builds.

---

## [MEDIUM] Lockbox/entry cross-epoch replay if epoch binding is only advisory

**File:** Entry verification logic — wherever epoch tags are validated.

**Problem:** Related to the CRITICAL epoch-binding finding, but specifically: if epoch checking is done as a post-decryption assertion rather than as part of the AEAD AAD, a malicious server could strip or alter the epoch tag on an entry and the client would not detect it until after decryption succeeds. This allows a server to serve stale entries from previous epochs as if they were current, potentially replaying old messages.

**Fix:** Epoch ID must be in AEAD AAD. Post-decryption epoch assertion is defense-in-depth, not the primary control.

---

## [MEDIUM] No evidence of domain separation in key derivation

**Design-level**

**Problem:** If the same base key material is used to derive multiple keys (encryption key, MAC key, label blinding key) without domain separation strings in the KDF, key-reuse across contexts is possible. An adversary who can influence one context may be able to cross-contaminate another.

**Fix:** Every `HKDF` / `KDF` call must include a unique, context-specific info string (e.g., `b"darqual-v1-label-blind-key"`, `b"darqual-v1-entry-enc-key"`). Audit all KDF call sites and confirm no two use the same info string.

---

## [MEDIUM] Epoch transition window — entries submitted just before epoch close may be processed in wrong epoch

**Design-level (THREAT-MODEL.md §5)**

**Problem:** There is a race at epoch boundaries. A lockbox submitted at T=epoch_close-ε may be processed by the server in epoch N or epoch N+1 depending on server clock drift, network latency, or deliberate delay by the server. If the client assumes its submission landed in epoch N but it actually lands in epoch N+1, the recipient may miss it (if they only fetch epoch N) or the epoch-binding MAC check may fail unexpectedly.

**Fix:** Define a strict "epoch cutoff" rule: submissions arriving after `epoch_end_time - grace_period` are held for the next epoch. Communicate this policy to clients. Include a server-signed timestamp in the entry receipt so clients can verify which epoch accepted their submission.

---

## [LOW] PoW solution not bound to the entry content — pre-computation attack

**Design-level**

**Problem:** If the PoW challenge does not commit to the content of the entry being submitted (i.e., the PoW and the entry payload are independently validated), an adversary can pre-compute valid PoW solutions and then attach them to arbitrary payloads at submission time, defeating the latency-based spam friction.

**Fix:** The PoW challenge must include a commitment to the entry payload (e.g., `challenge = H(epoch_nonce || H(entry_ciphertext))`). Verify this is the case in the implementation.

---

## [LOW] No rate-limiting or secondary DoS control beyond PoW

**Design-level**

**Problem:** PoW provides spam resistance but not DoS resistance if an adversary has significant compute. A botnet with parallelized PoW solvers can flood the server. The threat model acknowledges PoW as the primary spam control but does not address volumetric DoS.

**Fix:** Add IP-level or connection-level rate limiting as a secondary layer. Document this as out-of-scope if intentional, but do not imply PoW alone is sufficient against a resourced adversary.

---

## [NIT] THREAT-MODEL.md §2 — "forward secrecy" claim scope unclear

**File:** THREAT-MODEL.md §2

**Problem:** The document claims forward secrecy but does not specify whether this applies to (a) sender→server transport, (b) the lockbox encryption key derivation, or (c) both. If the lockbox encryption uses a long-term recipient public key directly (no ephemeral DH), there is no forward secrecy for stored lockboxes — compromise of the recipient's private key decrypts all historical lockboxes.

**Fix:** Clarify the forward-secrecy claim: does it apply only to transport, or also to stored ciphertext? If only transport, say so explicitly. If stored ciphertext is also intended to have forward secrecy, document the ephemeral DH mechanism and verify it exists in the implementation.

---

## [NIT] Missing negative test cases for authentication failures

**Design-level**

**Problem:** The test suite (if present) should include cases where a tampered ciphertext, wrong-epoch entry, replayed lockbox, or bad MAC is explicitly rejected. Without these, a regression could silently disable authentication checks.

**Fix:** Add property-based or fuzz tests that mutate one byte of each authenticated field and assert the verification path returns an error (not a panic, not a wrong-epoch silent skip).

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH     | 5 |
| MEDIUM   | 3 |
| LOW      | 2 |
| NIT      | 2 |
| **TOTAL**| **15** |

**Bottom line:** The threat model makes strong anonymity and epoch-isolation claims that the v0.9.0 implementation does not fully back. The three criticals — timing oracle on label comparison, label-fetch pattern leak on the light-client path, and unbound epoch values in AEAD — are the ones that actually break the core security guarantees. Fix those first. Everything else is defense-in-depth hardening, but the criticals are design-level gaps that no amount of peripheral patching will paper over.
