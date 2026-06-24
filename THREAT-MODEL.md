# Darqual — Threat Model & Security Status

**Status: RESEARCH PROTOTYPE. NOT AUDITED. Do NOT use to protect real people yet.**
This documents what Darqual defends, by which mechanism, and — just as important — what it
does NOT yet defend. Honesty is the security property that comes first.

---

## Adversary
- **Global passive observer** — can watch all network traffic.
- **Dishonest supermajority** of participants (within the anytrust-per-epoch assumption: ≥1
  honest committee member per epoch).
- **Device seizure** — adversary later obtains a participant's device/keys.
- **NOT yet defended against:** a global *active* adversary that also corrupts an entire
  epoch's committee, or that mounts end-to-end traffic-correlation at scale (the Anonymity
  Trilemma tax — see §"Known gaps").

---

## Security goals — defended / mechanism / status

| Goal | Mechanism (stage) | Status |
|---|---|---|
| **Content confidentiality** | x25519 ECDH + ChaCha20-Poly1305 lockbox (S0) | ✅ implemented + tested |
| **Sender anonymity (content)** | ephemeral-key sealed box — no sender identity in envelope (S0) | ✅ implemented + tested |
| **Recipient anonymity** | hold-all + trial-decrypt; dead-drop labels; cover traffic (S2/S3/S8) | ✅ mechanism implemented + tested |
| **Contact-graph privacy** | labels unlinkable to identity; per-epoch rotation (S3) | ✅ implemented + tested |
| **Integrity / tamper-evidence** | AEAD + blake3 Merkle blocks + hash-linked chain (S0/S2) | ✅ implemented + tested |
| **Forward-secret metadata** | keywheel hash-ratchet — past labels unrecoverable after seizure (S7) | ✅ implemented + tested |
| **Spam / Sybil resistance** | Proof-of-Work gate, difficulty-enforced (S4) | ✅ PoW tier; RLN = research |
| **Availability under churn** | Reed-Solomon erasure + DA sampling + repair (S5) | ✅ implemented + tested |
| **Bandwidth scaling** | prefix-bucket sharding (privacy↔bandwidth dial) (S5) | ✅ implemented + tested |
| **Serverless trust** | VRF-elected per-epoch committees (S6) | 🟡 election only; full anytrust protocol = research |
| **Traffic-analysis resistance** | cover traffic + DP dead-drop noise (S8) | 🟡 Vuvuzela-tier; Loopix mix = research |

---

## Per-goal argument (the honest reasoning)

**Content confidentiality / sender anonymity.** Each message is an anonymous sealed box: a fresh
ephemeral x25519 key per message, ECDH to the recipient's static key, blake3-KDF, ChaCha20-Poly1305.
The envelope carries `ephemeral_pub‖nonce‖ciphertext` and NO sender identity. Only the recipient's
static key opens it. *Residual:* no post-compromise security on the recipient's static key — a seized
recipient key opens all past lockboxes addressed to it (forward secrecy for content is future work;
the keywheel currently protects metadata, not content keys).

**Recipient anonymity / contact-graph privacy.** Two parties derive a per-epoch dead-drop label from
a shared secret (static-static ECDH, then keywheel-ratcheted). An observer sees labels but cannot
link them to identities or across epochs. Cover traffic + DP noise hide whether a given pair is
communicating. *Residual:* in the local/light-client model we hold the whole block (or fetch by
label); a *networked* fetch of a specific label leaks which label you wanted — true private retrieval
needs PIR (documented, not built). The light-client demo fetches a whole block (no per-message leak),
but at scale this is the PIR gap.

**Forward-secret metadata.** The keywheel ratchets one-way per epoch; seizing today's state cannot
recover yesterday's labels. *Residual:* does not protect content (see above) and assumes the ratchet
state itself wasn't exfiltrated earlier.

**Spam/Sybil.** PoW binds a nonce to (label‖envelope) and the ledger enforces a difficulty floor,
rate-limiting writes. *Residual:* PoW is a blunt instrument (cost to honest senders; ASIC asymmetry).
The intended upgrade — RLN (zk rate-limiting nullifiers) — gives anonymous per-epoch rate limits
without a payment graph, but is **not implemented** (needs zk-SNARK tooling).

**Availability / scaling.** Erasure coding + DA sampling means even a dishonest supermajority cannot
convince a light node that withheld data is available; buckets bound per-node bandwidth. *Residual:*
repair/committee orchestration under real churn is untested at scale.

**Serverless trust.** VRF sortition elects unbiasable, unpredictable per-epoch committees. *Residual:*
this is the **election mechanism only**. The full anytrust protocol (committee runs DPF-commit + PIR
notify + IBE PKG) depends on un-built primitives, and a **sybil-resistant participant set is an open
research problem** (stake? PoW? proof-of-storage?). The VRF here is a deterministic-ed25519
construction — production must use standard ECVRF (RFC 9381).

---

## Known gaps (do not pretend these are closed)
1. **No real anonymity network yet** — transport is TCP, not Tor/Arti. IP-level location privacy is
   NOT yet provided. (Arti onion-service swap = the next transport increment.)
2. **PIR not implemented** — networked retrieval by label leaks the label. Whole-block fetch avoids
   intra-block leak but doesn't scale; PIR is the real fix.
3. **Full RLN / DPF / IBE / Loopix-Sphinx** — all documented, none implemented (research-grade crypto).
4. **Content forward secrecy / post-compromise security** — not implemented (no Double Ratchet yet).
5. **Anonymity Trilemma** — strong-anonymity + low-latency + low-bandwidth can't coexist; Darqual is
   deliberately ASYNC. It is not a real-time messenger and does not claim global-active-adversary
   resistance.
6. **No external audit. No formal proofs. No constant-time guarantees reviewed.** The crypto uses
   vetted primitives (dalek, RustCrypto) but the *composition* is unaudited.

---

## Before this protects a real person, it needs (Stage 10, mostly NOT autonomously possible)
- [ ] External professional security audit
- [ ] Tor/Arti transport (kill the IP-leak)
- [ ] PIR retrieval (close the label-fetch leak)
- [ ] Content forward secrecy (Double Ratchet)
- [ ] Constant-time review of all secret-dependent paths
- [ ] Real closed beta with adversarial testing
- [x] Threat-model document (this file)
- [~] Property + fuzz-style parser tests (v0.10.0)

**Bottom line:** Darqual is a working, tested *spine* of a metadata-resistant messenger with every
tractable mechanism implemented and honestly labeled. It is a research prototype. Treat it as one.
