# Darqual — Threat Model & Security Status

**Status: RESEARCH PROTOTYPE. NOT AUDITED. Do NOT use to protect real people yet.**
This documents what Darqual defends, by which mechanism, and — just as important — what it
does NOT defend. Honesty is the security property that comes first.

> **MISSION A (locked S222):** Darqual is anonymity *research* — its target is **metadata-
> darkness against a global passive observer** (hide who-talks-to-whom from mass/dragnet
> observation). It is **NOT** a personal-safety tool for an individual a hostile state is
> hunting. See "Explicitly NOT for" below — that boundary is part of the security model, not a
> disclaimer footnote.

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

## Explicitly NOT for (Mission A boundary — out of scope by design)
These are not bugs or TODOs — they are *outside the mission*. Darqual targets *mass* metadata
observation, not the protection of a *marked individual*. No wire crypto fixes any of these:
- **Endpoint compromise** (Pegasus-grade spyware) — reads plaintext on-device, defeats all
  message crypto. For a *targeted* person this is the dominant risk; Darqual does not address it.
- **Targeted nation-state w/ physical access** — seizure, border search, raids.
- **Coercion / duress** — rubber-hose key extraction; no panic-wipe / duress-password /
  hidden-volume. Deniability stops a courtroom, not a regime that skips courtrooms.
- **Internet shutdowns** — Tor-only; dies when the net is cut. (Briar's BT/LAN mesh is that
  answer; Darqual deliberately does not chase it.)
- **Tool-usage detection** — vanilla Tor is fingerprintable; no pluggable transports. Where
  *using* a circumvention tool is itself the crime, encryption never gets to matter.
- **Safe first contact under danger** — no anonymous discovery; bootstrap needs a pre-existing
  secure channel.

> If a nation-state is hunting *you specifically*: Darqual is not your shield. Use Briar/Signal
> + opsec + physical safety, and get out with help.

---

## Security goals — defended / mechanism / status

| Goal | Mechanism (stage) | Status |
|---|---|---|
| **Content confidentiality** | x25519 ECDH + ChaCha20-Poly1305 lockbox (S0) | ✅ implemented + tested |
| **Sender anonymity (to network)** | ephemeral-key sealed box — no sender identity on the wire (S0) | ✅ implemented + tested |
| **Sender auth — deniable** | Noise IK static-static DH; sender id encrypted inside AEAD (S222) | ✅ implemented + tested |
| **Content forward secrecy + PCS** | Double Ratchet — per-msg keys + DH ratchet self-heal (S222) | ✅ implemented + tested |
| **Header / metadata privacy** | encrypted ratchet headers — no linkable pubkeys/counters (S222) | ✅ implemented + tested |
| **Recipient anonymity** | hold-all + trial-decrypt; dead-drop labels (S2/S3) | 🟡 Tier-1 wired; relay access timing remains |
| **Contact-graph privacy** | no direct peer dial in Tier-1; per-epoch labels | 🟡 single-relay MVP, not global-observer privacy |
| **Integrity / tamper-evidence** | AEAD + blake3 Merkle blocks + hash-linked chain (S0/S2) | ✅ implemented + tested |
| **Forward-secret metadata** | keywheel hash-ratchet — past labels unrecoverable after seizure (S7) | ✅ implemented + tested |
| **Spam / Sybil resistance** | Proof-of-Work gate, difficulty-enforced (S4) | ✅ PoW tier; RLN = research |
| **Availability under churn** | Reed-Solomon erasure + DA sampling + repair (S5) | ✅ implemented + tested |
| **Bandwidth scaling** | prefix-bucket sharding (privacy↔bandwidth dial) (S5) | ✅ implemented + tested |
| **Serverless trust** | VRF-elected per-epoch committees (S6) | 🟡 election only; full anytrust protocol = research |
| **Traffic-analysis resistance** | cover traffic + DP dead-drop noise (S8) | 🟡 Vuvuzela-tier; Loopix mix = research |

---

## Per-goal argument (the honest reasoning)

**Content confidentiality / sender anonymity.** Each first-contact message is a Noise-IK lockbox: a
fresh ephemeral x25519 key, ECDH to the recipient's static key, blake3-KDF, ChaCha20-Poly1305, with
the sender's static identity encrypted *inside* the AEAD (deniable auth — the recipient is convinced
it's you but cannot prove it to a third party, since the static-static DH is symmetric and forgeable
by the recipient). Ongoing messages run a **Double Ratchet**: per-message message keys (forward
secrecy — a seized key cannot decrypt earlier messages) + a DH ratchet that re-keys every round-trip
(post-compromise security / self-healing) + **encrypted headers** (no linkable pubkeys/counters on
the wire). *Residual (S222 closed the old one):* the prior "seized static key opens all past
lockboxes" gap is GONE for session traffic; a one-shot v1 lockbox (sessionless bootstrap) still has
only sender-side FS. Endpoint compromise still defeats everything (see "Explicitly NOT for").

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
1. **Tier-1 is wired; full anonymity is not** — branch `feat/tier1-dead-drop-mvp` adds a
   persistent single-relay async path over Tor. In dead-drop mode Alice and Bob dial only the relay,
   not each other, and Bob can retrieve after being offline. This closes the running app's direct
   peer-dial requirement for the MVP. **Residual:** one relay sees write/read timing; writes are not
   DPF-private, reads are not PIR-private, cover traffic is not mandatory, and no multi-relay
   anytrust committee runs the protocol. Who-talks-to-whom darkness against a global observer is
   therefore still aspirational. See `docs/TIER1-LIVE-VERIFICATION.md`.
2. **PIR not implemented** — networked retrieval by label leaks the label. Whole-block fetch avoids
   intra-block leak but doesn't scale; PIR is the real fix.
3. **Full RLN / DPF / IBE / Loopix-Sphinx** — all documented, none implemented (research-grade crypto).
4. **No anonymous discovery / safe bootstrap** — contact add needs a pre-existing secure channel
   (IBE add-friend is research). For the mission this is a gap, not a blocker.
5. **Anonymity Trilemma** — strong-anonymity + low-latency + low-bandwidth can't coexist; Darqual is
   deliberately ASYNC. It is not a real-time messenger and does not claim global-active-adversary
   resistance.
6. **Message-size leak — closed to coarse buckets.** Fixed-bucket padding (`padding.rs`, ladder
   `[256, 1k, 4k, 16k, 64k, 256k]`) wraps every lockbox + ratchet plaintext before AEAD; cover
   envelopes go through the same path. Residual: bucket-level inference (an observer learns which
   bucket, not the exact length).
7. **No external audit. No formal proofs. No constant-time guarantees reviewed.** The crypto uses
   vetted primitives (dalek, RustCrypto) but the *composition* is unaudited.

---

## Before this is a credible anonymity-research deployment (Mission A; mostly NOT autonomously possible)
- [ ] External professional security audit
- [x] Tor/Arti transport (S222 — IP-leak killed)
- [x] Content forward secrecy + PCS (Double Ratchet, S222)
- [x] **Wire a Tier-1 single-relay dead-drop path into the node** (2026-07-19 — async/offline,
      no direct Alice→Bob dial; see live verification). **Residual:** keywheel persistence, mandatory
      cover, DPF/PIR, and multi-relay anytrust are still open before the mission claim is credible.
- [ ] PIR retrieval (close the label-fetch leak)
- [ ] Constant-time review of all secret-dependent paths
- [ ] Real closed beta with adversarial testing
- [x] Threat-model document (this file)
- [x] Property + fuzz-style parser tests (v0.10.0)

> Note: "protects a real *targeted* person" is **out of mission** (see "Explicitly NOT for"). This
> list is about Darqual being a credible *anonymity system against mass observation*, not a
> bodyguard for a marked individual.

**Bottom line:** Darqual now has two running paths: strong content crypto over a direct Tor dial,
and a Tier-1 persistent async dead-drop path where both peers contact only one relay. The latter is
a real store-and-forward MVP, not the finished anonymity system: its single relay still exposes
access timing, and private writes/reads, mandatory cover, and multi-relay anytrust remain open. It
is an unaudited research prototype. Treat it as one.
