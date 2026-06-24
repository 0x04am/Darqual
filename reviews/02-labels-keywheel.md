# Darqual — Code Review 02: Addressing / Forward-Secrecy Crypto
**Reviewer:** Shady (subagent)  
**Scope:** `crates/darqual-core/src/label.rs`, `conversation.rs`, `keywheel.rs`  
**Spec ref:** `SPEC.md` §4 "dead-drop label", §2 "forward secrecy"; `THREAT-MODEL.md` §"forward-secret metadata"  
**Read:** label.rs (20 LOC), conversation.rs (77 LOC), keywheel.rs (288 LOC), supporting: identity.rs, lockbox.rs, pow.rs, contact.rs  

---

## Executive Summary

The spine is good. The crypto primitives chosen are solid (BLAKE3 keyed-hash, x25519-dalek, ChaCha20-Poly1305), the domain-separation thinking is present, and the forward-secrecy machinery actually works for its stated purpose. The tests are thorough and honest about what they're testing. None of this should be taken as minimizing the findings — in a nation-state threat model, the issues below are exactly the kind of thing that gets journalists killed, not just pwned.

**Overall verdict: 6/10.** The 4 missing points aren't style nits. Two of them are structural cryptographic weaknesses that need to be fixed before this code protects any real person, even in a prototype. The rest are legitimately dangerous in production. Read every finding.

---

## 🔥 What's Actually Good (yes, Shady gives credit)

- **Domain separation exists and is consistent.** `RATCHET_DOMAIN`, `LABEL_DOMAIN`, `SEED_CONTEXT`, `LABEL_DOMAIN` (conversation), `KDF_CONTEXT` (lockbox), `POW_DOMAIN` — all distinct, all versioned with `-v1`. This is the single most important thing you can do in a multi-use hash construction and someone actually did it. Respect.
- **Debug redaction** on `Keywheel` and `Conversation` is present and correct. `state` is never printed; only epoch counter leaks. Same for `Identity`. A dev accidentally `println!("{:?}", wheel)` won't burn the secret.
- **Keywheel API correctly refuses backward traversal.** `label_at()` returning `None` for `target_epoch < self.epoch` is the right API contract for forward secrecy. The API makes the wrong thing hard to do, not just forbidden by convention.
- **`label_at()` is read-only (non-mutating).** The "look ahead without consuming" semantics are correct and tested. Not obvious to get right, and they did.
- **Tests are honest.** `keywheel_cannot_go_backward`, `forward_secrecy_state_is_one_way`, `keywheel_different_conversations_differ` — these are real tests of real security properties, not just "does it compile" smoke tests. The `forward_secrecy_state_is_one_way` test in particular is doing actual reasoning.
- **THREAT-MODEL.md is refreshingly honest.** "Do NOT use to protect real people yet." That's the most important security property a prototype can have.

---

## 💀 Critical & High Findings

---

### [CRITICAL] `conversation.rs:36-40` — Static-Static X25519 ECDH Is Unauthenticated: Identity-Substitution Attack Is Trivially Possible

**File:** `crates/darqual-core/src/conversation.rs`, lines 35–40

**Code:**
```rust
pub fn new(me: &Identity, them: &ContactCard) -> Self {
    let their_x_pub = X25519PublicKey::from(them.x_pub);
    let shared = me.x_secret.diffie_hellman(&their_x_pub);
    Conversation {
        shared: *shared.as_bytes(),
    }
}
```

**Problem — the math:**  
Static-static X25519 is symmetric by the DH property: `DH(alice_sk, bob_pk) == DH(bob_sk, alice_pk)`. That part is correct. But *no binding to identity happens here*. The `ContactCard` carries both `ed_pub` (signing key) and `x_pub` (encryption key), but the conversation only uses `x_pub`. There is **zero proof that the owner of `x_pub` is the same entity that signed the `ed_pub`** in the card.

Concrete attack: Mallory generates a fresh X25519 keypair `m_sk / m_pk`. She creates a `ContactCard` with any `ed_pub` she wants (say, Alice's real `ed_pub` from a public directory) and her own `m_pk` as `x_pub`. `ContactCard::verify()` checks `address == BLAKE3(ed_pub)[..20]`, which will pass because she used a real `ed_pub`. The address looks like Alice's. But `Conversation::new(bob, mallory_card)` derives `DH(bob_sk, m_pk)`. Mallory also computes `DH(m_sk, bob_pk)`. They get the same shared secret. Mallory can now compute all of Bob's dead-drop labels for Alice and read all his metadata — or substitute herself in any dead-drop.

**Why this is CRITICAL:**  
The threat model says "Contact-graph privacy: who-talks-to-whom is hidden." This attack breaks that entirely. The address looks right. The card verifies. The ECDH gives a shared secret. Everything looks normal. Nothing tells you the card was tampered with.

**Root cause:**  
`ContactCard::verify()` only checks that `address` is consistent with `ed_pub`. It does NOT verify that `x_pub` belongs to the same entity as `ed_pub`. There's no cross-binding signature: no `ed_sign(x_pub)` anywhere in the card.

**Fix:**  
The `ContactCard` needs an attestation: `ed_sign(ed_pub || x_pub)` included in the card. During `Conversation::new`, verify this signature before computing the ECDH. A weaker fix: bind both keys into the address (BLAKE3(ed_pub || x_pub)[..20]), which at least makes a tampered x_pub produce a visibly wrong address. But the signature approach is the correct one — it gives you a proof-of-possession of both keys.

```rust
// What ContactCard needs:
pub struct ContactCard {
    pub address: DarqualAddress,
    pub ed_pub: [u8; 32],
    pub x_pub:  [u8; 32],
    pub binding_sig: [u8; 64],  // ed_sign(ed_pub || x_pub)
}
impl ContactCard {
    pub fn verify_binding(&self) -> bool {
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&self.ed_pub);
        msg[32..].copy_from_slice(&self.x_pub);
        verify_ed(&self.ed_pub, &msg, &self.binding_sig)
    }
}
```

---

### [CRITICAL] `keywheel.rs:67-72` — Ratchet Domain Is Pre-pended, Not Keyed: BLAKE3 Length-Extension Is Not The Problem, But The Construction Is Weaker Than It Looks

**File:** `crates/darqual-core/src/keywheel.rs`, lines 67–72

**Code:**
```rust
fn ratchet_state(state: [u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(RATCHET_DOMAIN.len() + 32);
    input.extend_from_slice(RATCHET_DOMAIN);
    input.extend_from_slice(&state);
    *blake3::hash(&input).as_bytes()
}
```

**Problem:**  
This uses `blake3::hash()` — the *unkeyed* hash — with the domain prepended. This is inconsistent with every other hash usage in this codebase (`blake3::keyed_hash` for labels, `blake3::derive_key` for lockbox KDF, `blake3::keyed_hash` for seed). For the ratchet, specifically, you want the state to be the key, not the data, for the same reason `derive_label` does it right:

```rust
// derive_label (CORRECT): state is the KEY
fn derive_label(state: &[u8; 32]) -> Label {
    let hash = blake3::keyed_hash(state, LABEL_DOMAIN); // key=state, data=domain
}

// ratchet_state (INCONSISTENT): state is the DATA
fn ratchet_state(state: [u8; 32]) -> [u8; 32] {
    blake3::hash(RATCHET_DOMAIN ++ state) // state is data, no key
}
```

Why does this matter? The comment in `derive_label` explains the design intent: "state as the key (state is already 32 bytes — perfect)." But `ratchet_state` breaks that pattern. With `blake3::hash(domain || state)`, the domain is only a prefix-based separator. If a future developer adds another hash call with the same pattern, prefix collisions become possible (e.g., a domain that is a prefix of another domain + state bytes). With `blake3::keyed_hash(state, RATCHET_DOMAIN)`, the 32-byte key is cryptographically mixed in, domain injection is structurally impossible, and the construction is tighter.

**Additionally:** BLAKE3 does not have length-extension (it's a Merkle tree construction), so the prepend pattern isn't classically exploitable here the way SHA-2 would be. But the *inconsistency* itself is a finding — the codebase has a deliberate keyed-hash pattern everywhere else and broke it here for no apparent reason.

**Fix:**
```rust
fn ratchet_state(state: [u8; 32]) -> [u8; 32] {
    // Consistent with derive_label: state is the key, domain is the data.
    *blake3::keyed_hash(&state, RATCHET_DOMAIN).as_bytes()
}
```

This is strictly more correct and consistent. Make it.

---

### [HIGH] `conversation.rs:47-57` — Static Label PRF and Keywheel PRF Use Different Domain Strings for Conceptually the Same Output: Cross-Stage Label Aliasing Risk

**File:** `crates/darqual-core/src/conversation.rs`, line 14 vs. `keywheel.rs`, line 37

**Code:**
```rust
// conversation.rs:14
const LABEL_DOMAIN: &[u8] = b"darqual-deaddrop-v1";

// keywheel.rs:37
const LABEL_DOMAIN: &[u8] = b"darqual-keywheel-label-v1";
```

These are two different constants with the same Rust name (`LABEL_DOMAIN`) in two different modules, both producing `Label` outputs. This is fine so far — they're in different scopes, the domains differ, and the outputs are distinct.

**The actual problem:** A consumer of the API can call `conversation.label(epoch)` and `conversation.keywheel(epoch).label()` for the same epoch and get *two completely different labels for the same conversation and epoch*. There is no error, no warning, no reconciliation. The code comment in keywheel.rs says the static PRF is "Stage 3" and the keywheel is "Stage 7 / Alpenhorn" — but both are currently exported and live in the same codebase on `main`.

This means:
1. If one part of the code uses `conversation.label(epoch)` for dead-drop routing and another uses `keywheel.label()`, they'll never find each other's messages. Silently.
2. An adversary who can make one party use `conversation.label()` while the other uses `keywheel.label()` has just created a denial-of-service on the conversation.
3. The SPEC says Stage 3 replaces the static PRF with keywheel rotation — but there's no deprecation, no migration path, no runtime choice mechanism. Both coexist, producing different labels.

**Fix:**  
One of two paths:
- **Path A (clean):** Remove `conversation.label()` entirely. The keywheel IS the label derivation now. Have `Conversation::keywheel()` be the only way to get labels.
- **Path B (migration-safe):** Mark `conversation.label()` as `#[deprecated]` with a note directing to `keywheel.label()`. Add a test that explicitly asserts the two outputs differ (so readers understand they are NOT interchangeable). Document which one the network protocol uses at any given version.

---

### [HIGH] `keywheel.rs:91-98` — Keywheel Seed Is The Raw Shared Secret: The Keywheel Is Only As Secure As ECDH Output Entropy

**File:** `crates/darqual-core/src/keywheel.rs`, lines 91–98

**Code:**
```rust
pub(crate) fn from_seed(seed: &[u8; 32], start_epoch: u64) -> Self {
    let state = *blake3::keyed_hash(seed, SEED_CONTEXT.as_bytes()).as_bytes();
    Keywheel { epoch: start_epoch, state }
}
```

And the call site in `conversation.rs:74-76`:
```rust
pub fn keywheel(&self, start_epoch: u64) -> Keywheel {
    Keywheel::from_seed(&self.shared, start_epoch)
}
```

`self.shared` is the raw output of `me.x_secret.diffie_hellman(&their_x_pub)` — the X25519 shared secret bytes.

**Problem:**  
X25519 output has low-order bits that are always zero (cofactor clearing). The `x25519-dalek` crate returns 32 bytes but those bytes do not have full 256-bit entropy — specifically, the 3 low-order bits are clamped during scalar multiplication. This isn't a catastrophic weakness, but it means the keywheel seed has at most 253 bits of entropy rather than 256. More importantly, it means that for a **static-static ECDH** (as opposed to ephemeral), the same `self.shared` is derived *every time* you call `Conversation::new(alice, bob_card)`. The keywheel is deterministically seeded from a value that never changes unless Alice or Bob changes their key. This is by design — both sides need the same seed — but it means:

- If the shared secret is compromised (e.g., Alice's `x_secret` is seized), ALL historical keywheel states can be re-derived by rerunning `Keywheel::from_seed(stolen_shared, 0)` and advancing forward. The "forward secrecy" of the ratchet protects state you've already advanced past (the API doesn't give backward access), but an attacker who seized `x_secret` doesn't need backward access — they recompute from the start.

This is acknowledged in the THREAT-MODEL: *"assumes the ratchet state itself wasn't exfiltrated earlier."* Fine. But the threat model does NOT acknowledge that **seizure of x_secret lets you recompute the entire ratchet from epoch 0 onwards**. The wording implies only exfiltration of the ratchet state matters. The truth is: the raw static key is sufficient.

**Fix / documentation:**  
This is partially a documentation bug and partially a design constraint. The fix for the documentation is easy: update THREAT-MODEL.md to explicitly say "Seizure of your x25519 static secret (`x_secret`) allows an adversary to recompute all keywheel labels from epoch 0 for all conversations — not just from the point of seizure." The design fix is harder: it requires a Double Ratchet or periodic fresh ephemeral key exchange to rotate the seed. Mark this as a known gap, explicitly.

---

### [HIGH] `keywheel.rs:75-82` — `derive_label` Uses `blake3::keyed_hash(state, LABEL_DOMAIN)` But LABEL_DOMAIN Is 24 Bytes, Not 32: The Key and Data Arguments Are Swapped From Their Intuitive Roles

**File:** `crates/darqual-core/src/keywheel.rs`, lines 75–82

**Code:**
```rust
fn derive_label(state: &[u8; 32]) -> Label {
    // LABEL_DOMAIN must fit in 32 bytes for blake3::keyed_hash key; we use it
    // as the data and state as the key (state is already 32 bytes — perfect).
    let hash = blake3::keyed_hash(state, LABEL_DOMAIN);
```

The comment says "we use [LABEL_DOMAIN] as the data and state as the key." This is intentional and the comment explains the why. The API call is `keyed_hash(key: &[u8; 32], data: &[u8])`.

**BUT** — read the comment more carefully: *"LABEL_DOMAIN must fit in 32 bytes for blake3::keyed_hash key"*. This is wrong reasoning. `blake3::keyed_hash` takes the *key* as a `&[u8; 32]` (fixed size). The *data* is variadic `&[u8]`. `LABEL_DOMAIN = b"darqual-keywheel-label-v1"` is 24 bytes — it does NOT fit in 32 bytes as a key without zero-padding. The comment is confused about which argument would need to be 32 bytes and which is variadic.

The call `blake3::keyed_hash(state, LABEL_DOMAIN)` is:
- key = `state` (32 bytes ✅)
- data = `LABEL_DOMAIN` (24 bytes ✅ — variadic, fine)

So the actual call is **correct**. But the comment is **misleading**: it implies the reason for the role assignment is that LABEL_DOMAIN needs to fit in 32 bytes, when the actual reason is that `blake3::keyed_hash` requires a 32-byte key and `state` is already 32 bytes. A developer reading this comment could conclude the roles could be swapped if LABEL_DOMAIN happened to be 32 bytes — and that would be wrong, because then you'd have a constant key and variable data.

**The real issue the comment misses:** If the roles were swapped (LABEL_DOMAIN as key, state as data), you'd have a constant key with varying data. That would mean the "keyed" hash provides no extra security over an unkeyed hash with LABEL_DOMAIN prepended — the secrecy of `state` wouldn't be leveraged. With state-as-key, the PRF output is secret even if LABEL_DOMAIN is known (which it always is — it's a constant). This is the correct design.

**Fix:**  
Rewrite the comment to be accurate:
```rust
fn derive_label(state: &[u8; 32]) -> Label {
    // state is the PRF key (32 bytes, secret); LABEL_DOMAIN is the public input.
    // Using state as the key means the output is secret even if LABEL_DOMAIN
    // is public knowledge. DO NOT swap: a constant key would make this an
    // unkeyed hash in all but name.
    let hash = blake3::keyed_hash(state, LABEL_DOMAIN);
```

---

## 🤡 Medium Findings

---

### [MEDIUM] `conversation.rs:47-57` — `label()` Truncates to 16 Bytes After a 32-Byte Hash: No Collision Analysis Documented

**File:** `crates/darqual-core/src/conversation.rs`, lines 47–57

```rust
pub fn label(&self, epoch: u64) -> Label {
    let hash = blake3::keyed_hash(&self.shared, &data);
    let bytes = hash.as_bytes();
    let mut label = [0u8; 16];
    label.copy_from_slice(&bytes[..16]);
    Label(label)
}
```

Same truncation in `keywheel.rs:79-81`. 16 bytes = 128 bits. For a dead-drop label in an anonymous system, collisions matter differently than for a hash function: if two conversations ever land on the same label for the same epoch, both parties download each other's ciphertext during trial-decrypt. That's not catastrophic (they can't decrypt it), but it leaks: "these two conversations were active in the same epoch," which in a metadata-dark system is meaningful.

The birthday-bound collision probability for N conversations over E epochs with 128-bit labels is approximately `N²E / 2^128`. For a small network (N < 10^6, E < 10^5) this is negligible (~10^-26). But:

1. The spec mentions "global observer" as the adversary. A global observer who can force a large number of simultaneous conversations (Sybil) increases N.
2. There's no documented threat analysis justifying 128 bits. The choice looks like it came from "16 bytes is a round number."
3. The SPEC says "Dead-drop label: per-epoch PRF(shared_secret, epoch) → the slot a lockbox lives in." It doesn't specify label width. The implementation chose 128 bits with no documented rationale.

**Fix:**  
Either (a) document the collision analysis explicitly — why 128 bits is sufficient given the expected network size — or (b) increase to 256 bits (use the full hash output). The full BLAKE3 output is 32 bytes, there's no cost to using it, and the `Label` type would just become `[u8; 32]`. Carrying the extra 16 bytes is free compared to the privacy gain.

---

### [MEDIUM] `keywheel.rs:115-127` — `label_at(target)` Does O(target - self.epoch) Work With No Bound: DoS on Desync'd State

**File:** `crates/darqual-core/src/keywheel.rs`, lines 115–127

```rust
pub fn label_at(&self, target_epoch: u64) -> Option<Label> {
    if target_epoch < self.epoch {
        return None;
    }
    let mut state = self.state;
    let mut epoch = self.epoch;
    while epoch < target_epoch {
        state = ratchet_state(state);
        epoch += 1;
    }
    Some(derive_label(&state))
}
```

If a peer's keywheel is at epoch 5 and they call `label_at(5_000_000)`, that's 4,999,995 BLAKE3 hash operations in a tight loop on the caller's thread. No bound. No error. No timeout.

In a protocol where epoch numbers come from a ledger that peers sync with, this might seem harmless — you shouldn't be millions of epochs behind. But consider:

1. A peer that was offline for a long period resync'd from the ledger. They now have the current epoch (say, 50,000) but their local keywheel is at epoch 0. They call `label_at(50_000)` to catch up. That's 50,000 BLAKE3 ops. At ~5ns each, ~250µs — fine. But the codebase has no documented maximum epoch gap.
2. A malicious `ContactCard` could have its epoch counter spoofed to `u64::MAX` in a future protocol extension, causing a legitimate peer to call `label_at(u64::MAX)` and spin forever (heat death of the universe).
3. The API offers no "advance by N" method that would let callers rate-limit their own catch-up.

**Fix:**  
Add a `MAX_LOOKAHEAD` constant and return `None` (or a new `Err`) if `target_epoch - self.epoch > MAX_LOOKAHEAD`. Alternatively, add an explicit `advance_to(&mut self, target: u64) -> Result<()>` that validates the gap before mutating.

---

### [MEDIUM] `label.rs:7-8` — `Label` Has `pub` Inner Bytes: Secret Material Exposed at Type Level

**File:** `crates/darqual-core/src/label.rs`, lines 7–8

```rust
pub struct Label(pub [u8; 16]);
```

The inner `[u8; 16]` is public. Labels are dead-drop addresses — they're supposed to be published (you write to the label, anyone with the label can see you wrote something there). So this isn't a "secret key leaked" finding. BUT:

`Label` is used in two contexts:
1. As a public dead-drop address (the thing you publish to the ledger). Public. Fine.
2. As a PRF output derived from a secret shared key. Semi-sensitive.

With a public field, nothing stops someone from constructing `Label([0u8; 16])` — a label that collides with epoch 0 of any conversation where the PRF output happens to be all-zeros. This is astronomically unlikely but the type provides zero protection against test code or protocol confusion code accidentally using a hardcoded label that collides with a real one.

More concretely: in `pow.rs:35`, `pow_hash` takes `&Label` and includes `label.0` in the hash input. With a public field, anyone can pass a synthetic `Label([some_known_bytes; 16])` to target a known dead-drop. This is fine for PoW (you have to know the label anyway to write to it), but it means there's no type-level distinction between "a label I derived from a secret" and "a label I just made up."

**Fix:**  
Keep the pub field for now (labels are public by design at the ledger level), but add a newtype constructor or at least a comment: `/// Constructed exclusively via `Conversation::label()` or `Keywheel::label()`; direct construction is for tests only`. Alternatively, make the field private and expose accessors + `Label::from_bytes` marked `#[cfg(test)]` or behind a feature flag.

---

### [MEDIUM] `conversation.rs:35-40` — No Contributory Key Binding: Both Parties' Keys Should Appear in the KDF Input

**File:** `crates/darqual-core/src/conversation.rs`, lines 35–40

```rust
pub fn new(me: &Identity, them: &ContactCard) -> Self {
    let their_x_pub = X25519PublicKey::from(them.x_pub);
    let shared = me.x_secret.diffie_hellman(&their_x_pub);
    Conversation { shared: *shared.as_bytes() }
}
```

The raw X25519 output is used directly as the conversation secret. Best practice for static-static ECDH is to feed the DH output through a KDF that includes both parties' public keys as context. This follows the "contributory" pattern:

```
shared_secret = KDF(dh_output, alice_pub || bob_pub)
```

Why? Because:
1. Without binding the public keys into the KDF, the shared secret doesn't commit to *which* keys were used. If you ever have multiple key versions (rotation), two conversations with different key versions could derive the same DH output by bad luck (yes, astronomically unlikely with X25519, but the pattern is the defensive standard: HKDF with both pubkeys in the info field).
2. The DH output has low entropy structure (cofactor bits are zeroed). Running it through `BLAKE3_keyed(dh_output || alice_pub || bob_pub, domain)` distributes that entropy better.
3. This is how Noise Protocol Framework does it (see `IKpsk2`, `XX` handshake patterns). It's how Signal does it. The reason it's a standard isn't paranoia — it's that "just use the DH bytes" has caused real-world failures when implementations cut corners elsewhere.

**Fix:**
```rust
pub fn new(me: &Identity, them: &ContactCard) -> Self {
    let their_x_pub = X25519PublicKey::from(them.x_pub);
    let dh = me.x_secret.diffie_hellman(&their_x_pub);
    let my_pub = x25519_dalek::PublicKey::from(&me.x_secret);
    
    // Bind both public keys into the shared secret derivation.
    // Sort so the output is symmetric (independent of who is "me" vs "them").
    let (pk_lo, pk_hi) = if my_pub.as_bytes() < them.x_pub.as_ref() {
        (my_pub.as_bytes(), &them.x_pub)
    } else {
        (&them.x_pub, my_pub.as_bytes())
    };
    
    let mut input = [0u8; 96]; // 32 + 32 + 32
    input[..32].copy_from_slice(dh.as_bytes());
    input[32..64].copy_from_slice(pk_lo);
    input[64..].copy_from_slice(pk_hi);
    
    let shared = *blake3::keyed_hash(
        dh.as_bytes(),
        &input[32..], // pk_lo || pk_hi as data
    ).as_bytes();
    
    Conversation { shared }
}
```

(Note: the sort ensures symmetry so both parties derive the same value regardless of call order. The `Zeroize` issue below applies to the intermediate `dh` too.)

---

## 🔵 Low Findings

---

### [LOW] `conversation.rs:37-39` — ECDH Output Not Zeroized

**File:** `crates/darqual-core/src/conversation.rs`, lines 37–39

```rust
let shared = me.x_secret.diffie_hellman(&their_x_pub);
Conversation { shared: *shared.as_bytes() }
```

`shared` here is an `x25519_dalek::SharedSecret`. When it drops at end of scope, the secret bytes stay in stack/heap memory until overwritten. `Conversation` stores a copy as `[u8; 32]` but the `SharedSecret` intermediate isn't zeroized. Compare with `identity.rs:76-77`:

```rust
ed_seed.zeroize();
x_seed.zeroize();
```

That's careful. This isn't.

`x25519_dalek::SharedSecret` does implement `Zeroize` (via the `zeroize` feature). But `Conversation::new` doesn't explicitly drop/zeroize it — it relies on the struct's `Drop` impl which is implicit and may or may not zero on the stack depending on compiler optimizations.

Relatedly, `Conversation` itself doesn't `#[derive(Zeroize)]` or `impl Drop` to zeroize `self.shared`. So when a `Conversation` is dropped, its secret stays in memory until overwritten.

**Fix:**
```rust
use zeroize::Zeroize;

impl Drop for Conversation {
    fn drop(&mut self) {
        self.shared.zeroize();
    }
}
```

And explicitly drop the `SharedSecret` in `new()` via `drop(shared)` after copying, or use `zeroize::Zeroizing<[u8;32]>`.

---

### [LOW] `keywheel.rs:48-52` — `Keywheel` State Not Zeroized on Drop

**File:** `crates/darqual-core/src/keywheel.rs`, lines 48–52

```rust
pub struct Keywheel {
    pub epoch: u64,
    state: [u8; 32],
}
```

`state` is the current ratchet key. When a `Keywheel` is dropped (e.g., after `advance()` in a future persist-to-disk codepath), the old `state` bytes sit in memory. This is the exact thing forward secrecy is supposed to prevent. The whole point of the ratchet is that old state should be gone — but "gone from the API" is not the same as "gone from RAM."

**Fix:**
```rust
impl Drop for Keywheel {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}
```

And in `advance()`, zeroize the old state before overwriting:
```rust
pub fn advance(&mut self) {
    let new_state = ratchet_state(self.state);
    self.state.zeroize(); // overwrite old secret
    self.state = new_state;
    self.epoch += 1;
}
```

Without this, the operating system's memory and swap files might retain old ratchet states. On a seized device, a memory forensics tool could reconstruct old labels.

---

### [LOW] `keywheel.rs:40` — `SEED_CONTEXT` Is `pub(crate)` Without Documented Reason

**File:** `crates/darqual-core/src/keywheel.rs`, line 40

```rust
pub(crate) const SEED_CONTEXT: &str = "keywheel-seed";
```

Every other domain constant in this crate is module-private (`const`, no pub). This one is `pub(crate)`. Why? Looking at usages: it's only referenced inside `keywheel.rs` itself (`from_seed` on line 93). There's no other crate-internal usage.

This is either a mistake (should be private) or a forward-compatibility thing (planning to use it from another module). If it's the latter, document it. If it's the former, fix it. Unnecessary pub-visibility on domain constants is an invitation to misuse them.

**Fix:** Change to `const SEED_CONTEXT: &str = "keywheel-seed";` (private to the module).

---

### [LOW] `keywheel.rs:121` — `label_at()` Silently Discards Intermediate States Without Zeroizing

**File:** `crates/darqual-core/src/keywheel.rs`, lines 119–127

```rust
let mut state = self.state;
let mut epoch = self.epoch;
while epoch < target_epoch {
    state = ratchet_state(state);
    epoch += 1;
}
```

The temporary `state` variable runs through all intermediate ratchet states between `self.epoch` and `target_epoch`. Those intermediate values are genuine ratchet states — if an attacker reads RAM during this computation, they could extract any of them. Rust won't guarantee they're zeroized when the function returns. For a forward-secrecy system, "intermediate state during lookahead" leaking is a real concern on a shared-memory system (think: VM with memory snapshot capabilities, or a process that's `ptrace`d).

This is a lower-severity issue than the `advance()` case because `label_at` is a read-only lookahead, not an "advance and discard" path. But it's still worth noting: the lookahead operation creates temporary forward states in stack memory.

**Fix:**  
Use a `Zeroizing` wrapper or explicitly zeroize the `state` variable at function end:
```rust
let mut state = Zeroizing::new(self.state);
// ... loop ...
let label = derive_label(&state);
// state is zeroized on drop
label
```

---

## 🔬 Nit-Level Findings

---

### [NIT] `label.rs:10-14` — `Debug` for `Label` Prints the Full Hex Value: Potential Log Leakage

**File:** `crates/darqual-core/src/label.rs`, lines 10–14

```rust
impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label({})", hex::encode(self.0))
    }
}
```

Labels are dead-drop addresses — publicly posted to the ledger. So printing them isn't *secret*. But: in a `RUST_LOG=debug` scenario during development, this means any debug log that includes a `Label` will emit the full dead-drop address. An adversary with access to debug logs (CI server, crash reporter, development machine) now has a map of all active dead-drops and which conversations they belong to (because labels are scoped per-conversation).

The THREAT-MODEL explicitly says the threat model includes "device seizure." CI logs are on a server. CI servers get seized. Development logs get dumped in bug reports.

**Fix:**  
Either redact `Debug` (`Label(<redacted>)`) or shorten to a partial display (`Label({}...)` with first 4 bytes only) for debug builds. `Display` can still show the full value for legitimate use.

---

### [NIT] `conversation.rs:63-68` — `seal()` Discards `self` Context: No Binding Between Label and Lockbox Nonce

**File:** `crates/darqual-core/src/conversation.rs`, lines 63–68

```rust
pub fn seal(&self, them: &ContactCard, epoch: u64, msg: &[u8]) -> Result<(Label, Vec<u8>)> {
    let lbl = self.label(epoch);
    let their_x_pub = X25519PublicKey::from(them.x_pub);
    let lockbox = Lockbox::seal(&their_x_pub, msg)?;
    Ok((lbl, lockbox.envelope.into_bytes()))
}
```

The lockbox's AEAD nonce is random (from `OsRng` in `lockbox.rs:40-41`). The label is derived from the shared secret + epoch. There's no binding between the label and the lockbox — an adversary could take a lockbox from conversation A's dead-drop and replay it into conversation B's dead-drop for the same epoch (assuming epoch numbers are shared across conversations, which they are since epochs are global ledger epochs).

The lockbox itself is authenticated (ChaCha20-Poly1305 would fail to decrypt under the wrong key), so the content is safe. But the *label* used for routing is not authenticated against the lockbox content. This means the label and lockbox could be swapped between slots by a malicious relay without the recipient being able to detect it — they'd just see the wrong label in their slot, fail to decrypt, and move on. That's not catastrophic but it's a detectable-only-by-absence attack pattern.

**Fix (future):** In a DPF write path (Stage 4), the write itself is authenticated. In the current PoW path, binding the PoW to (label ‖ envelope) is done in `pow.rs` — which is correct. But `Conversation::seal` doesn't invoke PoW. Make sure the layer above this that *does* invoke PoW uses `Conversation::seal`'s label output as the PoW label input — document this invariant.

---

### [NIT] `keywheel.rs:101-104` — `advance()` Does Not Check for `u64::MAX` Overflow

**File:** `crates/darqual-core/src/keywheel.rs`, lines 101–104

```rust
pub fn advance(&mut self) {
    self.state = ratchet_state(self.state);
    self.epoch += 1;
}
```

`self.epoch += 1` will panic in debug builds and silently wrap in release builds when `epoch == u64::MAX`. At one epoch per second this takes 585 billion years to hit. Not a real concern. But Rust's `u64::MAX` overflow is UB-free (wraps or panics), and in a cryptographic ratchet, a wrapping epoch counter that returns to 0 would cause label reuse — specifically, epoch 0 labels would re-appear.

**Fix:** `self.epoch = self.epoch.checked_add(1).expect("epoch overflow");` — or document that this is a non-issue at any realistic epoch duration.

---

### [NIT] `keywheel.rs:56-62` — `Debug` Leaks Epoch Counter: Minor but Worth Knowing

**File:** `crates/darqual-core/src/keywheel.rs`, lines 56–62

```rust
impl fmt::Debug for Keywheel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keywheel")
            .field("epoch", &self.epoch)
            .field("state", &"<redacted>")
            .finish()
    }
}
```

The state is correctly redacted. But `epoch` is printed. In isolation, the epoch counter is public information (it corresponds to a global ledger epoch). But combined with the presence of a `Keywheel` in a debug log, it reveals: "this process has an active conversation with a live ratchet at epoch N." That's metadata — specifically, when this conversation was last synced. This probably doesn't matter in practice, but in a strict metadata-dark design, logging "I have a ratchet at epoch 5000" reveals conversation continuity.

**Fix:** Low priority. Document the tradeoff. Or redact epoch too if you want zero metadata in debug logs.

---

## Cross-Cutting Observations

**1. Two label derivation paths, one Label type, no type-level distinction.**  
`conversation.label()` and `keywheel.label()` both return `Label` but they're from different PRF constructions. The type system doesn't prevent mixing them. A type alias or wrapper (`StaticLabel` vs `RatchetLabel`) would let the compiler catch confusion, at the cost of ergonomics.

**2. No zeroize-on-drop for the secret-bearing types: Conversation and Keywheel.**  
`Identity` in `identity.rs` correctly zeroizes seeds during save/load. But neither `Conversation` (which holds `shared: [u8; 32]`) nor `Keywheel` (which holds `state: [u8; 32]`) implement `Drop` to zeroize. This is a consistent gap across the three target files.

**3. BLAKE3 usage is mostly consistent but has one outlier.**  
- `derive_key()` for lockbox KDF: correct (context-based derivation).  
- `keyed_hash(state, domain_bytes)` for label derivation: correct.  
- `keyed_hash(seed, context_bytes)` for keywheel seed: correct.  
- `hash(domain ++ state)` for ratchet step: inconsistent with everything else. Fix it.

**4. The `ContactCard::verify()` check is insufficient for trust.**  
`verify()` only checks address-to-ed_pub consistency. It does not verify ed_pub-to-x_pub binding. This is the root of the [CRITICAL] finding above, but it bears repeating as a cross-cutting observation: any time someone calls `ContactCard::verify()` they may think they've done a full trust check. They haven't.

---

## Counts

| Severity   | Count |
|------------|-------|
| CRITICAL   | 2     |
| HIGH       | 3     |
| MEDIUM     | 4     |
| LOW        | 4     |
| NIT        | 4     |
| **Total**  | **17**|

---

*Review by Shady. Read-only. Fix it yourself — that's your job. Mine is to make sure you can't pretend you didn't know.*
