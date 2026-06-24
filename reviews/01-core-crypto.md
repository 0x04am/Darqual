# Darqual Core Crypto Review — 01-core-crypto.md

**Scope:** `crates/darqual-core/src/lockbox.rs`, `crates/darqual-core/src/identity.rs`
**Crate versions audited:** `x25519-dalek 2.0.1`, `ed25519-dalek 2.2.0`, `chacha20poly1305 0.10.1`,
`blake3 1.8.5`, `zeroize 1.9.0`
**Against:** SPEC.md v0 + THREAT-MODEL.md
**Reviewer:** Silverhand (automated red-team pass)

---

## Summary

The core crypto construction is *sound in its primitives*. The ECDH sealed-box pattern, the KDF call,
and the AEAD usage are all correct. Several real weaknesses exist — none break confidentiality
outright today, but two are serious enough to qualify as HIGH under a nation-state threat model, and
one is a design-level gap that will matter the instant the crate moves to v0.1 network transport.

---

## Findings

---

### [HIGH] F-01 — Shared ECDH output fed raw into KDF; no contributory binding prevents unknown-key-share

**File:line:** `lockbox.rs:36`

```rust
let key_bytes = blake3::derive_key(KDF_CONTEXT, shared.as_bytes());
```

**Problem:**
The KDF input is *only* the raw ECDH shared secret (`shared.as_bytes()`, 32 bytes). Neither the
ephemeral public key nor the recipient's static public key is mixed into the KDF input. This is
a well-known gap in naïve Diffie-Hellman based key derivation (CWE-325, NIST SP 800-56C §5.8).

**Why it matters:**
In a standard anonymous sealed-box the full transcript — `eph_pub ‖ recipient_static_pub ‖ shared`
— is hashed together as the KDF input. Omitting them opens two concrete attack paths:

1. **Unknown-key-share (UKS):** A malicious third party, C, who has a static X25519 key, can
   construct an envelope where C's share collides with the legitimate sender's share, then claim
   *they* sent the message. In a zero-sender-identity protocol the UKS primitive is the only
   authentication; without transcript binding it doesn't hold.
2. **Reflection / misdirection:** If the sender and recipient public keys are not included in the
   KDF, two different ephemeral→recipient pairs that happen to produce the same raw shared secret
   (e.g. via small-subgroup or crafted input in the absence of constant-time checks) yield
   identical keys. The KDF context string (`KDF_CONTEXT`) only names the *application*, not the
   specific key exchange instance.

For comparison: libsodium's `crypto_box_seal` hashes `eph_pub ‖ recipient_pub` before the
shared secret, and Signal's X3DH mandates full transcript inclusion in the KDF input.

**Fix:**
Include the ephemeral public key and the recipient's static public key as KDF input alongside
the shared secret:

```rust
// Bind the entire key-exchange transcript
let mut kdf_input = Vec::with_capacity(32 + 32 + 32);
kdf_input.extend_from_slice(shared.as_bytes());
kdf_input.extend_from_slice(eph_pub.as_bytes());
kdf_input.extend_from_slice(recipient_x_pub.as_bytes());
let key_bytes = blake3::derive_key(KDF_CONTEXT, &kdf_input);
```

Apply the same in `open()` at `lockbox.rs:114` (include `eph_pub_bytes` and the recipient's
own static public key `X25519PublicKey::from(&identity.x_secret).as_bytes()`).

---

### [HIGH] F-02 — Static secret and signing key are NOT zeroized on drop; in-memory key material lingers

**File:line:** `identity.rs:25-28` (struct definition), `identity.rs:96-106` (`load()`)

```rust
pub struct Identity {
    pub signing_key: SigningKey,
    pub x_secret: StaticSecret,
}
```

**Problem:**
`Identity` does not implement `Zeroize` or `Drop`-with-zeroize. The `signing_key` and `x_secret`
fields sit in heap/stack memory for the entire lifetime of the `Identity` value and are NOT wiped
when it is dropped. Rust's `Drop` does not guarantee zeroed memory on deallocation; the secret
key bytes may persist in freed pages, core dumps, swap, or a `/proc/PID/mem` read for an
indeterminate time after use.

`ed25519-dalek 2.x`'s `SigningKey` implements `ZeroizeOnDrop` internally — that part is fine.
`x25519-dalek 2.x`'s `StaticSecret` also implements `ZeroizeOnDrop`. *However*, deriving
`StaticSecret` from raw bytes at `identity.rs:98` (`StaticSecret::from(x_bytes)`) copies the
bytes into a new allocation; the source `x_bytes` is zeroized after (`line 100`) but there is no
guarantee the `From` conversion doesn't leave intermediate copies. More critically: the struct
itself has no `ZeroizeOnDrop` derive, so if an `Identity` is cloned (not done today, but the
struct is `pub` and the fields are `pub`) the clone escapes the dalek-internal zeroize.

The `save()` function (`lines 68-77`) correctly zeroizes the intermediate `ed_seed`/`x_seed` byte
arrays after encoding — that path is clean. The issue is the live struct.

**Why it matters:**
THREAT-MODEL.md §"Device seizure": "adversary later obtains a participant's device/keys." Memory
forensics on a killed process, a crash dump, or a hibernation image can recover key material that
was never wiped. For a journalism/dissident target this is a realistic attack.

**Fix:**
Derive `ZeroizeOnDrop` on `Identity` via the `zeroize` crate (already a dependency):

```rust
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct Identity {
    pub signing_key: SigningKey,  // already ZeroizeOnDrop internally
    pub x_secret: StaticSecret,   // already ZeroizeOnDrop internally
}
```

This ensures the compiler inserts zeroing of the struct fields in the generated `Drop` impl.
Also make the fields private (see F-05) to prevent caller-side copies.

---

### [MEDIUM] F-03 — KDF domain-separation string is not a true context + subkey tag; collision risk at future protocol expansion

**File:line:** `lockbox.rs:15`

```rust
const KDF_CONTEXT: &str = "darqual lockbox v1 :: x25519-chacha20poly1305";
```

**Problem:**
`blake3::derive_key` takes a `context` string that is supposed to be a *globally unique,
application-specific* string. The current string is reasonable, but it acts as both the protocol
version tag and the subkey purpose label. As the protocol grows (dead-drop labels, keywheel
ratchet PRF outputs, PRNG seeds for future Double Ratchet) all will need distinct context
strings. If any future call re-uses this exact string for a different purpose — a copy/paste
error — the same KDF output would be used for both the lockbox AEAD key and the other primitive,
potentially leaking key material across subsystems.

**Why it matters:**
blake3's `derive_key` is formally equivalent to a domain-separated PRF. Its safety guarantee
holds *if and only if* context strings are unique per usage. BLAKE3's documentation explicitly
warns: "the context string should be hardcoded, globally unique, and application-specific."
There is no current collision, but the project has 10 planned stages and this is the pattern-
establishing moment.

**Fix:**
Adopt a structured naming convention now, before other crates follow suit:

```rust
// Format: "<project> <crate> <primitive> <purpose> v<version>"
const KDF_CONTEXT_LOCKBOX_KEY: &str = "darqual-core lockbox chacha20poly1305-key v1";
```

Maintain a `KDF_CONTEXTS.md` registry in the repo root listing every `derive_key` call,
its location, and its purpose. This costs nothing and prevents a class of future mistakes.

---

### [MEDIUM] F-04 — Random nonce for ChaCha20-Poly1305 with static key is safe *only* because the key is fresh per-message; this invariant is implicit and fragile

**File:line:** `lockbox.rs:39-42`

```rust
let mut nonce_bytes = [0u8; 12];
OsRng.fill_bytes(&mut nonce_bytes);
let nonce = Nonce::from(nonce_bytes);
```

**Problem:**
The 96-bit random nonce is acceptable *only* because a fresh ephemeral x25519 key is generated
per message, meaning the AEAD key derived from the ECDH output is also fresh per message
(computationally independent). Under that invariant the nonce-reuse window is per-message and
a collision requires two messages to share both the same ephemeral→recipient ECDH output *and*
the same 96-bit nonce — negligible probability.

However, the code does not make this dependency explicit or enforced. If a future refactor
caches the AEAD key (e.g. for a multi-recipient batch seal or a re-encryption path) and retains
the random nonce strategy, nonce collision over a long-lived key becomes a catastrophic failure
mode: ChaCha20-Poly1305 nonce reuse leaks keystream XOR of plaintexts (classical OTP plaintext
recovery) and destroys AEAD integrity.

This is not a current bug. It is a design assumption that is one refactor away from becoming
one, and it is not documented in the code.

**Why it matters:**
Nonce-reuse under ChaCha20-Poly1305 is an absolute break (CWE-330 / AEAD misuse). The safety
here is entirely load-bearing on the ephemeral key being fresh. That dependency is invisible.

**Fix:**
Add an explicit invariant comment in `seal()`:

```rust
// SECURITY INVARIANT: The AEAD key is derived from a fresh ephemeral x25519 key,
// making it unique per message. Random 96-bit nonces are safe under this invariant.
// If this function is ever changed to reuse an AEAD key across messages, nonces MUST
// be switched to a monotonic counter or the key derivation changed to prevent reuse.
```

Long-term: when the keywheel ratchet lands (Stage 7), the messaging layer will need a proper
nonce strategy (counter-based or SIV mode) independent of key freshness.

---

### [MEDIUM] F-05 — `Identity` fields are `pub`; raw secret material is directly accessible to any crate in the workspace

**File:line:** `identity.rs:26-28`

```rust
pub struct Identity {
    pub signing_key: SigningKey,
    pub x_secret: StaticSecret,
}
```

**Problem:**
Both the ed25519 `SigningKey` and the x25519 `StaticSecret` are public fields. Any code in the
workspace — including future crates added in Stages 1–9 — can read, copy, or move the raw key
material without going through `Identity`'s controlled interface.

Concretely:

- `lockbox.rs:111`: `identity.x_secret.diffie_hellman(&eph_pub)` — direct field access instead
  of a method call. This works fine today but means `lockbox.rs` bypasses any future access
  control (e.g. hardware-backed key storage, rate limiting, audit logging of key uses).
- Any caller can do `let key_copy = identity.x_secret.clone()` — except `StaticSecret` doesn't
  implement `Clone` (good), but `identity.signing_key` through `SigningKey` may expose signing
  operations without audit.

**Why it matters:**
Principle of least privilege for key material. The `Identity` struct is the trust anchor of the
entire system. Exposing raw fields makes it impossible to retrofit hardware key storage (e.g.
OS keychain, TPM) or key-use auditing without breaking the public API.

**Fix:**
Make fields private; expose only the minimum API needed:

```rust
pub struct Identity {
    signing_key: SigningKey,
    x_secret: StaticSecret,
}

impl Identity {
    /// Perform ECDH against an ephemeral public key. Returns the derived AEAD key bytes.
    pub(crate) fn ecdh_derive_key(&self, eph_pub: &X25519PublicKey) -> [u8; 32] {
        let shared = self.x_secret.diffie_hellman(eph_pub);
        blake3::derive_key(KDF_CONTEXT, shared.as_bytes())
    }
    // ... sign(), verifying_key(), address(), contact_card() already exist
}
```

---

### [LOW] F-06 — Keystore file written before permissions are set; race window exposes secret key material

**File:line:** `identity.rs:80-84`

```rust
let toml_str = toml::to_string(&file)?;
fs::write(path, toml_str.as_bytes())?;   // line 80 — written world-readable (umask-dependent)

// 0600 perms
let perms = fs::Permissions::from_mode(0o600);
fs::set_permissions(path, perms)?;        // line 84 — restricted *after* write
```

**Problem:**
`fs::write` creates the file with default permissions (typically `0o644` or `0o664` depending
on the process `umask`). The `set_permissions` call happens *after* the file exists on disk.
Between lines 80 and 84 there is a TOCTOU window — the file is readable by other users on a
multi-user system or by any process that scans newly-created files (e.g. backup daemons,
antivirus agents, audit systems).

This is a standard UNIX keyfile race (CWE-362). Admittedly the window is microseconds and the
parent directory is `~/.darqual/` (user-owned), but on shared-hosting or containerized
environments with a permissive `umask` the file is briefly world-readable.

**Why it matters:**
The TOML file contains the raw hex-encoded ed25519 seed and x25519 seed — *all* of the user's
key material in one file. A brief world-readable window is all an attacker needs if they can
watch `inotifywait` on the home directory.

**Fix:**
Write to a temp file with correct permissions set *before* content is written, then atomically
rename it into place:

```rust
use std::os::unix::fs::OpenOptionsExt;

let tmp_path = path.with_extension("tmp");
{
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)          // O_CREAT with 0600 — never world-readable
        .open(&tmp_path)?;
    f.write_all(toml_str.as_bytes())?;
    f.flush()?;
}
fs::rename(&tmp_path, path)?;   // atomic on POSIX (same filesystem)
```

---

### [LOW] F-07 — `IdentityFile` (the on-disk struct with raw key seeds) is not zeroized after deserialization

**File:line:** `identity.rs:92-98`

```rust
let file: IdentityFile = toml::from_str(&content)?;  // line 92

let mut ed_bytes = decode_hex_32(&file.ed_seed)?;    // line 94 — copy into mutable buf
let mut x_bytes = decode_hex_32(&file.x_seed)?;

let signing_key = SigningKey::from_bytes(&ed_bytes); // line 97
let x_secret = StaticSecret::from(x_bytes);

ed_bytes.zeroize();   // line 100 — correctly zeroized
x_bytes.zeroize();
```

**Problem:**
`ed_bytes` and `x_bytes` are correctly zeroized. However, `file.ed_seed` and `file.x_seed` —
the `String` values in the deserialized `IdentityFile` struct — are *not* zeroized. They are
plain `String`s containing the hex-encoded key seeds. `IdentityFile` does not implement
`Zeroize` and does not have a `Drop` that wipes the heap allocation backing the strings.

Additionally, `content` — the raw TOML string from `fs::read_to_string` — also holds the seeds
in plaintext and is not zeroized.

**Why it matters:**
The attack is the same as F-02: memory forensics after process death. The `String` heap
allocations will sit in freed memory containing the seed material. The `ed_bytes`/`x_bytes`
zeroization is commendable but incomplete because it only covers the second copy, not the first.

**Fix:**

```rust
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Zeroize)]
struct IdentityFile {
    ed_seed: String,
    x_seed: String,
}
```

And in `load()`, drop the struct after extracting bytes:

```rust
let signing_key = SigningKey::from_bytes(&ed_bytes);
let x_secret = StaticSecret::from(x_bytes);
ed_bytes.zeroize();
x_bytes.zeroize();
file.ed_seed.zeroize();   // wipe the intermediate String
file.x_seed.zeroize();
```

Note: `content` (the full TOML string) also holds the seeds; zeroize it too:
```rust
let mut content = fs::read_to_string(path)?;
// ... parse, use, then:
content.zeroize();
```

---

### [LOW] F-08 — Version check in `open()` uses a non-constant-time comparison; not a current issue but establishes a dangerous pattern

**File:line:** `lockbox.rs:91-97`

```rust
let version = wire[0];
if version != VERSION {
    return Err(Error::InvalidLockbox(format!(
        "unknown version: {}",
        version
    )));
}
```

**Problem:**
`version != VERSION` is a single-byte integer comparison — not a secret-dependent branch
in the cryptographic sense. This specific check is fine. However, the error path leaks version
bytes in the error message (`format!("unknown version: {}", version)`), and the pattern of
early-returning on structural parsing before AEAD verification sets a template that future
contributors may extend with secret-dependent early-exits (e.g. comparing a session ID or
sender hint that gets added in a future version).

More immediately: the error message reveals to an oracle whether the rejection was due to
version mismatch vs. AEAD failure (`Error::Decrypt`) vs. parse failure. An active attacker
probing the `open()` API can distinguish these three outcomes and gain information about
the envelope structure.

**Why it matters:**
Differential error oracles are a class of side-channel (Bleichenbacher, Lucky Thirteen). The
current code isn't a padding oracle (ChaCha20-Poly1305 has no padding), but a distinct error
type for structural vs. AEAD failure leaks information about *why* decryption failed, which can
assist a chosen-ciphertext attacker in distinguishing valid-format-but-wrong-key from
invalid-format envelopes.

**Fix:**
Collapse structural and AEAD failures into the same error type when returning to an untrusted
caller. Keep verbose errors for internal logging only:

```rust
// Return a uniform error to callers; log internally if needed
.map_err(|_| Error::Decrypt)?  // same as AEAD failure
```

Apply to all parse failures in `open()` that an external caller sees, so every rejection is
indistinguishable from a failed AEAD.

---

### [NIT] F-09 — `BOX_PREFIX` case sensitivity check is implicit; a typo in a future caller passes the prefix check on lowercase input

**File:line:** `lockbox.rs:70-75`

```rust
let lower_prefix = envelope
    .get(..BOX_PREFIX.len())
    .ok_or_else(|| Error::InvalidLockbox("too short".to_string()))?;

if lower_prefix != BOX_PREFIX {
```

**Problem:**
The variable is misleadingly named `lower_prefix` (suggesting it has been lowercased) but is
not actually lowercased — it is a raw slice of the input. If a caller passes `"DQBOx1..."` the
check correctly rejects it, but the variable name implies a case-insensitive check was intended
that was then never implemented. This is a documentation/naming issue.

**Fix:**
Rename the variable to `prefix` to match what the code actually does, or implement the
case-fold if case-insensitive matching is actually desired:

```rust
let prefix = envelope
    .get(..BOX_PREFIX.len())
    .ok_or_else(|| Error::InvalidLockbox("too short".to_string()))?;

if prefix != BOX_PREFIX {
```

---

### [NIT] F-10 — `verify_ed` returns `false` on any error rather than a typed error; silent failures are undiagnosable

**File:line:** `identity.rs:142-148`

```rust
pub fn verify_ed(ed_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let vk = match VerifyingKey::from_bytes(ed_pub) {
        Ok(k) => k,
        Err(_) => return false,   // bad public key bytes silently == failed verification
    };
    let signature = Signature::from_bytes(sig);
    vk.verify(msg, &signature).is_ok()
}
```

**Problem:**
A malformed public key (31 zero-bytes and one nonzero, e.g.) returns `false` — the same result
as a valid key with a mismatched signature. A caller cannot distinguish "signature is
cryptographically invalid" from "the public key bytes are not a valid curve point." In a
security-critical context these have different operational meanings (the former is normal message
rejection; the latter indicates a corrupted or maliciously crafted ContactCard).

**Fix:**

```rust
pub fn verify_ed(ed_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<bool> {
    let vk = VerifyingKey::from_bytes(ed_pub)
        .map_err(|e| Error::Key(format!("invalid ed25519 pubkey: {}", e)))?;
    let signature = Signature::from_bytes(sig);
    Ok(vk.verify(msg, &signature).is_ok())
}
```

Or at minimum document the collapse explicitly so callers know the `false` return is ambiguous.

---

## Design-level observations (not counted as findings)

**Sender anonymity claim holds — for now.**
The wire format `[version 1][eph_pub 32][nonce 12][ct+mac]` contains no sender identity. The
SPEC claim "sender identity is NOT in the lockbox" is accurate at the content layer. Caveat: as
soon as any transport layer (Stage 1, Tor/Arti) attaches a delivery header, sender anonymity
shifts to the transport layer and must be proven there separately. The crypto layer is clean.

**Ephemeral key handling is correct.**
`EphemeralSecret::random_from_rng(OsRng)` uses the dalek `EphemeralSecret` type, which is
deliberately non-`Clone` and non-`Copy` and is consumed by `diffie_hellman()` — it cannot be
reused. This is the correct approach. The ephemeral secret is gone after line 33.

**No forward secrecy for content — acknowledged in THREAT-MODEL.md.**
The static X25519 key is long-lived; device seizure opens all past lockboxes. This is a known,
documented gap (`known-gaps §4`). Not a finding for this audit scope; noted for completeness.

**ChaCha20-Poly1305 is the right choice.**
No timing side channels from table lookups (unlike AES-GCM without hardware AES-NI), 256-bit
key, 128-bit auth tag. Good call for a software-first prototype targeting platforms without
guaranteed AES-NI.

**blake3 `derive_key` is the right KDF interface.**
Using the dedicated `derive_key` function (as opposed to a plain `hash()` or `keyed_hash()`)
is correct — it uses a domain-separated mode that is distinct from all other blake3 modes.
The flaw (F-01) is in *what is fed in*, not in the choice of primitive.

---

## Findings count

| Severity | Count |
|----------|-------|
| CRITICAL | 0     |
| HIGH     | 2     |
| MEDIUM   | 3     |
| LOW      | 3     |
| NIT      | 2     |
| **Total**| **10**|

**Most urgent:** F-01 (KDF transcript binding) and F-02 (struct-level zeroize) — fix these
before any network-exposed deployment.
