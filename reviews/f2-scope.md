# F-2 Scope: Remove cleartext sender static x25519 pubkey from the Tor wire frame

**Finding:** CRITICAL. The node wire frame prepends the sender's static x25519 public key
in cleartext, giving any network observer / malicious relay a stable, linkable, global
identifier for the sender — defeating the entire point of the header-encryption ratchet
(`crates/darqual-core/src/ratchet.rs:1-21`, whose design goal is explicitly "no rotating
pubkey, no counters, nothing to link two messages").

**Verdict on the proposed fix direction: CONFIRMED, with two corrections** (§3.2, §5.1 below):
1. `SessionStore` has **no** iterate-all-sessions API — one must be added (`session.rs:32-116`
   exposes only `load`/`save`/`load_or_init_*` keyed by a known `peer_x_pub`).
2. The first-contact v1 frame should carry the **initial `RatchetMessage` inside the
   lockbox AEAD**, not a bare plaintext — so ratchet state stays in sync from message #1
   and the receiver's bootstrap path is identical to today's `load_or_init_responder` flow.

---

## 1. Current frame + why the tag is load-bearing

**Frame (documented at `crates/darqual-tor/src/main.rs:12`):**

```
[ sender_x_pub : 32B ][ bincode(RatchetMessage) ]
```

**Send side** (`main.rs:152-155`): `send_cmd` serializes the `RatchetMessage`, then
`frame.extend_from_slice(&identity.x_pub())` (`main.rs:154`) — the sender's *static*
key from `Identity::x_pub()` (`crates/darqual-core/src/identity.rs:137-139`) — before
the ciphertext.

**Receive side** (`main.rs:94-133`): `handle_frame` does `frame.split_at(32)`
(`main.rs:99`) and uses the cleartext `sender_x_pub` for **two load-bearing purposes**:

1. **Session lookup / persistence key** — `store.load_or_init_responder(identity, &sender_x_pub)`
   (`main.rs:111`) and `store.save(&sender_x_pub, &sess)` (`main.rs:122`). The store maps
   `peer_x_pub → <dir>/<hex(peer_x_pub)>.bin` (`crates/darqual-core/src/session.rs:51-53`).
2. **DH material for responder bootstrap** — on first contact, `load_or_init_responder`
   computes `shared_secret_with(me, sender_x_pub)` and calls
   `RatchetSession::init_responder` (`session.rs:100-110`). Without knowing who the
   sender is, the responder cannot derive the conversation SK.

So the tag cannot simply be deleted; both roles must be replaced.

**Leak severity confirmed:** the `RatchetMessage` itself is fully opaque
(`enc_header: Vec<u8>, ciphertext: Vec<u8>`, `ratchet.rs:100-105`) — the 32B prefix is
the *only* linkable material on the wire, and it is the strongest possible one (static,
per-identity, forever).

---

## 2. New wire format — versioned envelope, no cleartext identity

### Before
```
[ sender_x_pub : 32B ][ bincode(RatchetMessage) ]
```

### After
```
Frame v1 (first-contact bootstrap):
  [ 0x01 ][ lockbox-v2 wire bytes ]
     where lockbox payload (inside AEAD) = bincode(RatchetMessage)

Frame v2 (established session):
  [ 0x02 ][ bincode(RatchetMessage) ]
```

Constants in `crates/darqual-tor/src/main.rs`:
```rust
const FRAME_BOOTSTRAP: u8 = 0x01; // lockbox-v2-wrapped RatchetMessage
const FRAME_SESSION:   u8 = 0x02; // bare RatchetMessage, trial-decrypted
```
(Do not confuse with the lockbox-internal version bytes `V1`/`V2` at
`crates/darqual-core/src/lockbox.rs:15-16` — those live *inside* the 0x01 payload.)

**What the wire now shows:**
- v1: version byte + lockbox v2 = `[0x02][eph_pub 32][nonce0 12][enc_s 48][nonce1 12][enc_msg]`
  (`lockbox.rs:27-34, 168-175`). Only a **fresh ephemeral pubkey** is visible; the sender's
  static `x_pub` is encrypted under `k0 = KDF(es)` inside `enc_s` (`lockbox.rs:146-156`)
  — verified: `seal_authenticated` AEAD-encrypts `alice_x_pub_bytes` (`lockbox.rs:152-154`)
  and `open_v2` recovers it only after the recipient's static DH (`lockbox.rs:279-289`).
- v2: version byte + `enc_header || ciphertext` — fully opaque, unlinkable.

**Lockbox API note:** `Lockbox` is string-enveloped (`"dqbox1" + BASE64`, `lockbox.rs:42-44`)
and `open_authenticated` takes the envelope string (`lockbox.rs:199-226`). For v1 frames,
embed `lockbox.envelope.as_bytes()` after the version byte and reconstruct via
`std::str::from_utf8`. (A raw-bytes seal/open API would save ~33% overhead; **optional**,
not required for correctness — defer.)

---

## 3. `handle_frame` rewrite (`crates/darqual-tor/src/main.rs:94-133`)

```rust
fn handle_frame(identity: &Identity, store: &SessionStore, frame: &[u8]) {
    let Some((&ver, body)) = frame.split_first() else {
        eprintln!("[recv] empty frame"); return;
    };
    match ver {
        FRAME_BOOTSTRAP => handle_bootstrap(identity, store, body),
        FRAME_SESSION   => handle_session(identity, store, body),
        v => eprintln!("[recv] unknown frame version 0x{v:02x}"),
    }
}
```

### 3.1 v1 branch — lockbox decrypt + responder bootstrap

```rust
fn handle_bootstrap(identity: &Identity, store: &SessionStore, body: &[u8]) {
    let envelope = match std::str::from_utf8(body) { Ok(s) => s, Err(_) => { /* log; return */ } };
    // Sender identity is recovered from INSIDE the AEAD — lockbox.rs:284-289.
    let (rm_bytes, sender) = match Lockbox::open_authenticated(identity, envelope) {
        Ok((pt, Some(sender))) => (pt, sender),
        Ok((_, None)) => { eprintln!("[recv] anonymous v1 lockbox rejected as bootstrap"); return; }
        Err(e) => { eprintln!("[recv] bootstrap open failed: {e}"); return; }
    };
    let rm: RatchetMessage = match bincode::deserialize(&rm_bytes) { /* ... */ };
    // Idempotent: loads existing session if one exists, else init_responder — session.rs:100-110.
    let mut sess = match store.load_or_init_responder(identity, &sender) { /* ... */ };
    match sess.decrypt(&rm) {
        Ok(pt) => { let _ = store.save(&sender, &sess); println!("[recv] {}", String::from_utf8_lossy(&pt)); }
        Err(e) => eprintln!("[recv] bootstrap ratchet decrypt failed: {e}"), // do NOT save
    }
}
```

Note the `Ok((_, None))` arm: a lockbox-**v1** (anonymous, `lockbox.rs:96-117, 233-256`)
returns `sender = None` — it cannot bootstrap a session and must be rejected here.

### 3.2 v2 branch — the trial-decrypt loop

**Correction to the plan:** `SessionStore` has **no list/iterate API** — `session.rs:32-116`
only offers point lookups. **Add to `session.rs`:**

```rust
/// Iterate all persisted sessions as (peer_x_pub, session) pairs.
/// peer_x_pub is recovered from the hex filename (`path_for`, session.rs:51-53).
pub fn list(&self) -> Result<Vec<([u8; 32], RatchetSession)>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(&self.dir)? {
        let path = entry?.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        let Ok(bytes) = hex::decode(stem) else { continue };          // skip .tmp / junk
        let Ok(peer): std::result::Result<[u8; 32], _> = bytes.try_into() else { continue };
        if let Some(sess) = self.load(&peer)? { out.push((peer, sess)); }
    }
    Ok(out)
}
```
(~15 LoC + a test. Skip files not matching 64 hex chars — the atomic-save `.bin.tmp`
files from `session.rs:71` must not be parsed.)

**The loop:**

```rust
fn handle_session(identity: &Identity, store: &SessionStore, body: &[u8]) {
    let rm: RatchetMessage = match bincode::deserialize(body) { /* ... */ };
    let sessions = match store.list() { /* ... */ };
    for (peer, mut sess) in sessions {
        match sess.decrypt(&rm) {
            Ok(pt) => {
                let _ = store.save(&peer, &sess);
                println!("[recv] {}", String::from_utf8_lossy(&pt));
                return;
            }
            Err(_) => continue, // wrong session — safe, see below
        }
    }
    eprintln!("[recv] v2 frame matched no session ({} tried) — dropped", n);
}
```

**Why trying `decrypt` directly is safe (F-1 verified):** `RatchetSession::decrypt`
(`ratchet.rs:368-401`) is now **clone-and-commit**: all mutations run on `let mut trial =
self.clone()` (`ratchet.rs:377`) and `*self = trial` happens only after AEAD + unpad
succeed (`ratchet.rs:398-399`). On a wrong session the failure happens at
`decrypt_header` (`ratchet.rs:405-417`), which trial-decrypts `enc_header` against `hkr`
then `nhkr` via `hdec` — and `hdec` (`ratchet.rs:251-261`) returns `Err(Error::Decrypt)`
on auth failure, never panics ("trial-decryption depends on it", `ratchet.rs:249-250` and
module doc `ratchet.rs:21`). One caveat: the skipped-keys fast path `try_skipped_he`
(`ratchet.rs:419-443`) runs *before* the clone and mutates on a **hit only** — a header
that authenticates under a stored `(hk, n)` *is* the right session, so a hit is never a
false positive; misses don't mutate. **No new `decrypt` variant is needed.** The failed
sessions are simply not saved (same discipline as today's `main.rs:128-131`).

**Cost of a wrong-session probe:** 2 `hdec` attempts (hkr, nhkr) + up to
`skipped.len()` `hdec` attempts in `try_skipped_he` (`ratchet.rs:423-430`) — each a
ChaCha20-Poly1305 open on a ~68-byte `enc_header`. Cheap, but see §6 for the O(N) bound.

---

## 4. `send_cmd` change (`crates/darqual-tor/src/main.rs:135-165`)

Stop prepending `identity.x_pub()` (`main.rs:153-155`). New logic:

```rust
// Decide BEFORE load_or_init_initiator mutates our view:
let had_session = store.load(&card.x_pub)?.is_some();          // session.rs:56-65
let mut sess = store.load_or_init_initiator(&identity, &card)?; // session.rs:86-96
let bootstrap = !had_session || !sess.received_from_peer();     // see below
let rm = sess.encrypt(message.as_bytes())?;
store.save(&card.x_pub, &sess)?;
let rm_bytes = bincode::serialize(&rm)?;

let frame = if bootstrap {
    // Recipient may not know who we are yet → wrap in lockbox v2 (Noise IK).
    let lb = Lockbox::seal_authenticated(&identity, &card, &rm_bytes)?; // lockbox.rs:135-180
    let mut f = vec![FRAME_BOOTSTRAP];
    f.extend_from_slice(lb.envelope.as_bytes());
    f
} else {
    let mut f = vec![FRAME_SESSION];
    f.extend_from_slice(&rm_bytes);
    f
};
```

**When v1 vs v2 — the precise rule:** send v1 (bootstrap) until we have *evidence the
peer has our session*, i.e. **until we have received at least one message from them**.
Rationale: if we've sent 3 messages but never heard back, the peer may have received
none of them and still has no session — a v2 frame would trial-decrypt against nothing
and be dropped. The clean indicator is the receiving chain: an initiator's `ckr` stays
`None` until the first inbound message triggers `dh_ratchet_he`
(`ratchet.rs:295-311` init sets `ckr: None`; `ratchet.rs:477-489` sets it). `ckr` is
private, so **add to `ratchet.rs`:**

```rust
/// True once we have successfully received at least one message from the peer
/// (receiving chain established). Used for first-contact vs established routing.
pub fn received_from_peer(&self) -> bool { self.ckr.is_some() }
```
(~4 LoC. `init_responder` also starts with `ckr: None` (`ratchet.rs:321-337`), but a
responder can't `encrypt` before receiving anyway — `encrypt` errors on `cks: None`,
`ratchet.rs:342-344` — so the rule is consistent both directions.)

This means repeated pre-reply sends are all v1 lockboxes — each ~105B + padding-bucket
overhead. Acceptable; each one is independently bootstrappable and idempotent (§5).

---

## 5. Bootstrap state machine

```
A (initiator)                              B (responder)
─────────────                              ─────────────
send #1: no session → init_initiator,
  encrypt rm₁, wrap in lockbox v2,
  frame v1 ──────────────────────────────▶ open_authenticated → sender = A.x_pub
                                           load_or_init_responder(B, A.x_pub)   [no file → init_responder]
                                           decrypt(rm₁) ok → save(A.x_pub)
send #2 (still no reply): ckr = None
  → STILL frame v1 ──────────────────────▶ open lockbox → sender = A
                                           load_or_init_responder → LOADS existing session (session.rs:105)
                                           decrypt(rm₂) ok → save          ← idempotent re-bootstrap ✓
                                           B replies: B has received from A → ckr Some
                                           → B sends frame v2 ◀──────────
A receives v2: trial-decrypt over store,
  matches session-with-B, ckr now Some.
send #3: received_from_peer() == true
  → frame v2 ────────────────────────────▶ trial-decrypt → match → save
```

**v1 arrives but a session already exists (re-bootstrap):** handled for free —
`load_or_init_responder` prefers the persisted session (`session.rs:105-107`), then
ratchet `decrypt` handles the message wherever it falls in the chain (in-order,
skipped-key, or DH-ratchet step). No special casing. A *replayed* old v1 frame fails the
ratchet decrypt (message key already consumed, or falls outside `MAX_SKIP`) and is
dropped without state advance — same replay posture as today.

**Simultaneous first contact both directions** (A→B v1 and B→A v1 crossing): each side
independently runs `init_initiator` outbound and `init_responder` inbound *under the same
peer key*, so the responder-init overwrites/coexists per the existing
`load_or_init_*` semantics — this is exactly the behavior the current code has (the
crossing-sessions question is pre-existing, not changed by F-2; the existing test
`first_contact_both_directions` at `session.rs:240-271` covers the non-crossing case only).
Out of scope; note in the PR.

**v2 arrives, no session matches** (e.g. receiver lost `~/.darqual/sessions/`): frame is
dropped with a log line. Recovery requires the sender to fall back to v1 — a
session-reset/renegotiation signal is a **follow-up**, not in F-2 (today's code has the
same failure mode: `load_or_init_responder` would init a fresh responder whose header
keys can't decrypt a mid-conversation message either).

---

## 6. Honest residuals

- **Trial-decrypt O(N) CPU:** an anonymous attacker can spray garbage v2 frames; each
  costs the receiver `N_sessions × (2 + skipped.len()) ` header-AEAD attempts. Bounded:
  `skipped` ≤ `MAX_SKIP_STORE = 2000` per session (`ratchet.rs:51`), header is 40B
  plaintext / ~68B ciphertext, so worst case ≈ `N × 2002` ChaCha-Poly opens — microseconds
  per session for typical stores, but a node with hundreds of sessions and full skip
  stores should know this is linear. Mitigation is inherent (drop after loop, no state
  written, no disk writes on failure). Optional hardening (defer): probe only
  `hkr`/`nhkr` first across all sessions before falling back to skipped-key probing.
- **v1 lockbox open cost:** attacker forces 2 x25519 DHs + 2 AEAD opens per garbage v1
  frame (`lockbox.rs:279-297`) — constant, fine, and `check_dh` rejects degenerate
  points (`lockbox.rs:81-86`).
- **F-12 (SEPARATE, out of F-2 scope):** the on-disk session filename is still
  `hex(peer_x_pub).bin` (`session.rs:51-53`) — anyone reading `~/.darqual/sessions/`
  learns the full contact graph. F-2 fixes the *wire*; the disk-side identifier leak
  (and the plaintext session secrets, per the module's own warning `session.rs:10-16`)
  is tracked separately. The new `list()` API depends on hex filenames; when F-12
  renames files (e.g. `blake3(identity_key ‖ peer_x_pub)`), `list()` must switch to
  reading the peer key from (encrypted) file content — design `list()`'s callers to not
  care where the key comes from.
- **Traffic-shape distinguisher:** the version byte itself tells an observer "first
  contact" vs "established". Acceptable: it reveals no identity, and the lockbox's fresh
  ephemeral makes v1 frames pairwise unlinkable. Note it in the frame doc comment.
- **No back-compat:** old nodes send 32B-prefixed frames; new nodes will read the first
  byte of an x25519 pubkey as a version byte (1/128 chance it's 0x01/0x02 → garbage
  decrypt → dropped). Pre-release software; flag-day acceptable. State it in the PR.

## 7. Effort, files touched, risk

| File | Change | Est. |
|---|---|---|
| `crates/darqual-tor/src/main.rs` | frame constants; `handle_frame` split into `handle_bootstrap`/`handle_session`; `send_cmd` v1/v2 routing; doc comment `:12` | ~90 LoC |
| `crates/darqual-core/src/session.rs` | add `SessionStore::list()`; update the frame-mirroring test helpers (`session.rs:129-143`) + new tests (bootstrap idempotency, trial-decrypt multi-peer, junk-file skip) | ~70 LoC |
| `crates/darqual-core/src/ratchet.rs` | add `received_from_peer()` accessor | ~4 LoC |
| `crates/darqual-core/src/lockbox.rs` | **no change** (existing `seal_authenticated`/`open_authenticated` suffice) | 0 |

**Effort:** ~1 day incl. tests. **Risk: low-medium.** The crypto is all existing,
tested primitives (lockbox v2 `lockbox.rs:319-339`, transactional decrypt
`session.rs:276-313`); the new surface is routing + the `list()` loop. Highest-risk
spot is the v1-vs-v2 send rule (`received_from_peer`) — get the crossing/no-reply cases
under test. No changes to key derivation, no changes to persisted session format.
