# Darqual — Remediation Design (Wave 1, post-F-2)

**Scope:** every outstanding Wave-1 finding (`reviews/wave1-synthesis.md`) plus the
structural "empty center" and the Mission C doc re-aim. Already fixed and NOT re-covered
here: F-1, F-2, F-7, F-9, F-14, F-17, F-19, F-22, F-25, F-26, F-27, F-28, F-30.
F-2's design doc (`reviews/f2-scope.md`) is the **template** for all wire/envelope work
below (versioned byte-tagged frames, lockbox-v2 bootstrap, trial-decrypt session path).

## 1. Executive summary

**The remediation thesis: the primitives are solid; the SYSTEM doesn't exist.**

The crypto core is genuinely good. Double Ratchet with encrypted headers and
clone-and-commit decrypt (`crates/darqual-core/src/ratchet.rs`, 808 lines), Noise-IK
lockbox v2 that hides the sender's static key inside the first AEAD layer
(`lockbox.rs:27-34`), fixed-bucket padding with hostile-input-safe unpad
(`padding.rs:25-46`), a forward-secret keywheel (`keywheel.rs:95-137`), a Merkle-linked
hot-window ledger (`ledger.rs`, `block.rs`), erasure coding + DA sampling
(`darqual-storage`), a VRF committee-election sketch (`darqual-committee/src/vrf.rs`),
and a live Arti onion transport (`darqual-tor/src/lib.rs`). ~7.2K LOC, 164 tests.

But three structural facts void the mission claims today:

1. **There is no system.** Eight library crates and two demo binaries. `darqual-node`
   (`crates/darqual-node/src/main.rs`) is a CLI that builds ONE block for ONE epoch,
   serves it until Ctrl-C, and exits. No daemon, no epoch clock, no persistent ledger,
   no gossip, no scheduler. Every 🟡 "lib only" row in SPEC §2 is 🟡 *because this
   composition layer is missing*, not because any given library is unfinished.
2. **The mission path runs the weakest crypto.** The async dead-drop path — the entire
   point of the project — uses Lockbox **v1** (`main.rs:213`: `Lockbox::seal`, no
   forward secrecy, no authentication) and the static PRF label (`main.rs:208`:
   `conv.label(epoch)`) instead of the keywheel. Meanwhile the *demo* Tor path got the
   Double Ratchet. The good crypto exists; it is wired into the wrong pipe.
3. **The docs declare a mission that was superseded.** SPEC.md/THREAT-MODEL.md still say
   Mission A (locked S222); Mission C (two-adversary, three traffic modes) was decided
   S223 and lives only in note 21.

**Fix order** (each tier unblocks the next):

| Order | What | Why first |
|---|---|---|
| 1 | **TIER 0 — `darqual-runtime`** (epoch loop, scheduler, mode policy, transport trait) | Every other fix needs a place to *run*. F-3/F-4/F-5/F-8 are unfixable-in-practice without an epoch clock and a persistent session/ledger lifecycle. |
| 2 | **TIER 1 — crypto into the mission path** (F-20 envelope enum → F-3 ratchet-over-dead-drops → F-4 keywheel labels → F-8 keywheel persistence → F-6/F-12 at-rest encryption) | F-20 is the data-structure prerequisite for F-3; F-8 is the state prerequisite for F-4. |
| 3 | **TIER 2 — math + traffic** (F-11 integer DLap, F-5 cover parity) | Correctness of the anonymity *claims*; depends on runtime (real difficulty, real buckets) to be meaningful. |
| 4 | **TIER 3 — debt** (F-10/F-13/F-15/F-16/F-18/F-21/F-23/F-24/F-29) | Parallelizable; F-10/F-24 partially precede Tier 0 (transport trait, state versioning). |
| 5 | **TIER 4 — Mission C doc re-aim** | Written LAST so the docs describe the system that now exists, with honest status columns. |
| 6 | **TIER 5 — research stubs** | Approach documents only; each is scoped as engineering vs paper-shaped research. |

## 2. Out of scope: external audit + closed-beta users

Two ROADMAP Stage-10 items are **explicitly excluded** from this design because they are
not code-fixable — no commit can close them:

1. **External security audit.** An audit is by definition performed by an independent
   third party; self-review (this document, the four Wave-1 reviews) does not and cannot
   count. It is also *premature*: auditing the current codebase would audit a system that
   doesn't exist yet (§1, empty center) and burn the one-shot credibility of a first
   audit on code that Tier 0–2 will substantially rewrite. **Precondition, not action
   item:** the audit becomes schedulable only after Tier 0–2 land and the runtime is
   feature-stable. Until then, THREAT-MODEL.md's banner ("RESEARCH PROTOTYPE. NOT
   AUDITED." — `THREAT-MODEL.md:3`) stays, verbatim, in every doc Tier 4 touches.

2. **Real closed-beta users.** Requires real humans voluntarily using the system —
   a recruitment/ethics/operations problem, not an engineering one. It is also currently
   *unethical to attempt*: SPEC §2 marks contact-graph privacy 🟡 ("node still
   direct-dials"), so inviting users whose threat model includes a network observer would
   expose exactly the metadata Darqual promises to hide. Beta becomes permissible only
   after Tier 0–2 make the running node's guarantees match at least the Async-Anonymous
   mode's claims, and after CLIENT-OBLIGATIONS.md (Tier 4) exists so testers know what
   the client layer does NOT protect.

Everything else in the Wave-1 synthesis and the roadmap gap list is code- or
doc-fixable and is designed below.

## 3. TIER 0 — darqual-runtime: the empty-center fix

### 3.0 The gap, precisely

What exists today at the "system" layer:

- `darqual-node publish` builds **one** block with `prev_hash = [0u8; 32]` hardcoded
  (`crates/darqual-node/src/main.rs:220`) — there is no chain, only genesis blocks.
- The epoch is read once (`main.rs:204`, `epoch_now()`) — nothing ticks. `EPOCH_SECONDS
  = 60` (`crates/darqual-ledger/src/epoch.rs:7`) is a constant nobody schedules against.
- `Ledger` (`crates/darqual-ledger/src/ledger.rs:18-25`) — the validated, chain-linked,
  PoW-gated hot window — is instantiated **nowhere outside tests**.
- Cover traffic is a per-publish CLI arg (`main.rs:218`, `pad_block(..., cover + 1, ...)`)
  instead of an always-on emission policy; DP cover (`dp.rs:129`, `add_dp_cover`) has
  zero call sites outside tests.
- No gossip: blocks are served point-to-point by `serve_block` (`darqual-net/src/
  block_transport.rs:46-50`) — the fetcher must know the publisher's address, which IS
  the contact graph the labels were supposed to hide.
- `SessionStore` and `Keywheel` have no owner process, so per-epoch advancement (F-8)
  and post-decrypt saves have no lifecycle to hang off.

**The fix is one new crate, `crates/darqual-runtime`**, plus turning `darqual-node`
into a thin CLI over it. Every 🟡 in SPEC §2 mounts onto this crate.

### 3.1 Crate layout

```
crates/darqual-runtime/
├── src/
│   ├── lib.rs          // Node: the composition root
│   ├── config.rs       // NodeConfig (mode, epoch len, difficulty, dirs, peers)
│   ├── clock.rs        // EpochClock — the tick source
│   ├── mode.rs         // Mode enum + ModePolicy (Mission C, note 21)
│   ├── scheduler.rs    // TrafficScheduler — outbox → per-epoch emission plan
│   ├── outbox.rs       // durable queue of pending sends (survives restart)
│   ├── ledger_svc.rs   // LedgerService — persistent chain + block building
│   ├── sync.rs         // BlockSync — pull-gossip of epoch blocks over Transport
│   ├── receive.rs      // ReceivePipeline — label-match + envelope open + session save
│   └── state.rs        // NodeState dirs: sessions/, keywheels/, ledger/, outbox/
└── Cargo.toml          // deps: darqual-{core,ledger,cover,net}; tokio; NOT darqual-tor
```

Dependency rule: `darqual-runtime` depends on the message-level `Transport` trait from
`darqual-net` (§6.1/F-10) only. The Arti implementation lives in `darqual-tor` (workspace-
excluded, `Cargo.toml:15-16`) and is injected by the binary — the runtime never links Arti,
keeping `verify.sh` fast.

### 3.2 The epoch clock

```rust
// clock.rs
pub struct EpochClock { epoch_secs: u64 }

pub struct Tick {
    pub epoch: Epoch,          // epoch that JUST closed (build + publish it)
    pub next_deadline: Instant // when the following tick fires
}

impl EpochClock {
    /// Stream of ticks aligned to wall-clock epoch boundaries
    /// (epoch_at(), crates/darqual-ledger/src/epoch.rs:10-12).
    pub fn ticks(&self) -> impl Stream<Item = Tick>;
}
```

- Implemented on `tokio::time::sleep_until` against wall-clock boundaries, NOT
  `interval()` — drift-free across suspend/resume; on resume, missed epochs are yielded
  as a catch-up burst (the receive pipeline must tolerate gaps anyway — Tor is lossy).
- **Timing-jitter rule:** the tick fires at the boundary, but every *emission* the
  scheduler derives from a tick gets uniform random jitter within the first
  `epoch_secs / 4` — a node that publishes at exactly `t ≡ 0 (mod 60)` is a fingerprint.
- `EPOCH_SECONDS = 60` (`epoch.rs:7`) becomes the *default* of `NodeConfig.epoch_secs`;
  Async-Anonymous mode may lengthen it (§3.4). Epoch numbering stays `unix / epoch_secs`
  so `Conversation::label(epoch)` and keywheel epochs remain network-global.

### 3.3 LedgerService — the persistent chain

```rust
// ledger_svc.rs
pub struct LedgerService {
    ledger: Ledger,            // hot window — darqual-ledger/src/ledger.rs:18
    dir: PathBuf,              // <state>/ledger/, one file per block
    difficulty: u32,           // network PoW floor (NOT 0 — main.rs:216 fixed here)
}

impl LedgerService {
    pub fn open(dir: &Path, window: usize, difficulty: u32) -> Result<Self>; // replay files → Ledger::append (ledger.rs:54)
    pub fn tip_hash(&self) -> [u8; 32];                    // replaces the [0u8;32] at main.rs:220
    pub fn build_block(&self, epoch: Epoch, entries: Vec<LedgerEntry>) -> Block; // Block::new with REAL prev_hash
    pub fn ingest(&mut self, block: Block) -> Result<IngestOutcome>; // validate + append + persist file
    pub fn block_at(&self, epoch: Epoch) -> Option<&Block>;
}
```

- Persistence: `<state>/ledger/<epoch>.block` (bincode + a 1-byte format version, per
  F-24 §6.7), replayed through `Ledger::append` on open so every restart re-validates
  Merkle roots, chain links, and PoW (`ledger.rs:54-70`).
- `IngestOutcome` distinguishes `Appended` / `AlreadyHave` / `Fork` — fork handling in
  v0 is "reject and log"; real fork choice is committee work (Tier 5, §8.2).

### 3.4 Mode policy — Mission C's three modes as a type

Direct encoding of note 21 (`21-mission-c-and-modes.md`, "Traffic modes"):

```rust
// mode.rs
pub enum Mode {
    /// DEFAULT. Defends the LOCAL adversary. Low latency, silent-when-idle,
    /// obfuscated transport. Honest cost: loses to the global observer.
    StealthRealtime,
    /// OPT-IN. Defends the GLOBAL observer. Constant-rate cover, batching,
    /// longer epochs. Honest cost: slow, chatty (a tell to a local watcher).
    AsyncAnonymous { epoch_secs: u64, rate: EmissionRate, epsilon_num: u32, epsilon_den: u32 },
    /// DEFERRED opt-in dial inside stealth: intermittent decoy bursts that
    /// break the local watcher's "active = talking" inference. NEVER labeled
    /// as global-observer resistance (note 21: trilemma forbids cheap faking).
    StealthWithDecoy { burst_rate: DecoyRate },
}

pub struct ModePolicy;
impl ModePolicy {
    /// What this epoch's emission must look like, independent of real demand.
    pub fn emission_plan(&self, mode: &Mode, epoch: Epoch, rng: &mut impl CryptoRng) -> EmissionPlan;
}

pub struct EmissionPlan {
    pub publish: bool,             // StealthRealtime: only if outbox non-empty
    pub min_entries: usize,        // AsyncAnonymous: CONSTANT (e.g. 16) even at zero demand
    pub bucket_mix: BucketMix,     // cover distribution across padding BUCKETS (F-5, §5.2)
    pub dp_extra: bool,            // apply add_dp_cover on top (dp.rs:129)
    pub jitter: Duration,
}
```

Semantics per mode:

- **StealthRealtime** — messages flush immediately (next tick, or a sub-epoch fast path
  over the ratchet transport channel, i.e. today's `darqual-tor` direct path); NO cover
  when idle (silence IS the stealth property); relies on the obfuscated transport
  (obfs4/Snowflake — Tier 5 engineering, §8.6) for the "is it Tor?" question.
- **AsyncAnonymous** — the headline mode. Every epoch emits exactly `min_entries`
  entries: real ones from the outbox first, `pad_block` cover for the rest
  (`cover.rs:74-78`), plus DP noise (`add_dp_cover`, fixed per §5.1), then a
  cryptographic shuffle. Zero demand and full demand are *byte-identical on the wire*.
  Overflow demand queues to later epochs — the latency IS the anonymity.
- **StealthWithDecoy** — StealthRealtime plus a Poisson-ish schedule of fake transport
  bursts shaped like real publishes. Deferred to a post-runtime increment, but the enum
  variant and the residual-leak doc string land now so the API doesn't churn.
- **Mode transitions leak** (note 21's open residual): `ModePolicy` exposes
  `transition(from, to) -> TransitionPlan` that ramps cover rate over N epochs instead
  of step-changing it. v0: linear ramp, documented as "mitigation, not solution."

### 3.5 TrafficScheduler + durable outbox

```rust
// outbox.rs — durable send queue (survives crash between compose and publish)
pub struct Outbox { dir: PathBuf }
pub struct QueuedSend {
    pub id: [u8; 16],
    pub peer_x_pub: [u8; 32],   // stored encrypted at rest — same wrapper as F-6, §4.4
    pub plaintext: Vec<u8>,     // encrypted at rest; ratchet-encrypted only at emission
}

// scheduler.rs
pub struct TrafficScheduler;
impl TrafficScheduler {
    /// Turn (plan, outbox drain) into concrete ledger entries.
    /// Real entries: ratchet-encrypt NOW (so ratchet state advances exactly once,
    /// at emission — not at queue time), keywheel label for `epoch` (F-4, §4.2),
    /// Envelope::Ratchet (F-20, §4.1), PoW at plan difficulty (block.rs:22).
    /// Cover entries: cover_entry_shaped() (F-5, §5.2) at the SAME difficulty.
    pub fn build_entries(
        &self, plan: &EmissionPlan, outbox: &mut Outbox,
        sessions: &SessionStore, wheels: &mut KeywheelStore,
        difficulty: u32, rng: &mut impl CryptoRng,
    ) -> Result<Vec<LedgerEntry>>;
}
```

Key invariant: **encrypt-at-emission.** Ratchet `encrypt()` mutates session state
(`ratchet.rs`), so it must happen exactly once per wire emission, immediately followed
by `SessionStore::save` (`session.rs:68`) — mirroring the F-1 discipline on the send
side. Queue time stores plaintext (at rest encrypted, §4.4), not ciphertext.

### 3.6 BlockSync — pull-gossip, not point-to-point

Today's fetch model requires knowing the sender's address (`main.rs:250-263`) — a
contact-graph leak. Replacement: nodes sync **whole epoch blocks from any/every peer**,
so fetching reveals nothing about who you talk to (everyone fetches everything; the
label match happens locally — the Talek "notify" pattern, `notify.rs:7-9`, unchanged).

```rust
// sync.rs
pub struct BlockSync<T: Transport> { transport: T, peers: Vec<PeerAddr> }
impl<T: Transport> BlockSync<T> {
    /// Serve our chain: respond to GetTip / GetBlock(epoch) requests.
    pub async fn serve(&self, ledger: SharedLedger) -> Result<()>;
    /// Each tick: ask peers for tips, pull blocks we lack, ingest.
    pub async fn pull_round(&self, ledger: &mut LedgerService) -> Result<SyncStats>;
    /// Push our freshly built block to all peers (fire-and-forget, jittered).
    pub async fn announce(&self, block: &Block) -> Result<()>;
}
```

- Wire messages (versioned, F-2 style byte tags): `0x01 GetTip`, `0x02 Tip{epoch,hash}`,
  `0x03 GetBlock{epoch}`, `0x04 BlockFrame{bytes}` — over the message-level `Transport`
  (§6.1), so the same code runs on TCP (tests) and Arti onion services (production).
- v0 topology: static peer list in `NodeConfig` (`.onion` addresses). Peer discovery /
  committee-directed placement is Stage 6 research (§8.2). This is honest: a static
  full-replication mesh already delivers "fetcher reveals nothing" for small networks.
- Bandwidth note: full replication is O(network × entries). Fine for a research network;
  the erasure/DA layer (`darqual-storage`) mounts here later — `sync.rs` is where DA
  sampling replaces "pull every block" (already-built lib, `da.rs`).

### 3.7 ReceivePipeline

Per ingested block, for each conversation:

1. **Label match** — `KeywheelStore` (§4.3) yields the expected label(s) for the block's
   epoch (current + previous, replacing the skew hack at `main.rs:277`); `Block::fetch`
   (`block.rs:128-134`) returns candidate envelopes. O(contacts), no trial-decrypt of
   the whole block (that stays available as `sweep_window` fallback, `sweep.rs:20`).
2. **Envelope open** — `Envelope::decode` (F-20, §4.1): `Ratchet` → session
   trial-decrypt via `SessionStore` (the F-2 `handle_session` loop, generalized);
   `LockboxV2` → bootstrap path (`load_or_init_responder`, `session.rs:100-110`).
3. **Commit** — on success: `SessionStore::save`, advance+persist keywheel if the epoch
   moved (F-8, §4.3), deliver plaintext to the inbox channel. On failure: save nothing
   (F-1 discipline).

### 3.8 The Node — composition root + control plane

```rust
// lib.rs
pub struct Node<T: Transport> {
    config: NodeConfig,          // mode, epoch_secs, difficulty, state_dir, peers
    identity: Identity,
    clock: EpochClock,
    ledger: LedgerService,
    sessions: SessionStore,      // darqual-core/src/session.rs:28
    wheels: KeywheelStore,       // NEW, §4.3
    outbox: Outbox,
    scheduler: TrafficScheduler,
    sync: BlockSync<T>,
    policy: ModePolicy,
}

pub enum Command {                       // control plane (unix socket / channel)
    Send { peer: ContactCard, msg: Vec<u8> },
    SetMode(Mode),
    Status,                              // epoch, tip, outbox depth, peer health
    Shutdown,
}
pub enum Event { Received { peer_x_pub: [u8;32], msg: Vec<u8> }, EpochPublished(Epoch), ModeChanged(Mode) }

impl<T: Transport> Node<T> {
    pub async fn run(mut self,
        mut cmds: mpsc::Receiver<Command>,
        events: mpsc::Sender<Event>,
    ) -> Result<()> {
        let mut ticks = self.clock.ticks();
        loop {
            tokio::select! {
                Some(tick) = ticks.next() => {
                    let plan = self.policy.emission_plan(&self.config.mode, tick.epoch, &mut OsRng);
                    if plan.publish {
                        let entries = self.scheduler.build_entries(&plan, &mut self.outbox,
                            &self.sessions, &mut self.wheels, self.config.difficulty, &mut OsRng)?;
                        let block = self.ledger.build_block(tick.epoch, entries);
                        self.ledger.ingest(block.clone())?;
                        tokio::time::sleep(plan.jitter).await;
                        self.sync.announce(&block).await?;
                    }
                    let stats = self.sync.pull_round(&mut self.ledger).await?;
                    for block in stats.new_blocks {
                        self.receive_pipeline(&block, &events).await?;
                    }
                }
                Some(cmd) = cmds.recv() => { /* Send → outbox.enqueue; SetMode → policy.transition; ... */ }
            }
        }
    }
}
```

`darqual-node` becomes: `darqual-node daemon --mode async-anonymous` (constructs
`Node<ArtiTransport>` or `Node<TcpTransport>` behind a feature flag) plus `send`/
`status`/`mode` subcommands that talk to the daemon's control socket. The Stage-1/
Stage-9 demo subcommands (`main.rs:50-106`) are deleted, not maintained.

### 3.9 Testing strategy for the runtime

- **Deterministic sim harness:** `EpochClock` behind a trait (`tokio::time::pause()` +
  manual advance) + `TcpTransport` on localhost ⇒ multi-node integration tests that run
  N epochs in milliseconds. This is also the F-23 answer for `darqual-node` (§6.4).
- **Golden traffic-shape test:** run one node with zero demand and one with heavy demand
  in AsyncAnonymous for K epochs; assert the *serialized block byte-lengths and entry
  counts are identical* — the executable statement of the cover-traffic claim (F-5's
  acceptance test).
- **Crash-recovery test:** kill between encrypt and announce; on restart, assert no
  ratchet desync and no outbox loss.

## 4. TIER 1 — mission-critical crypto (F-3, F-4, F-20, F-6, F-8, F-12)

Ordering inside the tier: **F-20 → F-3 → F-4 → F-8 → F-6 → F-12.** F-20 is the data
structure F-3 rides on; F-8 is the state store F-4 rides on; F-6 and F-12 share one
at-rest encryption mechanism.

### 4.1 F-20 — versioned `Envelope` enum (prerequisite for everything)

**Problem:** `LedgerEntry.envelope` is documented as "raw UTF-8 bytes of the lockbox
envelope string" (`crates/darqual-ledger/src/block.rs:11-12`) and every consumer
hard-assumes it: `notify.rs:19-20` and `sweep.rs:13-14` do `str::from_utf8` →
`Lockbox::open`. A `RatchetMessage` (`ratchet.rs:100-105`) cannot ride in a ledger
entry at all — which is *why* the dead-drop path is stuck on Lockbox v1 (F-3).

**Fix — reuse F-2's byte-tagged versioning pattern** (`reviews/f2-scope.md` §2), but as
a typed enum in `darqual-core` (new module `envelope.rs`) since it crosses crates:

```rust
// darqual-core/src/envelope.rs
pub enum Envelope {
    /// 0x01 — legacy anonymous lockbox (v1 string envelope). DECODE-ONLY after
    /// migration: never emitted by the runtime; kept one release for old blocks.
    LockboxV1(String),
    /// 0x02 — Noise-IK lockbox v2 carrying bincode(RatchetMessage) as payload:
    /// the dead-drop BOOTSTRAP flight (exactly F-2's FRAME_BOOTSTRAP semantics).
    LockboxV2(String),
    /// 0x03 — bare bincode(RatchetMessage): established-session dead-drop flight
    /// (F-2's FRAME_SESSION semantics).
    Ratchet(Vec<u8>),
}

impl Envelope {
    pub fn encode(&self) -> Vec<u8>;                 // [tag u8][body]
    pub fn decode(bytes: &[u8]) -> Result<Envelope>; // unknown tag → Error::Encoding
}
```

- `LedgerEntry.envelope: Vec<u8>` keeps its type — the enum lives *inside* the bytes, so
  `canonical_bytes()` (`block.rs:35-41`), Merkle leaves, and PoW binding
  (`pow.rs:35-42` hashes label ++ envelope ++ nonce) are all untouched. No ledger or
  merkle code changes.
- **Cover parity constraint (feeds F-5):** cover entries must emit tags 0x02/0x03 in the
  same proportion as real traffic (§5.2) — a cover generator that only emits 0x01 would
  recreate the distinguishability bug one level up.
- `notify::fetch_open` (`notify.rs:13-23`) and `sweep::trial_decrypt` (`sweep.rs:8-17`)
  are rewritten to take `&SessionStore` + `&Identity` and dispatch on
  `Envelope::decode` — signature change ripples only to `darqual-node` (`main.rs:280`)
  and ledger tests.

### 4.2 F-3 — ratchet-over-dead-drops (the mission path gets the good crypto)

**Problem:** the async publish path seals with `Lockbox::seal` — v1: no sender auth, no
forward secrecy, no post-compromise security (`crates/darqual-node/src/main.rs:212-213`).
The demo Tor path meanwhile runs the full Double Ratchet. The *mission* path has the
*weakest* crypto — inverted priorities.

**Fix:** the dead-drop payload becomes exactly the F-2 wire design, transplanted from
the Tor frame into the ledger entry via `Envelope`:

*Send (in `TrafficScheduler::build_entries`, §3.5):*
1. `sessions.load_or_init_initiator(me, peer)` (`session.rs:86-96`).
2. `let rm = sess.encrypt(pt)?` — Double Ratchet, encrypted header.
3. First flight for this peer (no persisted session existed)? →
   `Envelope::LockboxV2(seal_authenticated(peer_x_pub, bincode(rm)))` — the receiver
   recovers our static key from *inside* the AEAD (`lockbox.rs:146-156, 279-289`), never
   from the wire. Established? → `Envelope::Ratchet(bincode(rm))`.
4. `sessions.save(&peer.x_pub, &sess)` BEFORE the entry leaves the scheduler.
5. `LedgerEntry::mint(keywheel_label, envelope.encode(), difficulty)` (`block.rs:22`).

*Receive (ReceivePipeline §3.7, per label-matched entry):*
- `LockboxV2` → `open_authenticated` → sender x_pub from AEAD →
  `load_or_init_responder` (`session.rs:100-110`) → decrypt → save. Identical to F-2's
  `handle_bootstrap`.
- `Ratchet` → we already know which peer this label belongs to (the keywheel that
  matched, §4.3), so decrypt against THAT session first; fall back to the F-2
  trial-decrypt loop across `SessionStore::list()` only if it fails. F-1's
  clone-and-commit makes wrong-session trials side-effect-free (`ratchet.rs:342-367`).

**Deliberate non-goal:** no new cryptography. This is plumbing existing, tested
primitives (ratchet + lockbox v2) into the ledger path. The Tor real-time path and the
dead-drop path end up running the *same* session objects from the *same* `SessionStore`
— one crypto stack, two transports, which is Mission C's mode model in code.

### 4.3 F-4 — keywheel labels on the publish path (+ KeywheelStore)

**Problem:** publish derives its dead-drop label from the static PRF —
`conv.label(epoch)` at `main.rs:208`, backed by `blake3::keyed_hash(shared_secret, ...)`
(`conversation.rs:69-79`). The shared secret is *static*: seize the device at any time
and every past and future label is computable — the "forward-secret metadata" headline
(SPEC §2, THREAT-MODEL "keywheel" row) is void for running code. The keywheel that fixes
this exists (`keywheel.rs`) and has zero call sites outside tests.

**Fix:** all label derivation in the runtime goes through a persisted `KeywheelStore`
(new, `darqual-core/src/keywheel_store.rs`, file layout mirroring `SessionStore`):

```rust
pub struct KeywheelStore { dir: PathBuf }  // <state>/keywheels/, encrypted at rest (§4.4/§4.5)

impl KeywheelStore {
    /// First contact: seed from conversation secret at the CURRENT epoch
    /// (Conversation::keywheel, conversation.rs:96-98), persist immediately.
    /// Thereafter: load-advance-save only. NEVER re-seed an existing wheel —
    /// re-derivation from the static secret is exactly the F-8 bug.
    pub fn wheel_for(&mut self, me: &Identity, peer: &ContactCard, now: Epoch) -> Result<Keywheel>;
    /// Labels to watch for a block at `epoch`: label_at(epoch) and
    /// label_at(epoch-1) via clone-ahead (keywheel.rs:124-136) — replaces the
    /// static-PRF skew fallback at main.rs:277.
    pub fn expected_labels(&self, peer_x_pub: &[u8;32], epoch: Epoch) -> Result<Vec<Label>>;
    /// On epoch tick: advance every wheel to `now`, persist, drop old state.
    pub fn advance_all(&mut self, now: Epoch) -> Result<()>;
}
```

- `Conversation::label` (`conversation.rs:69-79`) is demoted: `#[deprecated]` for the
  send path, retained only as the *bootstrap* label for the very first epoch of a brand-
  new conversation where both sides must converge with no prior state (sender publishes
  under the seeded wheel's epoch-N label; the receiver's `wheel_for` seeds at the same
  network-global epoch, so they agree — same symmetry as `keywheel_label_is_symmetric`,
  `keywheel.rs:159-169`).
- Late-message policy: a wheel advanced past epoch E cannot re-derive E's label
  (`keywheel.rs:124-127` returns `None`) — that's the security property, not a bug. The
  runtime therefore keeps a bounded **lookback buffer of derived labels** (labels only,
  not states — labels are public-ish once used) for the last `W` epochs to match
  stragglers, then discards. W = hot-window size, default 8.

### 4.4 F-8 — keywheel forward secrecy: derive-once, advance-only

**Problem:** every current keywheel use re-derives the wheel from the *static* shared
secret on demand — `Conversation::keywheel(start_epoch)` (`conversation.rs:96-98`) calls
`Keywheel::from_seed(&self.shared, start_epoch)` (`keywheel.rs:100-107`). The ratchet
inside the wheel is one-way, but as long as the caller can re-run `from_seed`, *any*
past state is re-derivable from the identity key: the forward secrecy is theater.
Compromise of `identity.toml` ⇒ all historical labels, exactly what the keywheel exists
to prevent.

**Fix (mechanism — the store in §4.3 is the vehicle):**
1. `Keywheel::from_seed` visibility stays `pub(crate)` (`keywheel.rs:100`), and its only
   production caller becomes `KeywheelStore::wheel_for` on the *first-contact* path.
   Enforced by a `#[cfg(test)]`-gated escape hatch for the existing symmetry tests.
2. `Keywheel` gets `Serialize`/`Deserialize` (state + epoch; both already there,
   `keywheel.rs:50-55`) + `ZeroizeOnDrop` semantics preserved (`keywheel.rs:58-62`).
3. On every epoch tick: `advance()` (`keywheel.rs:110-113`) → persist → old state
   overwritten on disk (write-tmp-rename, same as `session.rs:68-81`; the tmp file is
   the fsync boundary).
4. **The residual that must be documented:** the wheel is seeded from the static-static
   DH, so an attacker holding `identity.toml` + the *peer list* can re-seed a fresh
   wheel from the current epoch onward (future labels). Forward secrecy protects the
   PAST only — matches the ratchet's guarantee, and THREAT-MODEL.md must say so (§7).

### 4.5 F-6 — sessions (and all secret state) AEAD-wrapped at rest

**Problem:** `SessionStore::save` writes bincode of the full `RatchetSession` — root
key, chain keys, DH secret, skipped message keys (`ratchet.rs:111-131`) — as cleartext
`fs::write` (`session.rs:68-81`); the module doc openly defers this (`session.rs:10-16`).
Device seizure yields every active session.

**Fix — one shared at-rest wrapper in `darqual-core` (new `atrest.rs`), used by
sessions, keywheels (§4.3), and the outbox (§3.5):**

```rust
// Key hierarchy: one storage root key, derived from the identity's x25519 secret.
//   srk        = blake3::derive_key("darqual storage-root v1", x_secret_bytes)
//   file_key   = blake3::keyed_hash(srk, filename_nonce)   // per-file, see F-12
// Blob format: [MAGIC "dqsr1"][nonce 12][AEAD(file_key, nonce, bincode(payload))]
pub struct AtRestKey([u8; 32]);           // ZeroizeOnDrop
impl AtRestKey {
    pub fn from_identity(id: &Identity) -> Self;
    pub fn seal(&self, file_nonce: &[u8], plaintext: &[u8]) -> Vec<u8>;
    pub fn open(&self, file_nonce: &[u8], blob: &[u8]) -> Result<Vec<u8>>;
}
```

- AEAD = ChaCha20-Poly1305, same as everything else in the stack (`lockbox.rs:57-60`) —
  no new primitive.
- **Honest limitation (document, don't hide):** the wrapping key is derived from
  `identity.toml`, which sits in the *same* `~/.darqual/` directory at the same 0600
  protection. This defeats *partial* seizure (backup of `sessions/` alone, sync tools,
  misconfigured perms) and prepares the real fix — a passphrase-KDF'd or OS-keystore
  root key — which is a **client obligation** (CLIENT-OBLIGATIONS.md, §7): the protocol
  layer exposes `AtRestKey::from_external(key)` so a client can supply a
  keystore-backed root.
- Migration: `SessionStore::load` (`session.rs:56-65`) sniffs the `dqsr1` magic; legacy
  cleartext files are read once, re-saved encrypted, originals shredded (best-effort
  overwrite + unlink). One release later, cleartext read support is deleted.

### 4.6 F-12 — session filenames are the contact graph

**Problem:** one file per peer named `hex(peer_x_pub).bin` (`session.rs:51-53`). `ls
~/.darqual/sessions/` = the complete contact list in cleartext, surviving even after
F-6 encrypts the *contents*. Worse, F-2's new `SessionStore::list()` **depends** on the
hex filename to recover the peer key (`session.rs:117-139` decodes the file stem) — so
the fix must rework `list()`, not just rename files.

**Fix — random filenames; peer key moves inside the encrypted blob:**

```rust
// New on-disk record (inside the F-6 AEAD):
struct SessionRecord { peer_x_pub: [u8; 32], session: RatchetSession }

// Filename: hex(random 16 bytes), generated once at first save, remembered via
// an in-memory index built by scanning the dir at open():
pub struct SessionStore {
    dir: PathBuf,
    key: AtRestKey,
    index: HashMap<[u8; 32], PathBuf>,   // peer_x_pub → file (loaded at open)
}
```

- `open()` reads every `*.bin`, decrypts, builds `index` — O(contacts), paid once per
  process. `path_for` (`session.rs:51`) is replaced by an index lookup +
  `random-name-on-miss`. The file's random name doubles as the F-6 `filename_nonce`,
  binding blob to filename (a swapped/copied file fails AEAD open — tamper-evidence for
  free).
- **`list()` rework (the F-2 dependency):** signature unchanged —
  `list() -> Result<Vec<([u8;32], RatchetSession)>>` — but implemented as "decrypt each
  file, return `record.peer_x_pub`" instead of hex-decoding stems. The junk-skip
  behaviour (`session.rs:128-133`, tested at `session.rs:401-431`) becomes "skip
  files that fail magic-sniff or AEAD" — the tests' *assertions* survive, their
  planted-junk fixtures change from bad-hex names to bad-content files.
- Deterministic-name alternative (`blake3(srk, peer_x_pub)` filenames) was considered
  and rejected: it avoids the index but lets anyone holding `srk` *confirm* a suspected
  contact by filename without reading file contents — random names + index is strictly
  better for one HashMap of cost.
- Same treatment applies to `KeywheelStore` (§4.3) and `Outbox` (§3.5) from day one —
  they are new code and never ship the leaky layout.

## 5. TIER 2 — math + traffic (F-11, F-5)

### 5.1 F-11 — broken DP mechanism → integer-arithmetic discrete Laplace

**Problem (two independent breaks in `crates/darqual-cover/src/dp.rs`):**

1. **Float sampling.** `discrete_laplace` samples geometrics via
   `(u.ln() / q.ln()).floor()` on `f64` (`dp.rs:71-98`). Floating-point inverse-CDF
   sampling does not produce the claimed distribution: `f64` has non-uniform gaps, `ln`
   is correctly-rounded-ish but not exact, and the achievable outputs form a
   distinguishable subset — the class of attack Mironov ("On Significance of the Least
   Significant Bits," CCS 2012) demonstrated against float-Laplace DP. The stated ε is
   simply not delivered.
2. **Asymmetric clamping.** `noisy_cover_count` computes `max(0, 1 + noise)`
   (`dp.rs:109-118`). With base = 1, nearly half the noise mass hits the clamp: the
   output distribution around a slot with real activity vs without is no longer an
   ε-DP pair — the truncation is exactly the "asymmetric clamping breaks ε" finding.

**Fix — Canonne–Kamath–Steinke 2020 ("The Discrete Gaussian for Differential Privacy",
already cited at `dp.rs:28-29`), whose §Alg. 2 gives an *exact*, integer/rational-only
discrete-Laplace sampler:**

```rust
// dp.rs (rewritten) — no f64 anywhere; rng: impl CryptoRng + Rng
/// ε = eps_num / eps_den  (rational — callers pass e.g. (1,1) for ε=1).
pub fn discrete_laplace(eps_num: u64, eps_den: u64, rng: &mut (impl CryptoRng + Rng)) -> i64
```

Implementation (CKS Alg. 2, verbatim structure):
1. `bernoulli_exp(num, den)` — exact sampling of Bernoulli(exp(−num/den)) using only
   integer comparisons on uniform draws (CKS Prop. 25: for γ ≤ 1 accept via the
   alternating-series trick; for γ > 1 chain ⌊γ⌋ Bernoulli(e⁻¹) factors).
2. Geometric via repeated `bernoulli_exp` (CKS Alg. 2 lines 3–9), sign via fair coin,
   reject 0-with-negative-sign; output `sign * magnitude`.
3. Unit test against the exact pmf `P(k) = tanh(ε/2)·exp(−ε|k|)` by chi-square on ~10⁶
   draws, plus the existing shape tests (`dp.rs:156-219`) ported to rational ε.

**Clamping fix:** raise the base so truncation is negligible *and account for it*:

```rust
/// base B chosen so P(B + noise < 0) ≤ 2⁻⁶⁴:  B = ⌈64·ln2 / ε⌉  (tail of DLap).
pub fn noisy_cover_count(eps_num: u64, eps_den: u64, rng: ...) -> usize
```

For ε = 1 that is B ≈ 45 cover entries per noised slot per epoch — the honest
bandwidth price of the Vuvuzela mechanism (their deployment used comparable means).
This cost lands in `EmissionPlan.min_entries` (§3.4) so AsyncAnonymous mode budgets it
explicitly; the doc comment's per-epoch composition note (`dp.rs:31-37`) gains a
concrete ledger: the runtime tracks cumulative `T·ε` and surfaces it in `Status` (§3.8).
`Mode::AsyncAnonymous` carries ε as `(epsilon_num, epsilon_den)` (§3.4) for this reason.

### 5.2 F-5 — cover traffic distinguishable from real traffic

**Problem (three distinguishers in `crates/darqual-cover/src/cover.rs`):**

1. **PoW = 0.** `cover_entry` mints with `difficulty = 0` (`cover.rs:66`) — the module
   doc itself flags it (`cover.rs:17-21`). Once the network enforces difficulty > 0,
   every zero-work entry is cover *by inspection of one hash*.
2. **v1-only shape.** Cover seals a `Lockbox::seal` (v1) envelope (`cover.rs:62`). After
   F-20/F-3, real mission traffic is tag 0x02/0x03 (`Envelope::LockboxV2/Ratchet`) —
   cover would be the only 0x01 traffic on the network: perfectly distinguishable.
3. **Single bucket.** Cover is always a 1-byte plaintext → the 256 B bucket
   (`cover.rs:59-64`); real traffic spans `BUCKETS = [256, 1024, 4096, 16384, 65536,
   262144]` (`padding.rs:25`). Every non-256 B entry is real by inspection of length.

**Fix — cover must be sampled from the same (tag × bucket × work) distribution as
real traffic:**

```rust
// cover.rs (rewritten)
pub struct CoverShape {
    pub tag_mix: [(EnvelopeTag, u16); 2],  // e.g. [(Ratchet, 90%), (LockboxV2, 10%)]
    pub bucket_weights: [u16; BUCKETS.len()], // fixed network-wide constant, NOT
                                              // per-node empirical (see note below)
}

pub fn cover_entry_shaped(shape: &CoverShape, difficulty: u32,
                          rng: &mut (impl CryptoRng + Rng)) -> LedgerEntry
```

- **Tag 0x03 cover (`Ratchet`):** a synthetic `RatchetMessage` with
  `enc_header = random(12 + 40 + 16)` (nonce ‖ AEAD of the 40-byte header,
  `ratchet.rs:90-105`) and `ciphertext = random(12 + bucket + 16)`. AEAD ciphertext is
  indistinguishable from uniform randomness without the key, so random bytes of the
  correct length are a perfect decoy — no throwaway ratchet needed.
- **Tag 0x02 cover (`LockboxV2`):** keep today's throwaway-recipient construction
  (`cover.rs:55-57` — real seal to a discarded key) but via `seal_authenticated` with a
  throwaway *sender* identity too, plaintext = random bytes padded to the sampled
  bucket. Structurally valid, openable by nobody.
- **Work parity:** `LedgerEntry::mint(label, envelope, difficulty)` with the *network*
  difficulty (`block.rs:22`). This makes cover *expensive* — that is the design, and the
  cost multiplies with §5.1's B ≈ 45: PoW difficulty and DP base are now coupled dials
  that `EmissionPlan` must budget jointly (a difficulty a node can't grind 45×/epoch
  forces lower difficulty or longer epochs — surface this in `Status`).
- **Bucket weights are a network constant**, not learned from the node's own real
  traffic: shaping cover to your own send distribution leaks your send distribution.
  v0 ships a fixed prior (heavily weighted to 256/1024); revisiting it is measurement
  work, not code work.
- `cover_envelope_len()` (`cover.rs:32-40`) is deleted — there is no longer one
  canonical length. The size-parity test (`cover.rs:103-139`) becomes: *for each bucket,
  for each tag*, cover length == real length; plus the golden traffic-shape test in
  §3.9 as the end-to-end acceptance check.
- `pad_block` (`cover.rs:74-78`) keeps its signature but takes the shape + difficulty,
  and the scheduler **shuffles** real+cover before block build (the "callers should
  shuffle" comment at `cover.rs:72-73` becomes enforced code in §3.5, not advice).

## 6. TIER 3 — architecture/engineering (F-10, F-13, F-16, F-15, F-18, F-21, F-23, F-24, F-29)

These nine are **parallelizable debt** — none blocks another except where noted. Two of
them (F-10 transport trait, F-24 state versioning) are *prerequisites* the runtime
consumes, so they land in Phase 0 (§9); the rest slot in after Tier 0–2 or alongside them.
The four mechanical ones (F-15, F-18, F-21, and the version-byte half of F-24) are a single
afternoon between them.

### 6.1 F-10 — the transport trait is unusable and unused (effort: L)

**Problem — two independent defects.** The `Transport` trait
(`crates/darqual-net/src/transport/mod.rs:14-23`) is a *stream-level* abstraction whose
associated `Stream` type is bound to `tokio::io::AsyncRead + tokio::io::AsyncWrite`
(`mod.rs:15`). Arti's `DataStream` is a **futures-io** type; wiring it into this trait needs
a `tokio_util::compat` shim on every stream, and the trait then leaks the tokio/futures
split into every caller. Worse, the trait has **zero call sites**: the only `impl` is for
`TcpTransport` (`mod.rs:25-36`), and every actual network path uses concrete types instead —
`send_lockbox` dials a bare `tokio::net::TcpStream` (`lib.rs:27`), `serve_listener` accepts
on a concrete `TcpListener` (`lib.rs:64`), `serve_block`/`fetch_block` likewise
(`block_transport.rs:47,59,89`). The trait abstracts nothing and is instantiated nowhere.
Meanwhile `darqual-tor` re-implements the exact same length-prefixed framing a third time —
`write_frame`/`read_frame` at `darqual-tor/src/lib.rs:105-118` duplicate
`darqual-net/src/frame.rs:24-` byte-for-byte (u32-BE length prefix, `MAX_FRAME` cap).

**Fix — delete the stream-level trait; build a message-level one.** The runtime (§3.6)
only ever exchanges whole frames (`GetTip`/`BlockFrame`/…), never raw byte streams, so the
abstraction boundary belongs at the message layer where TCP and Arti actually agree:

```rust
// darqual-net/src/transport/mod.rs (rewritten)
pub enum PeerAddr {
    Tcp(String),        // "127.0.0.1:9000" — tests + LAN
    Onion(String),      // "<b32>.onion:9999" — production
}

/// One request/response of length-prefixed frames. Transport-agnostic:
/// the SAME BlockSync (§3.6) runs on TCP in sim tests and Arti in production.
pub trait Transport: Send + Sync {
    /// Dial `peer`, write one frame, read one frame back, close.
    fn send_frame(&self, peer: &PeerAddr, frame: Vec<u8>)
        -> impl Future<Output = Result<Vec<u8>>> + Send;
    /// Bind and yield inbound (frame, responder) pairs for a serve loop.
    fn incoming(&self, bind: &PeerAddr)
        -> impl Future<Output = Result<impl Stream<Item = (Vec<u8>, Responder)>>> + Send;
}
```

- `TcpTransport` impls it over `frame::{write_frame,read_frame}` (the existing, tested
  `frame.rs` module — one framing implementation, network-wide).
- `ArtiTransport` (in `darqual-tor`, workspace-excluded) impls it by wrapping the Arti
  `DataStream` in `tokio_util::compat::FuturesAsyncReadCompatExt` **once**, at the transport
  boundary, then reusing the identical `frame` codec — which **folds `darqual-tor`'s
  duplicate framing** (`lib.rs:105-118`) into the shared module. `darqual-tor` gains a
  `tokio-util` dep for the compat layer.
- Call-site migration: `send_lockbox`/`serve`/`serve_block`/`fetch_block` become thin
  wrappers over `Transport::send_frame`/`incoming`, so the JSON block codec
  (`block_transport.rs:61,91`) and the lockbox path share one dial/serve implementation.
  This is the L in the tier: ~all of `darqual-net`'s public surface moves behind the trait,
  and `BlockSync` (§3.6) is written against it from day one.

### 6.2 F-13 — serial accept loops let one slow peer stall everything (effort: M)

**Problem.** Both serve loops process connections **serially**: `serve_listener` accepts,
then `await`s the full `read_frame` (guarded only by a 30 s `CONN_TIMEOUT`) before accepting
the next connection (`lib.rs:63-73`); `serve_block_listener` is worse — it re-`serde_json`-
serialises the *entire block* inside the loop body per client and blocks the accept on the
write (`block_transport.rs:57-77`). A single peer that opens a connection and dribbles bytes
holds the listener for up to `CONN_TIMEOUT`; N such peers serialise to N×30 s. For a
gossip mesh (§3.6) where every node pulls from every peer each epoch, this is a
self-inflicted DoS.

**Fix.** `tokio::spawn` one task per accepted connection so the accept loop never blocks on
per-connection I/O, and **serialise the block once** outside the loop:

```rust
pub async fn serve_block_listener(listener: TcpListener, block: Block) -> Result<()> {
    let framed = Arc::new(serde_json::to_vec(&block)?);   // ONCE, not per-client
    loop {
        let (stream, peer) = listener.accept().await?;
        let framed = framed.clone();
        tokio::spawn(async move {                          // per-connection, non-blocking
            if let Err(e) = tokio::time::timeout(
                frame::CONN_TIMEOUT, frame::write_frame(&mut stream, &framed)).await { … }
        });
    }
}
```

Same treatment for `serve_listener` (`lib.rs:59-74`). Keep `CONN_TIMEOUT` per task; add a
bounded concurrent-connection semaphore so unbounded spawns can't OOM the node. When F-10
lands, this logic moves into `Transport::incoming`'s serve helper so both transports inherit
it.

### 6.3 F-16 — no CI; darqual-tor never compiled in gating (effort: M)

**Problem.** There is no `.github/` — nothing runs `verify.sh` on push, so the gated checks
exist only when someone remembers to run them locally. And `darqual-tor` is
workspace-excluded (`Cargo.toml:13-15`) precisely so `verify.sh` stays fast, which means the
Arti transport is **never built by any automated gate** — it can rot silently (it already
duplicates framing, §6.1, which no gate would catch).

**Fix — a GitHub Actions workflow mirroring `verify.sh` plus a separate tor job:**

```yaml
# .github/workflows/ci.yml
jobs:
  verify:              # mirrors verify.sh: fmt --check, clippy -D warnings, test --all
    steps: [checkout, {uses: dtolnay/rust-toolchain@stable}, {uses: Swatinem/rust-cache},
            "cargo fmt --all --check", "cargo clippy --all-targets -- -D warnings",
            "cargo test --workspace"]
  darqual-tor:         # the excluded crate gets its OWN check/build job
    steps: [checkout, rust-toolchain, rust-cache,
            "cargo check  --manifest-path crates/darqual-tor/Cargo.toml",
            "cargo build  --manifest-path crates/darqual-tor/Cargo.toml",
            "cargo test   --manifest-path crates/darqual-tor/Cargo.toml"]  # live-Tor tests stay #[ignore]d
```

The tor job pays Arti's ~350-crate compile once per CI run (cached across runs via
`rust-cache`), keeping it off the fast `verify` gate exactly as the workspace exclusion
intends — but now it *is* compiled, and the `onion_roundtrip` test
(`darqual-tor/src/lib.rs:130-132`) stays `#[ignore]`d so CI never needs a live Tor network.
`verify.sh` remains the local source of truth; the workflow is a mechanical mirror of it.

### 6.4 F-23 — the three binaries have no tests (effort: M)

**Problem.** `darqual-cli`, `darqual-node`, and `darqual-tor` ship zero test coverage of
their binary behaviour — the only test anywhere in the three is the `#[ignore]`d live-Tor
roundtrip (`darqual-tor/src/lib.rs:123-132`). The composition logic (argument parsing,
publish/fetch wiring, framing) is exercised by nothing.

**Fix.**
- `darqual-node`: the deterministic sim harness from §3.9 (paused `EpochClock` +
  `TcpTransport` on localhost) doubles as the integration test — spin two `Node`s, run K
  epochs, assert a message sent on node A is delivered on node B. This is the primary F-23
  answer and it comes free with Tier 0.
- `darqual-tor` framing: extract the frame codec (post-§6.1 it's the shared `frame` module)
  and test it over an **in-memory duplex** (`tokio::io::duplex()`) — full send/receive
  roundtrip with no Tor network, so it runs in the fast gate. The live path stays
  `#[ignore]`d.
- `darqual-cli`: `assert_cmd`-style smoke tests — keygen writes a 0600 `identity.toml`
  (`identity.rs:94-98`), address round-trips through `FromStr` (`address.rs:45-64`), bad
  args exit non-zero.

### 6.5 F-24 — bincode 1 for persisted session state, unversioned (effort: S–M)

**Problem.** `SessionStore` serialises the full `RatchetSession` with **bincode 1** and no
version tag (`session.rs:62,72`; dep `darqual-core/Cargo.toml` `bincode = "1"`). bincode's
encoding is not self-describing and not stable across a struct-layout change: add a field to
`RatchetSession` (`ratchet.rs`) — which Tier 1 will, for keywheel binding — and every
persisted session on disk becomes an undecodable blob with no version to branch on.
`darqual-tor` also uses bincode 1 on the wire (`darqual-tor/src/lib.rs`, `bincode = "1"`),
same fragility.

**Fix — a 1-byte format version, pinned codec.** This is the same mechanism §4.5 already
introduces for the at-rest wrapper (`[MAGIC "dqsr1"][…]`): the `dqsr1` magic *is* the
version tag. Concretely: `SessionStore::save` writes `[0x01][bincode(SessionRecord)]`;
`load` reads the leading byte, dispatches on it, and returns `Error::Encoding` on an unknown
version instead of a bincode panic (`session.rs:62`). Pin the wire contract by setting
explicit bincode options (fixint, little-endian, bounded) rather than the defaults, and add a
`serialize/deserialize` roundtrip test at each version. The version byte future-proofs the
Tier-1 `RatchetSession` field additions (F-4/F-8 add keywheel-epoch binding) — old files are
detected and migrated (§4.5's re-save-on-open path), never silently corrupted.

### 6.6 Mechanical group — F-15, F-18, F-21 (effort: S each)

**F-21 — no `[workspace.dependencies]`; 7 duplicated versions.** The root `Cargo.toml:1-15`
declares members but no `[workspace.dependencies]`, so common deps are re-pinned per crate:
`blake3 = "1"` in core/committee/cover/ledger/storage, `thiserror = "1"` in
core/committee/cover/ledger, `rand = "0.8"` in cover/core/storage, `serde` in core/ledger,
`tokio = { version = "1", … }` in net/node (and tor), `x25519-dalek = "2"` in
core/cover/ledger(dev), `bincode = "1"` in core (and tor). A version bump means editing five
files and risking a skew. **Fix:** hoist to `[workspace.dependencies]` in the root
`Cargo.toml` and replace each crate entry with `blake3.workspace = true` etc. Mechanical;
`darqual-tor` stays independent (it has its own `[workspace]`, `Cargo.toml`) and keeps its
pins. `verify.sh` catches any resolution break.

**F-18 — `Identity` secret fields are `pub`.** `signing_key: SigningKey` and
`x_secret: StaticSecret` are public fields (`identity.rs:26-29`), so any caller can move or
copy raw secret material out of an `Identity` and dodge the zeroize discipline the module
otherwise keeps (`identity.rs:82-83,115-116`). **Fix:** privatize both fields; the public
accessors already exist for the *public* halves (`ed_pub`/`x_pub`/`sign`,
`identity.rs:126-139`). Add a crate-internal borrow accessor `pub(crate) fn x_secret(&self)
-> &StaticSecret` for the DH call sites (lockbox/session), and a signing borrow if needed —
no secret bytes ever leave by value. Pure encapsulation change; the `Debug` impl already
redacts (`identity.rs:31-37`).

**F-15 — 160-bit address → 80-bit collision resistance.** `DarqualAddress::from_keys`
truncates `blake3(ed_pub ‖ x_pub)` to **20 bytes** (`address.rs:26`), and `FromStr` enforces
exactly 20 (`address.rs:58`). 160 bits gives ~80-bit collision resistance — comfortably
grindable for a *collision* (two identities sharing an address), though not a second-preimage
against a *given* address. **Fix — document, don't widen.** The address already commits to
the full Ed25519 signing key *and* the x25519 key (`address.rs:12-15`, `from_keys` hashes
both), and the `ContactCard` carries the full 32-byte keys — so the address is a *fingerprint
over authenticated keys*, and the security-relevant property is **second-preimage** (~160-bit
here), not collision. MITM requires forging a card whose full keys re-hash to a target
address: a second-preimage, not a birthday collision. **Prescription:** keep 20 bytes; add a
doc note to `address.rs:11-15` stating that (a) collision resistance is ~80-bit and
irrelevant to the substitution threat because the card binds the full keys, and (b) the
32-byte-widen option is available behind a format-version prefix if a future threat model
ever needs collision resistance. If the team prefers belt-and-suspenders, widen to 32 bytes —
but that is a wire-format change gated on the same version-byte discipline as F-24, so it is
*not* free and should be justified by threat, not reflex.

### 6.7 F-29 — missing proptests for pad/unpad and merkle proofs (effort: S–M)

**Problem.** `proptest` is already a dev-dep in both `darqual-core` and `darqual-ledger`
(`Cargo.toml` dev-deps) but the two highest-value invariants have only example-based tests.
`padding::{pad,unpad}` (`padding.rs:31,50`) is tested with a fixed bucket sweep and two
rejection cases (`padding.rs:178-195`) — no randomized roundtrip. And the Merkle layer
carries an **explicit unresolved audit note**: bare last-node duplication has the
**CVE-2012-2459** duplicate-leaf malleability (`merkle.rs:44-46`), yet `merkle_proof` /
`verify_proof` (`merkle.rs:71,112`) have no property coverage.

**Fix — add the two proptests:**
1. **pad/unpad roundtrip:** `∀ pt: Vec<u8>` (incl. empty and > largest bucket),
   `unpad(pad(pt)) == pt`, and `pad(pt).len() ∈ BUCKETS` (or a multiple of the largest,
   `padding.rs:33-40`). Plus a hostile-input strategy feeding random bytes to `unpad` and
   asserting it never panics — only `Ok`/`Err` (the `padding.rs:50` contract).
2. **Merkle proof soundness + CVE-2012-2459:** `∀ leaves, ∀ i`,
   `verify_proof(merkle_root(leaves), leaves[i], merkle_proof(leaves, i)) == true`, and any
   mutated leaf/sibling verifies `false`. Add a **directed** duplicate-leaf test that
   constructs the second-preimage tree the CVE exploits (append the duplicated
   odd-node pair) and asserts either the root differs or the proof is rejected — turning the
   `merkle.rs:44-46` audit note into an executable regression. If the property fails (it will,
   for the bare-duplication scheme), the fix is to tag interior vs leaf nodes with a domain
   separator byte before hashing — a small `merkle.rs` change the proptest then locks in.

## 7. TIER 4 — Mission C doc re-aim

**This is pure doc work — no code.** The decision is already made: Mission A (locked S222)
was superseded by **Mission C** (two-adversary layered model + three traffic modes) at S223,
and the full ground-up reasoning lives in `~/Jawz/notes/projects/anon-messenger-research/21-mission-c-and-modes.md`
(referenced throughout below as **note 21**). The docs never caught up: `SPEC.md:12` still
opens "Mission & what Darqual is" under Mission A, `SPEC.md:33,38` still frame anti-goals as
"Under Mission A," and `THREAT-MODEL.md` is single-adversary. Note 21's own trailing
checklist (`21-…:135-142`) is the authoritative TODO; this section is its execution plan,
file by file. Tier 4 is written **last** (§1) so the docs describe the system Tier 0–2 built,
with honest status columns.

**Hard rule for every file below:** the audit banner
(`THREAT-MODEL.md:3` — "RESEARCH PROTOTYPE. NOT AUDITED.") stays verbatim (§2). Nothing in
this re-aim may soften it.

### 7.1 SPEC.md — §1, §3, §3a → Mission C (note 21 §"Why C", §"The spine")

- **§1 "Mission"** (`SPEC.md:12-`): replace the single-adversary Mission-A statement with
  note 21's unifying sentence (`21-…:31-34`): *"Unobservable communication — hide both that
  the conversation happened (from the network) and that you're the one having it (from
  someone watching you)."* State the two adversaries explicitly as note 21's table
  (`21-…:38-43`): **Global Passive Observer (A)** — sees all network traffic, wants
  who-talks-to-whom; **Local Targeting Adversary (B)** — sees your link/device, wants
  *whether you use the tool at all*. Add the honesty boundary that they *don't compose for
  free* (`21-…:45-48`): the defenses fight (cover beats A but is the tell that outs you to B),
  which is the Anonymity Trilemma (Das et al., S&P'18) — cite it as note 21 does.
- **New §"Protocol, not product"** (from note 21 §"Scope", `21-…:51-68`): Darqual is the
  math + networking layer; the UI/client is the community's job, sorted on the wire-vs-screen
  line. This paragraph is what justifies CLIENT-OBLIGATIONS.md (§7.4) and must land in SPEC
  so the scope claim is normative, not a note.
- **§3 "Threat model"** (`SPEC.md:86-`): reframe as *per-adversary* — for each guarantee,
  which of A/B it defends (this is the same two-column structure THREAT-MODEL gets, §7.2;
  SPEC references it rather than duplicating).
- **§3a "Anti-goals"** (`SPEC.md:38-`): the current "Under Mission A, these are out of scope"
  becomes note 21's **refusal list** (`21-…:70-75`): live endpoint compromise (Pegasus-grade)
  is *permanently, forever* out — no wire defense touches on-screen plaintext; client-layer
  threats (app discoverability, panic UX, secure-storage UI) are **delegated to the community
  client with published obligations** (§7.4), not silently dropped. Keep the "honesty is the
  first security property" framing (`SPEC.md:40`) — it is exactly note 21's tone.
- **Modes** — add a SPEC subsection introducing the three traffic modes as a *user-selectable
  per-conversation* choice (note 21 §"Traffic modes", `21-…:79-125`), cross-referencing the
  `Mode` enum the runtime now implements (§3.4, `mode.rs`). Each mode names the adversary it
  beats and its honest cost. This closes the gap where SPEC's status columns (🟡 "lib only")
  had no mode vocabulary to describe *which* guarantee a running node delivers.

### 7.2 THREAT-MODEL.md — two-column "which adversary" + modes section

- **Two-column goal table.** Convert the single-adversary goal list into a table with a
  column per adversary (Global Passive **A** / Local Targeting **B**) and, per goal, a cell
  stating *by which mechanism* it is defended against that adversary — or "✗ does not defend"
  (the honest cells are the point). This is note 21's checklist item `21-…:138` and mirrors
  the adversary table at `21-…:38-43`.
- **Modes section** (note 21 §"Traffic modes"): document all three with their honest costs
  verbatim in spirit — **Stealth-Realtime** (default, beats B, *loses to A*: realtime+bursty
  is end-to-end timing-correlatable, obfs4 is an arms race not a wall, `21-…:85-93`);
  **Async-Anonymous** (opt-in, beats A, the only mode that delivers the headline, *slow &
  heavy & its constant cover is the tell to B*, `21-…:95-103`); **Decoy** (deferred opt-in
  inside stealth, breaks a local watcher's "active = talking" inference, **never** labeled as
  global-observer resistance, `21-…:105-119`).
- **Two documented residuals** THREAT-MODEL must now carry, both from note 21 and both
  surfaced by Tier 0–1 code: (a) **mode-transition leak** — flipping silent→constant-cover is
  itself a signal to a local watcher (`21-…:127-131`); the runtime's `ModePolicy::transition`
  ramp (§3.4) is the mitigation, "not solution." (b) **keywheel forward secrecy is
  past-only** — an attacker with `identity.toml` + peer list can re-seed future labels
  (§4.4); THREAT-MODEL must say the keywheel row protects the *past*, matching the ratchet.
- Keep `THREAT-MODEL.md:3` banner unchanged (§2).

### 7.3 README.md — safety banner: two-adversary + protocol-not-product

Rewrite the SAFETY banner to the two-adversary + protocol-not-product framing (note 21
checklist `21-…:139`). Two sentences it must contain: (1) *"Darqual defends against two
different adversaries with two different modes; each mode names the one it beats and the one
it does not"* — no single config, because forcing one config quietly overclaims (the Mission
A sin, `21-…:82-83`). (2) The honest scope claim verbatim from note 21 `21-…:66-68`: *"we
provide the protocol layer that makes a safe client POSSIBLE and publish the obligations; we
do not and cannot guarantee any given client is safe."* Link to CLIENT-OBLIGATIONS.md.

### 7.4 NEW — CLIENT-OBLIGATIONS.md (the contract a community client must meet)

The new honesty boundary Mission C forces (note 21 `21-…:63-68`): a perfect protocol under a
sloppy client still gets a user killed (client backs up contacts to iCloud → done). This file
is the **normative contract** a community UI must satisfy to be allowed to call itself a
Darqual client. Minimum clauses, each traceable to a protocol affordance built above:

- **No cloud backup** of identity or contacts. (Protocol side: identity is a single 0600
  `identity.toml`, `identity.rs:94-98`; the client must not sync it.)
- **Local key storage with wipe**, ideally OS-keystore-backed. The protocol exposes the seam:
  `AtRestKey::from_external(key)` (§4.5) lets a client supply a keystore/passphrase root key
  instead of the identity-derived default. The obligation is that the client *uses* it.
- **No analytics / no telemetry.**
- **Honest tool-detectability disclosure** — the client must tell the user which mode is
  active and which adversary it does *not* defend (Stealth loses to A; Async is a tell to B).
- **Deniable-storage / fast-wipe primitives are exposed, not guaranteed** — the client owns
  the panic/duress UX (note 21's wire-vs-screen split, `21-…:55-61`); the protocol only
  provides the primitive.

Frame the file as note 21 frames it (`21-…:63-68`): the protocol makes a safe client
*possible* and publishes this contract; it cannot enforce it. This file is also a **§2
precondition** for closed-beta — testers can't be invited until it exists so they know what
the client layer does not protect.

### 7.5 ROADMAP.md — stack ordering (the fork is dead; it's a stack)

Rewrite the roadmap from an A-vs-B fork to note 21's **stack** (`21-…:141-142`), in
dependency order: **content anonymity (done)** → **contact-graph privacy** (Tier 1 F-4/F-12,
the current SPEC §2 🟡 gap #1) → **transport obfuscation** (obfs4 / Snowflake into Arti,
Tier 5 §8.6) → **offline transport** (BT/LAN mesh, Tier 5) → **deniable primitives**. This
ordering is not cosmetic: each layer is only meaningful once the one below it runs, and it
matches the execution roadmap in §9. Mark external audit + closed beta as
**out-of-scope preconditions** here too (§2), so the roadmap and this design agree.

## 8. TIER 5 — research stubs (approach per item)

**These are not bugs.** They are honest, documented, unbuilt deep-ends — the difference
between "we shipped a broken X" and "we have not built X and say so." Each item below gets:
the honest approach, whether it's **tractable now** (a hard month of engineering) or
**genuinely blocked** (an open research question no amount of engineering closes), and — the
load-bearing distinction — **whether the Tier 0 runtime unblocks it.** The pattern: most of
these were blocked not by their own difficulty but by having *nowhere to run*; the runtime
(§3) is what turns several from "blocked" into merely "hard."

| Item | Class | Runtime unblocks? |
|---|---|---|
| §8.1 RLN/DPF zk rate-limiting | hard month (integration) → open (params) | yes — needs the epoch clock + ledger |
| §8.2 Anytrust per-epoch committee | **open research (the paper)** | partially — gives it a place to run, not an answer |
| §8.3 IBE add-friend (Alpenhorn/BLS12-381) | hard month | no — orthogonal to the runtime |
| §8.4 Loopix/Sphinx mixing | hard month (Sphinx) → open (mixnet ops) | yes — BlockSync is the mount point |
| §8.5 Sybil-resistant participant set | **open research (governance)** | no — social/economic, not code |
| §8.6 Transport obfuscation (obfs4/Snowflake) | hard month (integration) | yes — `Transport` trait is the seam |

### 8.1 RLN / DPF — zero-knowledge rate limiting

**Honest approach.** Anonymous publishing to the ledger needs a way to stop a single actor
flooding an epoch without deanonymizing anyone. Two real primitives: **RLN** (Rate-Limiting
Nullifiers — a Semaphore-style zk membership proof plus a per-epoch nullifier that slashes a
secret share on the *second* message, so one-per-epoch is enforceable without identity) and
**DPF** (Distributed Point Functions, the Express/Riposte write-privacy primitive). RLN is the
better first fit: the ledger already has an epoch (`epoch.rs:7`) and a per-entry PoW slot
(`block.rs:22`), and RLN's nullifier is epoch-scoped by construction.

**Tractable now? Hard month, not open.** The cryptography exists and is deployed (RLN ships
in production at Waku). The work is integration: a circuit + proof verification hung off
`LedgerEntry` validation, replacing/augmenting PoW as the anti-flood gate. The *open* part is
only parameter choice (rate, tree depth, membership-set governance — which bleeds into §8.5).

**Runtime unblocks it: yes.** RLN is meaningless without a real per-epoch validation
lifecycle — exactly what `LedgerService::ingest` (§3.3) and the epoch clock (§3.2) provide.
Today there is no epoch loop to scope a nullifier to. Do this *after* Tier 0.

### 8.2 Anytrust per-epoch committee protocol — **the novel core**

**Honest approach.** This is the actual research contribution and the actual paper question:
an **anytrust** committee (secure if ≥1 member is honest, the Vuvuzela/Karaoke trust model),
re-elected per epoch via VRF, that collectively performs the mix/shuffle and certifies the
epoch block — replacing today's single-publisher, single-genesis-block model
(`main.rs:220`, `prev_hash = [0u8;32]`). The pieces that exist are *sketches*: the VRF
election (`darqual-committee/src/vrf.rs`, `election.rs`) and the "reject-and-log fork
handling" placeholder the runtime ships (§3.3, `IngestOutcome::Fork`).

**Tractable now? Genuinely blocked — this is an open research question, not engineering.**
The hard parts are unsolved *for this system*: committee key-agreement and threshold
mix under churn, the per-epoch handoff protocol, what "certifies the block" cryptographically
means, and fork choice when committees disagree. This is a distributed-systems + cryptography
*paper*, not a sprint. Everything else in this document is deliberately scoped to *not*
require solving it — the runtime ships single-node full-replication (§3.6) precisely so the
system is a credible research artifact *before* the committee protocol is designed.

**Runtime unblocks it: partially.** Tier 0 gives the committee a place to run (an epoch loop,
a persistent chain, a gossip mesh, a `Fork` outcome to make real) — it removes the "nowhere
to run" blocker but does **not** touch the research blocker. This is the honest ceiling: the
runtime makes the committee *buildable* once the protocol is *designed*; it cannot design it.

### 8.3 IBE add-friend (Alpenhorn, pairing crypto BLS12-381)

**Honest approach.** Adding a contact without leaking *who you added* to a network observer —
the Alpenhorn "add-friend / dialing" protocol, built on Identity-Based Encryption over a
pairing-friendly curve (**BLS12-381**). Today contact exchange is out-of-band `ContactCard`
sharing (`contact.rs`); Alpenhorn makes the *introduction* itself metadata-private.

**Tractable now? Hard month, not open.** The protocol is published (Lazar & Zeldovich, OSDI
'16) and BLS12-381 has mature Rust libraries (`blstrs`/`arkworks`). The work is real —
pairing crypto is a new primitive class for this codebase (everything today is
25519/ChaCha/BLAKE3, `lockbox.rs:57-60`), so it's a new dependency, a new key type, and an
IBE-PKG trust decision — but it is engineering against a known design.

**Runtime unblocks it: no.** Add-friend is orthogonal to the epoch loop; it rides the same
dead-drop transport but its blocker is "we haven't written pairing crypto," which the runtime
doesn't touch. Sequence it independently, after the mission path (Tier 1) proves out.

### 8.4 Loopix / Sphinx mixing

**Honest approach.** Real mixing for Async-Anonymous mode: **Sphinx** packet format (constant
per-hop size, unlinkable) routed through a **Loopix** stratified mixnet with Poisson mixing
and loop cover. Today's "mix" is a single-block cover-pad-and-shuffle (§5.2, `cover.rs`) — a
one-hop approximation. Loopix/Sphinx is the multi-hop version that actually breaks
sender-receiver linkability against a global observer.

**Tractable now? Sphinx itself is a hard month; the mixnet is open-ish.** The Sphinx packet
format is well-specified and has reference implementations — encodable as engineering. The
*operational* mixnet (running mix nodes, stratified topology, the same node-membership /
who-runs-a-mix problem as §8.2/§8.5) is where it gets research-shaped. First increment:
Sphinx packets over the existing `BlockSync` transport (§3.6), single logical mix layer, then
grow layers.

**Runtime unblocks it: yes.** `BlockSync`/`Transport` (§3.6, §6.1) is the mount point — Sphinx
packets are just framed messages over the same trait. Note 21 names Loopix/Vuvuzela as the
Async-Anonymous reference (`21-…:97`), so this is the mode's eventual real implementation,
replacing §5.2's single-block approximation.

### 8.5 Sybil-resistant participant set

**Honest approach.** Every anonymity guarantee above assumes an adversary can't just *be* most
of the network — anonymity loves company, and fake company is worse than none. Who is allowed
into the membership set (§8.1's RLN tree, §8.2's committee, §8.4's mixnet)?

**Tractable now? Genuinely blocked — open research, and partly non-technical.** Sybil
resistance has no clean technical answer for a permissionless anonymity network: proof-of-work
(centralizes to hardware), proof-of-stake (centralizes to capital + needs a token), social-
graph / web-of-trust (leaks the graph — the exact thing Darqual hides), or a trusted
gatekeeper (kills the trust model). This is governance + economics as much as cryptography.
**Document it as a known open problem and a stated assumption** (the membership set is
externally provisioned in v0), not a thing v0 solves.

**Runtime unblocks it: no.** It's upstream of all the code — a design/governance decision the
runtime inherits rather than enables.

### 8.6 Transport obfuscation (obfs4 / Snowflake into Arti) — the Stealth-mode engineering

**Honest approach.** Stealth-Realtime mode's core claim (a local watcher can't tell it's Tor,
note 21 `21-…:87`) requires pluggable transports: **obfs4** ("look like noise") and
**Snowflake** ("look like WebRTC") in front of the Arti channel (`darqual-tor/src/lib.rs`).

**Tractable now? Hard month, integration.** Arti has growing pluggable-transport support;
this is wiring + testing, not new crypto. The honest caveat note 21 insists on
(`21-…:92-93`): obfs4 raises detection *cost*, it is not a wall — an arms race, and the docs
must say so (§7.2).

**Runtime unblocks it: yes, via the seam.** The message-level `Transport` trait (§6.1) is
exactly the injection point — obfs4/Snowflake become alternate `Transport` impls the binary
selects, the runtime unchanged. This is the first Tier-5 item to pick up because it is pure
engineering, it directly serves the *default* mode, and F-10 already builds its seam.

## 9. Ordered execution roadmap

**Thesis (from §1, §3): `darqual-runtime` is the trunk; everything branches off it.** The
empty center is why every 🟡 in SPEC §2 is yellow, and why the mission path runs the weakest
crypto — there is no process to host the good crypto's lifecycle. So the plan is not "fix the
findings in severity order"; it is "grow the trunk, then graft each branch onto it in
dependency order." Two branches (F-10, F-24) are grown *before* the trunk because the trunk
consumes them.

### Phase 0 — pre-trunk prerequisites (parallel, cheap, unblock Tier 0)

Everything the runtime imports on day one, none of it dependent on the runtime:

| Finding | One-line | Effort |
|---|---|---|
| **F-10** message-level `Transport` trait + `PeerAddr`, fold in tor framing (§6.1) | L | ← runtime's `BlockSync` is written against it |
| **F-24** version-byte + pinned bincode codec for persisted state (§6.5) | S–M | ← runtime's `LedgerService`/`SessionStore` persist through it |
| **F-21** `[workspace.dependencies]` (§6.6) | S | mechanical, do first |
| **F-18** privatize `Identity` secrets (§6.6) | S | mechanical |
| **F-15** document 20-byte address rationale (§6.6) | S | doc-only |

Phase 0 ships nothing user-visible but is the **critical-path entry**: F-10 gates the runtime.

### Phase 1 — TIER 0: the trunk (`darqual-runtime`, §3)

The one new crate: epoch clock (§3.2), `LedgerService` persistent chain (§3.3), `Mode`/
`ModePolicy` (§3.4), scheduler + durable outbox (§3.5), `BlockSync` pull-gossip (§3.6),
`ReceivePipeline` (§3.7), `Node` composition root (§3.8), deterministic sim harness (§3.9).
`darqual-node` becomes a thin CLI over it. **This is the single largest work item and the spine
of the critical path** — F-3/F-4/F-5/F-8 are literally unfixable-in-practice without it (§1).
Effort: **L (the biggest L).**

### Phase 2 — TIER 1: crypto into the mission path (§4)

Strictly ordered inside the tier: **F-20 → F-3 → F-4 → F-8 → F-6 → F-12** (§4 intro). F-20
(versioned `Envelope`) is the data structure F-3 rides; F-8 (keywheel derive-once store) is
the state F-4 rides; F-6/F-12 share one at-rest wrapper (`atrest.rs`). This is where the
"good crypto is wired into the wrong pipe" defect (§1.2) is finally corrected: the dead-drop
path gets the Double Ratchet + keywheel labels + encrypted-at-rest sessions. Depends wholly on
Phase 1 (needs the scheduler/receive lifecycle to hang encrypt-at-emission and save-on-decrypt
off). Effort: **M–L.**

### Phase 3 — TIER 2: math + traffic correctness (§5)

**F-11** (integer discrete-Laplace, kills the float/clamp DP breaks) and **F-5** (cover
sampled from the real tag×bucket×work distribution). These make the *anonymity claims* true,
and they depend on Phase 1–2: F-5's tag parity needs F-20's envelope tags to exist, and both
DP base (B≈45) and cover cost fold into `EmissionPlan.min_entries` (§3.4). The **golden
traffic-shape test** (§3.9 — zero-demand vs heavy-demand nodes produce byte-identical blocks)
is the executable acceptance criterion for the whole mission claim. Effort: **M.**

### Phase 4 — TIER 3: remaining debt (parallel with Phases 2–3)

The findings not already pulled into Phase 0: **F-13** (spawn-per-connection, §6.2),
**F-16** (CI + tor job, §6.3), **F-23** (binary/integration tests, §6.4 — largely *free* from
Phase 1's sim harness), **F-29** (pad/unpad + merkle proptests, §6.7). None blocks the
critical path; F-16 and F-29 should land early anyway because they *guard* the rest. Effort:
**M total**, parallelizable across the Phase 2–3 window.

### Phase 5 — TIER 4: doc re-aim (§7)

Written **last** so the docs describe what now exists: SPEC §1/§3/§3a → Mission C,
THREAT-MODEL two-column + modes + residuals, README banner, new CLIENT-OBLIGATIONS.md,
ROADMAP stack ordering. Pure doc work, but gated on Phases 1–3 landing so status columns are
honest. Effort: **S–M.**

### Phase 6 — TIER 5: research approach docs (§8)

Approach documents + first tractable increment. Sequence by the §8 table: **§8.6 transport
obfuscation first** (pure engineering, serves the default mode, seam already built by F-10),
then §8.1 RLN and §8.4 Sphinx (runtime-unblocked hard-months), then §8.3 IBE (independent).
**§8.2 committee** and **§8.5 sybil** stay documented open questions — the artifact ships
without them (§8.2 is the paper). Effort: open-ended by design; not on the artifact critical
path.

### Critical path & the "credible research artifact" line

```
F-10 ─▶ TIER 0 runtime ─▶ F-20 ─▶ F-3 ─▶ F-4 ─▶ F-8 ─▶ F-11/F-5 ─▶ golden traffic test
(P0)      (P1)            └────────── TIER 1 (P2) ──────────┘   (P3)      = ARTIFACT
```

Everything else (F-21/18/15/24 in P0; F-13/16/23/29 in P4; docs in P5) hangs off the sides of
this line and can proceed in parallel. **A credible research artifact ships at the end of
Phase 3 + the doc re-aim (Phase 5):** a running daemon with an epoch clock and persistent
chain, the mission path on Double-Ratchet + keywheel + encrypted-at-rest, correct DP and
byte-indistinguishable cover proven by the golden test, honest Mission-C docs, and
CLIENT-OBLIGATIONS.md. **Explicitly minus** external audit and closed-beta (§2 — out of
scope, precondition-gated on exactly this line landing). Phase 6's committee/sybil open
questions are honestly out-of-band; their absence is documented, not hidden.

## 10. Risk register

The risks are in *executing* this remediation — the ways the plan above fails even if each
finding's fix is individually correct.

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | **Hand-rolled crypto composition.** Tier 1 composes tested primitives (ratchet, lockbox v2, keywheel, `atrest.rs`) in *new* arrangements — encrypt-at-emission + save (§3.5), trial-decrypt dispatch on `Envelope` tags (§4.2), a per-file AEAD key hierarchy (§4.5). Composition bugs (nonce reuse, save-before-encrypt ratchet desync, wrong key in the hierarchy) don't show up as test failures — they show up as silent secrecy loss. | Medium | **Critical** | No *new* primitives (design rule, §4.2/§4.5 both state it). Reuse ChaCha20-Poly1305 everywhere (`lockbox.rs:57-60`). Encode the F-1 clone-and-commit + save-after-encrypt discipline as invariants with the crash-recovery test (§3.9). Defer the real committee/mix crypto to Tier 5 (§8.2) rather than hand-roll it now. The audit (§2) is the eventual backstop — but it audits *this* composition, so keep it small. |
| R2 | **The runtime is a big new attack + bug surface.** `darqual-runtime` is the largest single work item (§9 P1) and the most privileged — it owns the epoch clock, persistence, gossip, and every secret's lifecycle. A big new crate is where regressions and DoS live (the serial-accept class, F-13, is exactly this pattern already in the tree). | High | High | Deterministic sim harness from day one (§3.9) — multi-node, K-epochs-in-ms, so the surface is *tested*, not just written. `tokio::spawn`-per-connection + bounded semaphore (§6.2) so the gossip mesh can't be stalled. Keep Arti *out* of the runtime crate (§3.1 dependency rule) so its 350-crate surface never links into the core. Ship single-node full-replication (§3.6) — deliberately minimal — before any committee complexity. |
| R3 | **F-2 / F-12 coupling: `list()` depends on hex filenames.** F-2's `SessionStore::list()` recovers the peer key by decoding the hex *filename* (`session.rs:117-139`); F-12 must randomize filenames and move the peer key *inside* the encrypted blob (§4.6). Get the rework wrong and either `list()` breaks (F-2's trial-decrypt path dies) or the contact graph stays in the directory listing (F-12 unfixed). | Medium | High | Rework `list()` and the filename scheme in one change (§4.6): decrypt-each-file returns `record.peer_x_pub`, in-memory `index` built at `open()`. Preserve F-2's *test assertions* while swapping the junk-fixtures from bad-hex-names to bad-content files (§4.6) — the tests prove the coupling didn't regress. Random name doubles as the AEAD `filename_nonce`, so a swapped file fails open (tamper-evidence catches a botched migration). |
| R4 | **Format-migration risk (bincode / session / keywheel).** Tier 1 adds fields to `RatchetSession` (keywheel binding) and re-lays-out session files (F-6 encryption + F-12 rename), while bincode 1 is non-self-describing (§6.5). A migration that mis-detects legacy vs new files corrupts live sessions → ratchet desync → unrecoverable conversations, and there's no version to branch on if F-24 hasn't landed first. | Medium | High | **Sequence F-24 into Phase 0** (§9) so the version byte / `dqsr1` magic exists *before* any struct change. Migration is sniff-magic → read-once → re-save-encrypted → shred (§4.5), with a roundtrip test per format version. One release of legacy-read support, then delete. Never mutate a file in place — write-tmp-rename (`session.rs:68-81`) is the fsync/atomicity boundary. |
| R5 | **Scope discipline: research stubs balloon the runtime.** The temptation to start building the committee (§8.2), a real mixnet (§8.4), or RLN (§8.1) *inside* Tier 0 because the runtime "is right there." This is how the trunk turns into a swamp and the artifact never ships — §8.2 is a *paper*, not a phase. | Medium | Medium | Hard scope line: Tier 0 ships single-publisher full-replication with `IngestOutcome::Fork` = "reject and log" (§3.3), full stop. Tier 5 items are **approach docs + one tractable increment** (§8), gated *after* the artifact line (§9). The §8 table's "runtime unblocks?" column is the discipline tool — it says the runtime makes these *buildable later*, not *build them now*. Keep the two genuinely-open items (§8.2 committee, §8.5 sybil) explicitly out of the artifact so their difficulty can't leak into the critical path. |
