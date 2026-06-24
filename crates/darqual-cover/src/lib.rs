//! # darqual-cover — Stage 8: Metadata Hardening
//!
//! Implements **tractable, testable** Vuvuzela-style metadata protection:
//!
//! 1. **Cover traffic** (`cover` module) — every epoch a node pads its outgoing
//!    block to at least `min_count` entries using indistinguishable dummy entries.
//!    Cover entries are size-identical to real lockbox envelopes and carry random
//!    bytes that decrypt for nobody.
//!
//! 2. **Differential-privacy noise** (`dp` module) — discrete Laplace noise is
//!    added to dead-drop access counts so aggregate patterns cannot reveal whether
//!    two parties are communicating.  This is Vuvuzela's core mechanism with an
//!    explicit ε budget.
//!
//! ## What is NOT built here (documented research path)
//!
//! The **Loopix / Sphinx mix layer** is the full global-passive-adversary
//! defence.  It requires:
//!
//! * **Sphinx packet format** — onion-layered, fixed-size packets with per-hop
//!   MAC/encryption so intermediate nodes learn only the next hop.  The Sphinx
//!   spec (Danezis & Goldberg, 2009) is well-defined but production
//!   implementations (e.g. `nym-sphinx`) are complex and require a live mixnet
//!   topology.
//!
//! * **Poisson per-hop delays** — each mix node holds a packet for
//!   `Exp(μ)`-distributed time before forwarding.  This breaks traffic-analysis
//!   timing correlations against a global adversary at the cost of latency.
//!
//! * **Loopix loop cover traffic** — clients send "loop" packets that return to
//!   themselves through the mix to mask the absence of real traffic and let
//!   clients monitor mix reliability.
//!
//! These are documented in ROADMAP Stage 8 and SPEC §3, and will require a
//! live mixnet deployment.  The cover + DP mechanisms in this crate are the
//! tractable increment that hides timing/volume leaks within a single epoch.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod cover;
pub mod dp;

pub use cover::{cover_entry, pad_block};
pub use dp::{add_dp_cover, discrete_laplace, noisy_cover_count};
