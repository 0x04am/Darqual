//! Election mechanism only.
//!
//! This crate implements per-epoch committee election via a deterministic VRF built on
//! ed25519's RFC 8032 deterministic signatures. It is the tractable, testable core of
//! Stage 6 (Darqual v0.6.0).
//!
//! # What is NOT here (and why)
//!
//! The full anytrust per-epoch protocol — DPF commit + PIR notify + IBE PKG share
//! distribution — depends on primitives that have not yet been built (DPF, PIR, IBE).
//! Those are staged for v0.7.x (IBE/Alpenhorn) and v0.4.x/v0.3.x (DPF/PIR).
//!
//! Sybil-resistant participant-set design (stake, PoW, proof-of-storage, or anonymous
//! credential) is an open research question (SPEC §8, §11). No safe shortcut exists;
//! it will be revisited once the threat model is validated in Stage 10.
//!
//! # Production VRF note
//!
//! The VRF in this crate uses ed25519 deterministic signatures as a *poor-man's VRF*
//! (output is unpredictable without the secret key, verifiable with the public key,
//! and unbiasable by the keyholder once the seed is fixed). This is sound for the
//! current prototype but **not** a standard ECVRF. Production should migrate to a
//! proper ECVRF per RFC 9381 (e.g. `vrf` crate or `ristretto255-vrf`) where the
//! proof additionally guarantees uniqueness and full VRF security.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod election;
pub mod error;
pub mod manifest;
pub mod vrf;

pub use election::{elect, is_member, seed_for_epoch, Candidate};
pub use error::CommitteeError;
pub use manifest::{CommitteeManifest, ManifestError, RelayEndpoint};
pub use vrf::{vrf_eval, vrf_verify};
