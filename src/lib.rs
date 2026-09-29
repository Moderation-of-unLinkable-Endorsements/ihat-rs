//! Rollatini: an issuer-hiding anonymous token.
//!
//! An Anchor issues an Endorsement to a Client in a three-move partially
//! blind signature: the Anchor learns neither the Endorsement nor the
//! redemption context bound into it. The Client later redeems the
//! Endorsement at a Moderator, which holds an ordered Anchor Set of public
//! keys. The redemption shows the signature under a rerandomized key and
//! proves, in size logarithmic in the Anchor Set, that the key is a shift of
//! one of the Anchor Set's keys, without revealing which. The Moderator
//! learns the Endorsement's nullifier and nothing about which Anchor issued
//! it.
//!
//! This crate implements
//! [draft-authors-mole-rollatini](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-rollatini.html)
//! for the `P256-SHA256` ciphersuite.
//!
//! # Flow
//!
//! ```
//! use rollatini::{PublicKey, SecretKey};
//!
//! // The Anchor holds a key pair and publishes the public key.
//! let secret_key: SecretKey = SecretKey::generate()?;
//! let public_key = secret_key.public_key();
//! let ctx_iss = b"epoch-42";
//! let ctx_red = b"moderator.example";
//!
//! // Issuance: the Anchor commits, the Client challenges, the Anchor
//! // responds, and the Client finalizes an Endorsement.
//! let (anchor_state, commitment) = rollatini::commit(ctx_iss, b"session-1")?;
//! let (client_state, challenge) =
//!     rollatini::challenge(&public_key, ctx_iss, ctx_red, &commitment)?;
//! let response = rollatini::respond(&secret_key, anchor_state, &challenge)?;
//! let endorsement = rollatini::finalize(&public_key, client_state, &response)?;
//!
//! // Redemption: the Moderator accepts Endorsements from any Anchor in its
//! // Anchor Set; the Client proves its Anchor is one of them.
//! let other: PublicKey = SecretKey::generate()?.public_key();
//! let anchor_set = [other, public_key];
//! let challenge_digest = b"moderator challenge";
//! let redemption =
//!     rollatini::redeem(&anchor_set, 1, endorsement, ctx_iss, ctx_red, challenge_digest)?;
//! let nf = rollatini::verify_redemption(&anchor_set, &redemption, ctx_iss, ctx_red, challenge_digest)?;
//! // ... the Moderator rejects a repeated `nf` and records it here ...
//! # let _ = nf;
//! # Ok::<(), rollatini::Error>(())
//! ```
//!
//! Every message and the Endorsement have the wire encoding of the draft,
//! exposed as `to_bytes` and `from_bytes` on each type.
//!
//! # Backends
//!
//! Group and hash operations come from a [`Backend`], selected with Cargo
//! features: `rustcrypto` (default, pure Rust) or `boringssl` (BoringSSL
//! through `bssl-sys`, as used by Chromium). When both are enabled,
//! `boringssl` is the [`DefaultBackend`]; every type takes the backend as a
//! type parameter that defaults to it.
//!
//! # Security notes
//!
//! * [`respond`] consumes the Anchor's state, [`finalize`] the Client's, and
//!   [`redeem`] the Endorsement, so none can be used twice within a process.
//!   Persisted copies are the application's responsibility.
//! * The Moderator must reject a repeated nullifier and record it before
//!   granting anything on the strength of a redemption.
//! * Operations on the Anchor's signing key and session state, on the
//!   Client's blinding factors, and on the redemption's `delta`, Anchor
//!   index, trapdoors, and openings are constant time with respect to those
//!   values.
//! * Secrets are zeroized on drop.

// TODO: move the backend, hashing, and derivation layers into a `mole-p256`
// crate shared with act-rs. `backend` has the names and signatures of
// act-rs's backend, less what only ACT uses, and `hash` has act-rs's
// hashing and derivation functions with the protocol context as a
// parameter, so both crates can depend on one copy. `random` can move with
// them.

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![warn(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks
)]

extern crate alloc;

#[cfg(not(any(feature = "rustcrypto", feature = "boringssl")))]
compile_error!("enable at least one backend feature: `rustcrypto` or `boringssl`");

pub mod backend;
mod commitment;
mod hash;
mod permutation;
mod protocol;
mod random;
mod wire;

#[cfg(test)]
mod tests;

/// Compiles the README's example as a doctest so it cannot drift.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme {}

use core::fmt;

pub use backend::Backend;
pub use protocol::{
    AnchorState, ChallengeMessage, ClientState, CommitMessage, Endorsement, PublicKey, Redemption,
    ResponseMessage, SecretKey, challenge, commit, finalize, redeem, respond, verify,
    verify_redemption,
};

/// The backend selected by the enabled Cargo features.
///
/// `boringssl` takes precedence over `rustcrypto` when both are enabled.
#[cfg(feature = "boringssl")]
pub type DefaultBackend = backend::boringssl::BoringSsl;

/// The backend selected by the enabled Cargo features.
///
/// `boringssl` takes precedence over `rustcrypto` when both are enabled.
#[cfg(all(feature = "rustcrypto", not(feature = "boringssl")))]
pub type DefaultBackend = backend::rustcrypto::RustCrypto;

/// The ciphersuite identifier, `P256-SHA256`.
pub const CIPHERSUITE_IDENTIFIER: &[u8] = b"P256-SHA256";

/// The protocol context `ctx_proto = "Rollatiniv1-" || identifier`.
pub const PROTOCOL_CONTEXT: &[u8] = b"Rollatiniv1-P256-SHA256";

/// The seed length `Nseed` consumed by every scalar derivation.
pub const SEED_LENGTH: usize = 48;

/// The nullifier length `Nn`.
pub const NULLIFIER_LENGTH: usize = 32;

/// The errors of the draft. Any error aborts the affected protocol run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A byte string is not a canonical encoding of the expected type
    /// (`DeserializeError`). This includes the identity element, a
    /// non-minimal length prefix, and a redemption whose vectors do not
    /// match the Anchor Set.
    Deserialize,
    /// A received value failed a verification check (`VerifyError`).
    Verify,
    /// A message does not belong to the session whose state it was given
    /// (`SessionError`).
    Session,
    /// A deterministic derivation failed to produce a usable scalar
    /// (`DeriveError`). This has negligible probability.
    Derive,
    /// An input has an invalid length or is outside its permitted range
    /// (`ValueError`), for instance a context longer than `2^16 - 1` bytes
    /// or an index outside the Anchor Set.
    InvalidInput,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Deserialize => "byte string is not a canonical encoding",
            Error::Verify => "verification failed",
            Error::Session => "message does not belong to this session",
            Error::Derive => "derivation failed to produce a usable scalar",
            Error::InvalidInput => "input has an invalid length or value",
        })
    }
}

impl core::error::Error for Error {}
