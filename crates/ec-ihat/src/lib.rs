#![doc = include_str!("../README.md")]
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

mod commitment;
mod permutation;
mod protocol;
mod storage;
mod wire;

#[cfg(test)]
mod tests;

use core::fmt;

pub use mole_p256::backend;
pub use mole_p256::backend::Backend;
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

/// The protocol context `ctx_proto = "EC-IHATv1-" || identifier`.
pub const PROTOCOL_CONTEXT: &[u8] = b"EC-IHATv1-P256-SHA256";

pub use mole_p256::SEED_LENGTH;

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
    /// A deterministic derivation failed to produce a usable scalar
    /// (`DeriveError`). This has negligible probability.
    Derive,
    /// An input has an invalid length or is outside its permitted range
    /// (`ValueError`), for instance a context longer than `2^16 - 1` bytes
    /// or an index outside the Anchor Set.
    InvalidInput,
    /// The system random number generator is unavailable.
    Entropy,
}

impl From<mole_p256::Error> for Error {
    fn from(error: mole_p256::Error) -> Self {
        match error {
            mole_p256::Error::InvalidInput => Self::InvalidInput,
            mole_p256::Error::Derive => Self::Derive,
            mole_p256::Error::Entropy => Self::Entropy,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Deserialize => "byte string is not a canonical encoding",
            Error::Verify => "verification failed",
            Error::Derive => "derivation failed to produce a usable scalar",
            Error::InvalidInput => "input has an invalid length or value",
            Error::Entropy => "the system random number generator failed",
        })
    }
}

impl core::error::Error for Error {}
