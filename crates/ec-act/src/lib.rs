// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

mod hash;
mod protocol;
mod sigma;
mod statements;
mod wire;

#[cfg(test)]
mod tests;

use core::fmt;

pub use mole_p256::backend;
pub use mole_p256::backend::{Backend, BackendFixedBaseExt};
pub use protocol::{
    ClientIssuanceState, ClientSpendState, Credential, IssueRequestMessage, IssueResponseMessage,
    Params, PublicKey, RefundMessage, SecretKey, SpendMessage, VerifiedIssueRequest, VerifiedSpend,
    finalize_issue, finalize_refund, issue_refund, issue_request, issue_response, prove_spend,
    verify_issue_request, verify_spend,
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

/// The protocol context `ctx_proto = "EC-ACTv1-" || identifier`.
pub const PROTOCOL_CONTEXT: &[u8] = b"EC-ACTv1-P256-SHA256";

/// The largest permitted balance width `L` (`MAX_BIT_LENGTH`).
pub const MAX_BALANCE_WIDTH: u8 = 64;

pub use mole_p256::SEED_LENGTH;

/// The errors of the draft. Any error aborts the affected protocol run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A byte string is not a canonical encoding of the expected type
    /// (`DeserializeError`). This includes the identity element and a
    /// message whose shape does not match its amounts.
    Deserialize,
    /// A received value failed a verification check (`VerifyError`).
    Verify,
    /// A deterministic derivation failed to produce a usable scalar
    /// (`DeriveError`). This has negligible probability.
    Derive,
    /// A balance or amount is outside the range admitted by the balance
    /// width (`AmountError`).
    Amount,
    /// An input has an invalid length or is outside its permitted range
    /// (`ValueError`), for instance a context longer than `2^16 - 1` bytes.
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
            Error::Amount => "amount is outside the permitted range",
            Error::InvalidInput => "input has an invalid length or value",
            Error::Entropy => "the system random number generator failed",
        })
    }
}

impl core::error::Error for Error {}
