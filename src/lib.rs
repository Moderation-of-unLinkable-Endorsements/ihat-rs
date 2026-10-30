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

//! Anonymous Credit Tokens (ACT).
//!
//! ACT is a keyed-verification anonymous credential whose hidden state is a
//! *balance* of credits. A Moderator issues a [`Credential`] with an initial
//! balance; the Client later *spends* a public amount `s`, proving in zero
//! knowledge that the Credential covers it and has not been spent before, and
//! receives a *refund*: a fresh Credential for the remainder plus a
//! Moderator-chosen return amount `t`. The Moderator never learns the balance
//! and cannot link a spend to the issuance or refund that produced the
//! Credential, nor two spends to each other.
//!
//! This crate implements
//! [draft-authors-mole-act](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-act.html)
//! for the `P256-SHA256` ciphersuite. The zero-knowledge proofs are compact
//! NARG strings of `draft-irtf-cfrg-sigma-protocols-03`, produced by
//! statement-specific provers that emit the same bytes as the generic
//! construction while sharing work across equations.
//!
//! # Flow
//!
//! ```
//! use act::{Params, SecretKey};
//!
//! // Both parties agree on the balance width `L` and a credential context.
//! let params: Params = Params::new(8)?;
//! let ctx_cred = b"epoch-42";
//!
//! // The Moderator holds the key pair and publishes the public key.
//! let secret_key = SecretKey::generate()?;
//! let public_key = secret_key.public_key();
//!
//! // Issuance: the Client requests, the Moderator chooses the balance.
//! let (state, request) = act::issue_request(&params)?;
//! let verified = act::verify_issue_request(&params, &request)?;
//! let response = act::issue_response(&secret_key, ctx_cred, 100, verified)?;
//! let credential = act::finalize_issue(&params, &public_key, ctx_cred, state, &response)?;
//! assert_eq!(credential.balance(), 100);
//!
//! // Spending: spend 30 credits under the challenge digest `ctx_spend`,
//! // with no top-up allowance; the Moderator returns 5 credits.
//! let ctx_spend = b"challenge-digest";
//! let (state, spend) = act::prove_spend(&params, credential, ctx_cred, 30, 0, ctx_spend)?;
//! let verified = act::verify_spend(&params, &secret_key, ctx_cred, ctx_spend, &spend)?;
//! // ... the Moderator grants `verified.allowance()` and atomically records
//! // `verified.nullifier()` together with the refund ...
//! let refund = act::issue_refund(verified, 5)?;
//! let credential = act::finalize_refund(&params, &public_key, ctx_cred, state, &refund)?;
//! assert_eq!(credential.balance(), 75);
//! # Ok::<(), act::Error>(())
//! ```
//!
//! Every message and the Credential have a fixed wire encoding, exposed as
//! `to_bytes` and `from_bytes` on each type.
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
//! * `prove_spend` consumes the Credential and `finalize_issue` and
//!   `finalize_refund` consume their state, so a value cannot be used twice
//!   within a process. Persisted copies are the wallet's responsibility.
//! * [`verify_spend`] returns a [`VerifiedSpend`] that is bound to the exact
//!   message, key, configuration, and contexts it checked. The Moderator must
//!   reject a repeated nullifier and record it atomically with the refund.
//! * Operations on the Client's balance and blinding factors, and on the
//!   Moderator's signing key, are constant time with respect to those values.
//!   The exception is point addition in the BoringSSL backend, which branches
//!   when its operands are equal or negatives of each other; when a secret
//!   operand is random and independent of the other, the branch is taken
//!   with negligible probability.
//! * Secrets are zeroized on drop.

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
mod hash;
mod protocol;
mod random;
mod sigma;
mod statements;
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

/// The protocol context `ctx_proto = "ACTv1-" || identifier`.
pub const PROTOCOL_CONTEXT: &[u8] = b"ACTv1-P256-SHA256";

/// The largest permitted balance width `L` (`MAX_BIT_LENGTH`).
pub const MAX_BALANCE_WIDTH: u8 = 64;

/// The seed length `Nseed` consumed by every scalar derivation.
pub const SEED_LENGTH: usize = 48;

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
