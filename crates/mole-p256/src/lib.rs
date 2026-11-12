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

#[cfg(all(
    feature = "rustcrypto",
    feature = "boringssl",
    not(feature = "backend-parity")
))]
compile_error!(
    "`rustcrypto` and `boringssl` are mutually exclusive; disable default features for a BoringSSL-only build, or enable `backend-parity` for tests"
);

pub mod backend;
pub mod hash;
pub mod random;

#[cfg(test)]
mod tests;

use core::fmt;

/// The seed length `Nseed` consumed by every scalar derivation.
pub const SEED_LENGTH: usize = 48;

/// A failure of a primitive. The protocol crates map each to their own
/// errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// An input has an invalid length or count.
    InvalidInput,
    /// Derivation failed to produce a usable scalar or group element.
    Derive,
    /// The system random number generator is unavailable.
    Entropy,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "input has an invalid length or count",
            Self::Derive => "derivation failed to produce a usable scalar or group element",
            Self::Entropy => "the system random number generator failed",
        })
    }
}

impl core::error::Error for Error {}
