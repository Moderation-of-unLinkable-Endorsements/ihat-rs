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

//! Shared primitives from IHAT and ACT's fixed-base multiplication extension.

use core::fmt::Debug;

pub use ec_ihat::backend::{Backend, ORDER, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar, Sha256};

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

#[cfg(feature = "boringssl")]
pub mod boringssl;

/// A point prepared for repeated multiplication by secret scalars.
///
/// The ciphersuite generators `H1` to `H4` are the bases of most
/// multiplications in a proof, so a backend may precompute tables for them
/// once per [`crate::Params`]. Multiplication must be constant time in the
/// scalar; the point itself is public.
pub trait FixedBase<P: Point>: Clone + Debug + Send + Sync {
    /// Prepares `point`.
    fn new(point: P) -> Self;

    /// The point.
    fn point(&self) -> &P;

    /// `scalar * point`.
    fn mul(&self, scalar: &P::Scalar) -> P;
}

/// ACT's fixed-base multiplication extension to IHAT's [`Backend`].
///
/// Each backend selects its own precomputed representation, independently
/// of the shared hashing and derivation methods.
pub trait BackendFixedBaseExt: Backend {
    /// Points with precomputation.
    type FixedBase: FixedBase<Self::Point>;
}
