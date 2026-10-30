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

//! Group and hash primitives behind the protocol.
//!
//! The protocol is written against the [`Backend`] trait, which supplies the
//! P-256 scalar field and group, SHA-256, hash-to-curve, and the operating
//! system's random number generator. Two implementations are provided:
//!
//! * `rustcrypto::RustCrypto` (feature `rustcrypto`): the `p256`, `sha2`,
//!   and `getrandom` crates.
//! * `boringssl::BoringSsl` (feature `boringssl`): BoringSSL through the
//!   `bssl-sys` bindings, as Chromium builds it. BoringSSL does not export
//!   SHAKE128, so that one primitive comes from the `shake` crate for now
//!   (the `shake` module).
//!
//! Both encode scalars as 32-byte big-endian integers below the group order
//! and points as 33-byte compressed SEC1 strings, and neither accepts an
//! encoding of the identity element.

use core::fmt::Debug;
use core::ops::{Add, Mul, Neg, Sub};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

#[cfg(feature = "boringssl")]
#[allow(unsafe_code)]
pub mod boringssl;

pub mod shake;

/// Length of a serialized scalar, `Ns`.
pub const SCALAR_LENGTH: usize = 32;

/// Length of a serialized group element, `Ne`.
pub const POINT_LENGTH: usize = 33;

/// The order of the P-256 group, big-endian.
pub const ORDER: [u8; SCALAR_LENGTH] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// An element of the P-256 scalar field.
///
/// Arithmetic is modulo the group order and constant time in both operands.
/// `Default` is zero.
pub trait Scalar:
    Copy
    + Debug
    + Default
    + Zeroize
    + ConstantTimeEq
    + ConditionallySelectable
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + From<u64>
{
    /// The multiplicative inverse, or `None` for zero, in constant time.
    fn invert(&self) -> CtOption<Self>;

    /// Whether the scalar is zero, in constant time.
    fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::default())
    }

    /// Decodes a big-endian integer, rejecting values not below the order.
    fn from_bytes(bytes: &[u8; SCALAR_LENGTH]) -> CtOption<Self>;

    /// Encodes the scalar as a big-endian integer.
    fn to_bytes(&self) -> [u8; SCALAR_LENGTH];
}

/// An element of the P-256 group.
///
/// Points are not required to be `Copy`: the BoringSSL backend keeps a heap
/// handle so that intermediate values, some of which depend on secrets, are
/// never decompressed again. Arithmetic is constant time in both operands,
/// except the BoringSSL backend's addition of equal or opposite points.
pub trait Point: Clone + Debug + PartialEq + Eq + Sized {
    /// The associated scalar type.
    type Scalar: Scalar;

    /// The identity element.
    fn identity() -> Self;

    /// The group generator `B`.
    fn generator() -> Self;

    /// Whether the point is the identity, in constant time.
    fn is_identity(&self) -> Choice;

    /// Constant-time equality.
    fn ct_eq(&self, other: &Self) -> Choice;

    /// `self + other`.
    fn add(&self, other: &Self) -> Self;

    /// `2 * self`.
    fn double(&self) -> Self;

    /// `scalar * self`.
    fn mul(&self, scalar: &Self::Scalar) -> Self;

    /// `scalar * B`, for the group generator `B`.
    fn mul_generator(scalar: &Self::Scalar) -> Self {
        Self::generator().mul(scalar)
    }

    /// `sum_i scalar_i * point_i`.
    ///
    /// The default computes each product separately; a backend may use a
    /// multi-scalar multiplication. Must be constant time in the scalars.
    fn lincomb<const N: usize>(terms: [(&Self, &Self::Scalar); N]) -> Self {
        terms.iter().fold(Self::identity(), |acc, (point, scalar)| {
            acc.add(&point.mul(scalar))
        })
    }

    /// Decodes a compressed SEC1 point, rejecting the identity and any
    /// non-canonical or off-curve encoding.
    fn from_bytes(bytes: &[u8; POINT_LENGTH]) -> CtOption<Self>;

    /// Encodes the point in compressed SEC1 form, or `None` for the identity,
    /// which has no encoding of this length.
    fn to_bytes(&self) -> Option<[u8; POINT_LENGTH]>;

    /// Overwrites the point with the identity so that a secret-dependent
    /// value does not outlive its use.
    fn zeroize(&mut self);
}

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

/// An incremental SHA-256 computation whose state can be cloned.
pub trait Sha256: Clone {
    /// A fresh context.
    fn new() -> Self;

    /// Absorbs `data`.
    fn update(&mut self, data: &[u8]);

    /// The digest of everything absorbed.
    fn finalize(self) -> [u8; 32];
}

/// An absorbing SHAKE128 sponge.
///
/// The Fiat-Shamir transform derives session identifiers and challenges
/// from it. Every input is public.
pub trait Shake128: Sized {
    /// The squeezing half of the sponge.
    type Reader: Shake128Reader;

    /// A fresh sponge.
    fn new() -> Self;

    /// Absorbs `data`; splitting the input across calls does not change the
    /// output.
    fn absorb(&mut self, data: &[u8]);

    /// Pads the input and switches to squeezing.
    fn finalize(self) -> Self::Reader;
}

/// A squeezing SHAKE128 sponge. Consecutive reads continue one stream.
pub trait Shake128Reader {
    /// Fills `out` with the next bytes of the output stream.
    fn read(&mut self, out: &mut [u8]);
}

/// The primitives the protocol is built on.
///
/// A backend is a zero-sized marker type. It must be safe to use from any
/// thread.
pub trait Backend: 'static + Copy + Debug + Default + PartialEq + Eq + Send + Sync {
    /// Scalars of the P-256 field.
    type Scalar: Scalar;

    /// Points of the P-256 group.
    type Point: Point<Scalar = Self::Scalar>;

    /// Points with precomputation.
    type FixedBase: FixedBase<Self::Point>;

    /// Incremental SHA-256.
    type Sha256: Sha256;

    /// SHAKE128.
    type Shake128: Shake128;

    /// `P256_XMD:SHA-256_SSWU_RO_` of RFC 9380 over the concatenation of
    /// `msg` with the concatenation of `dst` as the domain separation tag.
    ///
    /// Returns `None` only for a tag whose length the backend rejects; the
    /// tags of this crate are short constants.
    fn hash_to_curve(msg: &[&[u8]], dst: &[&[u8]]) -> Option<Self::Point>;

    /// Fills `buf` from the operating system's cryptographic random number
    /// generator, returning [`Error::Entropy`](crate::Error::Entropy) if it
    /// is unavailable.
    fn random_bytes(buf: &mut [u8]) -> Result<(), crate::Error>;
}
