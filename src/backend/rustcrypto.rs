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

//! The pure-Rust backend on the RustCrypto `p256` stack.

use core::sync::atomic::{Ordering, compiler_fence};

use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::ops::{Double, LinearCombination};
use p256::elliptic_curve::point::DecompressPoint;
use p256::elliptic_curve::{Field, Group, PrimeField};
use p256::hash2curve::{ExpandMsgXmd, hash_from_bytes};
use p256::{AffinePoint, CompressedPoint, FieldBytes, NistP256, ProjectivePoint};
use sha2::Digest;
use subtle::{Choice, ConstantTimeEq, CtOption};

use super::{POINT_LENGTH, SCALAR_LENGTH};

/// The RustCrypto backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RustCrypto;

impl super::Scalar for p256::Scalar {
    fn invert(&self) -> CtOption<Self> {
        Field::invert(self)
    }

    fn is_zero(&self) -> Choice {
        Field::is_zero(self)
    }

    fn from_bytes(bytes: &[u8; SCALAR_LENGTH]) -> CtOption<Self> {
        Self::from_repr(FieldBytes::from(*bytes))
    }

    fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        self.to_repr().into()
    }
}

impl super::Point for ProjectivePoint {
    type Scalar = p256::Scalar;

    fn identity() -> Self {
        Self::IDENTITY
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    fn is_identity(&self) -> Choice {
        Group::is_identity(self)
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(self, other)
    }

    fn add(&self, other: &Self) -> Self {
        self + other
    }

    fn double(&self) -> Self {
        Double::double(self)
    }

    fn neg(&self) -> Self {
        -self
    }

    fn mul(&self, scalar: &Self::Scalar) -> Self {
        self * scalar
    }

    fn mul_generator(scalar: &Self::Scalar) -> Self {
        <Self as Group>::mul_by_generator(scalar)
    }

    fn lincomb<const N: usize>(terms: [(&Self, &Self::Scalar); N]) -> Self {
        let terms = terms.map(|(point, scalar)| (*point, *scalar));
        <Self as LinearCombination<[(Self, Self::Scalar); N]>>::lincomb(&terms)
    }

    fn from_bytes(bytes: &[u8; POINT_LENGTH]) -> CtOption<Self> {
        // `GroupEncoding::from_bytes` maps the all-zero string to the
        // identity; the draft requires that it be rejected.
        <Self as GroupEncoding>::from_bytes(&CompressedPoint::from(*bytes))
            .and_then(|point| CtOption::new(point, !Group::is_identity(&point)))
    }

    fn to_bytes(&self) -> Option<[u8; POINT_LENGTH]> {
        if bool::from(Group::is_identity(self)) {
            return None;
        }
        Some(GroupEncoding::to_bytes(self).into())
    }

    fn is_x_coordinate(x: &[u8; SCALAR_LENGTH]) -> Choice {
        // Decompression checks `x` below the modulus and takes the square
        // root of `x^3 + a * x + b`, both in constant time; the sign bit
        // does not affect whether a point exists.
        AffinePoint::decompress(&FieldBytes::from(*x), Choice::from(0)).is_some()
    }

    #[allow(unsafe_code)]
    fn zeroize(&mut self) {
        // SAFETY: `self` is a valid, exclusively borrowed `ProjectivePoint`,
        // which is `Copy` and has no drop glue, so overwriting it in place is
        // sound. The volatile write keeps the overwrite from being elided as
        // dead when the value is about to be dropped.
        unsafe { core::ptr::write_volatile(self, Self::IDENTITY) };
        compiler_fence(Ordering::SeqCst);
    }
}

/// SHA-256 from the `sha2` crate.
#[derive(Clone)]
pub struct Sha256(sha2::Sha256);

impl super::Sha256 for Sha256 {
    fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl super::Backend for RustCrypto {
    type Scalar = p256::Scalar;
    type Point = ProjectivePoint;
    type Sha256 = Sha256;

    fn hash_to_curve(msg: &[&[u8]], dst: &[&[u8]]) -> Option<Self::Point> {
        hash_from_bytes::<NistP256, ExpandMsgXmd<sha2::Sha256>>(msg, dst).ok()
    }

    #[allow(clippy::expect_used)]
    fn random_bytes(buf: &mut [u8]) {
        // An unavailable system random number generator is unrecoverable
        // for this protocol: every secret is derived from its output.
        getrandom::fill(buf).expect("the operating system random number generator failed");
    }
}
