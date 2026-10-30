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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};

use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::ops::{Double, LinearCombination};
use p256::elliptic_curve::{BatchNormalize, Field, Group, PrimeField};
use p256::hash2curve::{ExpandMsgXmd, hash_from_bytes};
use p256::{AffinePoint, CompressedPoint, FieldBytes, NistP256, ProjectivePoint};
use sha2::Digest;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

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
        // Only compressed encodings are canonical. `GroupEncoding::from_bytes`
        // also accepts the SEC1 compact tag 0x05, and maps the all-zero
        // string to the identity, which the draft requires be rejected; the
        // prefix check excludes both, and the identity is checked anyway.
        if bytes[0] != 2 && bytes[0] != 3 {
            return CtOption::new(Self::IDENTITY, Choice::from(0));
        }
        <Self as GroupEncoding>::from_bytes(&CompressedPoint::from(*bytes))
            .and_then(|point| CtOption::new(point, !Group::is_identity(&point)))
    }

    fn to_bytes(&self) -> Option<[u8; POINT_LENGTH]> {
        if bool::from(Group::is_identity(self)) {
            return None;
        }
        Some(GroupEncoding::to_bytes(self).into())
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

/// Bits per window of the fixed-base tables.
const WINDOW_BITS: usize = 4;
/// Entries per window, one per digit value.
const WINDOW_SIZE: usize = 1 << WINDOW_BITS;
/// Windows covering a 256-bit scalar.
const WINDOWS: usize = 256 / WINDOW_BITS;

/// A point with a fixed-base table: for every 4-bit window `w` of a scalar
/// and every digit `d`, the affine point `d * 2^(4w) * P`.
///
/// A multiplication is then 64 constant-time table lookups and 64 mixed
/// additions, with no doublings, about a quarter of the cost of a general
/// multiplication. The table holds 1024 affine points (72 KiB) per base and
/// costs about a thousand group operations to build, once per `Params`.
#[derive(Clone)]
pub struct FixedPoint {
    point: ProjectivePoint,
    table: Box<[AffinePoint]>,
}

impl fmt::Debug for FixedPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FixedPoint").field(&self.point).finish()
    }
}

impl super::FixedBase<ProjectivePoint> for FixedPoint {
    fn new(point: ProjectivePoint) -> Self {
        let mut projective = Vec::with_capacity(WINDOWS * WINDOW_SIZE);
        let mut base = point;
        for _ in 0..WINDOWS {
            // Entries 0 * base, 1 * base, ..., 15 * base; the running sum
            // ends at 16 * base, the next window's base.
            let mut multiple = ProjectivePoint::IDENTITY;
            for _ in 0..WINDOW_SIZE {
                projective.push(multiple);
                multiple += base;
            }
            base = multiple;
        }
        let table =
            <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize(&projective);
        Self {
            point,
            table: table.into_boxed_slice(),
        }
    }

    fn point(&self) -> &ProjectivePoint {
        &self.point
    }

    fn mul(&self, scalar: &p256::Scalar) -> ProjectivePoint {
        let bytes = scalar.to_repr();
        let mut acc = ProjectivePoint::IDENTITY;
        for (w, window) in self.table.chunks_exact(WINDOW_SIZE).enumerate() {
            // Window `w` is the `w`-th nibble from the least significant end
            // of the big-endian encoding.
            let byte = bytes[bytes.len() - 1 - w / 2];
            let digit = (byte >> (WINDOW_BITS * (w % 2))) & (WINDOW_SIZE as u8 - 1);
            let mut entry = AffinePoint::IDENTITY;
            for (d, candidate) in window.iter().enumerate() {
                entry.conditional_assign(candidate, digit.ct_eq(&(d as u8)));
            }
            acc += entry;
        }
        acc
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
    type FixedBase = FixedPoint;
    type Sha256 = Sha256;
    type Shake128 = super::shake::RustCryptoShake128;

    fn hash_to_curve(msg: &[&[u8]], dst: &[&[u8]]) -> Option<Self::Point> {
        hash_from_bytes::<NistP256, ExpandMsgXmd<sha2::Sha256>>(msg, dst).ok()
    }

    fn random_bytes(buf: &mut [u8]) -> Result<(), crate::Error> {
        getrandom::fill(buf).map_err(|_| crate::Error::Entropy)
    }
}
