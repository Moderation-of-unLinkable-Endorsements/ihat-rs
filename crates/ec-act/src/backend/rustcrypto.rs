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

pub use ec_ihat::backend::rustcrypto::*;
use p256::elliptic_curve::{BatchNormalize, PrimeField};
use p256::{AffinePoint, ProjectivePoint};
use subtle::{ConditionallySelectable, ConstantTimeEq};

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

impl super::BackendFixedBaseExt for RustCrypto {
    type FixedBase = FixedPoint;
}
