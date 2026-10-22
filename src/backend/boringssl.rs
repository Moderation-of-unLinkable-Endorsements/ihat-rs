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

//! The BoringSSL backend over the `bssl-sys` FFI bindings.

// TODO(boringssl): bind BoringSSL's Keccak once it is exported through a
// public header and `bssl-sys`. For now we use the `shake` crate for both the
// `boringssl` and `rustcrypto` backends.

pub use ec_ihat::backend::boringssl::*;

/// A point without precomputation: BoringSSL's public API offers tables
/// for the generator only, which `EC_POINT_mul` uses on its own.
#[derive(Clone, Debug)]
pub struct FixedPoint(Point);

impl super::FixedBase<Point> for FixedPoint {
    fn new(point: Point) -> Self {
        Self(point)
    }

    fn point(&self) -> &Point {
        &self.0
    }

    fn mul(&self, scalar: &Scalar) -> Point {
        super::Point::mul(&self.0, scalar)
    }
}

impl super::BackendFixedBaseExt for BoringSsl {
    type FixedBase = FixedPoint;
}
