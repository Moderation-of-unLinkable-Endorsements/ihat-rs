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
//!
//! Scalars are 32-byte big-endian integers below the order and use
//! BoringSSL's constant-time bignum routines: `BN_mod_add_quick`,
//! `BN_mod_sub_quick`, Montgomery multiplication, and
//! `BN_mod_exp_mont_consttime` for inversion. Points are heap `EC_POINT`
//! handles in projective form, so that values derived from secrets are
//! never re-parsed from a compressed encoding. BoringSSL point addition has
//! exceptional paths for equal or opposite operands; callers must account
//! for them when operands depend on secrets. The x-coordinate test of the
//! permutation uses the same constant-time bignum routines modulo the field
//! prime.
//! Hash-to-curve, SHA-256, and randomness are BoringSSL's as well.
//!
//! Raw calls and allocation ownership are confined to the private `ffi` module.
//! Allocation failure is treated as fatal, as in `bssl-crypto`.

use core::fmt;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use super::{FIELD_MODULUS, ORDER, POINT_LENGTH, SCALAR_LENGTH};

#[allow(unsafe_code)]
mod ffi;

/// The BoringSSL backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BoringSsl;

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

/// A P-256 scalar as its canonical big-endian encoding.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Scalar([u8; SCALAR_LENGTH]);

impl Scalar {
    const ZERO: Self = Self([0; SCALAR_LENGTH]);

    /// Whether `bytes` is below the order, in constant time.
    fn is_canonical(bytes: &[u8; SCALAR_LENGTH]) -> Choice {
        below(bytes, &ORDER)
    }
}

/// Whether the big-endian integer `bytes` is below `modulus`, in constant
/// time.
fn below(bytes: &[u8; SCALAR_LENGTH], modulus: &[u8; SCALAR_LENGTH]) -> Choice {
    // Compute `modulus - bytes` and keep only the final borrow: it is set
    // exactly when `bytes > modulus`. A zero difference means equality.
    let mut borrow = 0i16;
    let mut nonzero = 0u8;
    for i in (0..SCALAR_LENGTH).rev() {
        let diff = i16::from(modulus[i]) - i16::from(bytes[i]) - borrow;
        borrow = (diff >> 15) & 1;
        nonzero |= diff as u8;
    }
    let below_or_equal = Choice::from((borrow == 0) as u8);
    below_or_equal & !nonzero.ct_eq(&0)
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar({})", Hex(&self.0))
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = [0u8; SCALAR_LENGTH];
        for ((out, a), b) in out.iter_mut().zip(&a.0).zip(&b.0) {
            *out = u8::conditional_select(a, b, choice);
        }
        Self(out)
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        let mut out = [0u8; SCALAR_LENGTH];
        out[SCALAR_LENGTH - 8..].copy_from_slice(&value.to_be_bytes());
        Self(out)
    }
}

impl core::ops::Add for Scalar {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let a = ffi::Bignum::from_bytes(&self.0);
        let b = ffi::Bignum::from_bytes(&other.0);
        Self(a.order_add(&b).to_bytes())
    }
}

impl core::ops::Sub for Scalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let a = ffi::Bignum::from_bytes(&self.0);
        let b = ffi::Bignum::from_bytes(&other.0);
        Self(a.order_sub(&b).to_bytes())
    }
}

impl core::ops::Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self {
        Self::ZERO - self
    }
}

impl core::ops::Mul for Scalar {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        // a * b = MulMont(ToMont(a), b): one conversion instead of three.
        let a = ffi::Bignum::from_bytes(&self.0);
        let b = ffi::Bignum::from_bytes(&other.0);
        Self(a.order_mul(&b).to_bytes())
    }
}

impl super::Scalar for Scalar {
    fn invert(&self) -> CtOption<Self> {
        // Fermat: a^(n-2) mod n, with the base treated as secret. Zero maps
        // to zero, which the returned `CtOption` flags.
        let base = ffi::Bignum::from_bytes(&self.0);
        let exponent = ffi::Bignum::from_bytes(&order_minus_two());
        let r = base.order_exp(&exponent);
        CtOption::new(Self(r.to_bytes()), !self.ct_eq(&Self::ZERO))
    }

    fn from_bytes(bytes: &[u8; SCALAR_LENGTH]) -> CtOption<Self> {
        CtOption::new(Self(*bytes), Self::is_canonical(bytes))
    }

    fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        self.0
    }
}

/// The coefficient `b` of P-256, big-endian.
const CURVE_B: [u8; SCALAR_LENGTH] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];

/// `(p + 1) / 4` for the field modulus `p`, big-endian.
const SQRT_EXPONENT: [u8; SCALAR_LENGTH] = [
    0x3f, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// `ORDER - 2`, big-endian.
fn order_minus_two() -> [u8; SCALAR_LENGTH] {
    let mut out = ORDER;
    // The order is odd and its low byte is 0x51, so no borrow propagates.
    out[SCALAR_LENGTH - 1] -= 2;
    out
}

// ---------------------------------------------------------------------------
// Points
// ---------------------------------------------------------------------------

/// A P-256 point backed by the private BoringSSL FFI wrapper.
#[derive(Clone)]
pub struct Point(ffi::EcPoint);

impl fmt::Debug for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match super::Point::to_bytes(self) {
            Some(bytes) => write!(f, "Point({})", Hex(&bytes)),
            None => f.write_str("Point(identity)"),
        }
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        bool::from(super::Point::ct_eq(self, other))
    }
}

impl Eq for Point {}

impl super::Point for Point {
    type Scalar = Scalar;

    fn identity() -> Self {
        Self(ffi::EcPoint::identity())
    }

    fn generator() -> Self {
        Self(ffi::EcPoint::generator())
    }

    fn is_identity(&self) -> Choice {
        Choice::from(self.0.is_identity() as u8)
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from(self.0.ct_eq(&other.0) as u8)
    }

    fn add(&self, other: &Self) -> Self {
        Self(self.0.add(&other.0))
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }

    fn neg(&self) -> Self {
        Self(self.0.invert())
    }

    fn mul(&self, scalar: &Self::Scalar) -> Self {
        let scalar = ffi::Bignum::from_bytes(&scalar.0);
        Self(self.0.mul(&scalar))
    }

    fn mul_generator(scalar: &Self::Scalar) -> Self {
        let scalar = ffi::Bignum::from_bytes(&scalar.0);
        Self(ffi::EcPoint::mul_generator(&scalar))
    }

    fn ct_select<'a, I>(table: I, index: usize) -> CtOption<Self>
    where
        I: IntoIterator<Item = &'a Self>,
    {
        // `EC_POINT` is opaque, so the selection runs over the bytes of the
        // compressed encodings. Encoding the keys and decoding the selected key
        // must be implemented in constant time.
        let mut selected = [0u8; POINT_LENGTH];
        let mut found = Choice::from(0);
        let mut no_identity = Choice::from(1);
        for (i, point) in table.into_iter().enumerate() {
            let at = i.ct_eq(&index);
            match super::Point::to_bytes(point) {
                Some(encoding) => {
                    for (out, byte) in selected.iter_mut().zip(&encoding) {
                        out.conditional_assign(byte, at);
                    }
                }
                None => no_identity = Choice::from(0),
            }
            found |= at;
        }
        let valid = found & no_identity;
        let point = if bool::from(valid) {
            let (point, decoded) = ffi::EcPoint::decode(&selected);
            assert!(decoded);
            point
        } else {
            ffi::EcPoint::identity()
        };
        selected.zeroize();
        CtOption::new(Self(point), valid)
    }

    fn from_bytes(bytes: &[u8; POINT_LENGTH]) -> CtOption<Self> {
        let (point, valid) = ffi::EcPoint::decode(bytes);
        CtOption::new(Self(point), Choice::from(valid as u8))
    }

    fn to_bytes(&self) -> Option<[u8; POINT_LENGTH]> {
        self.0.encode()
    }

    fn is_x_coordinate(x: &[u8; SCALAR_LENGTH]) -> Choice {
        // An out-of-range `x` is replaced by zero so that the computation
        // below runs on a reduced value either way.
        let canonical = below(x, &FIELD_MODULUS);
        let mut x_reduced = [0u8; SCALAR_LENGTH];
        for (out, byte) in x_reduced.iter_mut().zip(x) {
            *out = u8::conditional_select(&0, byte, canonical);
        }
        let x = ffi::Bignum::from_bytes(&x_reduced);
        x_reduced.zeroize();
        let field = ffi::FieldArithmetic::new();

        // rhs = x^3 - 3 * x + b.
        let x2 = field.mul(&x, &x);
        let x3 = field.mul(&x, &x2);
        let two_x = field.add(&x, &x);
        let three_x = field.add(&two_x, &x);
        let rhs = field.sub(&x3, &three_x);
        let rhs = field.add(&rhs, &ffi::Bignum::from_bytes(&CURVE_B));

        // The modulus is 3 mod 4, so y = rhs^((p + 1) / 4) is a square root
        // of rhs exactly when one exists.
        let y = field.exp(&rhs, &SQRT_EXPONENT);
        let y2 = field.mul(&y, &y);
        canonical & y2.to_bytes().ct_eq(&rhs.to_bytes())
    }

    fn zeroize(&mut self) {
        // The previous `EC_POINT` is cleansed when freed.
        *self = super::Point::identity();
    }
}

// ---------------------------------------------------------------------------
// Hashing and randomness
// ---------------------------------------------------------------------------

/// SHA-256 from BoringSSL. The context is cleansed on drop, since a
/// midstate can be derived from secrets.
#[derive(Clone)]
pub struct Sha256(ffi::Sha256Ctx);

impl super::Sha256 for Sha256 {
    fn new() -> Self {
        Self(ffi::Sha256Ctx::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        self.0.finalize()
    }
}

impl super::Backend for BoringSsl {
    type Scalar = Scalar;
    type Point = Point;
    type Sha256 = Sha256;

    fn hash_to_curve(msg: &[&[u8]], dst: &[&[u8]]) -> Option<Self::Point> {
        let msg: alloc::vec::Vec<u8> = msg.concat();
        let dst: alloc::vec::Vec<u8> = dst.concat();
        ffi::EcPoint::hash_to_curve(&msg, &dst).map(Point)
    }

    fn random_bytes(buf: &mut [u8]) -> Result<(), crate::Error> {
        if ffi::random_bytes(buf) {
            Ok(())
        } else {
            Err(crate::Error::Entropy)
        }
    }
}

/// Lowercase hex for `Debug` output.
struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

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
