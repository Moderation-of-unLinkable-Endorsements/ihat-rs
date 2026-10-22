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

//! The BoringSSL backend through the `boring` crate.
//!
//! Scalars are 32-byte big-endian integers below the order and use
//! BoringSSL's constant-time bignum routines: `BN_mod_add_quick`,
//! `BN_mod_sub_quick`, Montgomery multiplication, and
//! `BN_mod_exp_mont_consttime` for inversion. Points are heap `EC_POINT`
//! handles in projective form, so that values derived from secrets are
//! never re-parsed from a compressed encoding; P-256 point arithmetic in
//! BoringSSL is constant time. The x-coordinate test of the permutation
//! uses the same constant-time bignum routines modulo the field prime.
//! Hash-to-curve, SHA-256, and randomness are BoringSSL's as well.
//!
//! Constant-time bignum operations and hash-to-curve which are not exposed by
//! `boring` use its companion `boring-sys` bindings directly, as do fixed-size
//! serialization calls where the safe API requires a temporary allocation.
//! Every such call carries a `SAFETY` comment. Allocation failure is treated
//! as fatal, as in `bssl-crypto`.

use core::ffi::c_void;
use core::fmt;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use boring::bn::{BigNum, BigNumContext};
use boring::ec::{EcGroupRef, EcPoint};
use foreign_types::{ForeignType, ForeignTypeRef};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

use super::{FIELD_MODULUS, ORDER, POINT_LENGTH, SCALAR_LENGTH};

/// The BoringSSL backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BoringSsl;

// ---------------------------------------------------------------------------
// Group constants
// ---------------------------------------------------------------------------

fn group() -> &'static EcGroupRef {
    // SAFETY: BoringSSL documents `EC_group_p256` as returning a static group.
    // `EcGroupRef` borrows the pointer and therefore does not free it.
    unsafe {
        let group = boring_sys::EC_group_p256();
        assert!(!group.is_null());
        EcGroupRef::from_ptr(group.cast_mut())
    }
}

fn order() -> Bignum {
    Bignum::from_bytes(&ORDER)
}

/// The Montgomery context for the group order, created once per process.
fn order_mont() -> *const boring_sys::BN_MONT_CTX {
    static MONT: AtomicPtr<boring_sys::BN_MONT_CTX> = AtomicPtr::new(null_mut());
    let existing = MONT.load(Ordering::Acquire);
    if !existing.is_null() {
        return existing;
    }
    let order = order();
    // SAFETY: `order` is a valid public modulus; a null `BN_CTX` makes
    // BoringSSL allocate one internally.
    let fresh = unsafe { boring_sys::BN_MONT_CTX_new_for_modulus(order.as_ptr(), null_mut()) };
    assert!(!fresh.is_null());
    match MONT.compare_exchange(null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        Err(winner) => {
            // SAFETY: `fresh` was allocated above and never published.
            unsafe { boring_sys::BN_MONT_CTX_free(fresh) };
            winner
        }
    }
}

/// The Montgomery context for the field modulus, created once per process.
fn field_mont() -> *const boring_sys::BN_MONT_CTX {
    static MONT: AtomicPtr<boring_sys::BN_MONT_CTX> = AtomicPtr::new(null_mut());
    let existing = MONT.load(Ordering::Acquire);
    if !existing.is_null() {
        return existing;
    }
    let modulus = Bignum::from_bytes(&FIELD_MODULUS);
    // SAFETY: `modulus` is a valid public odd modulus; a null `BN_CTX` makes
    // BoringSSL allocate one internally.
    let fresh = unsafe { boring_sys::BN_MONT_CTX_new_for_modulus(modulus.as_ptr(), null_mut()) };
    assert!(!fresh.is_null());
    match MONT.compare_exchange(null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        Err(winner) => {
            // SAFETY: `fresh` was allocated above and never published.
            unsafe { boring_sys::BN_MONT_CTX_free(fresh) };
            winner
        }
    }
}

// ---------------------------------------------------------------------------
// RAII wrappers
// ---------------------------------------------------------------------------

struct Bignum(BigNum);

impl Bignum {
    fn new() -> Self {
        Self(BigNum::new().unwrap_or_else(|_| alloc_failed()))
    }

    /// A bignum from big-endian bytes; the width is fixed by the length.
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(BigNum::from_slice(bytes).unwrap_or_else(|_| alloc_failed()))
    }

    /// The value as `SCALAR_LENGTH` big-endian bytes; the value must fit.
    fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        let mut out = [0u8; SCALAR_LENGTH];
        // `boring::bn::BigNumRef::to_vec_padded` allocates a temporary `Vec`;
        // write into the fixed-size output directly instead.
        // SAFETY: `out` has `SCALAR_LENGTH` bytes and `self` is valid.
        let ret =
            unsafe { boring_sys::BN_bn2bin_padded(out.as_mut_ptr(), out.len(), self.as_ptr()) };
        assert_eq!(ret, 1);
        out
    }

    fn as_ptr(&self) -> *const boring_sys::BIGNUM {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&self) -> *mut boring_sys::BIGNUM {
        self.0.as_ptr()
    }
}

struct BnCtx(BigNumContext);

impl BnCtx {
    fn new() -> Self {
        Self(BigNumContext::new().unwrap_or_else(|_| alloc_failed()))
    }

    fn as_mut_ptr(&self) -> *mut boring_sys::BN_CTX {
        self.0.as_ptr()
    }
}

/// Allocation failure is not handled short of aborting, as in `bssl-crypto`.
#[cold]
#[allow(clippy::panic)]
fn alloc_failed() -> ! {
    panic!("BoringSSL allocation failed")
}

/// Operations on values already validated by this backend cannot fail.
#[cold]
#[allow(clippy::panic)]
fn operation_failed() -> ! {
    panic!("BoringSSL operation failed")
}

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

    /// `(self OP other) mod order` for the quick, constant-time BoringSSL
    /// operations, which require both operands below the modulus.
    fn mod_op(
        &self,
        other: &Self,
        op: unsafe extern "C" fn(
            *mut boring_sys::BIGNUM,
            *const boring_sys::BIGNUM,
            *const boring_sys::BIGNUM,
            *const boring_sys::BIGNUM,
        ) -> i32,
    ) -> Self {
        let a = Bignum::from_bytes(&self.0);
        let b = Bignum::from_bytes(&other.0);
        let r = Bignum::new();
        let order = order();
        // SAFETY: all pointers are valid and both operands are canonical,
        // as the `_quick` functions require.
        let ret = unsafe { op(r.as_mut_ptr(), a.as_ptr(), b.as_ptr(), order.as_ptr()) };
        assert_eq!(ret, 1);
        Self(r.to_bytes())
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
        self.mod_op(&other, boring_sys::BN_mod_add_quick)
    }
}

impl core::ops::Sub for Scalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self.mod_op(&other, boring_sys::BN_mod_sub_quick)
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
        let a = Bignum::from_bytes(&self.0);
        let b = Bignum::from_bytes(&other.0);
        let a_mont = Bignum::new();
        let r = Bignum::new();
        let ctx = BnCtx::new();
        let mont = order_mont();
        // SAFETY: all pointers are valid; `a` is canonical as
        // `BN_to_montgomery` requires.
        let ret = unsafe {
            boring_sys::BN_to_montgomery(a_mont.as_mut_ptr(), a.as_ptr(), mont, ctx.as_mut_ptr())
        };
        assert_eq!(ret, 1);
        // SAFETY: all pointers are valid; both operands are below the order.
        let ret = unsafe {
            boring_sys::BN_mod_mul_montgomery(
                r.as_mut_ptr(),
                a_mont.as_ptr(),
                b.as_ptr(),
                mont,
                ctx.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 1);
        Self(r.to_bytes())
    }
}

impl super::Scalar for Scalar {
    fn invert(&self) -> CtOption<Self> {
        // Fermat: a^(n-2) mod n, with the base treated as secret. Zero maps
        // to zero, which the returned `CtOption` flags.
        let base = Bignum::from_bytes(&self.0);
        let exponent = Bignum::from_bytes(&order_minus_two());
        let r = Bignum::new();
        let ctx = BnCtx::new();
        // SAFETY: all pointers are valid and `base` is canonical, as
        // `BN_mod_exp_mont_consttime` requires.
        let ret = unsafe {
            boring_sys::BN_mod_exp_mont_consttime(
                r.as_mut_ptr(),
                base.as_ptr(),
                exponent.as_ptr(),
                order().as_ptr(),
                ctx.as_mut_ptr(),
                order_mont(),
            )
        };
        assert_eq!(ret, 1);
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

/// Constant-time arithmetic modulo the field prime, on reduced operands.
struct FieldArithmetic {
    modulus: Bignum,
    ctx: BnCtx,
    mont: *const boring_sys::BN_MONT_CTX,
}

impl FieldArithmetic {
    fn new() -> Self {
        Self {
            modulus: Bignum::from_bytes(&FIELD_MODULUS),
            ctx: BnCtx::new(),
            mont: field_mont(),
        }
    }

    /// `a * b`, as `MulMont(ToMont(a), b)`.
    fn mul(&self, a: &Bignum, b: &Bignum) -> Bignum {
        let a_mont = Bignum::new();
        let r = Bignum::new();
        // SAFETY: all pointers are valid; `a` is reduced, as
        // `BN_to_montgomery` requires.
        let ret = unsafe {
            boring_sys::BN_to_montgomery(
                a_mont.as_mut_ptr(),
                a.as_ptr(),
                self.mont,
                self.ctx.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 1);
        // SAFETY: all pointers are valid; both operands are reduced.
        let ret = unsafe {
            boring_sys::BN_mod_mul_montgomery(
                r.as_mut_ptr(),
                a_mont.as_ptr(),
                b.as_ptr(),
                self.mont,
                self.ctx.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 1);
        r
    }

    /// `a OP b` for a quick, constant-time BoringSSL operation.
    fn quick(
        &self,
        a: &Bignum,
        b: &Bignum,
        op: unsafe extern "C" fn(
            *mut boring_sys::BIGNUM,
            *const boring_sys::BIGNUM,
            *const boring_sys::BIGNUM,
            *const boring_sys::BIGNUM,
        ) -> i32,
    ) -> Bignum {
        let r = Bignum::new();
        // SAFETY: all pointers are valid and both operands are reduced, as
        // the `_quick` functions require.
        let ret = unsafe {
            op(
                r.as_mut_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                self.modulus.as_ptr(),
            )
        };
        assert_eq!(ret, 1);
        r
    }

    /// `base^exponent`, with the base treated as secret.
    fn exp(&self, base: &Bignum, exponent: &[u8; SCALAR_LENGTH]) -> Bignum {
        let exponent = Bignum::from_bytes(exponent);
        let r = Bignum::new();
        // SAFETY: all pointers are valid and `base` is reduced, as
        // `BN_mod_exp_mont_consttime` requires.
        let ret = unsafe {
            boring_sys::BN_mod_exp_mont_consttime(
                r.as_mut_ptr(),
                base.as_ptr(),
                exponent.as_ptr(),
                self.modulus.as_ptr(),
                self.ctx.as_mut_ptr(),
                self.mont,
            )
        };
        assert_eq!(ret, 1);
        r
    }
}

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

/// A P-256 point as an owned `EC_POINT`.
pub struct Point(EcPoint);

impl Point {
    fn new() -> Self {
        Self(EcPoint::new(group()).unwrap_or_else(|_| alloc_failed()))
    }

    fn as_ptr(&self) -> *const boring_sys::EC_POINT {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut boring_sys::EC_POINT {
        self.0.as_ptr()
    }
}

impl Clone for Point {
    fn clone(&self) -> Self {
        Self(self.0.to_owned(group()).unwrap_or_else(|_| alloc_failed()))
    }
}

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
        let mut point = Self::new();
        let group = group();
        // SAFETY: `group` and `point` are valid.
        let ret =
            unsafe { boring_sys::EC_POINT_set_to_infinity(group.as_ptr(), point.as_mut_ptr()) };
        assert_eq!(ret, 1);
        point
    }

    fn generator() -> Self {
        let group = group();
        Self(
            group
                .generator()
                .to_owned(group)
                .unwrap_or_else(|_| alloc_failed()),
        )
    }

    fn is_identity(&self) -> Choice {
        let group = group();
        // SAFETY: `group` and `self` are valid.
        let ret = unsafe { boring_sys::EC_POINT_is_at_infinity(group.as_ptr(), self.as_ptr()) };
        Choice::from((ret == 1) as u8)
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        // `EC_POINT_cmp` compares in constant time.
        let group = group();
        let mut ctx = BigNumContext::new().unwrap_or_else(|_| alloc_failed());
        Choice::from(
            self.0
                .eq(group, &other.0, &mut ctx)
                .unwrap_or_else(|_| operation_failed()) as u8,
        )
    }

    fn add(&self, other: &Self) -> Self {
        let mut r = Self::new();
        let group = group();
        let mut ctx = BigNumContext::new().unwrap_or_else(|_| alloc_failed());
        r.0.add(group, &self.0, &other.0, &mut ctx)
            .unwrap_or_else(|_| operation_failed());
        r
    }

    fn double(&self) -> Self {
        let mut r = Self::new();
        let group = group();
        // SAFETY: all pointers are valid; `ctx` may be null.
        let ret = unsafe {
            boring_sys::EC_POINT_dbl(group.as_ptr(), r.as_mut_ptr(), self.as_ptr(), null_mut())
        };
        assert_eq!(ret, 1);
        r
    }

    fn neg(&self) -> Self {
        let mut r = self.clone();
        let group = group();
        let ctx = BigNumContext::new().unwrap_or_else(|_| alloc_failed());
        r.0.invert(group, &ctx)
            .unwrap_or_else(|_| operation_failed());
        r
    }

    fn mul(&self, scalar: &Self::Scalar) -> Self {
        let mut r = Self::new();
        let scalar = Bignum::from_bytes(&scalar.0);
        let group = group();
        let mut ctx = BigNumContext::new().unwrap_or_else(|_| alloc_failed());
        r.0.mul(group, &self.0, &scalar.0, &mut ctx)
            .unwrap_or_else(|_| operation_failed());
        r
    }

    fn mul_generator(scalar: &Self::Scalar) -> Self {
        let mut r = Self::new();
        let scalar = Bignum::from_bytes(&scalar.0);
        let group = group();
        let mut ctx = BigNumContext::new().unwrap_or_else(|_| alloc_failed());
        r.0.mul_generator(group, &scalar.0, &mut ctx)
            .unwrap_or_else(|_| operation_failed());
        r
    }

    fn from_bytes(bytes: &[u8; POINT_LENGTH]) -> CtOption<Self> {
        let group = group();
        let mut ctx = BigNumContext::new().unwrap_or_else(|_| alloc_failed());
        let parsed = EcPoint::from_bytes(group, bytes, &mut ctx);
        let valid_parse = parsed.is_ok();
        let point = Self(parsed.unwrap_or_else(|_| Self::identity().0));
        // Only compressed encodings are canonical, and the identity has
        // none of this length; BoringSSL rejects both, checked here anyway.
        let compressed = bytes[0] == 2 || bytes[0] == 3;
        let valid = valid_parse && compressed && !bool::from(super::Point::is_identity(&point));
        CtOption::new(point, Choice::from(valid as u8))
    }

    fn to_bytes(&self) -> Option<[u8; POINT_LENGTH]> {
        if bool::from(super::Point::is_identity(self)) {
            return None;
        }
        let group = group();
        let mut out = [0u8; POINT_LENGTH];
        // `boring::ec::EcPointRef::to_bytes` allocates a temporary `Vec`;
        // write into the fixed-size output directly instead.
        // SAFETY: all pointers are valid; `out` has `POINT_LENGTH` bytes.
        let written = unsafe {
            boring_sys::EC_POINT_point2oct(
                group.as_ptr(),
                self.as_ptr(),
                boring_sys::point_conversion_form_t::POINT_CONVERSION_COMPRESSED,
                out.as_mut_ptr(),
                out.len(),
                null_mut(),
            )
        };
        assert_eq!(written, POINT_LENGTH);
        Some(out)
    }

    fn is_x_coordinate(x: &[u8; SCALAR_LENGTH]) -> Choice {
        // An out-of-range `x` is replaced by zero so that the computation
        // below runs on a reduced value either way.
        let canonical = below(x, &FIELD_MODULUS);
        let mut x_reduced = [0u8; SCALAR_LENGTH];
        for (out, byte) in x_reduced.iter_mut().zip(x) {
            *out = u8::conditional_select(&0, byte, canonical);
        }
        let x = Bignum::from_bytes(&x_reduced);
        x_reduced.zeroize();
        let field = FieldArithmetic::new();

        // rhs = x^3 - 3 * x + b.
        let x2 = field.mul(&x, &x);
        let x3 = field.mul(&x, &x2);
        let two_x = field.quick(&x, &x, boring_sys::BN_mod_add_quick);
        let three_x = field.quick(&two_x, &x, boring_sys::BN_mod_add_quick);
        let rhs = field.quick(&x3, &three_x, boring_sys::BN_mod_sub_quick);
        let rhs = field.quick(
            &rhs,
            &Bignum::from_bytes(&CURVE_B),
            boring_sys::BN_mod_add_quick,
        );

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
pub struct Sha256(boring_sys::SHA256_CTX);

impl Drop for Sha256 {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid, initialized context of its own size.
        unsafe {
            boring_sys::OPENSSL_cleanse(
                (&raw mut self.0).cast::<c_void>(),
                core::mem::size_of::<boring_sys::SHA256_CTX>(),
            )
        };
    }
}

impl super::Sha256 for Sha256 {
    fn new() -> Self {
        let mut ctx = core::mem::MaybeUninit::<boring_sys::SHA256_CTX>::uninit();
        // SAFETY: `SHA256_Init` fully initializes `ctx` and returns 1.
        let ret = unsafe { boring_sys::SHA256_Init(ctx.as_mut_ptr()) };
        assert_eq!(ret, 1);
        // SAFETY: initialized above.
        Self(unsafe { ctx.assume_init() })
    }

    fn update(&mut self, data: &[u8]) {
        // SAFETY: `self.0` is initialized; `data` is a valid slice.
        let ret = unsafe {
            boring_sys::SHA256_Update(&mut self.0, data.as_ptr().cast::<c_void>(), data.len())
        };
        assert_eq!(ret, 1);
    }

    fn finalize(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: `out` has `SHA256_DIGEST_LENGTH` bytes; `self.0` is
        // initialized. `SHA256_Final` clears the context it consumes, and
        // `Drop` cleanses it again.
        let ret = unsafe { boring_sys::SHA256_Final(out.as_mut_ptr(), &mut self.0) };
        assert_eq!(ret, 1);
        out
    }
}

impl super::Backend for BoringSsl {
    type Scalar = Scalar;
    type Point = Point;
    type Sha256 = Sha256;

    fn hash_to_curve(msg: &[&[u8]], dst: &[&[u8]]) -> Option<Self::Point> {
        let msg: alloc::vec::Vec<u8> = msg.concat();
        let dst: alloc::vec::Vec<u8> = dst.concat();
        let mut point = Point::new();
        let group = group();
        // SAFETY: all pointers are valid; the slices carry their lengths.
        let ret = unsafe {
            boring_sys::EC_hash_to_curve_p256_xmd_sha256_sswu(
                group.as_ptr(),
                point.as_mut_ptr(),
                dst.as_ptr(),
                dst.len(),
                msg.as_ptr(),
                msg.len(),
            )
        };
        if ret != 1 {
            // SAFETY: clears the error the failed call queued.
            unsafe { boring_sys::ERR_clear_error() };
            return None;
        }
        Some(point)
    }

    fn random_bytes(buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        boring::rand::rand_bytes(buf).unwrap_or_else(|_| operation_failed());
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
