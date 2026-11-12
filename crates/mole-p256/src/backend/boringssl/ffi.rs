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

//! The unsafe boundary around BoringSSL's raw bindings.
//!
//! This module owns every BoringSSL allocation and exposes safe operations
//! to the backend. Every raw call documents the invariants that make it safe.

use core::ffi::c_void;
use core::ptr::{NonNull, null, null_mut};
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::backend::{FIELD_MODULUS, POINT_LENGTH, SCALAR_LENGTH};

fn group() -> *const bssl_sys::EC_GROUP {
    // SAFETY: returns a static group; no resources to release.
    let group = unsafe { bssl_sys::EC_group_p256() };
    assert!(!group.is_null());
    group
}

fn order() -> *const bssl_sys::BIGNUM {
    // SAFETY: `group()` is valid; the order is owned by the static group.
    let order = unsafe { bssl_sys::EC_GROUP_get0_order(group()) };
    assert!(!order.is_null());
    order
}

fn order_mont() -> *const bssl_sys::BN_MONT_CTX {
    static MONT: AtomicPtr<bssl_sys::BN_MONT_CTX> = AtomicPtr::new(null_mut());
    let existing = MONT.load(Ordering::Acquire);
    if !existing.is_null() {
        return existing;
    }
    // SAFETY: `order()` is a valid public modulus; a null `BN_CTX` makes
    // BoringSSL allocate one internally.
    let fresh = unsafe { bssl_sys::BN_MONT_CTX_new_for_modulus(order(), null_mut()) };
    assert!(!fresh.is_null());
    match MONT.compare_exchange(null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        Err(winner) => {
            // SAFETY: `fresh` was allocated above and never published.
            unsafe { bssl_sys::BN_MONT_CTX_free(fresh) };
            winner
        }
    }
}

fn field_mont() -> *const bssl_sys::BN_MONT_CTX {
    static MONT: AtomicPtr<bssl_sys::BN_MONT_CTX> = AtomicPtr::new(null_mut());
    let existing = MONT.load(Ordering::Acquire);
    if !existing.is_null() {
        return existing;
    }
    let modulus = Bignum::from_bytes(&FIELD_MODULUS);
    // SAFETY: `modulus` is a valid public odd modulus; a null `BN_CTX` makes
    // BoringSSL allocate one internally.
    let fresh = unsafe { bssl_sys::BN_MONT_CTX_new_for_modulus(modulus.as_ptr(), null_mut()) };
    assert!(!fresh.is_null());
    match MONT.compare_exchange(null_mut(), fresh, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        Err(winner) => {
            // SAFETY: `fresh` was allocated above and never published.
            unsafe { bssl_sys::BN_MONT_CTX_free(fresh) };
            winner
        }
    }
}

pub(super) struct Bignum(NonNull<bssl_sys::BIGNUM>);

impl Bignum {
    fn new() -> Self {
        // SAFETY: `BN_new` has no preconditions.
        let ptr = unsafe { bssl_sys::BN_new() };
        Self(NonNull::new(ptr).unwrap_or_else(|| alloc_failed()))
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        let bn = Self::new();
        // SAFETY: `bytes` is a valid buffer of its length; `bn` is valid.
        let ret = unsafe { bssl_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), bn.as_mut_ptr()) };
        assert!(!ret.is_null());
        bn
    }

    pub(super) fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        let mut out = [0u8; SCALAR_LENGTH];
        // SAFETY: `out` has `SCALAR_LENGTH` bytes; `self` is valid.
        let ret = unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), out.len(), self.as_ptr()) };
        assert_eq!(ret, 1);
        out
    }

    pub(super) fn order_add(&self, other: &Self) -> Self {
        self.order_quick(other, bssl_sys::BN_mod_add_quick)
    }

    pub(super) fn order_sub(&self, other: &Self) -> Self {
        self.order_quick(other, bssl_sys::BN_mod_sub_quick)
    }

    fn order_quick(
        &self,
        other: &Self,
        op: unsafe extern "C" fn(
            *mut bssl_sys::BIGNUM,
            *const bssl_sys::BIGNUM,
            *const bssl_sys::BIGNUM,
            *const bssl_sys::BIGNUM,
        ) -> i32,
    ) -> Self {
        let r = Self::new();
        // SAFETY: all pointers are valid and both operands are canonical, as
        // the `_quick` functions require.
        let ret = unsafe { op(r.as_mut_ptr(), self.as_ptr(), other.as_ptr(), order()) };
        assert_eq!(ret, 1);
        r
    }

    pub(super) fn order_mul(&self, other: &Self) -> Self {
        let a_mont = Self::new();
        let r = Self::new();
        let ctx = BnCtx::new();
        let mont = order_mont();
        // SAFETY: all pointers are valid; `self` is canonical as
        // `BN_to_montgomery` requires.
        let ret = unsafe {
            bssl_sys::BN_to_montgomery(a_mont.as_mut_ptr(), self.as_ptr(), mont, ctx.as_mut_ptr())
        };
        assert_eq!(ret, 1);
        // SAFETY: all pointers are valid; both operands are below the order.
        let ret = unsafe {
            bssl_sys::BN_mod_mul_montgomery(
                r.as_mut_ptr(),
                a_mont.as_ptr(),
                other.as_ptr(),
                mont,
                ctx.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 1);
        r
    }

    pub(super) fn order_exp(&self, exponent: &Self) -> Self {
        let r = Self::new();
        let ctx = BnCtx::new();
        // SAFETY: all pointers are valid and `self` is canonical, as
        // `BN_mod_exp_mont_consttime` requires.
        let ret = unsafe {
            bssl_sys::BN_mod_exp_mont_consttime(
                r.as_mut_ptr(),
                self.as_ptr(),
                exponent.as_ptr(),
                order(),
                ctx.as_mut_ptr(),
                order_mont(),
            )
        };
        assert_eq!(ret, 1);
        r
    }

    fn as_ptr(&self) -> *const bssl_sys::BIGNUM {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&self) -> *mut bssl_sys::BIGNUM {
        self.0.as_ptr()
    }
}

impl Drop for Bignum {
    fn drop(&mut self) {
        // SAFETY: allocated by `BN_new`; BoringSSL cleanses before freeing.
        unsafe { bssl_sys::BN_free(self.0.as_ptr()) };
    }
}

struct BnCtx(NonNull<bssl_sys::BN_CTX>);

impl BnCtx {
    fn new() -> Self {
        // SAFETY: `BN_CTX_new` has no preconditions.
        let ptr = unsafe { bssl_sys::BN_CTX_new() };
        Self(NonNull::new(ptr).unwrap_or_else(|| alloc_failed()))
    }

    fn as_mut_ptr(&self) -> *mut bssl_sys::BN_CTX {
        self.0.as_ptr()
    }
}

impl Drop for BnCtx {
    fn drop(&mut self) {
        // SAFETY: allocated by `BN_CTX_new`.
        unsafe { bssl_sys::BN_CTX_free(self.0.as_ptr()) };
    }
}

pub(super) struct FieldArithmetic {
    modulus: Bignum,
    ctx: BnCtx,
    mont: *const bssl_sys::BN_MONT_CTX,
}

impl FieldArithmetic {
    pub(super) fn new() -> Self {
        Self {
            modulus: Bignum::from_bytes(&FIELD_MODULUS),
            ctx: BnCtx::new(),
            mont: field_mont(),
        }
    }

    pub(super) fn mul(&self, a: &Bignum, b: &Bignum) -> Bignum {
        let a_mont = Bignum::new();
        let r = Bignum::new();
        // SAFETY: all pointers are valid; `a` is reduced, as
        // `BN_to_montgomery` requires.
        let ret = unsafe {
            bssl_sys::BN_to_montgomery(
                a_mont.as_mut_ptr(),
                a.as_ptr(),
                self.mont,
                self.ctx.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 1);
        // SAFETY: all pointers are valid; both operands are reduced.
        let ret = unsafe {
            bssl_sys::BN_mod_mul_montgomery(
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

    pub(super) fn add(&self, a: &Bignum, b: &Bignum) -> Bignum {
        self.quick(a, b, bssl_sys::BN_mod_add_quick)
    }

    pub(super) fn sub(&self, a: &Bignum, b: &Bignum) -> Bignum {
        self.quick(a, b, bssl_sys::BN_mod_sub_quick)
    }

    fn quick(
        &self,
        a: &Bignum,
        b: &Bignum,
        op: unsafe extern "C" fn(
            *mut bssl_sys::BIGNUM,
            *const bssl_sys::BIGNUM,
            *const bssl_sys::BIGNUM,
            *const bssl_sys::BIGNUM,
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

    pub(super) fn exp(&self, base: &Bignum, exponent: &[u8; SCALAR_LENGTH]) -> Bignum {
        let exponent = Bignum::from_bytes(exponent);
        let r = Bignum::new();
        // SAFETY: all pointers are valid and `base` is reduced, as
        // `BN_mod_exp_mont_consttime` requires.
        let ret = unsafe {
            bssl_sys::BN_mod_exp_mont_consttime(
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

pub(super) struct EcPoint(NonNull<bssl_sys::EC_POINT>);

// SAFETY: an `EC_POINT` may be read concurrently; it is mutated only while
// exclusively borrowed.
unsafe impl Send for EcPoint {}
// SAFETY: as above.
unsafe impl Sync for EcPoint {}

impl EcPoint {
    pub(super) fn new() -> Self {
        // SAFETY: `group()` is valid.
        let ptr = unsafe { bssl_sys::EC_POINT_new(group()) };
        Self(NonNull::new(ptr).unwrap_or_else(|| alloc_failed()))
    }

    pub(super) fn identity() -> Self {
        let mut point = Self::new();
        // SAFETY: `group()` and `point` are valid.
        let ret = unsafe { bssl_sys::EC_POINT_set_to_infinity(group(), point.as_mut_ptr()) };
        assert_eq!(ret, 1);
        point
    }

    pub(super) fn generator() -> Self {
        // SAFETY: `group()` is valid; the generator is owned by the group.
        let generator = unsafe { bssl_sys::EC_GROUP_get0_generator(group()) };
        assert!(!generator.is_null());
        // SAFETY: `generator` and `group()` are valid.
        let ptr = unsafe { bssl_sys::EC_POINT_dup(generator, group()) };
        Self(NonNull::new(ptr).unwrap_or_else(|| alloc_failed()))
    }

    pub(super) fn is_identity(&self) -> bool {
        // SAFETY: `group()` and `self` are valid.
        unsafe { bssl_sys::EC_POINT_is_at_infinity(group(), self.as_ptr()) == 1 }
    }

    pub(super) fn ct_eq(&self, other: &Self) -> bool {
        // `EC_POINT_cmp` compares in constant time.
        // SAFETY: all pointers are valid; `ctx` may be null.
        let ret =
            unsafe { bssl_sys::EC_POINT_cmp(group(), self.as_ptr(), other.as_ptr(), null_mut()) };
        assert!(ret >= 0);
        ret == 0
    }

    pub(super) fn add(&self, other: &Self) -> Self {
        let mut r = Self::new();
        // SAFETY: all pointers are valid; `ctx` may be null.
        let ret = unsafe {
            bssl_sys::EC_POINT_add(
                group(),
                r.as_mut_ptr(),
                self.as_ptr(),
                other.as_ptr(),
                null_mut(),
            )
        };
        assert_eq!(ret, 1);
        r
    }

    pub(super) fn double(&self) -> Self {
        let mut r = Self::new();
        // SAFETY: all pointers are valid; `ctx` may be null.
        let ret =
            unsafe { bssl_sys::EC_POINT_dbl(group(), r.as_mut_ptr(), self.as_ptr(), null_mut()) };
        assert_eq!(ret, 1);
        r
    }

    pub(super) fn invert(&self) -> Self {
        let mut r = self.clone();
        // SAFETY: `group()` and `r` are valid; `ctx` may be null.
        let ret = unsafe { bssl_sys::EC_POINT_invert(group(), r.as_mut_ptr(), null_mut()) };
        assert_eq!(ret, 1);
        r
    }

    pub(super) fn mul(&self, scalar: &Bignum) -> Self {
        let mut r = Self::new();
        // SAFETY: all pointers are valid; the scalar is canonical, as
        // `EC_POINT_mul` requires; `ctx` may be null.
        let ret = unsafe {
            bssl_sys::EC_POINT_mul(
                group(),
                r.as_mut_ptr(),
                null(),
                self.as_ptr(),
                scalar.as_ptr(),
                null_mut(),
            )
        };
        assert_eq!(ret, 1);
        r
    }

    pub(super) fn mul_generator(scalar: &Bignum) -> Self {
        let mut r = Self::new();
        // SAFETY: as in `mul`; a null point selects the generator, for
        // which BoringSSL uses a precomputed table.
        let ret = unsafe {
            bssl_sys::EC_POINT_mul(
                group(),
                r.as_mut_ptr(),
                scalar.as_ptr(),
                null(),
                null(),
                null_mut(),
            )
        };
        assert_eq!(ret, 1);
        r
    }

    pub(super) fn decode(bytes: &[u8; POINT_LENGTH]) -> (Self, bool) {
        let mut point = Self::new();
        // SAFETY: all pointers are valid; `bytes` has `POINT_LENGTH` bytes.
        let ret = unsafe {
            bssl_sys::EC_POINT_oct2point(
                group(),
                point.as_mut_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                null_mut(),
            )
        };
        if ret != 1 {
            // SAFETY: clears the error queue that a failed parse leaves.
            unsafe { bssl_sys::ERR_clear_error() };
        }
        let compressed = bytes[0] == 2 || bytes[0] == 3;
        let valid = ret == 1 && compressed && !point.is_identity();
        (point, valid)
    }

    pub(super) fn encode(&self) -> Option<[u8; POINT_LENGTH]> {
        if self.is_identity() {
            return None;
        }
        let mut out = [0u8; POINT_LENGTH];
        // SAFETY: all pointers are valid; `out` has `POINT_LENGTH` bytes.
        let written = unsafe {
            bssl_sys::EC_POINT_point2oct(
                group(),
                self.as_ptr(),
                bssl_sys::point_conversion_form_t::POINT_CONVERSION_COMPRESSED,
                out.as_mut_ptr(),
                out.len(),
                null_mut(),
            )
        };
        assert_eq!(written, POINT_LENGTH);
        Some(out)
    }

    pub(super) fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Option<Self> {
        let mut point = Self::new();
        // SAFETY: all pointers are valid; the slices carry their lengths.
        let ret = unsafe {
            bssl_sys::EC_hash_to_curve_p256_xmd_sha256_sswu(
                group(),
                point.as_mut_ptr(),
                dst.as_ptr(),
                dst.len(),
                msg.as_ptr(),
                msg.len(),
            )
        };
        if ret != 1 {
            // SAFETY: clears the error the failed call queued.
            unsafe { bssl_sys::ERR_clear_error() };
            return None;
        }
        Some(point)
    }

    fn as_ptr(&self) -> *const bssl_sys::EC_POINT {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut bssl_sys::EC_POINT {
        self.0.as_ptr()
    }
}

impl Clone for EcPoint {
    fn clone(&self) -> Self {
        // SAFETY: `self` and `group()` are valid.
        let ptr = unsafe { bssl_sys::EC_POINT_dup(self.as_ptr(), group()) };
        Self(NonNull::new(ptr).unwrap_or_else(|| alloc_failed()))
    }
}

impl Drop for EcPoint {
    fn drop(&mut self) {
        // SAFETY: allocated by `EC_POINT_new` or `EC_POINT_dup`; BoringSSL
        // cleanses before freeing.
        unsafe { bssl_sys::EC_POINT_free(self.0.as_ptr()) };
    }
}

#[derive(Clone)]
pub(super) struct Sha256Ctx(bssl_sys::SHA256_CTX);

impl Sha256Ctx {
    pub(super) fn new() -> Self {
        let mut ctx = core::mem::MaybeUninit::<bssl_sys::SHA256_CTX>::uninit();
        // SAFETY: `SHA256_Init` fully initializes `ctx` and returns 1.
        let ret = unsafe { bssl_sys::SHA256_Init(ctx.as_mut_ptr()) };
        assert_eq!(ret, 1);
        // SAFETY: initialized above.
        Self(unsafe { ctx.assume_init() })
    }

    pub(super) fn update(&mut self, data: &[u8]) {
        // SAFETY: `self.0` is initialized; `data` is a valid slice.
        let ret = unsafe {
            bssl_sys::SHA256_Update(&mut self.0, data.as_ptr().cast::<c_void>(), data.len())
        };
        assert_eq!(ret, 1);
    }

    pub(super) fn finalize(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: `out` has `SHA256_DIGEST_LENGTH` bytes; `self.0` is
        // initialized. `SHA256_Final` clears the context it consumes, and
        // `Drop` cleanses it again.
        let ret = unsafe { bssl_sys::SHA256_Final(out.as_mut_ptr(), &mut self.0) };
        assert_eq!(ret, 1);
        out
    }
}

impl Drop for Sha256Ctx {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid, initialized context of its own size.
        unsafe {
            bssl_sys::OPENSSL_cleanse(
                (&raw mut self.0).cast::<c_void>(),
                core::mem::size_of::<bssl_sys::SHA256_CTX>(),
            )
        };
    }
}

pub(super) fn random_bytes(buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    // SAFETY: `buf` is a valid buffer of its length. `RAND_bytes` returns 1
    // or aborts the process.
    unsafe { bssl_sys::RAND_bytes(buf.as_mut_ptr(), buf.len()) == 1 }
}

/// Allocation failure is not handled short of aborting, as in `bssl-crypto`.
#[cold]
#[allow(clippy::panic)]
fn alloc_failed() -> ! {
    panic!("BoringSSL allocation failed")
}
