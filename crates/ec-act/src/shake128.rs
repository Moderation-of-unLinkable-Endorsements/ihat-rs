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

//! SHAKE128 through the selected cryptographic backend.

#[cfg(feature = "boringssl")]
#[allow(unsafe_code)]
mod imp {
    use core::ffi::c_void;
    use core::ptr::{NonNull, null_mut};

    struct Digest(NonNull<bssl_sys::EVP_MD_CTX>);

    impl Digest {
        fn new() -> Self {
            // SAFETY: `EVP_MD_CTX_new` has no preconditions.
            let ptr = unsafe { bssl_sys::EVP_MD_CTX_new() };
            let digest = Self(NonNull::new(ptr).unwrap_or_else(|| alloc_failed()));
            // SAFETY: `digest` is a fresh context, `EVP_shake128` returns a
            // static descriptor, and a null engine selects the default.
            let ret = unsafe {
                bssl_sys::EVP_DigestInit_ex(digest.0.as_ptr(), bssl_sys::EVP_shake128(), null_mut())
            };
            assert_eq!(ret, 1);
            digest
        }

        fn update(&mut self, input: &[u8]) {
            // SAFETY: `self` is initialized, and `input` is a valid buffer of
            // the supplied length.
            let ret = unsafe {
                bssl_sys::EVP_DigestUpdate(
                    self.0.as_ptr(),
                    input.as_ptr().cast::<c_void>(),
                    input.len(),
                )
            };
            assert_eq!(ret, 1);
        }

        fn squeeze(&mut self, output: &mut [u8]) {
            // SAFETY: `self` is initialized for an XOF, and `output` is a
            // valid writable buffer of the supplied length.
            let ret = unsafe {
                bssl_sys::EVP_DigestSqueeze(self.0.as_ptr(), output.as_mut_ptr(), output.len())
            };
            assert_eq!(ret, 1);
        }
    }

    impl Drop for Digest {
        fn drop(&mut self) {
            // SAFETY: the context was allocated by `EVP_MD_CTX_new` and is
            // owned by this wrapper.
            unsafe { bssl_sys::EVP_MD_CTX_free(self.0.as_ptr()) };
        }
    }

    /// Allocation failure is not handled short of aborting, as in
    /// `bssl-crypto` and the rest of this crate's BoringSSL backend.
    #[cold]
    #[allow(clippy::panic)]
    fn alloc_failed() -> ! {
        panic!("BoringSSL allocation failed")
    }

    pub(super) fn hash(inputs: &[&[u8]], output: &mut [u8]) {
        let mut digest = Digest::new();
        for input in inputs {
            digest.update(input);
        }
        digest.squeeze(output);
    }
}

#[cfg(all(feature = "rustcrypto", not(feature = "boringssl")))]
mod imp {
    use shake::{ExtendableOutput, Shake128, Update, XofReader};

    pub(super) fn hash(inputs: &[&[u8]], output: &mut [u8]) {
        let mut sponge = Shake128::default();
        for input in inputs {
            sponge.update(input);
        }
        sponge.finalize_xof().read(output);
    }
}

pub(crate) fn hash(inputs: &[&[u8]], output: &mut [u8]) {
    imp::hash(inputs, output);
}
