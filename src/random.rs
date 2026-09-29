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

//! The single source of randomness of the draft, `random(n)`.

use core::marker::PhantomData;

use crate::backend::Backend;

/// Serves the bytes that `random(n)` returns.
///
/// Every algorithm draws seeds from this interface only, so replaying a
/// recorded byte string reproduces its outputs bit for bit; the test vectors
/// rely on this.
pub(crate) trait Random {
    /// Fills `buf` with the next bytes.
    fn fill(&mut self, buf: &mut [u8]);
}

/// The operating system's random number generator, through the backend.
pub(crate) struct SystemRandom<B>(PhantomData<B>);

impl<B: Backend> SystemRandom<B> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}

impl<B: Backend> Random for SystemRandom<B> {
    fn fill(&mut self, buf: &mut [u8]) {
        B::random_bytes(buf);
    }
}
