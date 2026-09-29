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

//! Crate-internal tests, run against every enabled backend: replayed test
//! vectors, protocol behavior, and primitive known answers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use alloc::vec::Vec;

use crate::random::Random;

/// Instantiates generic test functions for each enabled backend.
macro_rules! backend_tests {
    ($($name:ident),* $(,)?) => {
        #[cfg(feature = "rustcrypto")]
        mod rustcrypto {
            $(#[test] fn $name() { super::$name::<crate::backend::rustcrypto::RustCrypto>(); })*
        }
        #[cfg(feature = "boringssl")]
        mod boringssl {
            $(#[test] fn $name() { super::$name::<crate::backend::boringssl::BoringSsl>(); })*
        }
    };
}

mod primitives;
mod protocol;
mod vectors;

/// Serves `random` from a recorded byte string.
pub(crate) struct Replay {
    data: Vec<u8>,
    offset: usize,
}

impl Replay {
    pub(crate) fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            offset: 0,
        }
    }

    /// Asserts that every recorded byte was consumed.
    pub(crate) fn finish(self) {
        assert_eq!(self.offset, self.data.len(), "unconsumed replay bytes");
    }
}

impl Random for Replay {
    fn fill(&mut self, buf: &mut [u8]) {
        let end = self.offset + buf.len();
        assert!(
            end <= self.data.len(),
            "replay exhausted: {} of {}",
            end,
            self.data.len()
        );
        buf.copy_from_slice(&self.data[self.offset..end]);
        self.offset = end;
    }
}

/// The operating system's random number generator, for tests that do not
/// pin their randomness.
pub(crate) fn os_rng<B: crate::Backend>() -> crate::random::SystemRandom<B> {
    crate::random::SystemRandom::new()
}
