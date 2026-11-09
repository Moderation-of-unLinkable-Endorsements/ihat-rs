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

//! Crate-internal tests, run against every enabled backend: known answers
//! and properties of the primitives, and agreement between the backends.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
