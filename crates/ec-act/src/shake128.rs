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
#[path = "shake128/boringssl.rs"]
#[allow(unsafe_code)]
mod imp;

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
