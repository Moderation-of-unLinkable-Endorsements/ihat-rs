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

//! ACT-specific hashing tags, scalar decoding, and error conversion.

use ec_ihat::hash;
use ec_ihat::hash::BackendHashExt;
use subtle::CtOption;
use zeroize::Zeroize;

use crate::Error;
use crate::backend::Backend;

#[cfg(test)]
pub(crate) use hash::XmdPrefix;

pub(crate) const NSEED: usize = crate::SEED_LENGTH;

/// Domain separation tag of `HashToGroup`.
pub(crate) const DST_HASH_TO_GROUP: &[u8] = b"HashToGroup-ACTv1-P256-SHA256";
/// Domain separation tag of `HashToScalar`.
pub(crate) const DST_HASH_TO_SCALAR: &[u8] = b"HashToScalar-ACTv1-P256-SHA256";

impl From<hash::Error> for Error {
    fn from(error: hash::Error) -> Self {
        match error {
            hash::Error::InvalidInput => Self::InvalidInput,
            hash::Error::Derive => Self::Derive,
        }
    }
}

/// Checks that a `CtOption` holds a value, mapping absence to `error`.
pub(crate) fn require<T, E>(value: CtOption<T>, error: E) -> Result<T, E> {
    value.into_option().ok_or(error)
}

/// Fiat-Shamir's little-endian `DecodeUint` is specific to ACT.
pub(crate) fn reduce_le_48<B: Backend>(bytes: &[u8; 48]) -> B::Scalar {
    let mut reversed = *bytes;
    reversed.reverse();
    let scalar = B::reduce_be_48(&reversed);
    reversed.zeroize();
    scalar
}
