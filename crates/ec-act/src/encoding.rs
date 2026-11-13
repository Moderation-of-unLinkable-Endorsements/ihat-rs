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

//! Shared canonical-decoding helpers for wire and storage encodings.

use alloc::vec::Vec;

use crate::Error;
use crate::backend::{Backend, BackendFixedBaseExt, Point, SCALAR_LENGTH, Scalar};
use crate::hash::require;
use crate::protocol::Params;

/// Length of an encoded `uint64` amount.
pub(crate) const AMOUNT_LENGTH: usize = 8;

pub(crate) struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(length).ok_or(Error::Deserialize)?;
        let slice = self.data.get(self.offset..end).ok_or(Error::Deserialize)?;
        self.offset = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Deserialize)
    }

    pub(crate) fn element<B: Backend>(&mut self) -> Result<B::Point, Error> {
        require(B::Point::from_bytes(self.array()?), Error::Deserialize)
    }

    pub(crate) fn elements<B: Backend>(&mut self, count: usize) -> Result<Vec<B::Point>, Error> {
        (0..count).map(|_| self.element::<B>()).collect()
    }

    pub(crate) fn scalar<B: Backend>(&mut self) -> Result<B::Scalar, Error> {
        require(B::Scalar::from_bytes(self.array()?), Error::Deserialize)
    }

    pub(crate) fn amount<B: BackendFixedBaseExt>(
        &mut self,
        params: &Params<B>,
    ) -> Result<u64, Error> {
        let value = u64::from_be_bytes(*self.array()?);
        params.check_amount(value)?;
        Ok(value)
    }

    /// A compact NARG string for `witnesses` scalars, with every scalar
    /// checked to be canonical.
    pub(crate) fn proof<B: Backend>(&mut self, witnesses: usize) -> Result<&'a [u8], Error> {
        let proof = self.take((witnesses + 1) * SCALAR_LENGTH)?;
        for chunk in proof.chunks_exact(SCALAR_LENGTH) {
            let bytes: &[u8; SCALAR_LENGTH] = chunk.try_into().map_err(|_| Error::Deserialize)?;
            require(B::Scalar::from_bytes(bytes), Error::Deserialize)?;
        }
        Ok(proof)
    }

    pub(crate) fn finish(self) -> Result<(), Error> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(Error::Deserialize)
        }
    }
}

pub(crate) fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Deserialize)
}
