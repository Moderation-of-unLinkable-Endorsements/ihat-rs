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

//! Local storage encodings for secret client state.
//!
//! These encodings are not protocol messages. Callers are responsible for
//! protecting the returned bytes as secrets and for preventing rollback or
//! reuse of persisted credentials and continuations.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::Error;
use crate::backend::{BackendFixedBaseExt, POINT_LENGTH, SCALAR_LENGTH, Scalar};
use crate::encoding::{AMOUNT_LENGTH, Reader};
use crate::protocol::{ClientIssuanceState, ClientSpendState, Credential, Params, point_bytes};

impl<B: BackendFixedBaseExt> Credential<B> {
    /// The encoded length: `3 * Ns + 8 + Ne`.
    pub const LENGTH: usize = 3 * SCALAR_LENGTH + AMOUNT_LENGTH + POINT_LENGTH;

    /// Encodes as `Scalar k || uint64 c || Scalar r || Element A || Scalar e`,
    /// for local storage. The encoding is secret.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(Self::LENGTH));
        out.extend_from_slice(Zeroizing::new(self.k.to_bytes()).as_ref());
        out.extend_from_slice(&self.c.to_be_bytes());
        out.extend_from_slice(Zeroizing::new(self.r.to_bytes()).as_ref());
        out.extend_from_slice(&point_bytes(&self.a));
        out.extend_from_slice(Zeroizing::new(self.e.to_bytes()).as_ref());
        debug_assert_eq!(out.len(), Self::LENGTH);
        out
    }

    /// Decodes the local storage encoding of [`Self::to_bytes`], checking
    /// `c < 2^L`.
    pub fn from_bytes(params: &Params<B>, bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let credential = Self {
            k: reader.scalar::<B>()?,
            c: reader.amount(params)?,
            r: reader.scalar::<B>()?,
            a: reader.element::<B>()?,
            e: reader.scalar::<B>()?,
        };
        reader.finish()?;
        Ok(credential)
    }
}

impl<B: BackendFixedBaseExt> ClientIssuanceState<B> {
    /// The encoded length: `2 * Ns + Ne`.
    pub const LENGTH: usize = 2 * SCALAR_LENGTH + POINT_LENGTH;

    /// Encodes as `Scalar k || Scalar r || Element K`, for local storage. The
    /// encoding is secret.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(Self::LENGTH));
        out.extend_from_slice(Zeroizing::new(self.k.to_bytes()).as_ref());
        out.extend_from_slice(Zeroizing::new(self.r.to_bytes()).as_ref());
        out.extend_from_slice(&point_bytes(&self.k_commitment));
        debug_assert_eq!(out.len(), Self::LENGTH);
        out
    }

    /// Decodes the local storage encoding of [`Self::to_bytes`].
    pub fn from_bytes(_params: &Params<B>, bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let state = Self {
            k: reader.scalar::<B>()?,
            r: reader.scalar::<B>()?,
            k_commitment: reader.element::<B>()?,
        };
        reader.finish()?;
        Ok(state)
    }
}

impl<B: BackendFixedBaseExt> ClientSpendState<B> {
    /// The encoded length: `2 * Ns + 3 * 8 + Ne`.
    pub const LENGTH: usize = 2 * SCALAR_LENGTH + 3 * AMOUNT_LENGTH + POINT_LENGTH;

    /// Encodes as `Scalar kstar || Scalar r_star || uint64 v1 || uint64 s ||
    /// uint64 a || Element K_prime`, for local storage. The encoding is secret.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(Self::LENGTH));
        out.extend_from_slice(Zeroizing::new(self.kstar.to_bytes()).as_ref());
        out.extend_from_slice(Zeroizing::new(self.r_star.to_bytes()).as_ref());
        out.extend_from_slice(&self.v1.to_be_bytes());
        out.extend_from_slice(&self.s.to_be_bytes());
        out.extend_from_slice(&self.a.to_be_bytes());
        out.extend_from_slice(&point_bytes(&self.k_prime));
        debug_assert_eq!(out.len(), Self::LENGTH);
        out
    }

    /// Decodes the local storage encoding of [`Self::to_bytes`], checking the
    /// amounts against `2^L`.
    pub fn from_bytes(params: &Params<B>, bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let state = Self {
            kstar: reader.scalar::<B>()?,
            r_star: reader.scalar::<B>()?,
            v1: reader.amount(params)?,
            s: reader.amount(params)?,
            a: reader.amount(params)?,
            k_prime: reader.element::<B>()?,
        };
        reader.finish()?;
        Ok(state)
    }
}
