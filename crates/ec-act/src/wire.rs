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

//! The protocol-message encodings of Section 5.7 of the draft.
//!
//! Decoding checks lengths, canonical encodings (which excludes the identity
//! element), amount bounds against the balance width, and that a spend's
//! shape matches its amounts. Every proof scalar is checked to be canonical.

use alloc::vec::Vec;

use crate::Error;
use crate::backend::{BackendFixedBaseExt, POINT_LENGTH, SCALAR_LENGTH, Scalar};
use crate::encoding::{AMOUNT_LENGTH, Reader, array};
use crate::protocol::{
    IssueRequestMessage, IssueResponseMessage, Params, RefundMessage, SpendMessage, point_bytes,
};
use crate::statements::{spend_weights, spend_witness_count};

impl<B: BackendFixedBaseExt> IssueRequestMessage<B> {
    /// The encoded length: `Ne + 3 * Ns`.
    pub const LENGTH: usize = POINT_LENGTH + 3 * SCALAR_LENGTH;

    /// Encodes as `Element K || opaque pok[3 * Ns]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LENGTH);
        out.extend_from_slice(&point_bytes(&self.k_commitment));
        out.extend_from_slice(&self.pok);
        debug_assert_eq!(out.len(), Self::LENGTH);
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`].
    pub fn from_bytes(_params: &Params<B>, bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            k_commitment: reader.element::<B>()?,
            pok: array(reader.proof::<B>(2)?)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

impl<B: BackendFixedBaseExt> IssueResponseMessage<B> {
    /// The encoded length: `Ne + Ns + 8 + 2 * Ns`.
    pub const LENGTH: usize = POINT_LENGTH + 3 * SCALAR_LENGTH + AMOUNT_LENGTH;

    /// Encodes as `Element A || Scalar e || uint64 c || opaque pok[2 * Ns]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LENGTH);
        out.extend_from_slice(&point_bytes(&self.a));
        out.extend_from_slice(&self.e.to_bytes());
        out.extend_from_slice(&self.c.to_be_bytes());
        out.extend_from_slice(&self.pok);
        debug_assert_eq!(out.len(), Self::LENGTH);
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`], checking `c < 2^L`.
    pub fn from_bytes(params: &Params<B>, bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            a: reader.element::<B>()?,
            e: reader.scalar::<B>()?,
            c: reader.amount(params)?,
            pok: array(reader.proof::<B>(1)?)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

impl<B: BackendFixedBaseExt> RefundMessage<B> {
    /// The encoded length: `Ne + Ns + 8 + 2 * Ns`.
    pub const LENGTH: usize = POINT_LENGTH + 3 * SCALAR_LENGTH + AMOUNT_LENGTH;

    /// Encodes as `Element A || Scalar e || uint64 t || opaque pok[2 * Ns]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LENGTH);
        out.extend_from_slice(&point_bytes(&self.a));
        out.extend_from_slice(&self.e.to_bytes());
        out.extend_from_slice(&self.t.to_be_bytes());
        out.extend_from_slice(&self.pok);
        debug_assert_eq!(out.len(), Self::LENGTH);
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`], checking `t < 2^L`.
    pub fn from_bytes(params: &Params<B>, bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            a: reader.element::<B>()?,
            e: reader.scalar::<B>()?,
            t: reader.amount(params)?,
            pok: array(reader.proof::<B>(1)?)?,
        };
        reader.finish()?;
        Ok(message)
    }
}

impl<B: BackendFixedBaseExt> SpendMessage<B> {
    /// The encoded length of a spend of `s` with allowance `a` at the
    /// balance width of `params`.
    pub fn encoded_len(params: &Params<B>, s: u64, a: u64) -> Result<usize, Error> {
        let l = usize::from(params.balance_width());
        let refresh = s == 0 && a == 0;
        let commitments = 3 + if refresh {
            1
        } else {
            spend_weights(l, s, a)?.len()
        };
        Ok(SCALAR_LENGTH
            + 2 * AMOUNT_LENGTH
            + commitments * POINT_LENGTH
            + (spend_witness_count(l, s, a)? + 1) * SCALAR_LENGTH)
    }

    /// Encodes as `Scalar k || uint64 s || uint64 a || Element A_prime ||
    /// Element B_bar || Element K_n || Com1[n] or Com_c || pok`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let points = 3 + self.com1.len() + usize::from(self.com_c.is_some());
        let length = SCALAR_LENGTH + 2 * AMOUNT_LENGTH + points * POINT_LENGTH + self.pok.len();
        let mut out = Vec::with_capacity(length);
        out.extend_from_slice(&self.k.to_bytes());
        out.extend_from_slice(&self.s.to_be_bytes());
        out.extend_from_slice(&self.a.to_be_bytes());
        for point in [&self.a_prime, &self.b_bar, &self.k_n] {
            out.extend_from_slice(&point_bytes(point));
        }
        for point in self.com1.iter().chain(&self.com_c) {
            out.extend_from_slice(&point_bytes(point));
        }
        out.extend_from_slice(&self.pok);
        debug_assert_eq!(out.len(), length);
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`]. The shape is fixed by
    /// `s` and `a` and the balance width of `params`.
    pub fn from_bytes(params: &Params<B>, bytes: &[u8]) -> Result<Self, Error> {
        let l = usize::from(params.balance_width());
        let mut reader = Reader::new(bytes);
        let k = reader.scalar::<B>()?;
        let s = reader.amount(params)?;
        let a = reader.amount(params)?;
        let refresh = s == 0 && a == 0;
        let weights = spend_weights(l, s, a)?;
        let a_prime = reader.element::<B>()?;
        let b_bar = reader.element::<B>()?;
        let k_n = reader.element::<B>()?;
        let com1 = reader.elements::<B>(if refresh { 0 } else { weights.len() })?;
        let com_c = if refresh {
            Some(reader.element::<B>()?)
        } else {
            None
        };
        let pok = reader.proof::<B>(spend_witness_count(l, s, a)?)?.to_vec();
        reader.finish()?;
        Ok(Self {
            k,
            s,
            a,
            a_prime,
            b_bar,
            k_n,
            com1,
            com_c,
            pok,
        })
    }
}
