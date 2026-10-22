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

//! The encodings of Section 5.7 of the draft, plus storage encodings of the
//! Credential and the Client's states.
//!
//! Decoding checks lengths, canonical encodings (which excludes the identity
//! element), amount bounds against the balance width, and that a spend's
//! shape matches its amounts. Every proof scalar is checked to be canonical.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::Error;
use crate::backend::{Backend, BackendFixedBaseExt, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::hash::require;
use crate::protocol::{
    ClientIssuanceState, ClientSpendState, Credential, IssueRequestMessage, IssueResponseMessage,
    Params, RefundMessage, SpendMessage, point_bytes,
};
use crate::statements::{spend_weights, spend_witness_count};

/// Length of a `uint64` amount on the wire.
const AMOUNT_LENGTH: usize = 8;

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
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

    fn element<B: Backend>(&mut self) -> Result<B::Point, Error> {
        require(B::Point::from_bytes(self.array()?), Error::Deserialize)
    }

    fn elements<B: Backend>(&mut self, count: usize) -> Result<Vec<B::Point>, Error> {
        (0..count).map(|_| self.element::<B>()).collect()
    }

    fn scalar<B: Backend>(&mut self) -> Result<B::Scalar, Error> {
        require(B::Scalar::from_bytes(self.array()?), Error::Deserialize)
    }

    fn amount<B: BackendFixedBaseExt>(&mut self, params: &Params<B>) -> Result<u64, Error> {
        let value = u64::from_be_bytes(*self.array()?);
        params.check_amount(value)?;
        Ok(value)
    }

    /// A compact NARG string for `witnesses` scalars, with every scalar
    /// checked to be canonical.
    fn proof<B: Backend>(&mut self, witnesses: usize) -> Result<&'a [u8], Error> {
        let proof = self.take((witnesses + 1) * SCALAR_LENGTH)?;
        for chunk in proof.chunks_exact(SCALAR_LENGTH) {
            let bytes: &[u8; SCALAR_LENGTH] = chunk.try_into().map_err(|_| Error::Deserialize)?;
            require(B::Scalar::from_bytes(bytes), Error::Deserialize)?;
        }
        Ok(proof)
    }

    fn finish(self) -> Result<(), Error> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(Error::Deserialize)
        }
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Deserialize)
}

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

impl<B: BackendFixedBaseExt> Credential<B> {
    /// The encoded length: `3 * Ns + 8 + Ne`.
    pub const LENGTH: usize = 3 * SCALAR_LENGTH + AMOUNT_LENGTH + POINT_LENGTH;

    /// Encodes as `Scalar k || uint64 c || Scalar r || Element A || Scalar e`,
    /// for storage. The encoding is secret.
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

    /// Decodes the encoding of [`Self::to_bytes`], checking `c < 2^L`.
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

    /// Encodes as `Scalar k || Scalar r || Element K`, for storage. The
    /// encoding is secret.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(Self::LENGTH));
        out.extend_from_slice(Zeroizing::new(self.k.to_bytes()).as_ref());
        out.extend_from_slice(Zeroizing::new(self.r.to_bytes()).as_ref());
        out.extend_from_slice(&point_bytes(&self.k_commitment));
        debug_assert_eq!(out.len(), Self::LENGTH);
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`].
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
    /// uint64 a || Element K_prime`, for storage. The encoding is secret.
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

    /// Decodes the encoding of [`Self::to_bytes`], checking the amounts
    /// against `2^L`.
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
