//! The encodings of the draft: the three issuance messages, the
//! Endorsement, and the redemption.
//!
//! Decoding checks lengths, canonical encodings (which excludes the identity
//! element), minimal length prefixes, and that a redemption's vectors match
//! the depth of the Anchor Set's tree. Every other check is the protocol
//! algorithms'.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::backend::{Backend, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::commitment::depth;
use crate::hash::require;
use crate::protocol::{
    ChallengeMessage, CommitMessage, Endorsement, Redemption, ResponseMessage, Signature,
    point_bytes,
};
use crate::{Error, NULLIFIER_LENGTH};

/// Length of an encoded signature with its nullifier.
const SIGNATURE_LENGTH: usize = 4 * SCALAR_LENGTH + NULLIFIER_LENGTH;

/// Length of an encoded response.
const RESPONSE_LENGTH: usize = 3 * SCALAR_LENGTH;

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

    fn scalar<B: Backend>(&mut self) -> Result<B::Scalar, Error> {
        require(B::Scalar::from_bytes(self.array()?), Error::Deserialize)
    }

    /// A variable-length integer, rejecting any encoding that is not the
    /// shortest.
    fn length(&mut self) -> Result<usize, Error> {
        let first = self.take(1)?[0];
        let size = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.take(size - 1)? {
            value = (value << 8) | u64::from(*byte);
        }
        if size > 1 && value < 1 << (8 * (size / 2) - 2) {
            return Err(Error::Deserialize);
        }
        usize::try_from(value).map_err(|_| Error::Deserialize)
    }

    /// An `opaque value<V>`.
    fn vector(&mut self) -> Result<&'a [u8], Error> {
        let length = self.length()?;
        self.take(length)
    }

    /// A `Signature`, held in a `Zeroizing` so that a decoding failure
    /// wipes the fields read so far.
    fn signature<B: Backend>(&mut self) -> Result<Zeroizing<Signature<B>>, Error> {
        let mut signature = Zeroizing::new(Signature {
            c: B::Scalar::default(),
            s: B::Scalar::default(),
            y: B::Scalar::default(),
            t: B::Scalar::default(),
            nf: [0; NULLIFIER_LENGTH],
        });
        signature.c = self.scalar::<B>()?;
        signature.s = self.scalar::<B>()?;
        signature.y = self.scalar::<B>()?;
        signature.t = self.scalar::<B>()?;
        signature.nf = *self.array()?;
        Ok(signature)
    }

    fn finish(self) -> Result<(), Error> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(Error::Deserialize)
        }
    }
}

/// The minimum-size variable-length integer encoding of `value`, which is
/// below `2^62`.
fn length_prefix(value: usize) -> Vec<u8> {
    let value = value as u64;
    debug_assert!(value < 1 << 62);
    if value < 1 << 6 {
        alloc::vec![value as u8]
    } else if value < 1 << 14 {
        (value as u16 | 0x4000).to_be_bytes().to_vec()
    } else if value < 1 << 30 {
        (value as u32 | 0x8000_0000).to_be_bytes().to_vec()
    } else {
        (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec()
    }
}

/// Appends `opaque value<V>`.
fn put_vector(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&length_prefix(value.len()));
    out.extend_from_slice(value);
}

fn put_signature<B: Backend>(out: &mut Vec<u8>, signature: &Signature<B>) {
    for scalar in [&signature.c, &signature.s, &signature.y, &signature.t] {
        out.extend_from_slice(&scalar.to_bytes());
    }
    out.extend_from_slice(&signature.nf);
}

impl<B: Backend> CommitMessage<B> {
    /// Encodes as `opaque session_id<V> || Element A || Element C`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.session_id.len() + 2 * POINT_LENGTH);
        put_vector(&mut out, &self.session_id);
        out.extend_from_slice(&point_bytes(&self.a));
        out.extend_from_slice(&point_bytes(&self.c));
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            session_id: reader.vector()?.to_vec(),
            a: reader.element::<B>()?,
            c: reader.element::<B>()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

impl<B: Backend> ChallengeMessage<B> {
    /// Encodes as `opaque session_id<V> || Scalar challenge`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.session_id.len() + SCALAR_LENGTH);
        put_vector(&mut out, &self.session_id);
        out.extend_from_slice(&self.challenge.to_bytes());
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            session_id: reader.vector()?.to_vec(),
            challenge: reader.scalar::<B>()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

impl<B: Backend> ResponseMessage<B> {
    /// The encoded length: `3 * Ns`.
    pub const LENGTH: usize = RESPONSE_LENGTH;

    /// Encodes as `Scalar s || Scalar y || Scalar t`.
    pub fn to_bytes(&self) -> [u8; RESPONSE_LENGTH] {
        let mut out = [0u8; RESPONSE_LENGTH];
        for (chunk, scalar) in out
            .chunks_exact_mut(SCALAR_LENGTH)
            .zip([&self.s, &self.y, &self.t])
        {
            chunk.copy_from_slice(&scalar.to_bytes());
        }
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let message = Self {
            s: reader.scalar::<B>()?,
            y: reader.scalar::<B>()?,
            t: reader.scalar::<B>()?,
        };
        reader.finish()?;
        Ok(message)
    }
}

impl<B: Backend> Endorsement<B> {
    /// The encoded length: `4 * Ns + Nn`.
    pub const LENGTH: usize = SIGNATURE_LENGTH;

    /// Encodes as `Scalar c || Scalar s || Scalar y || Scalar t ||
    /// opaque nf[Nn]`, for storage by the Client. It is secret until
    /// redeemed and is never sent.
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut out = zeroize::Zeroizing::new(Vec::with_capacity(Self::LENGTH));
        put_signature(&mut out, &self.signature);
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let signature = reader.signature::<B>()?;
        reader.finish()?;
        Ok(Self {
            signature: (*signature).clone(),
        })
    }
}

impl<B: Backend> Redemption<B> {
    /// The encoded length of a redemption against an Anchor Set of `n`
    /// keys.
    pub fn encoded_len(n: usize) -> usize {
        let q = depth(n);
        POINT_LENGTH
            + SIGNATURE_LENGTH
            + 2 * SCALAR_LENGTH
            + length_prefix(q * POINT_LENGTH).len()
            + q * POINT_LENGTH
            + length_prefix(q * SCALAR_LENGTH).len()
            + q * SCALAR_LENGTH
    }

    /// Encodes as `Element rerandomized_key || Endorsement shown ||
    /// Scalar proof_challenge || Scalar response ||
    /// Element commitment_keys<V> || Scalar openings<V>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let q = self.commitment_keys.len();
        let mut out = Vec::with_capacity(
            POINT_LENGTH
                + SIGNATURE_LENGTH
                + 2 * SCALAR_LENGTH
                + 16
                + q * POINT_LENGTH
                + self.openings.len() * SCALAR_LENGTH,
        );
        out.extend_from_slice(&point_bytes(&self.x_hat));
        put_signature(&mut out, &self.shown);
        out.extend_from_slice(&self.proof_challenge.to_bytes());
        out.extend_from_slice(&self.response.to_bytes());
        let keys: Vec<u8> = self.commitment_keys.iter().flat_map(point_bytes).collect();
        put_vector(&mut out, &keys);
        let openings: Vec<u8> = self
            .openings
            .iter()
            .flat_map(|opening| opening.to_bytes())
            .collect();
        put_vector(&mut out, &openings);
        out
    }

    /// Decodes the encoding of [`Self::to_bytes`] for an Anchor Set of `n`
    /// keys, requiring `Depth(n)` commitment keys and openings.
    pub fn from_bytes(bytes: &[u8], n: usize) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let x_hat = reader.element::<B>()?;
        let shown = reader.signature::<B>()?;
        let proof_challenge = reader.scalar::<B>()?;
        let response = reader.scalar::<B>()?;
        let keys = reader.vector()?;
        let openings = reader.vector()?;
        reader.finish()?;

        let q = depth(n);
        if keys.len() != q * POINT_LENGTH || openings.len() != q * SCALAR_LENGTH {
            return Err(Error::Deserialize);
        }
        let mut keys = Reader::new(keys);
        let mut openings = Reader::new(openings);
        Ok(Self {
            x_hat,
            shown: (*shown).clone(),
            proof_challenge,
            response,
            commitment_keys: (0..q)
                .map(|_| keys.element::<B>())
                .collect::<Result<_, _>>()?,
            openings: (0..q)
                .map(|_| openings.scalar::<B>())
                .collect::<Result<_, _>>()?,
        })
    }
}
