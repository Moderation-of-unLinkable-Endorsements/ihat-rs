//! Secret-state codecs, distinct from the draft's network messages.
//! No storage, encryption, locking, expiry, or replay policy lives here.

use alloc::vec::Vec;
use zeroize::Zeroizing;

use crate::backend::{POINT_LENGTH, SCALAR_LENGTH, Scalar};
use crate::protocol::{point_bytes, u16_prefix};
use crate::wire::{Reader, put_vector};
use crate::{AnchorState, Backend, ClientState, Error, PROTOCOL_CONTEXT};

/// `label || "-" || ctx_proto`, following the draft's domain separation tags.
/// `ctx_proto` carries the version and ciphersuite.
fn header(label: &[u8]) -> Vec<u8> {
    [label, b"-", PROTOCOL_CONTEXT].concat()
}

fn reader<'a>(bytes: &'a [u8], label: &[u8]) -> Result<Reader<'a>, Error> {
    let header = header(label);
    let mut reader = Reader::new(bytes);
    if reader.take(header.len())? != header {
        return Err(Error::Deserialize);
    }
    Ok(reader)
}

/// Rejects a zero scalar, which honest state never holds: derived scalars are
/// nonzero (Section 4.2 of the draft) and so is the challenge (Section 5.2).
fn nonzero<S: Scalar>(scalars: &[&S]) -> Result<(), Error> {
    let zero = scalars
        .iter()
        .fold(subtle::Choice::from(0), |acc, s| acc | s.is_zero());
    if bool::from(zero) {
        Err(Error::Deserialize)
    } else {
        Ok(())
    }
}

impl<B: Backend> AnchorState<B> {
    /// Encodes the secret state for the Anchor's own storage, never the
    /// network: the session identifier, then `a`, `y`, `t`.
    ///
    /// Whoever can replay or modify a stored state recovers the signing key
    /// (Section 5.3 of the draft). Authenticate it, for example with an AEAD
    /// bound to the session identifier, and consume it at most once.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(header(b"AnchorState"));
        // Reserve before secrets are written; vector length prefixes use at most 8 bytes.
        out.reserve(8 + self.session_id.len() + 3 * SCALAR_LENGTH);
        put_vector(&mut out, &self.session_id);
        for scalar in [&self.a, &self.y, &self.t] {
            out.extend_from_slice(Zeroizing::new(scalar.to_bytes()).as_ref());
        }
        out
    }

    /// Decodes [`Self::to_bytes`], rejecting noncanonical encodings, zero
    /// scalars, and trailing bytes. It does not authenticate the input or
    /// know whether the state was already consumed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = reader(bytes, b"AnchorState")?;
        let mut state = Self {
            session_id: reader.vector()?.to_vec(),
            a: B::Scalar::default(),
            y: B::Scalar::default(),
            t: B::Scalar::default(),
        };
        state.a = reader.scalar::<B>()?;
        state.y = reader.scalar::<B>()?;
        state.t = reader.scalar::<B>()?;
        reader.finish()?;
        nonzero(&[&state.a, &state.y, &state.t])?;
        Ok(state)
    }
}

impl<B: Backend> ClientState<B> {
    /// Encodes the secret state for the Client's own storage, never the
    /// network: the nullifier, issuance context, commitment, then `r1`, `r2`,
    /// `gamma1`, `gamma2`, `challenge`, `c`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(header(b"ClientState"));
        // Reserve before secrets are written; vector length prefixes use at most 8 bytes.
        out.reserve(self.nf.len() + 8 + self.ctx_iss.len() + 2 * POINT_LENGTH + 6 * SCALAR_LENGTH);
        out.extend_from_slice(&self.nf);
        put_vector(&mut out, &self.ctx_iss);
        out.extend_from_slice(&point_bytes(&self.commitment_a));
        out.extend_from_slice(&point_bytes(&self.commitment_c));
        for scalar in [
            &self.r1,
            &self.r2,
            &self.gamma1,
            &self.gamma2,
            &self.challenge,
            &self.c,
        ] {
            out.extend_from_slice(Zeroizing::new(scalar.to_bytes()).as_ref());
        }
        out
    }

    /// Decodes [`Self::to_bytes`], rejecting noncanonical encodings, zero
    /// scalars, and trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = reader(bytes, b"ClientState")?;
        let nf = Zeroizing::new(*reader.array()?);
        let context = reader.vector()?;
        u16_prefix(context).map_err(|_| Error::Deserialize)?;
        let commitment_a = reader.element::<B>()?;
        let commitment_c = reader.element::<B>()?;
        let mut state = Self {
            nf: *nf,
            ctx_iss: context.to_vec(),
            commitment_a,
            commitment_c,
            r1: B::Scalar::default(),
            r2: B::Scalar::default(),
            gamma1: B::Scalar::default(),
            gamma2: B::Scalar::default(),
            challenge: B::Scalar::default(),
            c: B::Scalar::default(),
        };
        state.r1 = reader.scalar::<B>()?;
        state.r2 = reader.scalar::<B>()?;
        state.gamma1 = reader.scalar::<B>()?;
        state.gamma2 = reader.scalar::<B>()?;
        state.challenge = reader.scalar::<B>()?;
        state.c = reader.scalar::<B>()?;
        reader.finish()?;
        nonzero(&[
            &state.r1,
            &state.r2,
            &state.gamma1,
            &state.gamma2,
            &state.challenge,
            &state.c,
        ])?;
        Ok(state)
    }
}
