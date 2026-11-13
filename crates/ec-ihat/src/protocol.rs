//! The endorsement scheme: keys, issuance, verification, and redemption,
//! following Sections 3 to 5 of the draft.

use alloc::vec::Vec;
use core::fmt;

use mole_p256::SEED_LENGTH as NSEED;
use mole_p256::hash::BackendHashExt;
use mole_p256::random::{Random, SystemRandom};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::backend::{Backend, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::commitment::{self, Key, Node};
use crate::wire::require;
use crate::{DefaultBackend, Error, NULLIFIER_LENGTH, PROTOCOL_CONTEXT};

/// The protocol context under which every hash is computed.
const CTX: &[u8] = PROTOCOL_CONTEXT;

mod issuance;
mod redemption;

#[cfg(test)]
mod test_support;

pub use issuance::{challenge, commit, finalize, respond, verify};
pub use redemption::{redeem, verify_redemption};

#[cfg(test)]
pub(crate) use issuance::{challenge_with, commit_with};
#[cfg(test)]
pub(crate) use redemption::redeem_with;
#[cfg(test)]
pub(crate) use test_support::{
    compute_challenge_for_tests, context_base_for_tests, delta_for_tests,
};

/// The largest `ctx_red` that `Message` admits: the message is itself
/// length-prefixed, so it holds at most `2^16 - 1 - Nn - 4` bytes of it.
const MAX_REDEMPTION_CONTEXT: usize = u16::MAX as usize - NULLIFIER_LENGTH - 4;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// An Anchor's key pair `(skA, pkA)`.
#[derive(Clone)]
pub struct SecretKey<B: Backend = DefaultBackend> {
    pub(crate) sk: B::Scalar,
    pk: B::Point,
}

impl<B: Backend> SecretKey<B> {
    /// `G.DeriveKeyPair(seed, "GenerateKeyPair")`: derives a key pair from a
    /// seed.
    pub fn from_seed(seed: &[u8; NSEED]) -> Result<Self, Error> {
        let sk = B::derive_key_scalar(CTX, seed, b"GenerateKeyPair")?;
        let pk = B::Point::mul_generator(&sk);
        Ok(Self { sk, pk })
    }

    /// The public key `pkA`.
    pub fn public_key(&self) -> PublicKey<B> {
        PublicKey {
            pk: self.pk.clone(),
        }
    }
}

impl<B: Backend> Zeroize for SecretKey<B> {
    fn zeroize(&mut self) {
        self.sk.zeroize();
        self.pk.zeroize();
    }
}

impl<B: Backend> Drop for SecretKey<B> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<B: Backend> ZeroizeOnDrop for SecretKey<B> {}

impl<B: Backend> fmt::Debug for SecretKey<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("pk", &self.pk)
            .finish_non_exhaustive()
    }
}

/// An Anchor's public key `pkA`, published in its configuration and listed
/// in the Anchor Sets of the Moderators that accept its Endorsements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<B: Backend = DefaultBackend> {
    pub(crate) pk: B::Point,
}

impl<B: Backend> PublicKey<B> {
    /// `SerializeElement(pkA)`.
    pub fn to_bytes(&self) -> [u8; POINT_LENGTH] {
        point_bytes(&self.pk)
    }

    /// Parses `SerializeElement(pkA)`.
    pub fn from_bytes(bytes: &[u8; POINT_LENGTH]) -> Result<Self, Error> {
        Ok(Self {
            pk: require(B::Point::from_bytes(bytes), Error::Deserialize)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// The Anchor's state between [`commit`] and [`respond`]: `(a, y, t)`. It
/// answers at most one challenge.
pub struct AnchorState<B: Backend = DefaultBackend> {
    pub(crate) a: B::Scalar,
    pub(crate) y: B::Scalar,
    pub(crate) t: B::Scalar,
}

/// The Anchor's opening message, `CommitMessage`: the commitment `(A, C)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitMessage<B: Backend = DefaultBackend> {
    pub(crate) a: B::Point,
    pub(crate) c: B::Point,
}

/// The Client's state between [`challenge`] and [`finalize`]: the
/// nullifier, the issuance context, the Anchor's commitment, the blinding
/// factors, and both forms of the challenge. It is finalized against at
/// most one response.
pub struct ClientState<B: Backend = DefaultBackend> {
    pub(crate) nf: [u8; NULLIFIER_LENGTH],
    pub(crate) ctx_iss: Vec<u8>,
    pub(crate) commitment_a: B::Point,
    pub(crate) commitment_c: B::Point,
    pub(crate) r1: B::Scalar,
    pub(crate) r2: B::Scalar,
    pub(crate) gamma1: B::Scalar,
    pub(crate) gamma2: B::Scalar,
    pub(crate) challenge: B::Scalar,
    pub(crate) c: B::Scalar,
}

/// The Client's blinded challenge, `ChallengeMessage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeMessage<B: Backend = DefaultBackend> {
    pub(crate) challenge: B::Scalar,
}

/// The Anchor's response, `ResponseMessage`: `(s, y, t)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseMessage<B: Backend = DefaultBackend> {
    pub(crate) s: B::Scalar,
    pub(crate) y: B::Scalar,
    pub(crate) t: B::Scalar,
}

/// A signature `(c, s, y, t)` with its nullifier: the content of an
/// Endorsement, and the shown Endorsement of a redemption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Signature<B: Backend> {
    pub(crate) c: B::Scalar,
    pub(crate) s: B::Scalar,
    pub(crate) y: B::Scalar,
    pub(crate) t: B::Scalar,
    pub(crate) nf: [u8; NULLIFIER_LENGTH],
}

impl<B: Backend> Zeroize for Signature<B> {
    fn zeroize(&mut self) {
        self.c.zeroize();
        self.s.zeroize();
        self.y.zeroize();
        self.t.zeroize();
        self.nf.zeroize();
    }
}

/// An Endorsement `(c, s, y, t, nf)`: a signature on the message that binds
/// the nullifier `nf` and the redemption context, under the issuance
/// context and the Anchor's key. The Client holds it until it is redeemed.
pub struct Endorsement<B: Backend = DefaultBackend> {
    pub(crate) signature: Signature<B>,
}

impl<B: Backend> Endorsement<B> {
    /// The nullifier `nf`, which the redemption reveals.
    pub fn nullifier(&self) -> &[u8; NULLIFIER_LENGTH] {
        &self.signature.nf
    }
}

/// A redemption: the rerandomized key `X_hat`, the Endorsement adapted to
/// it, and the issuer-hiding proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redemption<B: Backend = DefaultBackend> {
    pub(crate) x_hat: B::Point,
    pub(crate) shown: Signature<B>,
    pub(crate) proof_challenge: B::Scalar,
    pub(crate) response: B::Scalar,
    pub(crate) commitment_keys: Vec<B::Point>,
    pub(crate) openings: Vec<B::Scalar>,
}

impl<B: Backend> Redemption<B> {
    /// The nullifier `nf` of the redeemed Endorsement.
    ///
    /// The Moderator must reject a redemption whose nullifier it has
    /// recorded, and record it before granting anything on its strength.
    pub fn nullifier(&self) -> &[u8; NULLIFIER_LENGTH] {
        &self.shown.nf
    }
}

/// A record that holds secrets: zeroized on drop and redacted in `Debug`.
macro_rules! secret_record {
    ($type:ident { $($scalar:ident),* ; $($point:ident),* ; $($plain:ident),* }) => {
        impl<B: Backend> Zeroize for $type<B> {
            fn zeroize(&mut self) {
                $(self.$scalar.zeroize();)*
                $(self.$point.zeroize();)*
                $(self.$plain.zeroize();)*
            }
        }

        impl<B: Backend> Drop for $type<B> {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl<B: Backend> ZeroizeOnDrop for $type<B> {}

        impl<B: Backend> fmt::Debug for $type<B> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($type)).finish_non_exhaustive()
            }
        }
    };
}

secret_record!(AnchorState { a, y, t; ; });
secret_record!(ClientState {
    r1, r2, gamma1, gamma2, challenge, c;
    commitment_a, commitment_c;
    nf, ctx_iss
});
secret_record!(Endorsement { ; ; signature });

// ---------------------------------------------------------------------------
// Shared computations
// ---------------------------------------------------------------------------

/// `I2OSP(len(value), 2)`, the prefix of `U16Prefixed(value)`.
pub(crate) fn u16_prefix(value: &[u8]) -> Result<[u8; 2], Error> {
    u16::try_from(value.len())
        .map(u16::to_be_bytes)
        .map_err(|_| Error::InvalidInput)
}

/// `SerializeElement(point)`, which has no value for the identity.
fn encode<P: Point>(point: &P) -> Result<[u8; POINT_LENGTH], Error> {
    point.to_bytes().ok_or(Error::InvalidInput)
}

/// Encodes a point that is not the identity by construction.
pub(crate) fn point_bytes<P: Point>(point: &P) -> [u8; POINT_LENGTH] {
    debug_assert!(!bool::from(point.is_identity()));
    // The identity cannot occur here; the all-zero string, which never
    // decodes, stands in rather than a panic.
    point.to_bytes().unwrap_or([0; POINT_LENGTH])
}

/// `CreateContextBase(ctx_iss)`.
fn context_base<B: Backend>(ctx_iss: &[u8]) -> Result<B::Point, Error> {
    B::hash_to_group(CTX, &[&u16_prefix(ctx_iss)?, ctx_iss, b"ContextBase"]).map_err(Into::into)
}

/// Checks that `Message(nf, ctx_red)` can be length-prefixed.
fn check_redemption_context(ctx_red: &[u8]) -> Result<(), Error> {
    if ctx_red.len() > MAX_REDEMPTION_CONTEXT {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

/// `ComputeChallenge(ctx_iss, (A, C), Message(nf, ctx_red))`.
fn compute_challenge<B: Backend>(
    ctx_iss: &[u8],
    a: &B::Point,
    c: &B::Point,
    nf: &[u8; NULLIFIER_LENGTH],
    ctx_red: &[u8],
) -> Result<B::Scalar, Error> {
    check_redemption_context(ctx_red)?;
    let element_len = (POINT_LENGTH as u16).to_be_bytes();
    let nf_len = (NULLIFIER_LENGTH as u16).to_be_bytes();
    let ctx_red_len = u16_prefix(ctx_red)?;
    let message_len = ((2 + NULLIFIER_LENGTH + 2 + ctx_red.len()) as u16).to_be_bytes();
    Ok(B::hash_to_scalar(
        CTX,
        &[
            &u16_prefix(ctx_iss)?,
            ctx_iss,
            &element_len,
            &encode(a)?,
            &element_len,
            &encode(c)?,
            &message_len,
            &nf_len,
            nf,
            &ctx_red_len,
            ctx_red,
            b"Challenge",
        ],
    ))
}
