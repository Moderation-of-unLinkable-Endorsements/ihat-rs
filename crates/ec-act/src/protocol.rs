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

//! The credential scheme: configuration, keys, issuance, spending, and
//! refunds, following Section 5 of the draft.

use alloc::vec::Vec;
use core::fmt;

use mole_p256::hash::BackendHashExt;
use mole_p256::random::{Random, SystemRandom};
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::backend::{
    Backend, BackendFixedBaseExt, FixedBase, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar,
};
use crate::hash::{self, NSEED};
use crate::sigma;
use crate::statements::{Commitment, Signature, Spend, fixed, spend_weights, weighted_scalars};
use crate::{DefaultBackend, Error, MAX_BALANCE_WIDTH, PROTOCOL_CONTEXT};

mod issuance;
mod spending;

#[cfg(test)]
mod test_support;

pub use issuance::{finalize_issue, issue_request, issue_response, verify_issue_request};
pub use spending::{finalize_refund, issue_refund, prove_spend, verify_spend};

#[cfg(test)]
pub(crate) use issuance::{issue_request_with, issue_response_with};
#[cfg(test)]
pub(crate) use spending::{issue_refund_with, prove_spend_with};
#[cfg(test)]
pub(crate) use test_support::context_scalar_for_tests;

/// The group generator `B` and the four ciphersuite generators, the latter
/// with whatever precomputation the backend offers.
///
/// `H1` commits to the balance, `H2` to the nullifier, `H3` is the
/// blinding base, and `H4` binds the credential context.
#[derive(Clone, Debug)]
pub(crate) struct Generators<B: BackendFixedBaseExt> {
    pub(crate) g: B::Point,
    pub(crate) h1: B::FixedBase,
    pub(crate) h2: B::FixedBase,
    pub(crate) h3: B::FixedBase,
    pub(crate) h4: B::FixedBase,
}

/// The ACT configuration: the `P256-SHA256` ciphersuite at a balance width.
///
/// Balances and amounts are integers in `[0, 2^L)`. `L` is fixed for the
/// lifetime of a key and credential context, and every party of a
/// deployment uses the same value.
#[derive(Clone, Debug)]
pub struct Params<B: BackendFixedBaseExt = DefaultBackend> {
    l: u8,
    max_amount: u64,
    gens: Generators<B>,
    sid_issue_request: [u8; 32],
    sid_issue_response: [u8; 32],
    sid_refund: [u8; 32],
}

impl<B: BackendFixedBaseExt> Params<B> {
    /// Instantiates the ciphersuite at balance width `balance_width`, which
    /// must be in `1..=64`.
    pub fn new(balance_width: u8) -> Result<Self, Error> {
        if balance_width == 0 || balance_width > MAX_BALANCE_WIDTH {
            return Err(Error::InvalidInput);
        }
        let generator = |label: &[u8]| -> Result<B::FixedBase, Error> {
            Ok(B::FixedBase::new(B::hash_to_group(
                PROTOCOL_CONTEXT,
                &[label],
            )?))
        };
        let gens = Generators {
            g: B::Point::generator(),
            h1: generator(b"GenH1")?,
            h2: generator(b"GenH2")?,
            h3: generator(b"GenH3")?,
            h4: generator(b"GenH4")?,
        };
        let session_id = |label: &[u8]| Ok::<_, Error>(sigma::session_id(&sigma::tag(label, &[])?));
        Ok(Self {
            l: balance_width,
            max_amount: u64::MAX >> (64 - u32::from(balance_width)),
            gens,
            sid_issue_request: session_id(b"IssueRequest")?,
            sid_issue_response: session_id(b"IssueResponse")?,
            sid_refund: session_id(b"Refund")?,
        })
    }

    /// The balance width `L`.
    pub fn balance_width(&self) -> u8 {
        self.l
    }

    /// The largest balance or amount, `2^L - 1`.
    pub fn max_amount(&self) -> u64 {
        self.max_amount
    }

    pub(crate) fn check_amount(&self, amount: u64) -> Result<(), Error> {
        if amount > self.max_amount {
            Err(Error::Amount)
        } else {
            Ok(())
        }
    }

    fn l(&self) -> usize {
        usize::from(self.l)
    }

    #[cfg(test)]
    pub(crate) fn generators(&self) -> &Generators<B> {
        &self.gens
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The Moderator's key pair. The secret scalar both signs and verifies.
#[derive(Clone)]
pub struct SecretKey<B: Backend = DefaultBackend> {
    pub(crate) sk: B::Scalar,
    pk: B::Point,
}

impl<B: Backend> SecretKey<B> {
    /// `G.DeriveKeyPair(seed, "GenerateKeyPair")`: derives a key pair from a
    /// seed.
    pub fn from_seed(seed: &[u8; NSEED]) -> Result<Self, Error> {
        let sk = B::derive_key_scalar(PROTOCOL_CONTEXT, seed, b"GenerateKeyPair")?;
        let pk = B::Point::mul_generator(&sk);
        Ok(Self { sk, pk })
    }

    /// The public key `pkM`.
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

/// The Moderator's public key `pkM`, published in its configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<B: Backend = DefaultBackend> {
    pk: B::Point,
}

impl<B: Backend> PublicKey<B> {
    /// `SerializeElement(pkM)`.
    pub fn to_bytes(&self) -> [u8; POINT_LENGTH] {
        point_bytes(&self.pk)
    }

    /// Parses `SerializeElement(pkM)`.
    pub fn from_bytes(bytes: &[u8; POINT_LENGTH]) -> Result<Self, Error> {
        Ok(Self {
            pk: hash::require(B::Point::from_bytes(bytes), Error::Deserialize)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// The Client's state between `issue_request` and `finalize_issue`.
///
/// Holds the nullifier `k` and blinding factor `r` of the Credential being
/// issued. It must be finalized against at most one response.
pub struct ClientIssuanceState<B: Backend = DefaultBackend> {
    pub(crate) k: B::Scalar,
    pub(crate) r: B::Scalar,
    pub(crate) k_commitment: B::Point,
}

/// The Client's opening message of issuance: `(K, pok)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueRequestMessage<B: Backend = DefaultBackend> {
    pub(crate) k_commitment: B::Point,
    pub(crate) pok: [u8; 3 * SCALAR_LENGTH],
}

/// The Moderator's response to an issuance request: `(A, e, c, pok)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueResponseMessage<B: Backend = DefaultBackend> {
    pub(crate) a: B::Point,
    pub(crate) e: B::Scalar,
    pub(crate) c: u64,
    pub(crate) pok: [u8; 2 * SCALAR_LENGTH],
}

impl<B: Backend> IssueResponseMessage<B> {
    /// The balance `c` the Moderator chose.
    pub fn balance(&self) -> u64 {
        self.c
    }
}

/// A Credential `(k, c, r, A, e)`: a signature on the hidden balance `c`,
/// nullifier `k`, and blinding factor `r`, under the context it was issued
/// under. It is held by the Client and never sent.
pub struct Credential<B: Backend = DefaultBackend> {
    pub(crate) k: B::Scalar,
    pub(crate) c: u64,
    pub(crate) r: B::Scalar,
    pub(crate) a: B::Point,
    pub(crate) e: B::Scalar,
}

impl<B: Backend> Credential<B> {
    /// The balance `c`.
    pub fn balance(&self) -> u64 {
        self.c
    }
}

/// The Client's state between `prove_spend` and `finalize_refund`.
///
/// Holds everything `finalize_refund` needs: the next Credential's
/// nullifier `kstar` and blinding factor `r_star`, the remainder `v1`, the
/// amounts, and the commitment `K_prime` the refund signs. It must be
/// stored durably before the spend proof leaves the Client, and finalized
/// against at most one refund.
pub struct ClientSpendState<B: Backend = DefaultBackend> {
    pub(crate) kstar: B::Scalar,
    pub(crate) r_star: B::Scalar,
    pub(crate) v1: u64,
    pub(crate) s: u64,
    pub(crate) a: u64,
    pub(crate) k_prime: B::Point,
}

impl<B: Backend> ClientSpendState<B> {
    /// The remainder `c - s` that the refund tops up.
    pub fn remainder(&self) -> u64 {
        self.v1
    }
}

/// A spend: the nullifier, the public amounts, the rerandomized signature,
/// the commitments, and the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendMessage<B: Backend = DefaultBackend> {
    pub(crate) k: B::Scalar,
    pub(crate) s: u64,
    pub(crate) a: u64,
    pub(crate) a_prime: B::Point,
    pub(crate) b_bar: B::Point,
    pub(crate) k_n: B::Point,
    pub(crate) com1: Vec<B::Point>,
    pub(crate) com_c: Option<B::Point>,
    pub(crate) pok: Vec<u8>,
}

impl<B: Backend> SpendMessage<B> {
    /// The nullifier `k` of the spent Credential, big-endian.
    ///
    /// The Moderator must reject a spend whose nullifier it has recorded,
    /// and record it atomically with verification and the refund.
    pub fn nullifier(&self) -> [u8; SCALAR_LENGTH] {
        self.k.to_bytes()
    }

    /// The spent amount `s`.
    pub fn amount(&self) -> u64 {
        self.s
    }

    /// The top-up allowance `a`.
    pub fn allowance(&self) -> u64 {
        self.a
    }
}

/// Evidence that an [`IssueRequestMessage`] passed [`verify_issue_request`]
/// under a specific configuration.
///
/// This value cannot be constructed or cloned by callers, so
/// [`issue_response`] never signs an unchecked request.
#[must_use = "pass this value to issue_response"]
#[derive(Debug)]
pub struct VerifiedIssueRequest<'a, B: BackendFixedBaseExt = DefaultBackend> {
    params: &'a Params<B>,
    request: &'a IssueRequestMessage<B>,
}

/// Evidence that a [`SpendMessage`] passed [`verify_spend`] under a specific
/// Moderator key, configuration, credential context, and spend context.
///
/// This value cannot be constructed or cloned by callers. Before consuming it
/// with [`issue_refund`], the Moderator must still grant its allowance and
/// atomically reject and record its nullifier. Holding the value borrows the
/// exact message, key, and configuration that were verified.
#[must_use = "check the allowance and nullifier, then pass this value to issue_refund"]
pub struct VerifiedSpend<'a, B: BackendFixedBaseExt = DefaultBackend> {
    params: &'a Params<B>,
    key: &'a SecretKey<B>,
    spend: &'a SpendMessage<B>,
    ctx: B::Scalar,
    k_prime: B::Point,
}

impl<B: BackendFixedBaseExt> VerifiedSpend<'_, B> {
    /// The nullifier of the verified Credential, big-endian.
    pub fn nullifier(&self) -> [u8; SCALAR_LENGTH] {
        self.spend.nullifier()
    }

    /// The verified spent amount `s`.
    pub fn amount(&self) -> u64 {
        self.spend.amount()
    }

    /// The verified top-up allowance `a`.
    pub fn allowance(&self) -> u64 {
        self.spend.allowance()
    }
}

impl<B: BackendFixedBaseExt> fmt::Debug for VerifiedSpend<'_, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedSpend")
            .field("nullifier", &self.nullifier())
            .field("amount", &self.amount())
            .field("allowance", &self.allowance())
            .finish_non_exhaustive()
    }
}

/// The Moderator's refund: a signature on the remainder plus `t`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundMessage<B: Backend = DefaultBackend> {
    pub(crate) a: B::Point,
    pub(crate) e: B::Scalar,
    pub(crate) t: u64,
    pub(crate) pok: [u8; 2 * SCALAR_LENGTH],
}

impl<B: Backend> RefundMessage<B> {
    /// The return amount `t`.
    pub fn return_amount(&self) -> u64 {
        self.t
    }
}

/// A point derived from secrets, zeroized when dropped.
struct SecretPoint<P: Point>(P);

impl<P: Point> core::ops::Deref for SecretPoint<P> {
    type Target = P;

    fn deref(&self) -> &P {
        &self.0
    }
}

impl<P: Point> Drop for SecretPoint<P> {
    fn drop(&mut self) {
        self.0.zeroize();
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

secret_record!(ClientIssuanceState { k, r; k_commitment; });
secret_record!(Credential { k, r, e; a; c });
secret_record!(ClientSpendState { kstar, r_star; k_prime; v1, s, a });

// ---------------------------------------------------------------------------
// Shared computations
// ---------------------------------------------------------------------------

/// `CreateContextScalar(ctx_cred)`.
fn context_scalar<B: Backend>(ctx_cred: &[u8]) -> Result<B::Scalar, Error> {
    let len = u16::try_from(ctx_cred.len()).map_err(|_| Error::InvalidInput)?;
    Ok(B::hash_to_scalar(
        PROTOCOL_CONTEXT,
        &[&len.to_be_bytes(), ctx_cred, b"CredentialContext"],
    ))
}

/// `B + c * H1 + ctx * H4 + K`, the message an issuance signs.
fn issuance_message<B: BackendFixedBaseExt>(
    gens: &Generators<B>,
    c: u64,
    ctx: &B::Scalar,
    k: &B::Point,
) -> B::Point {
    fixed::<B, 2>([(&gens.h1, &B::Scalar::from(c)), (&gens.h4, ctx)])
        .add(&gens.g)
        .add(k)
}

/// `SigningExponent`: the exponent `e` of a signature on `x_a`, derived
/// from the signing key and the message, and `x = e + skM`.
fn signing_exponent<B: Backend, R: Random>(
    key: &SecretKey<B>,
    label: &[u8],
    x_a: &B::Point,
    rng: &mut R,
) -> Result<(B::Scalar, Zeroizing<B::Scalar>), Error> {
    let x_a_bytes = x_a.to_bytes().ok_or(Error::Verify)?;
    let label_len = u16::try_from(label.len()).map_err(|_| Error::InvalidInput)?;
    let mut rand = Zeroizing::new([0u8; NSEED]);
    rng.fill(&mut *rand)?;
    let sk_bytes = Zeroizing::new(key.sk.to_bytes());
    let derived = B::derive_nonces(
        PROTOCOL_CONTEXT,
        &*sk_bytes,
        b"e",
        &[
            &label_len.to_be_bytes(),
            label,
            &(POINT_LENGTH as u16).to_be_bytes(),
            &x_a_bytes,
        ],
        &*rand,
        1,
    )?;
    let x = Zeroizing::new(derived[0] + key.sk);
    if bool::from(x.is_zero()) {
        // Here `e` is `-skM`; `derived` is wiped on return.
        return Err(Error::Derive);
    }
    Ok((derived[0], x))
}

/// A signature `(A, e)` with its `Signature` proof.
type SignedMessage<B> = (
    <B as Backend>::Point,
    <B as Backend>::Scalar,
    [u8; 2 * SCALAR_LENGTH],
);

/// Signs `x_a` as `(A, e)` with `A = x_a / (e + skM)` and proves it.
fn sign<B: Backend, R: Random>(
    key: &SecretKey<B>,
    label: &[u8],
    session_id: &[u8; 32],
    x_a: &B::Point,
    rng: &mut R,
) -> Result<SignedMessage<B>, Error> {
    let (e, x) = signing_exponent(key, label, x_a, rng)?;
    let x_inv = Zeroizing::new(hash::require(x.invert(), Error::Derive)?);
    let a = x_a.mul(&x_inv);
    drop(x_inv);
    let x_g = B::Point::mul_generator(&x);
    let statement = Signature {
        a: &a,
        x_a,
        x_g: &x_g,
    };
    let pok = sigma::prove::<B, _, _>(session_id, &statement, core::slice::from_ref(&*x), rng)?;
    Ok((a, e, proof_array(pok)?))
}

/// Verifies the `Signature` proof of `(a, e)` on `x_a` under `pk`.
fn verify_signature<B: Backend>(
    session_id: &[u8; 32],
    pk: &PublicKey<B>,
    a: &B::Point,
    e: &B::Scalar,
    x_a: &B::Point,
    pok: &[u8],
) -> Result<(), Error> {
    let x_g = B::Point::mul_generator(e).add(&pk.pk);
    sigma::verify::<B, _>(session_id, &Signature { a, x_a, x_g: &x_g }, pok)
}

/// `Bits(x, weights)`: the weighted decomposition of `x`, in constant time
/// with respect to `x`. The public weights cover exactly `[0, m]`.
fn bits<B: Backend>(x: u64, weights: &[u64]) -> Vec<B::Scalar> {
    let (zero, one) = (B::Scalar::default(), B::Scalar::from(1));
    let n = weights.len();
    if n == 0 {
        return Vec::new();
    }
    let top = (x >> (n - 1)) & 1;
    let rest = x - top * weights[n - 1];
    let mut out: Vec<B::Scalar> = (0..n - 1)
        .map(|j| {
            let bit = Choice::from(((rest >> j) & 1) as u8);
            B::Scalar::conditional_select(&zero, &one, bit)
        })
        .collect();
    out.push(B::Scalar::conditional_select(
        &zero,
        &one,
        Choice::from(top as u8),
    ));
    out
}

fn proof_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Verify)
}

/// Encodes a point that is not the identity by construction.
pub(crate) fn point_bytes<P: Point>(point: &P) -> [u8; POINT_LENGTH] {
    debug_assert!(!bool::from(point.is_identity()));
    // The identity cannot occur here; the all-zero string, which never
    // decodes, stands in rather than a panic.
    point.to_bytes().unwrap_or([0; POINT_LENGTH])
}

/// A range block's bit commitments and its blinding sum.
type RangeBlock<B> = (
    Vec<<B as Backend>::Point>,
    Zeroizing<<B as Backend>::Scalar>,
);

/// A weighted range block over `value` with blindings `s`: the bit commitments
/// `Com[j] = b[j] * H1 + s[j] * H3`, with the bits, blindings, and products
/// `u[j] = (1 - b[j]) * s[j]` appended to `witness` in that order. Returns the
/// commitments and `sum_j weights[j] * s[j]`, the block's contribution to the
/// blinding factor of the refunded Credential. Constant time in `value`.
///
/// `witness` must have room for `3 * l` more scalars, so that extending it
/// never reallocates.
fn range_block<B: BackendFixedBaseExt>(
    gens: &Generators<B>,
    value: u64,
    weights: &[u64],
    s: &[B::Scalar],
    witness: &mut Vec<B::Scalar>,
) -> Result<RangeBlock<B>, Error> {
    let n = weights.len();
    let one = B::Scalar::from(1);
    let blindings = s.get(..n).ok_or(Error::InvalidInput)?;
    let bits = Zeroizing::new(bits::<B>(value, weights));
    let mut commitments = Vec::with_capacity(n);
    for (bit, blinding) in bits.iter().zip(blindings) {
        commitments.push(fixed::<B, 2>([(&gens.h1, bit), (&gens.h3, blinding)]));
    }
    let products: Zeroizing<Vec<B::Scalar>> = Zeroizing::new(
        bits.iter()
            .zip(blindings)
            .map(|(b, s)| (one - *b) * *s)
            .collect(),
    );
    let blinding_sum = Zeroizing::new(weighted_scalars(blindings, weights));
    debug_assert!(witness.capacity() - witness.len() >= 3 * n);
    witness.extend_from_slice(&bits);
    witness.extend_from_slice(blindings);
    witness.extend_from_slice(&products);
    Ok((commitments, blinding_sum))
}
