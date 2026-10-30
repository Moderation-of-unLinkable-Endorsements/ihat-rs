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

use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::backend::{Backend, FixedBase, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::hash::{self, NSEED};
use crate::random::{Random, SystemRandom};
use crate::sigma;
use crate::statements::{Commitment, Signature, Spend, fixed, spend_weights, weighted_scalars};
use crate::{DefaultBackend, Error, MAX_BALANCE_WIDTH};

/// The group generator `B` and the four ciphersuite generators, the latter
/// with whatever precomputation the backend offers.
///
/// `H1` commits to the balance, `H2` to the nullifier, `H3` is the
/// blinding base, and `H4` binds the credential context.
#[derive(Clone, Debug)]
pub(crate) struct Generators<B: Backend> {
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
pub struct Params<B: Backend = DefaultBackend> {
    l: u8,
    max_amount: u64,
    gens: Generators<B>,
    sid_issue_request: [u8; 32],
    sid_issue_response: [u8; 32],
    sid_refund: [u8; 32],
}

impl<B: Backend> Params<B> {
    /// Instantiates the ciphersuite at balance width `balance_width`, which
    /// must be in `1..=64`.
    pub fn new(balance_width: u8) -> Result<Self, Error> {
        if balance_width == 0 || balance_width > MAX_BALANCE_WIDTH {
            return Err(Error::InvalidInput);
        }
        let generator = |label: &[u8]| {
            B::hash_to_curve(&[label], &[hash::DST_HASH_TO_GROUP])
                .map(B::FixedBase::new)
                .ok_or(Error::Derive)
        };
        let gens = Generators {
            g: B::Point::generator(),
            h1: generator(b"GenH1")?,
            h2: generator(b"GenH2")?,
            h3: generator(b"GenH3")?,
            h4: generator(b"GenH4")?,
        };
        let session_id =
            |label: &[u8]| Ok::<_, Error>(sigma::session_id::<B>(&sigma::tag(label, &[])?));
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
    sk: B::Scalar,
    pk: B::Point,
}

impl<B: Backend> SecretKey<B> {
    /// `G.GenerateKeyPair()`: a key pair from fresh randomness.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with(&mut SystemRandom::<B>::new())
    }

    pub(crate) fn generate_with<R: Random>(rng: &mut R) -> Result<Self, Error> {
        let mut seed = [0u8; NSEED];
        rng.fill(&mut seed)?;
        let key = Self::from_seed(&seed, b"GenerateKeyPair");
        seed.zeroize();
        key
    }

    /// `G.DeriveKeyPair(seed, info)`: a key pair from a seed of `Nseed`
    /// uniformly random bytes that is used for nothing else.
    pub fn from_seed(seed: &[u8; NSEED], info: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_scalar(hash::derive_key_scalar::<B>(seed, info)?))
    }

    /// The key pair whose secret scalar is `bytes`, big-endian.
    pub fn from_bytes(bytes: &[u8; SCALAR_LENGTH]) -> Result<Self, Error> {
        let sk = hash::require(B::Scalar::from_bytes(bytes), Error::Deserialize)?;
        if bool::from(sk.is_zero()) {
            return Err(Error::Deserialize);
        }
        Ok(Self::from_scalar(sk))
    }

    fn from_scalar(sk: B::Scalar) -> Self {
        let pk = B::Point::mul_generator(&sk);
        Self { sk, pk }
    }

    /// The secret scalar `skM`, big-endian.
    pub fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        self.sk.to_bytes()
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
pub struct VerifiedIssueRequest<'a, B: Backend = DefaultBackend> {
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
pub struct VerifiedSpend<'a, B: Backend = DefaultBackend> {
    params: &'a Params<B>,
    key: &'a SecretKey<B>,
    spend: &'a SpendMessage<B>,
    ctx: B::Scalar,
    k_prime: B::Point,
}

impl<B: Backend> VerifiedSpend<'_, B> {
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

impl<B: Backend> fmt::Debug for VerifiedSpend<'_, B> {
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
    Ok(hash::hash_to_scalar::<B>(
        &[&len.to_be_bytes(), ctx_cred, b"CredentialContext"],
        hash::DST_HASH_TO_SCALAR,
    ))
}

/// `B + c * H1 + ctx * H4 + K`, the message an issuance signs.
fn issuance_message<B: Backend>(
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
    let derived = hash::derive_nonces::<B>(
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
fn range_block<B: Backend>(
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

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// `IssueRequest`: commits to a fresh nullifier and blinding factor.
pub fn issue_request<B: Backend>(
    params: &Params<B>,
) -> Result<(ClientIssuanceState<B>, IssueRequestMessage<B>), Error> {
    issue_request_with(params, &mut SystemRandom::<B>::new())
}

pub(crate) fn issue_request_with<B: Backend, R: Random>(
    params: &Params<B>,
    rng: &mut R,
) -> Result<(ClientIssuanceState<B>, IssueRequestMessage<B>), Error> {
    let gens = &params.gens;
    let mut rand = Zeroizing::new([0u8; NSEED]);
    rng.fill(&mut *rand)?;
    // `derived` holds `(k, r)` and is wiped on every return.
    let derived = hash::derive_scalars::<B>(&*rand, b"IssueRequest", 2)?;
    drop(rand);

    let k_commitment = fixed::<B, 2>([(&gens.h2, &derived[0]), (&gens.h3, &derived[1])]);
    let statement = Commitment {
        gens,
        k: &k_commitment,
    };
    let pok = sigma::prove::<B, _, _>(&params.sid_issue_request, &statement, &derived, rng)?;

    Ok((
        ClientIssuanceState {
            k: derived[0],
            r: derived[1],
            k_commitment: k_commitment.clone(),
        },
        IssueRequestMessage {
            k_commitment,
            pok: proof_array(pok)?,
        },
    ))
}

/// `IssueResponse`, first half: checks the request's proof, returning the
/// evidence required by [`issue_response`].
///
/// Lets the Moderator reject a malformed request before it commits any
/// other state, such as a redemption, and sign only afterwards.
pub fn verify_issue_request<'a, B: Backend>(
    params: &'a Params<B>,
    request: &'a IssueRequestMessage<B>,
) -> Result<VerifiedIssueRequest<'a, B>, Error> {
    let statement = Commitment {
        gens: &params.gens,
        k: &request.k_commitment,
    };
    sigma::verify::<B, _>(&params.sid_issue_request, &statement, &request.pok)?;
    Ok(VerifiedIssueRequest { params, request })
}

/// `IssueResponse`, second half: signs a Credential with balance `c` under
/// `ctx_cred` for a request checked by [`verify_issue_request`].
pub fn issue_response<B: Backend>(
    key: &SecretKey<B>,
    ctx_cred: &[u8],
    c: u64,
    verified: VerifiedIssueRequest<'_, B>,
) -> Result<IssueResponseMessage<B>, Error> {
    issue_response_with(key, ctx_cred, c, verified, &mut SystemRandom::<B>::new())
}

pub(crate) fn issue_response_with<B: Backend, R: Random>(
    key: &SecretKey<B>,
    ctx_cred: &[u8],
    c: u64,
    verified: VerifiedIssueRequest<'_, B>,
    rng: &mut R,
) -> Result<IssueResponseMessage<B>, Error> {
    let VerifiedIssueRequest { params, request } = verified;
    params.check_amount(c)?;
    let ctx = context_scalar::<B>(ctx_cred)?;
    let x_a = issuance_message(&params.gens, c, &ctx, &request.k_commitment);
    let (a, e, pok) = sign(key, b"IssueResponse", &params.sid_issue_response, &x_a, rng)?;
    Ok(IssueResponseMessage { a, e, c, pok })
}

/// `FinalizeIssue`: checks the response and assembles the Credential.
///
/// Consumes `state`; the Client must not finalize one state against two
/// responses.
pub fn finalize_issue<B: Backend>(
    params: &Params<B>,
    public_key: &PublicKey<B>,
    ctx_cred: &[u8],
    state: ClientIssuanceState<B>,
    response: &IssueResponseMessage<B>,
) -> Result<Credential<B>, Error> {
    let gens = &params.gens;
    params.check_amount(response.c)?;
    let ctx = context_scalar::<B>(ctx_cred)?;
    let x_a = issuance_message(gens, response.c, &ctx, &state.k_commitment);
    verify_signature(
        &params.sid_issue_response,
        public_key,
        &response.a,
        &response.e,
        &x_a,
        &response.pok,
    )?;
    Ok(Credential {
        k: state.k,
        c: response.c,
        r: state.r,
        a: response.a.clone(),
        e: response.e,
    })
}

// ---------------------------------------------------------------------------
// Spending
// ---------------------------------------------------------------------------

/// `ProveSpend`: spends `s` credits of `credential` with top-up allowance
/// `a`, bound to `ctx_spend`.
///
/// Consumes the Credential. The returned state must be stored durably
/// before the message leaves the Client; the refund is unusable without
/// it, and a second proof from the same Credential reveals the same
/// nullifier.
pub fn prove_spend<B: Backend>(
    params: &Params<B>,
    credential: Credential<B>,
    ctx_cred: &[u8],
    s: u64,
    a: u64,
    ctx_spend: &[u8],
) -> Result<(ClientSpendState<B>, SpendMessage<B>), Error> {
    prove_spend_with(
        params,
        credential,
        ctx_cred,
        s,
        a,
        ctx_spend,
        &mut SystemRandom::<B>::new(),
    )
}

pub(crate) fn prove_spend_with<B: Backend, R: Random>(
    params: &Params<B>,
    credential: Credential<B>,
    ctx_cred: &[u8],
    s: u64,
    a: u64,
    ctx_spend: &[u8],
    rng: &mut R,
) -> Result<(ClientSpendState<B>, SpendMessage<B>), Error> {
    let gens = &params.gens;
    let l = params.l();
    params.check_amount(s)?;
    params.check_amount(a)?;
    let c = credential.c;
    // Over the integers: `s <= c` and `c + a < 2^L`.
    if s > c || u128::from(c) + u128::from(a) > u128::from(params.max_amount) {
        return Err(Error::Amount);
    }
    let v1 = c - s;
    let refresh = s == 0 && a == 0;
    let weights = spend_weights(l, s, a)?;
    let n = weights.len();

    let ctx = context_scalar::<B>(ctx_cred)?;
    let tag = sigma::tag(b"Spend", &[ctx_spend])?;
    let session_id = sigma::session_id::<B>(&tag);

    // Four fixed scalars, then one for each weighted bit of the remainder or
    // one for the commitment of a refresh.
    let count = 4 + if refresh { 1 } else { n };
    let mut rand = Zeroizing::new([0u8; NSEED]);
    rng.fill(&mut *rand)?;
    // `derived` holds every secret scalar of the spend and is wiped on every
    // return; the values computed from them below are held in wrappers that
    // wipe them on drop.
    let derived = hash::derive_scalars::<B>(&*rand, b"ProveSpend", count)?;
    drop(rand);
    let (r1, r2, kstar, rn) = (&derived[0], &derived[1], &derived[2], &derived[3]);

    // Rerandomize the signature.
    let c_scalar = Zeroizing::new(B::Scalar::from(c));
    let b_msg = SecretPoint(
        fixed::<B, 4>([
            (&gens.h1, &*c_scalar),
            (&gens.h2, &credential.k),
            (&gens.h3, &credential.r),
            (&gens.h4, &ctx),
        ])
        .add(&gens.g),
    );
    let r1r2 = Zeroizing::new(*r1 * *r2);
    let a_prime = credential.a.mul(&r1r2);
    let b_bar = b_msg.mul(r1);
    let r3 = Zeroizing::new(hash::require(r1.invert(), Error::Derive)?);
    let neg_e = Zeroizing::new(-credential.e);
    let a_bar = SecretPoint(B::Point::lincomb([(&b_bar, r2), (&a_prime, &*neg_e)]));

    // Commit to the next Credential's nullifier.
    let k_n = fixed::<B, 2>([(&gens.h2, kstar), (&gens.h3, rn)]);

    // Allocated at full size, so that no reallocation frees secret scalars.
    let witness_len = 7 + if refresh { 1 } else { 3 * n };
    let mut witness: Zeroizing<Vec<B::Scalar>> = Zeroizing::new(Vec::with_capacity(witness_len));
    for scalar in [
        &credential.e,
        r2,
        &*r3,
        &*c_scalar,
        &credential.r,
        kstar,
        rn,
    ] {
        witness.push(*scalar);
    }
    let mut com1 = Vec::new();
    let mut com_c = None;

    // Commit to the remainder: bitwise when it must be shown to be in the
    // public range, in one commitment when it is the balance of a refresh.
    let r_star;
    if !refresh {
        let (commitments, blinding_sum) =
            range_block::<B>(gens, v1, &weights, &derived[4..], &mut witness)?;
        com1 = commitments;
        r_star = Zeroizing::new(*rn + *blinding_sum);
    } else {
        let rc = &derived[4];
        com_c = Some(fixed::<B, 2>([(&gens.h1, &*c_scalar), (&gens.h3, rc)]));
        r_star = Zeroizing::new(*rn + *rc);
        witness.push(*rc);
    }
    debug_assert_eq!(witness.len(), witness_len);

    let h1_prime = fixed::<B, 2>([(&gens.h2, &credential.k), (&gens.h4, &ctx)]).add(&gens.g);
    let statement = Spend::new(
        gens,
        l,
        &a_prime,
        &b_bar,
        &a_bar,
        &h1_prime,
        &k_n,
        s,
        a,
        &com1,
        com_c.as_ref(),
    )?;
    let pok = sigma::prove::<B, _, _>(&session_id, &statement, &witness, rng)?;

    // The commitment the refund will sign, opened by the new Credential's
    // secrets; the Moderator recomputes it from the message.
    let v1_scalar = Zeroizing::new(B::Scalar::from(v1));
    let k_prime = fixed::<B, 3>([
        (&gens.h1, &*v1_scalar),
        (&gens.h2, kstar),
        (&gens.h3, &*r_star),
    ]);

    let state = ClientSpendState {
        kstar: *kstar,
        r_star: *r_star,
        v1,
        s,
        a,
        k_prime,
    };
    let message = SpendMessage {
        k: credential.k,
        s,
        a,
        a_prime,
        b_bar,
        k_n,
        com1,
        com_c,
        pok,
    };
    Ok((state, message))
}

/// `VerifySpend`: checks a spend proof under the Moderator's key and contexts,
/// returning the evidence required by [`issue_refund`].
///
/// Does not check the nullifier against the Moderator's record, nor
/// whether the Moderator grants the allowance `a`; the caller must do both
/// before issuing a refund.
pub fn verify_spend<'a, B: Backend>(
    params: &'a Params<B>,
    key: &'a SecretKey<B>,
    ctx_cred: &[u8],
    ctx_spend: &[u8],
    spend: &'a SpendMessage<B>,
) -> Result<VerifiedSpend<'a, B>, Error> {
    let gens = &params.gens;
    params.check_amount(spend.s)?;
    params.check_amount(spend.a)?;
    spend_weights(params.l(), spend.s, spend.a)?;
    let ctx = context_scalar::<B>(ctx_cred)?;
    let tag = sigma::tag(b"Spend", &[ctx_spend])?;
    // `A_bar` is a function of the signing key; it does not outlive the check.
    let a_bar = SecretPoint(spend.a_prime.mul(&key.sk));
    let h1_prime = fixed::<B, 2>([(&gens.h2, &spend.k), (&gens.h4, &ctx)]).add(&gens.g);
    let statement = spend_statement(params, spend, &a_bar, &h1_prime)?;
    sigma::verify::<B, _>(&sigma::session_id::<B>(&tag), &statement, &spend.pok)?;
    let k_prime = statement.balance_commitment();
    Ok(VerifiedSpend {
        params,
        key,
        spend,
        ctx,
        k_prime,
    })
}

fn spend_statement<'a, B: Backend>(
    params: &'a Params<B>,
    spend: &'a SpendMessage<B>,
    a_bar: &'a B::Point,
    h1_prime: &'a B::Point,
) -> Result<Spend<'a, B>, Error> {
    Spend::new(
        &params.gens,
        params.l(),
        &spend.a_prime,
        &spend.b_bar,
        a_bar,
        h1_prime,
        &spend.k_n,
        spend.s,
        spend.a,
        &spend.com1,
        spend.com_c.as_ref(),
    )
}

/// `B + K_prime + t * H1 + ctx * H4`, the message a refund signs.
fn refund_message<B: Backend>(
    gens: &Generators<B>,
    k_prime: &B::Point,
    t: u64,
    ctx: &B::Scalar,
) -> B::Point {
    fixed::<B, 2>([(&gens.h1, &B::Scalar::from(t)), (&gens.h4, ctx)])
        .add(&gens.g)
        .add(k_prime)
}

/// `IssueRefund`: consumes evidence of a successful [`verify_spend`] and signs
/// the remainder plus the return amount `t`, where `t <= s + a`.
///
/// Before calling this function, the Moderator must grant the verified
/// allowance and atomically reject and record the verified nullifier together
/// with the refund.
///
/// A raw [`SpendMessage`] cannot reach the refund signer:
///
/// ```compile_fail
/// use act::{Params, RefundMessage, SecretKey, SpendMessage};
///
/// fn refund_unverified(
///     params: &Params,
///     key: &SecretKey,
///     spend: &SpendMessage,
/// ) -> Result<RefundMessage, act::Error> {
///     act::issue_refund(params, key, b"credential context", spend, 0)
/// }
/// ```
pub fn issue_refund<B: Backend>(
    verified: VerifiedSpend<'_, B>,
    t: u64,
) -> Result<RefundMessage<B>, Error> {
    issue_refund_with(verified, t, &mut SystemRandom::<B>::new())
}

pub(crate) fn issue_refund_with<B: Backend, R: Random>(
    verified: VerifiedSpend<'_, B>,
    t: u64,
    rng: &mut R,
) -> Result<RefundMessage<B>, Error> {
    let VerifiedSpend {
        params,
        key,
        spend,
        ctx,
        k_prime,
    } = verified;
    params.check_amount(t)?;
    if u128::from(t) > u128::from(spend.s) + u128::from(spend.a) {
        return Err(Error::Amount);
    }
    let x_a = refund_message(&params.gens, &k_prime, t, &ctx);
    let (a, e, pok) = sign(key, b"Refund", &params.sid_refund, &x_a, rng)?;
    Ok(RefundMessage { a, e, t, pok })
}

/// `FinalizeRefund`: checks the refund and assembles the new Credential,
/// with balance `c - s + t`.
///
/// Consumes `state`; the Client must not finalize one state against two
/// refunds.
pub fn finalize_refund<B: Backend>(
    params: &Params<B>,
    public_key: &PublicKey<B>,
    ctx_cred: &[u8],
    state: ClientSpendState<B>,
    refund: &RefundMessage<B>,
) -> Result<Credential<B>, Error> {
    let t = refund.t;
    params.check_amount(t)?;
    let (s, a, v1) = (
        u128::from(state.s),
        u128::from(state.a),
        u128::from(state.v1),
    );
    if u128::from(t) > s + a || v1 + u128::from(t) > u128::from(params.max_amount) {
        return Err(Error::Amount);
    }
    let ctx = context_scalar::<B>(ctx_cred)?;
    let x_a = refund_message(&params.gens, &state.k_prime, t, &ctx);
    verify_signature(
        &params.sid_refund,
        public_key,
        &refund.a,
        &refund.e,
        &x_a,
        &refund.pok,
    )?;
    Ok(Credential {
        k: state.kstar,
        c: state.v1 + t,
        r: state.r_star,
        a: refund.a.clone(),
        e: refund.e,
    })
}

#[cfg(test)]
pub(crate) fn context_scalar_for_tests<B: Backend>(ctx_cred: &[u8]) -> B::Scalar {
    context_scalar::<B>(ctx_cred).unwrap_or_default()
}
