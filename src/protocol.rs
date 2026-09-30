//! The endorsement scheme: keys, issuance, verification, and redemption,
//! following Sections 3 to 5 of the draft.

use alloc::vec::Vec;
use core::fmt;

use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::backend::{Backend, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::commitment::{self, Key, Node};
use crate::hash::{self, NSEED};
use crate::random::{Random, SystemRandom};
use crate::{DefaultBackend, Error, NULLIFIER_LENGTH, PROTOCOL_CONTEXT};

/// The protocol context under which every hash is computed.
const CTX: &[u8] = PROTOCOL_CONTEXT;

/// The largest `ctx_red` that `Message` admits: the message is itself
/// length-prefixed, so it holds at most `2^16 - 1 - Nn - 4` bytes of it.
const MAX_REDEMPTION_CONTEXT: usize = u16::MAX as usize - NULLIFIER_LENGTH - 4;

/// The largest session identifier a variable-length integer can prefix.
const MAX_SESSION_ID: u64 = (1 << 62) - 1;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// An Anchor's key pair `(skA, pkA)`.
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
        rng.fill(&mut seed);
        let key = Self::from_seed(&seed, b"GenerateKeyPair");
        seed.zeroize();
        key
    }

    /// `G.DeriveKeyPair(seed, info)`: a key pair from a seed of `Nseed`
    /// uniformly random bytes that is used for nothing else.
    pub fn from_seed(seed: &[u8; NSEED], info: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_scalar(hash::derive_key_scalar::<B>(
            CTX, seed, info,
        )?))
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

    /// The secret scalar `skA`, big-endian.
    pub fn to_bytes(&self) -> [u8; SCALAR_LENGTH] {
        self.sk.to_bytes()
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
            pk: hash::require(B::Point::from_bytes(bytes), Error::Deserialize)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// The Anchor's state between [`commit`] and [`respond`]: `(a, y, t)` and
/// the session identifier. It answers at most one challenge.
pub struct AnchorState<B: Backend = DefaultBackend> {
    pub(crate) a: B::Scalar,
    pub(crate) y: B::Scalar,
    pub(crate) t: B::Scalar,
    pub(crate) session_id: Vec<u8>,
}

impl<B: Backend> AnchorState<B> {
    /// The session identifier the state was committed under.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
}

/// The Anchor's opening message, `CommitMessage`: the session identifier
/// and the commitment `(A, C)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitMessage<B: Backend = DefaultBackend> {
    pub(crate) session_id: Vec<u8>,
    pub(crate) a: B::Point,
    pub(crate) c: B::Point,
}

impl<B: Backend> CommitMessage<B> {
    /// The session identifier, which the Client echoes.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
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

/// The Client's blinded challenge, `ChallengeMessage`, echoing the session
/// identifier of the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeMessage<B: Backend = DefaultBackend> {
    pub(crate) session_id: Vec<u8>,
    pub(crate) challenge: B::Scalar,
}

impl<B: Backend> ChallengeMessage<B> {
    /// The session identifier, by which the Anchor finds its state.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
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

secret_record!(AnchorState { a, y, t; ; session_id });
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
    hash::hash_to_group::<B>(CTX, &[&u16_prefix(ctx_iss)?, ctx_iss, b"ContextBase"])
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
    Ok(hash::hash_to_scalar::<B>(
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

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// `Commit(ctx_iss)`, run by the Anchor to open the session `session_id`.
///
/// The Anchor keeps the state until it answers the session's challenge or
/// discards the session, and sends the message. It must not have two open
/// sessions with one identifier, and should draw identifiers at random.
pub fn commit<B: Backend>(
    ctx_iss: &[u8],
    session_id: &[u8],
) -> Result<(AnchorState<B>, CommitMessage<B>), Error> {
    commit_with(ctx_iss, session_id, &mut SystemRandom::<B>::new())
}

pub(crate) fn commit_with<B: Backend, R: Random>(
    ctx_iss: &[u8],
    session_id: &[u8],
    rng: &mut R,
) -> Result<(AnchorState<B>, CommitMessage<B>), Error> {
    if session_id.len() as u64 > MAX_SESSION_ID {
        return Err(Error::InvalidInput);
    }
    let z = context_base::<B>(ctx_iss)?;
    let mut rand = [0u8; NSEED];
    rng.fill(&mut rand);
    let derived = hash::derive_scalars::<B>(CTX, &rand, b"Commit", 3);
    rand.zeroize();
    let derived = derived?;
    let state = AnchorState {
        a: derived[0],
        t: derived[1],
        y: derived[2],
        session_id: session_id.to_vec(),
    };
    let a = B::Point::mul_generator(&state.a);
    let c = B::Point::mul_generator(&state.t).add(&z.mul(&state.y));
    encode(&c)?;
    let message = CommitMessage {
        session_id: session_id.to_vec(),
        a,
        c,
    };
    Ok((state, message))
}

/// `Challenge(pkA, ctx_iss, ctx_red, commitment)`, run by the Client: draws
/// the nullifier, blinds the commitment, and returns the blinded challenge
/// under the commitment's session identifier.
pub fn challenge<B: Backend>(
    public_key: &PublicKey<B>,
    ctx_iss: &[u8],
    ctx_red: &[u8],
    commitment: &CommitMessage<B>,
) -> Result<(ClientState<B>, ChallengeMessage<B>), Error> {
    challenge_with(
        public_key,
        ctx_iss,
        ctx_red,
        commitment,
        &mut SystemRandom::<B>::new(),
    )
}

pub(crate) fn challenge_with<B: Backend, R: Random>(
    public_key: &PublicKey<B>,
    ctx_iss: &[u8],
    ctx_red: &[u8],
    commitment: &CommitMessage<B>,
    rng: &mut R,
) -> Result<(ClientState<B>, ChallengeMessage<B>), Error> {
    if bool::from(public_key.pk.is_identity()) {
        return Err(Error::Verify);
    }
    u16_prefix(ctx_iss)?;
    check_redemption_context(ctx_red)?;
    let mut rand = Zeroizing::new([0u8; NULLIFIER_LENGTH + NSEED]);
    rng.fill(rand.as_mut());
    let derived = hash::derive_scalars::<B>(CTX, &rand[NULLIFIER_LENGTH..], b"Challenge", 4)?;
    let mut state = ClientState::<B> {
        nf: [0; NULLIFIER_LENGTH],
        ctx_iss: ctx_iss.to_vec(),
        commitment_a: commitment.a.clone(),
        commitment_c: commitment.c.clone(),
        r1: derived[0],
        r2: derived[1],
        gamma1: derived[2],
        gamma2: derived[3],
        challenge: B::Scalar::default(),
        c: B::Scalar::default(),
    };
    state.nf.copy_from_slice(&rand[..NULLIFIER_LENGTH]);
    drop(derived);
    drop(rand);

    let mut gamma = state.gamma1 * hash::require(state.gamma2.invert(), Error::Derive)?;
    let mut blinded_a = B::Point::mul_generator(&state.r1).add(&commitment.a.mul(&gamma));
    let mut blinded_c = commitment
        .c
        .mul(&state.gamma1)
        .add(&B::Point::mul_generator(&state.r2));
    gamma.zeroize();
    let c = compute_challenge::<B>(ctx_iss, &blinded_a, &blinded_c, &state.nf, ctx_red);
    blinded_a.zeroize();
    blinded_c.zeroize();
    state.c = c?;
    if bool::from(state.c.is_zero()) {
        return Err(Error::Verify);
    }
    state.challenge = state.c * state.gamma2;
    let message = ChallengeMessage {
        session_id: commitment.session_id.clone(),
        challenge: state.challenge,
    };
    Ok((state, message))
}

/// `Respond(skA, state, challenge)`, run by the Anchor. Consumes the state,
/// so a session answers at most one challenge.
///
/// Returns [`Error::Session`] if the challenge carries another session's
/// identifier.
pub fn respond<B: Backend>(
    secret_key: &SecretKey<B>,
    state: AnchorState<B>,
    challenge: &ChallengeMessage<B>,
) -> Result<ResponseMessage<B>, Error> {
    if !bool::from(state.session_id.ct_eq(&challenge.session_id)) {
        return Err(Error::Session);
    }
    if bool::from(challenge.challenge.is_zero()) {
        return Err(Error::Verify);
    }
    Ok(ResponseMessage {
        s: state.a + challenge.challenge * state.y * secret_key.sk,
        y: state.y,
        t: state.t,
    })
}

/// `Finalize(pkA, state, response)`, run by the Client: checks the response
/// against the commitment and the Anchor's key, and unblinds it into an
/// Endorsement. Consumes the state.
pub fn finalize<B: Backend>(
    public_key: &PublicKey<B>,
    state: ClientState<B>,
    response: &ResponseMessage<B>,
) -> Result<Endorsement<B>, Error> {
    if bool::from(public_key.pk.is_identity()) {
        return Err(Error::Verify);
    }
    let z = context_base::<B>(&state.ctx_iss)?;
    if bool::from(response.y.is_zero()) {
        return Err(Error::Verify);
    }
    let c = B::Point::mul_generator(&response.t).add(&z.mul(&response.y));
    if !bool::from(state.commitment_c.ct_eq(&c)) {
        return Err(Error::Verify);
    }
    let lhs = B::Point::mul_generator(&response.s);
    let rhs = state
        .commitment_a
        .add(&public_key.pk.mul(&(state.challenge * response.y)));
    if !bool::from(lhs.ct_eq(&rhs)) {
        return Err(Error::Verify);
    }
    let mut gamma = state.gamma1 * hash::require(state.gamma2.invert(), Error::Derive)?;
    let signature = Signature {
        c: state.c,
        s: gamma * response.s + state.r1,
        y: state.gamma1 * response.y,
        t: state.gamma1 * response.t + state.r2,
        nf: state.nf,
    };
    gamma.zeroize();
    Ok(Endorsement { signature })
}

/// `Verify(pkA, endorsement, ctx_iss, ctx_red)`: whether the Endorsement
/// was issued under `pkA` for these contexts, as `Ok(())` or
/// [`Error::Verify`].
pub fn verify<B: Backend>(
    public_key: &PublicKey<B>,
    endorsement: &Endorsement<B>,
    ctx_iss: &[u8],
    ctx_red: &[u8],
) -> Result<(), Error> {
    if bool::from(public_key.pk.is_identity()) {
        return Err(Error::Verify);
    }
    verify_signature(&public_key.pk, &endorsement.signature, ctx_iss, ctx_red)
}

/// `Verify` under a key that may be the Client's own choice.
fn verify_signature<B: Backend>(
    pk: &B::Point,
    signature: &Signature<B>,
    ctx_iss: &[u8],
    ctx_red: &[u8],
) -> Result<(), Error> {
    if bool::from(signature.c.is_zero() | signature.y.is_zero()) {
        return Err(Error::Verify);
    }
    let z = context_base::<B>(ctx_iss)?;
    check_redemption_context(ctx_red)?;
    let c = B::Point::mul_generator(&signature.t).add(&z.mul(&signature.y));
    let a = B::Point::lincomb([
        (&B::Point::generator(), &signature.s),
        (pk, &-(signature.c * signature.y)),
    ]);
    if bool::from(a.is_identity() | c.is_identity()) {
        return Err(Error::Verify);
    }
    let expected = compute_challenge::<B>(ctx_iss, &a, &c, &signature.nf, ctx_red)?;
    if bool::from(expected.ct_eq(&signature.c)) {
        Ok(())
    } else {
        Err(Error::Verify)
    }
}

// ---------------------------------------------------------------------------
// Redemption
// ---------------------------------------------------------------------------

/// `ProofStatement(anchor_set, X_hat, shown, ctx_iss, ctx_red,
/// challenge_digest)`.
fn proof_statement<B: Backend>(
    anchor_set: &[PublicKey<B>],
    x_hat: &B::Point,
    shown: &Signature<B>,
    ctx_iss: &[u8],
    ctx_red: &[u8],
    challenge_digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let n = u16::try_from(anchor_set.len()).map_err(|_| Error::InvalidInput)?;
    let mut out = Vec::with_capacity(
        2 + (anchor_set.len() + 1) * POINT_LENGTH
            + 4 * SCALAR_LENGTH
            + 8
            + NULLIFIER_LENGTH
            + ctx_iss.len()
            + ctx_red.len()
            + challenge_digest.len(),
    );
    out.extend_from_slice(&n.to_be_bytes());
    for key in anchor_set {
        out.extend_from_slice(&encode(&key.pk)?);
    }
    out.extend_from_slice(&encode(x_hat)?);
    for scalar in [&shown.c, &shown.s, &shown.y, &shown.t] {
        out.extend_from_slice(&scalar.to_bytes());
    }
    for value in [&shown.nf[..], ctx_iss, ctx_red, challenge_digest] {
        out.extend_from_slice(&u16_prefix(value)?);
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// `ComputeProofChallenge`: the challenge over the statement, the
/// commitment keys, and the root.
fn compute_proof_challenge<B: Backend>(
    statement: &[u8],
    commitment_keys: &[B::Point],
    root: &Node,
) -> Result<B::Scalar, Error> {
    let mut keys = Vec::with_capacity(commitment_keys.len() * POINT_LENGTH);
    for key in commitment_keys {
        keys.extend_from_slice(&encode(key)?);
    }
    Ok(hash::hash_to_scalar::<B>(
        CTX,
        &[statement, &keys, root, b"IssuerProof"],
    ))
}

/// The encodings of `BranchCommitment(proof_challenge, response, X_hat -
/// pkA)` for every `pkA` in the Anchor Set, or `error` if one is the
/// identity.
///
/// Each is computed as `(proof_challenge * X_hat + response * B) -
/// proof_challenge * pkA`, the same point.
fn branch_commitments<B: Backend>(
    anchor_set: &[PublicKey<B>],
    x_hat: &B::Point,
    proof_challenge: &B::Scalar,
    response: &B::Scalar,
    error: Error,
) -> Result<Vec<Node>, Error> {
    let base = B::Point::lincomb([(x_hat, proof_challenge), (&B::Point::generator(), response)]);
    anchor_set
        .iter()
        .map(|key| {
            base.sub(&key.pk.mul(proof_challenge))
                .to_bytes()
                .ok_or(error)
        })
        .collect()
}

/// `Redeem(anchor_set, index, endorsement, ctx_iss, ctx_red,
/// challenge_digest)`, run by the Client: rerandomizes the Anchor's key,
/// adapts the Endorsement to it, and proves that the key is a shift of the
/// key at `index` in the Anchor Set without revealing `index`. Consumes the
/// Endorsement.
///
/// The Anchor Set must be the Moderator's list, in its order. A redemption
/// against a set of one key names its Anchor.
pub fn redeem<B: Backend>(
    anchor_set: &[PublicKey<B>],
    index: usize,
    endorsement: Endorsement<B>,
    ctx_iss: &[u8],
    ctx_red: &[u8],
    challenge_digest: &[u8],
) -> Result<Redemption<B>, Error> {
    redeem_with(
        anchor_set,
        index,
        endorsement,
        ctx_iss,
        ctx_red,
        challenge_digest,
        &mut SystemRandom::<B>::new(),
    )
}

pub(crate) fn redeem_with<B: Backend, R: Random>(
    anchor_set: &[PublicKey<B>],
    index: usize,
    endorsement: Endorsement<B>,
    ctx_iss: &[u8],
    ctx_red: &[u8],
    challenge_digest: &[u8],
    rng: &mut R,
) -> Result<Redemption<B>, Error> {
    let n = anchor_set.len();
    if index >= n || n > usize::from(u16::MAX) {
        return Err(Error::InvalidInput);
    }
    let index = index as u16;
    let mut rand = Zeroizing::new([0u8; 2 * NSEED]);
    rng.fill(rand.as_mut());
    let mut delta = hash::derive_scalars::<B>(CTX, &rand[..NSEED], b"delta", 1)?[0];

    // X_hat = anchor_set[index] + delta * B, selecting the key by
    // multiplying each by 0 or 1 so that `index` does not steer memory
    // accesses.
    let (zero, one) = (B::Scalar::default(), B::Scalar::from(1));
    let mut x_hat = B::Point::mul_generator(&delta);
    for (i, key) in anchor_set.iter().enumerate() {
        let at = (i as u64).ct_eq(&u64::from(index));
        let mut selector = B::Scalar::conditional_select(&zero, &one, at);
        x_hat = x_hat.add(&key.pk.mul(&selector));
        selector.zeroize();
    }
    let signature = &endorsement.signature;
    let shown = Signature {
        c: signature.c,
        s: signature.s + signature.c * signature.y * delta,
        y: signature.y,
        t: signature.t,
        nf: signature.nf,
    };
    drop(endorsement);

    let proof = proof_statement(
        anchor_set,
        &x_hat,
        &shown,
        ctx_iss,
        ctx_red,
        challenge_digest,
    )
    .and_then(|statement| {
        prove_issuer(
            anchor_set,
            index,
            &delta,
            &x_hat,
            &statement,
            &rand[NSEED..],
        )
    });
    delta.zeroize();
    let (proof_challenge, response, keys, openings) = proof?;
    Ok(Redemption {
        x_hat,
        shown,
        proof_challenge,
        response,
        commitment_keys: keys.into_iter().map(|key| key.q).collect(),
        openings,
    })
}

/// The issuer-hiding proof `(proof_challenge, response, commitment_keys,
/// openings)`.
type IssuerProof<B> = (
    <B as Backend>::Scalar,
    <B as Backend>::Scalar,
    Vec<Key<B>>,
    Vec<<B as Backend>::Scalar>,
);

/// `ProveIssuer(anchor_set, index, delta, X_hat, shown, ctx_iss, ctx_red,
/// challenge_digest, rand)`, given the proof statement. Constant time in
/// `index` and `delta`.
fn prove_issuer<B: Backend>(
    anchor_set: &[PublicKey<B>],
    index: u16,
    delta: &B::Scalar,
    x_hat: &B::Point,
    statement: &[u8],
    rand: &[u8],
) -> Result<IssuerProof<B>, Error> {
    let n = anchor_set.len();
    let q = commitment::depth(n);
    if usize::from(index) >= n {
        return Err(Error::InvalidInput);
    }
    if rand.len() != NSEED {
        return Err(Error::InvalidInput);
    }
    let mut secret = [0u8; SCALAR_LENGTH + 2];
    secret[..SCALAR_LENGTH].copy_from_slice(&delta.to_bytes());
    secret[SCALAR_LENGTH..].copy_from_slice(&index.to_be_bytes());
    let derived =
        hash::derive_nonces::<B>(CTX, &secret, b"ProveIssuer", &[statement], rand, 2 * q + 1);
    secret.zeroize();
    let derived = derived?;
    let r = &derived[0];
    let trapdoors = &derived[1..=q];
    let first_openings = &derived[q + 1..];

    let mut a = B::Point::mul_generator(r);
    let mut value = Zeroizing::new(a.to_bytes().ok_or(Error::Derive)?);
    a.zeroize();
    let keys = commitment::generate_vec_bind::<B>(index, trapdoors)?;
    let first = commitment::commit_val_at_place(&keys, n, index, &value, first_openings)?;
    value.zeroize();
    let key_points: Vec<B::Point> = keys.iter().map(|key| key.q.clone()).collect();
    let proof_challenge = compute_proof_challenge::<B>(statement, &key_points, &first.root)?;
    let response = *r - proof_challenge * *delta;

    let leaves = branch_commitments(
        anchor_set,
        x_hat,
        &proof_challenge,
        &response,
        Error::Derive,
    )?;
    let leaves = leaves
        .iter()
        .map(|leaf| commitment::hash_node::<B>(leaf))
        .collect();
    let openings =
        commitment::vec_equivocate(&first, &keys, trapdoors, first_openings, leaves, index)?;
    Ok((proof_challenge, response, keys, openings))
}

/// `VerifyRedemption(anchor_set, redemption, ctx_iss, ctx_red,
/// challenge_digest)`, run by the Moderator: checks the shown Endorsement
/// under the rerandomized key and the issuer-hiding proof against the
/// Anchor Set, and returns the nullifier.
///
/// This does not enforce single use: the Moderator must reject a nullifier
/// it has recorded, and record it before granting anything.
pub fn verify_redemption<B: Backend>(
    anchor_set: &[PublicKey<B>],
    redemption: &Redemption<B>,
    ctx_iss: &[u8],
    ctx_red: &[u8],
    challenge_digest: &[u8],
) -> Result<[u8; NULLIFIER_LENGTH], Error> {
    verify_signature(&redemption.x_hat, &redemption.shown, ctx_iss, ctx_red)?;
    verify_issuer(anchor_set, redemption, ctx_iss, ctx_red, challenge_digest)?;
    Ok(redemption.shown.nf)
}

/// `VerifyIssuer`, as `Ok(())` or [`Error::Verify`].
fn verify_issuer<B: Backend>(
    anchor_set: &[PublicKey<B>],
    redemption: &Redemption<B>,
    ctx_iss: &[u8],
    ctx_red: &[u8],
    challenge_digest: &[u8],
) -> Result<(), Error> {
    let n = anchor_set.len();
    if n == 0 {
        return Err(Error::Verify);
    }
    let q = commitment::depth(n);
    if redemption.commitment_keys.len() != q || redemption.openings.len() != q {
        return Err(Error::Verify);
    }
    let statement = proof_statement(
        anchor_set,
        &redemption.x_hat,
        &redemption.shown,
        ctx_iss,
        ctx_red,
        challenge_digest,
    )?;
    let leaves = branch_commitments(
        anchor_set,
        &redemption.x_hat,
        &redemption.proof_challenge,
        &redemption.response,
        Error::Verify,
    )?;
    let keys = redemption
        .commitment_keys
        .iter()
        .map(|q| Key::<B>::public(q.clone()).map_err(|_| Error::Verify))
        .collect::<Result<Vec<_>, _>>()?;
    let root = commitment::vec_commit(&leaves, &keys, &redemption.openings, Error::Verify)?;
    let expected = compute_proof_challenge::<B>(&statement, &redemption.commitment_keys, &root)?;
    if bool::from(expected.ct_eq(&redemption.proof_challenge)) {
        Ok(())
    } else {
        Err(Error::Verify)
    }
}

// ---------------------------------------------------------------------------
// Test access
// ---------------------------------------------------------------------------

#[cfg(test)]
impl<B: Backend> AnchorState<B> {
    /// `SerializeScalar(a) || SerializeScalar(y) || SerializeScalar(t)`, the
    /// `commit.state` entry of the test vectors.
    pub(crate) fn vector_bytes(&self) -> Vec<u8> {
        [self.a, self.y, self.t]
            .iter()
            .flat_map(|scalar| scalar.to_bytes())
            .collect()
    }
}

#[cfg(test)]
impl<B: Backend> ClientState<B> {
    /// `nf || r1 || r2 || gamma1 || gamma2 || c`, the `challenge.state`
    /// entry of the test vectors.
    pub(crate) fn vector_bytes(&self) -> Vec<u8> {
        let mut out = self.nf.to_vec();
        for scalar in [self.r1, self.r2, self.gamma1, self.gamma2, self.c] {
            out.extend_from_slice(&scalar.to_bytes());
        }
        out
    }
}

#[cfg(test)]
pub(crate) fn context_base_for_tests<B: Backend>(ctx_iss: &[u8]) -> B::Point {
    context_base::<B>(ctx_iss).unwrap_or_else(|_| B::Point::identity())
}

#[cfg(test)]
pub(crate) fn delta_for_tests<B: Backend>(rand: &[u8]) -> B::Scalar {
    hash::derive_scalars::<B>(CTX, &rand[..NSEED], b"delta", 1)
        .map(|scalars| scalars[0])
        .unwrap_or_default()
}
