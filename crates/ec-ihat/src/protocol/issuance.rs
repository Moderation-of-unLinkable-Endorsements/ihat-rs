//! Endorsement issuance and verification.

use super::{
    AnchorState, Backend, BackendHashExt, CTX, ChallengeMessage, ClientState, CommitMessage,
    ConstantTimeEq, Endorsement, Error, NSEED, NULLIFIER_LENGTH, Point, PublicKey, Random,
    ResponseMessage, Scalar, SecretKey, Signature, SystemRandom, Zeroize, Zeroizing,
    check_redemption_context, compute_challenge, context_base, encode, require, u16_prefix,
};

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// `Commit(ctx_iss)`, run by the Anchor to open a session.
///
/// The Anchor keeps the state until it answers the session's challenge or
/// discards the session, and sends the message. Correlating the challenge
/// with this state is the Anchor's job; any identifier it uses must stay
/// out of the protocol (Section 8 of the draft).
pub fn commit<B: Backend>(ctx_iss: &[u8]) -> Result<(AnchorState<B>, CommitMessage<B>), Error> {
    commit_with(ctx_iss, &mut SystemRandom::<B>::new())
}

pub(crate) fn commit_with<B: Backend, R: Random>(
    ctx_iss: &[u8],
    rng: &mut R,
) -> Result<(AnchorState<B>, CommitMessage<B>), Error> {
    let z = context_base::<B>(ctx_iss)?;
    let mut rand = [0u8; NSEED];
    rng.fill(&mut rand)?;
    let derived = B::derive_scalars(CTX, &rand, b"Commit", 3);
    rand.zeroize();
    let derived = derived?;
    let state = AnchorState {
        a: derived[0],
        t: derived[1],
        y: derived[2],
    };
    let a = B::Point::mul_generator(&state.a);
    let c = B::Point::mul_generator(&state.t).add(&z.mul(&state.y));
    encode(&c)?;
    let message = CommitMessage { a, c };
    Ok((state, message))
}

/// `Challenge(pkA, ctx_iss, ctx_red, commitment)`, run by the Client: draws
/// the nullifier, blinds the commitment, and returns the blinded challenge.
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
    rng.fill(rand.as_mut())?;
    let derived = B::derive_scalars(CTX, &rand[NULLIFIER_LENGTH..], b"Challenge", 4)?;
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

    let mut gamma = state.gamma1 * require(state.gamma2.invert(), Error::Derive)?;
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
        challenge: state.challenge,
    };
    Ok((state, message))
}

/// `Respond(skA, state, challenge)`, run by the Anchor. Consumes the state,
/// so a session answers at most one challenge.
///
/// The Anchor must never run this on a state it has already used or
/// discarded, including a persisted copy: two responses from one state
/// disclose the signing key.
pub fn respond<B: Backend>(
    secret_key: &SecretKey<B>,
    state: AnchorState<B>,
    challenge: &ChallengeMessage<B>,
) -> Result<ResponseMessage<B>, Error> {
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
    let mut gamma = state.gamma1 * require(state.gamma2.invert(), Error::Derive)?;
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
pub(super) fn verify_signature<B: Backend>(
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
