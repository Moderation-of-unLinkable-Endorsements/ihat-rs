//! Endorsement redemption and issuer-hiding proof verification.

use super::issuance::verify_signature;
use super::{
    Backend, BackendHashExt, CTX, ConstantTimeEq, Endorsement, Error, Key, NSEED, NULLIFIER_LENGTH,
    Node, POINT_LENGTH, Point, PublicKey, Random, Redemption, SCALAR_LENGTH, Scalar, Signature,
    SystemRandom, Vec, Zeroize, Zeroizing, commitment, encode, u16_prefix,
};

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
    Ok(B::hash_to_scalar(
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
    rng.fill(rand.as_mut())?;
    let mut delta = B::derive_scalars(CTX, &rand[..NSEED], b"delta", 1)?[0];

    // X_hat = anchor_set[index] + delta * B, selecting the key in constant
    // time so that `index` does not steer memory accesses.
    let Some(mut selected) =
        B::Point::ct_select(anchor_set.iter().map(|key| &key.pk), usize::from(index)).into_option()
    else {
        delta.zeroize();
        return Err(Error::InvalidInput);
    };
    let x_hat = B::Point::mul_generator(&delta).add(&selected);
    selected.zeroize();
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
    let derived = B::derive_nonces(CTX, &secret, b"ProveIssuer", &[statement], rand, 2 * q + 1)?;
    secret.zeroize();
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
