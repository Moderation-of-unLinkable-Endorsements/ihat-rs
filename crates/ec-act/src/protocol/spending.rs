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

//! Credential spending and refunds.

use super::{
    BackendFixedBaseExt, BackendHashExt, ClientSpendState, Credential, Error, Generators, NSEED,
    PROTOCOL_CONTEXT, Params, Point, PublicKey, Random, RefundMessage, Scalar, SecretKey,
    SecretPoint, Spend, SpendMessage, SystemRandom, Vec, VerifiedSpend, Zeroizing, context_scalar,
    fixed, hash, range_block, sigma, sign, spend_weights, verify_signature,
};

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
pub fn prove_spend<B: BackendFixedBaseExt>(
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

pub(crate) fn prove_spend_with<B: BackendFixedBaseExt, R: Random>(
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
    let session_id = sigma::session_id(&tag);

    // Four fixed scalars, then one for each weighted bit of the remainder or
    // one for the commitment of a refresh.
    let count = 4 + if refresh { 1 } else { n };
    let mut rand = Zeroizing::new([0u8; NSEED]);
    rng.fill(&mut *rand)?;
    // `derived` holds every secret scalar of the spend and is wiped on every
    // return; the values computed from them below are held in wrappers that
    // wipe them on drop.
    let derived = B::derive_scalars(PROTOCOL_CONTEXT, &*rand, b"ProveSpend", count)?;
    drop(rand);
    let (r1, r2, kstar, rn) = (&derived[0], &derived[1], &derived[2], &derived[3]);

    // Rerandomize the signature.
    let h1_prime = fixed::<B, 2>([(&gens.h2, &credential.k), (&gens.h4, &ctx)]).add(&gens.g);
    let c_scalar = Zeroizing::new(B::Scalar::from(c));
    let b_msg = SecretPoint(
        fixed::<B, 2>([(&gens.h1, &*c_scalar), (&gens.h3, &credential.r)]).add(&h1_prime),
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
    let k_prime = statement.balance_commitment();

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
pub fn verify_spend<'a, B: BackendFixedBaseExt>(
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
    sigma::verify::<B, _>(&sigma::session_id(&tag), &statement, &spend.pok)?;
    let k_prime = statement.balance_commitment();
    Ok(VerifiedSpend {
        params,
        key,
        spend,
        ctx,
        k_prime,
    })
}

fn spend_statement<'a, B: BackendFixedBaseExt>(
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
fn refund_message<B: BackendFixedBaseExt>(
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
/// use ec_act::{Params, RefundMessage, SecretKey, SpendMessage};
///
/// fn refund_unverified(
///     params: &Params,
///     key: &SecretKey,
///     spend: &SpendMessage,
/// ) -> Result<RefundMessage, ec_act::Error> {
///     ec_act::issue_refund(params, key, b"credential context", spend, 0)
/// }
/// ```
pub fn issue_refund<B: BackendFixedBaseExt>(
    verified: VerifiedSpend<'_, B>,
    t: u64,
) -> Result<RefundMessage<B>, Error> {
    issue_refund_with(verified, t, &mut SystemRandom::<B>::new())
}

pub(crate) fn issue_refund_with<B: BackendFixedBaseExt, R: Random>(
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
pub fn finalize_refund<B: BackendFixedBaseExt>(
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
