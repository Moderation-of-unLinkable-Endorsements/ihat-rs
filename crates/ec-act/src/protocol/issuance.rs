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

//! Credential issuance.

use super::{
    BackendFixedBaseExt, BackendHashExt, ClientIssuanceState, Commitment, Credential, Error,
    IssueRequestMessage, IssueResponseMessage, NSEED, PROTOCOL_CONTEXT, Params, PublicKey, Random,
    SecretKey, SystemRandom, VerifiedIssueRequest, Zeroizing, context_scalar, fixed,
    issuance_message, proof_array, sigma, sign, verify_signature,
};

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// `IssueRequest`: commits to a fresh nullifier and blinding factor.
pub fn issue_request<B: BackendFixedBaseExt>(
    params: &Params<B>,
) -> Result<(ClientIssuanceState<B>, IssueRequestMessage<B>), Error> {
    issue_request_with(params, &mut SystemRandom::<B>::new())
}

pub(crate) fn issue_request_with<B: BackendFixedBaseExt, R: Random>(
    params: &Params<B>,
    rng: &mut R,
) -> Result<(ClientIssuanceState<B>, IssueRequestMessage<B>), Error> {
    let gens = &params.gens;
    let mut rand = Zeroizing::new([0u8; NSEED]);
    rng.fill(&mut *rand)?;
    // `derived` holds `(k, r)` and is wiped on every return.
    let derived = B::derive_scalars(PROTOCOL_CONTEXT, &*rand, b"IssueRequest", 2)?;
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
pub fn verify_issue_request<'a, B: BackendFixedBaseExt>(
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
pub fn issue_response<B: BackendFixedBaseExt>(
    key: &SecretKey<B>,
    ctx_cred: &[u8],
    c: u64,
    verified: VerifiedIssueRequest<'_, B>,
) -> Result<IssueResponseMessage<B>, Error> {
    issue_response_with(key, ctx_cred, c, verified, &mut SystemRandom::<B>::new())
}

pub(crate) fn issue_response_with<B: BackendFixedBaseExt, R: Random>(
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
pub fn finalize_issue<B: BackendFixedBaseExt>(
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
