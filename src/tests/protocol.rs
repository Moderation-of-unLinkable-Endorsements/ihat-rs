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

//! Behavior of the protocol beyond the vectors: rejection of tampered,
//! misdirected, and out-of-range inputs, and the encodings.

use alloc::vec::Vec;

use super::{Replay, os_rng};
use crate::backend::{Backend, FixedBase, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::protocol::{
    ClientIssuanceState, ClientSpendState, Credential, IssueRequestMessage, IssueResponseMessage,
    Params, PublicKey, RefundMessage, SecretKey, SpendMessage, finalize_issue, finalize_refund,
    issue_refund, issue_request, issue_request_with, issue_response, prove_spend, prove_spend_with,
    verify_issue_request, verify_spend,
};
use crate::{Error, MAX_BALANCE_WIDTH};

const CTX: &[u8] = b"epoch";
const CHALLENGE: &[u8] = b"challenge";

/// The four ciphersuite generators, for the vectors.
pub(crate) fn generators<B: Backend>(params: &Params<B>) -> [B::Point; 4] {
    let g = params.generators();
    [&g.h1, &g.h2, &g.h3, &g.h4].map(|base| base.point().clone())
}

/// `CreateContextScalar`, serialized.
pub(crate) fn context_scalar<B: Backend>(ctx_cred: &[u8]) -> [u8; 32] {
    crate::protocol::context_scalar_for_tests::<B>(ctx_cred).to_bytes()
}

struct Setup<B: Backend> {
    params: Params<B>,
    key: SecretKey<B>,
    public_key: PublicKey<B>,
}

fn new_setup<B: Backend>(l: u8) -> Setup<B> {
    let params = Params::<B>::new(l).unwrap();
    let key = SecretKey::<B>::generate().unwrap();
    let public_key = key.public_key();
    Setup {
        params,
        key,
        public_key,
    }
}

fn issue<B: Backend>(setup: &Setup<B>, ctx: &[u8], c: u64) -> Credential<B> {
    let (state, request) = issue_request(&setup.params).unwrap();
    let request = IssueRequestMessage::from_bytes(&setup.params, &request.to_bytes()).unwrap();
    let response = issue_response(
        &setup.key,
        ctx,
        c,
        verify_issue_request(&setup.params, &request).unwrap(),
    )
    .unwrap();
    let response = IssueResponseMessage::from_bytes(&setup.params, &response.to_bytes()).unwrap();
    finalize_issue(&setup.params, &setup.public_key, ctx, state, &response).unwrap()
}

/// One spend and refund, through the encodings.
fn spend<B: Backend>(
    setup: &Setup<B>,
    credential: Credential<B>,
    s: u64,
    a: u64,
    t: u64,
) -> (Credential<B>, SpendMessage<B>) {
    let (state, message) = prove_spend(&setup.params, credential, CTX, s, a, CHALLENGE).unwrap();
    let message = SpendMessage::from_bytes(&setup.params, &message.to_bytes()).unwrap();
    let verified = verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &message).unwrap();
    let refund = issue_refund(verified, t).unwrap();
    let refund = RefundMessage::from_bytes(&setup.params, &refund.to_bytes()).unwrap();
    let credential =
        finalize_refund(&setup.params, &setup.public_key, CTX, state, &refund).unwrap();
    (credential, message)
}

fn full_flow<B: Backend>() {
    let setup = new_setup::<B>(8);
    let credential = issue(&setup, CTX, 10);
    assert_eq!(credential.balance(), 10);
    let mut nullifiers = Vec::new();
    let mut credential = credential;
    for (s, a, t, expected) in [
        (3, 0, 1, 8),
        (0, 0, 0, 8),
        (0, 2, 2, 10),
        (3, 2, 5, 12),
        (12, 0, 0, 0),
        (0, 255, 255, 255),
    ] {
        let (next, message) = spend(&setup, credential, s, a, t);
        assert_eq!(next.balance(), expected);
        assert!(
            !nullifiers.contains(&message.nullifier()),
            "nullifier repeated"
        );
        nullifiers.push(message.nullifier());
        credential = next;
    }
}

fn contexts_are_bound<B: Backend>() {
    let setup = new_setup::<B>(4);
    let (state, request) = issue_request(&setup.params).unwrap();
    let response = issue_response(
        &setup.key,
        CTX,
        5,
        verify_issue_request(&setup.params, &request).unwrap(),
    )
    .unwrap();
    assert_eq!(
        finalize_issue(&setup.params, &setup.public_key, b"other", state, &response).unwrap_err(),
        Error::Verify
    );
    let credential = issue(&setup, CTX, 5);
    let (state, message) = prove_spend(&setup.params, credential, CTX, 1, 0, CHALLENGE).unwrap();
    assert_eq!(
        verify_spend(&setup.params, &setup.key, b"other", CHALLENGE, &message).unwrap_err(),
        Error::Verify
    );
    assert_eq!(
        verify_spend(&setup.params, &setup.key, CTX, b"other", &message).unwrap_err(),
        Error::Verify
    );
    let verified = verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &message).unwrap();
    let refund = issue_refund(verified, 1).unwrap();
    assert_eq!(
        finalize_refund(&setup.params, &setup.public_key, b"other", state, &refund).unwrap_err(),
        Error::Verify
    );
    let other = new_setup::<B>(4);
    let credential = issue(&setup, CTX, 5);
    let (_, message) = prove_spend(&setup.params, credential, CTX, 1, 0, CHALLENGE).unwrap();
    assert_eq!(
        verify_spend(&other.params, &other.key, CTX, CHALLENGE, &message).unwrap_err(),
        Error::Verify
    );
}

fn refunds_are_bound_to_their_spend<B: Backend>() {
    let setup = new_setup::<B>(4);
    let first = issue(&setup, CTX, 5);
    let second = issue(&setup, CTX, 5);
    let (state1, spend1) = prove_spend(&setup.params, first, CTX, 1, 0, CHALLENGE).unwrap();
    let (state2, spend2) = prove_spend(&setup.params, second, CTX, 1, 0, CHALLENGE).unwrap();
    let verified1 = verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &spend1).unwrap();
    let verified2 = verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &spend2).unwrap();
    let refund1 = issue_refund(verified1, 1).unwrap();
    let refund2 = issue_refund(verified2, 1).unwrap();
    assert_eq!(
        finalize_refund(&setup.params, &setup.public_key, CTX, state1, &refund2).unwrap_err(),
        Error::Verify
    );
    finalize_refund(&setup.params, &setup.public_key, CTX, state2, &refund2).unwrap();
    let _ = refund1;
}

fn unverified_spend_cannot_authorize_refund<B: Backend>() {
    let setup = new_setup::<B>(8);
    let credential = issue(&setup, CTX, 200);
    let (_, mut spend) = prove_spend(&setup.params, credential, CTX, 0, 0, CHALLENGE).unwrap();
    spend.pok.fill(0);

    // There is no public refund-signing path from `spend` itself: the only
    // accepted input is the token that this failed verification cannot return.
    assert_eq!(
        verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &spend).unwrap_err(),
        Error::Verify
    );
}

fn amounts_are_bounded<B: Backend>() {
    let setup = new_setup::<B>(4);
    let (state, request) = issue_request(&setup.params).unwrap();
    assert_eq!(
        issue_response(
            &setup.key,
            CTX,
            16,
            verify_issue_request(&setup.params, &request).unwrap()
        )
        .unwrap_err(),
        Error::Amount
    );
    let response = issue_response(
        &setup.key,
        CTX,
        15,
        verify_issue_request(&setup.params, &request).unwrap(),
    )
    .unwrap();
    let credential =
        finalize_issue(&setup.params, &setup.public_key, CTX, state, &response).unwrap();
    let cases: [(u64, u64, Error); 4] = [
        (16, 0, Error::Amount),
        (0, 16, Error::Amount),
        (0, 1, Error::Amount), // c + a = 16
        (15, 1, Error::Amount),
    ];
    let mut credential = credential;
    for (s, a, expected) in cases {
        let bytes = credential.to_bytes();
        assert_eq!(
            prove_spend(&setup.params, credential, CTX, s, a, CHALLENGE).unwrap_err(),
            expected
        );
        credential = Credential::from_bytes(&setup.params, &bytes).unwrap();
    }
    let (state, message) = prove_spend(&setup.params, credential, CTX, 5, 0, CHALLENGE).unwrap();
    let verified = verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &message).unwrap();
    assert_eq!(issue_refund(verified, 6).unwrap_err(), Error::Amount);
    let verified = verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &message).unwrap();
    let refund = issue_refund(verified, 5).unwrap();
    // A refund below 2^L but above what the state admits.
    let state_bytes = state.to_bytes();
    let bad_state = {
        let mut bytes = state_bytes.clone();
        bytes[64..72].copy_from_slice(&15u64.to_be_bytes()); // v1 = 15 makes v1 + t >= 2^L
        ClientSpendState::from_bytes(&setup.params, &bytes).unwrap()
    };
    assert_eq!(
        finalize_refund(&setup.params, &setup.public_key, CTX, bad_state, &refund).unwrap_err(),
        Error::Amount
    );
    let credential =
        finalize_refund(&setup.params, &setup.public_key, CTX, state, &refund).unwrap();
    assert_eq!(credential.balance(), 15);
    // Decoding checks amounts too.
    let mut bytes = credential.to_bytes();
    bytes[32..40].copy_from_slice(&16u64.to_be_bytes());
    assert_eq!(
        Credential::<B>::from_bytes(&setup.params, &bytes).unwrap_err(),
        Error::Amount
    );
}

fn balance_width_bounds<B: Backend>() {
    assert_eq!(Params::<B>::new(0).unwrap_err(), Error::InvalidInput);
    assert_eq!(
        Params::<B>::new(MAX_BALANCE_WIDTH + 1).unwrap_err(),
        Error::InvalidInput
    );
    assert_eq!(Params::<B>::new(64).unwrap().max_amount(), u64::MAX);
    assert_eq!(Params::<B>::new(1).unwrap().max_amount(), 1);
    let setup = new_setup::<B>(64);
    let credential = issue(&setup, CTX, u64::MAX);
    let (credential, _) = spend(&setup, credential, u64::MAX, 0, 1);
    assert_eq!(credential.balance(), 1);
    let (credential, _) = spend(&setup, credential, 1, u64::MAX - 1, u64::MAX);
    assert_eq!(credential.balance(), u64::MAX);
}

#[test]
fn weighted_ranges_cover_exact_bounds() {
    use crate::statements::{range_weights, spend_weights};

    for l in 1..=8 {
        let max = (1u64 << l) - 1;
        for m in 0..=max {
            let weights = range_weights(l, m).unwrap();
            assert!(weights.iter().all(|weight| *weight > 0));
            assert_eq!(weights.iter().sum::<u64>(), m);

            let mut covered = alloc::vec![false; (m + 1) as usize];
            for subset in 0..1usize << weights.len() {
                let sum = weights
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| subset & (1 << j) != 0)
                    .map(|(_, weight)| weight)
                    .sum::<u64>();
                assert!(sum <= m);
                covered[sum as usize] = true;
            }
            assert!(covered.into_iter().all(core::convert::identity));
        }
    }
    assert_eq!(range_weights(4, 16), Err(Error::Amount));
    assert_eq!(spend_weights(4, 16, 0), Err(Error::Amount));
    assert_eq!(spend_weights(4, 0, 16), Err(Error::Amount));
}

fn weighted_sums_match_direct_calculation<B: Backend>() {
    use crate::statements::{range_weights, weighted_points, weighted_scalars};

    let generator = B::Point::generator();
    for l in 1..=8 {
        let max = (1u64 << l) - 1;
        for m in 0..=max {
            let weights = range_weights(l, m).unwrap();
            let scalars = (1..=weights.len())
                .map(|value| B::Scalar::from(value as u64))
                .collect::<Vec<_>>();
            let points = scalars
                .iter()
                .map(|scalar| generator.mul(scalar))
                .collect::<Vec<_>>();
            let expected = scalars
                .iter()
                .zip(&weights)
                .fold(B::Scalar::default(), |sum, (scalar, weight)| {
                    sum + *scalar * B::Scalar::from(*weight)
                });

            assert_eq!(
                weighted_scalars(&scalars, &weights).to_bytes(),
                expected.to_bytes()
            );
            assert_eq!(weighted_points(&points, &weights), generator.mul(&expected));
        }
    }
}

fn tampering_is_rejected<B: Backend>() {
    let setup = new_setup::<B>(4);
    let (state, request) = issue_request(&setup.params).unwrap();
    let request_bytes = request.to_bytes();
    for i in (0..request_bytes.len()).step_by(5) {
        let mut bytes = request_bytes.clone();
        bytes[i] ^= 1;
        let result = IssueRequestMessage::from_bytes(&setup.params, &bytes).and_then(|request| {
            issue_response(
                &setup.key,
                CTX,
                3,
                verify_issue_request(&setup.params, &request)?,
            )
        });
        assert!(
            matches!(result, Err(Error::Deserialize | Error::Verify)),
            "byte {i}"
        );
    }
    let response = issue_response(
        &setup.key,
        CTX,
        3,
        verify_issue_request(&setup.params, &request).unwrap(),
    )
    .unwrap();
    let response_bytes = response.to_bytes();
    let state_bytes = state.to_bytes();
    for i in (0..response_bytes.len()).step_by(5) {
        let mut bytes = response_bytes.clone();
        bytes[i] ^= 1;
        let state = ClientIssuanceState::from_bytes(&setup.params, &state_bytes).unwrap();
        let result = IssueResponseMessage::from_bytes(&setup.params, &bytes).and_then(|response| {
            finalize_issue(&setup.params, &setup.public_key, CTX, state, &response)
        });
        assert!(
            matches!(
                result,
                Err(Error::Deserialize | Error::Verify | Error::Amount)
            ),
            "byte {i}"
        );
    }
    let credential =
        finalize_issue(&setup.params, &setup.public_key, CTX, state, &response).unwrap();

    let (state, message) = prove_spend(&setup.params, credential, CTX, 1, 1, CHALLENGE).unwrap();
    let message_bytes = message.to_bytes();
    for i in (0..message_bytes.len()).step_by(11) {
        let mut bytes = message_bytes.clone();
        bytes[i] ^= 1;
        let result = SpendMessage::from_bytes(&setup.params, &bytes).and_then(|message| {
            verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &message).map(|_| ())
        });
        assert!(
            matches!(
                result,
                Err(Error::Deserialize | Error::Verify | Error::Amount)
            ),
            "byte {i}"
        );
    }
    let verified = verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &message).unwrap();
    let refund = issue_refund(verified, 1).unwrap();
    let refund_bytes = refund.to_bytes();
    let state_bytes = state.to_bytes();
    for i in (0..refund_bytes.len()).step_by(5) {
        let mut bytes = refund_bytes.clone();
        bytes[i] ^= 1;
        let state = ClientSpendState::from_bytes(&setup.params, &state_bytes).unwrap();
        let result = RefundMessage::from_bytes(&setup.params, &bytes).and_then(|refund| {
            finalize_refund(&setup.params, &setup.public_key, CTX, state, &refund)
        });
        assert!(
            matches!(
                result,
                Err(Error::Deserialize | Error::Verify | Error::Amount)
            ),
            "byte {i}"
        );
    }
    finalize_refund(&setup.params, &setup.public_key, CTX, state, &refund).unwrap();
}

fn shape_must_match_amounts<B: Backend>() {
    let setup = new_setup::<B>(4);
    let credential = issue(&setup, CTX, 5);
    let (_, message) = prove_spend(&setup.params, credential, CTX, 3, 0, CHALLENGE).unwrap();
    let bytes = message.to_bytes();
    // Declaring s = 0 changes the expected shape and proof length.
    let mut zeroed = bytes.clone();
    zeroed[32..40].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        SpendMessage::<B>::from_bytes(&setup.params, &zeroed).unwrap_err(),
        Error::Deserialize
    );
    // Truncation and extension are rejected.
    assert_eq!(
        SpendMessage::<B>::from_bytes(&setup.params, &bytes[..bytes.len() - 1]).unwrap_err(),
        Error::Deserialize
    );
    let mut extended = bytes.clone();
    extended.push(0);
    assert_eq!(
        SpendMessage::<B>::from_bytes(&setup.params, &extended).unwrap_err(),
        Error::Deserialize
    );
    // The superseded two-range-proof encoding inserted a second commitment
    // block before the proof. It must not be accepted as the current shape.
    let proof_start = bytes.len() - message.pok.len();
    let points_start = SCALAR_LENGTH + 2 * core::mem::size_of::<u64>();
    let mut two_range = bytes[..proof_start].to_vec();
    for _ in 0..usize::from(setup.params.balance_width()) {
        two_range.extend_from_slice(&bytes[points_start..points_start + POINT_LENGTH]);
    }
    two_range.extend_from_slice(&bytes[proof_start..]);
    assert_eq!(
        SpendMessage::<B>::from_bytes(&setup.params, &two_range).unwrap_err(),
        Error::Deserialize
    );
    assert_eq!(
        SpendMessage::<B>::encoded_len(&setup.params, 3, 0).unwrap(),
        129 * 4 + 403
    );
    assert_eq!(
        SpendMessage::<B>::encoded_len(&setup.params, 0, 2).unwrap(),
        129 * 4 + 403
    );
    assert_eq!(
        SpendMessage::<B>::encoded_len(&setup.params, 3, 2).unwrap(),
        129 * 4 + 403
    );
    assert_eq!(
        SpendMessage::<B>::encoded_len(&setup.params, 8, 0).unwrap(),
        129 * 3 + 403
    );
    assert_eq!(
        SpendMessage::<B>::encoded_len(&setup.params, 15, 0).unwrap(),
        403
    );
    assert_eq!(
        SpendMessage::<B>::encoded_len(&setup.params, 0, 0).unwrap(),
        468
    );
    assert_eq!(
        SpendMessage::<B>::encoded_len(&setup.params, 15, 1),
        Err(Error::Amount)
    );
    assert_eq!(IssueRequestMessage::<B>::LENGTH, 129);
    assert_eq!(IssueResponseMessage::<B>::LENGTH, 137);
    assert_eq!(RefundMessage::<B>::LENGTH, 137);
}

fn non_canonical_encodings_are_rejected<B: Backend>() {
    let setup = new_setup::<B>(4);
    let (_, request) = issue_request(&setup.params).unwrap();
    let bytes = request.to_bytes();
    // The identity has no encoding of length Ne; the all-zero string is not one.
    let mut identity = bytes.clone();
    identity[..33].fill(0);
    assert_eq!(
        IssueRequestMessage::<B>::from_bytes(&setup.params, &identity).unwrap_err(),
        Error::Deserialize
    );
    // An uncompressed prefix is not canonical.
    let mut uncompressed = bytes.clone();
    uncompressed[0] = 4;
    assert_eq!(
        IssueRequestMessage::<B>::from_bytes(&setup.params, &uncompressed).unwrap_err(),
        Error::Deserialize
    );
    // A proof scalar equal to the order is not canonical.
    let mut order = bytes.clone();
    order[33..65].copy_from_slice(&crate::backend::ORDER);
    assert_eq!(
        IssueRequestMessage::<B>::from_bytes(&setup.params, &order).unwrap_err(),
        Error::Deserialize
    );
    // Trailing bytes are rejected.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        IssueRequestMessage::<B>::from_bytes(&setup.params, &trailing).unwrap_err(),
        Error::Deserialize
    );
    // Public keys likewise.
    assert_eq!(
        PublicKey::<B>::from_bytes(&[0; 33]).unwrap_err(),
        Error::Deserialize
    );
    assert_eq!(
        SecretKey::<B>::from_bytes(&[0; 32]).unwrap_err(),
        Error::Deserialize
    );
    assert_eq!(
        SecretKey::<B>::from_bytes(&crate::backend::ORDER).unwrap_err(),
        Error::Deserialize
    );
}

fn keys_round_trip<B: Backend>() {
    let key = SecretKey::<B>::generate().unwrap();
    let restored = SecretKey::<B>::from_bytes(&key.to_bytes()).unwrap();
    assert_eq!(restored.public_key(), key.public_key());
    let public_key = PublicKey::<B>::from_bytes(&key.public_key().to_bytes()).unwrap();
    assert_eq!(public_key, key.public_key());
    let seeded = SecretKey::<B>::from_seed(&[7; 48], b"GenerateKeyPair").unwrap();
    let mut rng = Replay::constant(7, 48);
    let generated = SecretKey::<B>::generate_with(&mut rng).unwrap();
    rng.finish();
    assert_eq!(seeded.to_bytes(), generated.to_bytes());
    assert_ne!(
        seeded.to_bytes(),
        SecretKey::<B>::from_seed(&[7; 48], b"other")
            .unwrap()
            .to_bytes()
    );
}

fn proofs_are_deterministic_in_the_randomness<B: Backend>() {
    let setup = new_setup::<B>(4);
    let mut rng = Replay::constant(3, 2 * 48);
    let (_, first) = issue_request_with(&setup.params, &mut rng).unwrap();
    rng.finish();
    let mut rng = Replay::constant(3, 2 * 48);
    let (_, second) = issue_request_with(&setup.params, &mut rng).unwrap();
    assert_eq!(first.to_bytes(), second.to_bytes());
    let mut rng = Replay::constant(4, 2 * 48);
    let (_, third) = issue_request_with(&setup.params, &mut rng).unwrap();
    assert_ne!(first.to_bytes(), third.to_bytes());

    let credential = issue(&setup, CTX, 5);
    let bytes = credential.to_bytes();
    let mut rng = Replay::constant(5, 2 * 48);
    let (_, first) =
        prove_spend_with(&setup.params, credential, CTX, 2, 0, CHALLENGE, &mut rng).unwrap();
    rng.finish();
    let credential = Credential::from_bytes(&setup.params, &bytes).unwrap();
    let mut rng = Replay::constant(5, 2 * 48);
    let (_, second) =
        prove_spend_with(&setup.params, credential, CTX, 2, 0, CHALLENGE, &mut rng).unwrap();
    assert_eq!(first.to_bytes(), second.to_bytes());
    let _verified = verify_spend(&setup.params, &setup.key, CTX, CHALLENGE, &second).unwrap();
}

/// `ValidateInstance` checks 8 and 9 for elements and images that are
/// computed rather than deserialized: each statement's `validate` must
/// reject the identity on its own, before any proof is examined.
fn statements_reject_identity_elements<B: Backend>() {
    use crate::backend::{FixedBase, Point};
    use crate::sigma::Statement;
    use crate::statements::{Commitment, Signature, Spend};

    let params = Params::<B>::new(1).unwrap();
    let gens = params.generators();
    let g = B::Point::generator();
    let identity = B::Point::identity();

    assert_eq!(
        Commitment { gens, k: &identity }.validate(),
        Err(Error::Verify)
    );
    assert_eq!(Commitment { gens, k: &g }.validate(), Ok(()));

    for (a, x_a, x_g) in [
        (&identity, &g, &g),
        (&g, &identity, &g),
        (&g, &g, &identity),
    ] {
        assert_eq!(
            Signature::<B> { a, x_a, x_g }.validate(),
            Err(Error::Verify)
        );
    }
    assert_eq!(
        Signature::<B> {
            a: &g,
            x_a: &g,
            x_g: &g
        }
        .validate(),
        Ok(())
    );

    // Check 8 on the computed elements `A_bar` and `H1_prime`.
    let com_c = g.clone();
    let spend = |a_bar: &B::Point, h1_prime: &B::Point| {
        Spend::new(
            gens,
            1,
            &g,
            &g,
            a_bar,
            h1_prime,
            &g,
            0,
            0,
            &[],
            Some(&com_c),
        )
        .unwrap()
        .validate()
    };
    assert_eq!(spend(&identity, &g), Err(Error::Verify));
    assert_eq!(spend(&g, &identity), Err(Error::Verify));
    assert_eq!(spend(&g, &g), Ok(()));

    // Check 9 on `K_n + s * H1 + sum w[j] * Com1[j]`: with `L = 1` and
    // `s = 1`, there are no commitments and `K_n = -H1` makes it identity.
    let minus_h1 = gens.h1.mul(&-B::Scalar::from(1));
    let statement = Spend::new(gens, 1, &g, &g, &g, &g, &minus_h1, 1, 0, &[], None).unwrap();
    assert_eq!(statement.validate(), Err(Error::Verify));
    let statement = Spend::new(gens, 1, &g, &g, &g, &g, &g, 1, 0, &[], None).unwrap();
    assert_eq!(statement.validate(), Ok(()));

    // Shapes that do not match the amounts are rejected at construction.
    let com1 = [g.clone()];
    assert!(Spend::new(gens, 1, &g, &g, &g, &g, &g, 1, 0, &[], Some(&com_c)).is_err());
    assert!(Spend::new(gens, 1, &g, &g, &g, &g, &g, 1, 0, &com1, None).is_err());
    assert!(Spend::new(gens, 1, &g, &g, &g, &g, &g, 0, 0, &com1, None).is_err());
    assert!(Spend::new(gens, 1, &g, &g, &g, &g, &g, 0, 0, &[], None).is_err());
    assert!(Spend::new(gens, 1, &g, &g, &g, &g, &g, 0, 1, &[], Some(&com_c)).is_err());
    assert!(matches!(
        Spend::new(gens, 1, &g, &g, &g, &g, &g, 1, 1, &[], None),
        Err(Error::Amount)
    ));
}

fn credentials_zeroize<B: Backend>() {
    // The Drop impls run without panicking on every record type.
    let setup = new_setup::<B>(4);
    let credential = issue(&setup, CTX, 5);
    let (state, _) = prove_spend(&setup.params, credential, CTX, 1, 0, CHALLENGE).unwrap();
    drop(state);
    drop(setup);
    let mut rng = os_rng::<B>();
    let _ = SecretKey::<B>::generate_with(&mut rng);
    let _ = B::Scalar::default();
}

fn entropy_failure_is_an_error<B: Backend>() {
    struct Failing;
    impl crate::random::Random for Failing {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
            Err(Error::Entropy)
        }
    }
    let params = Params::<B>::new(4).unwrap();
    assert!(matches!(
        issue_request_with(&params, &mut Failing),
        Err(Error::Entropy)
    ));
}

backend_tests!(
    entropy_failure_is_an_error,
    full_flow,
    contexts_are_bound,
    refunds_are_bound_to_their_spend,
    unverified_spend_cannot_authorize_refund,
    amounts_are_bounded,
    balance_width_bounds,
    weighted_sums_match_direct_calculation,
    tampering_is_rejected,
    shape_must_match_amounts,
    non_canonical_encodings_are_rejected,
    keys_round_trip,
    proofs_are_deterministic_in_the_randomness,
    statements_reject_identity_elements,
    credentials_zeroize,
);
