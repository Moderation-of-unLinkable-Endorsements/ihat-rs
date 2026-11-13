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

//! Known answers for ACT's own primitives: its SHAKE128 sponge, coefficients,
//! and little-endian reduction. `mole-p256` tests the group and hashing beneath
//! them.

use mole_p256::hash::BackendHashExt;

use crate::backend::{Backend, SCALAR_LENGTH, Scalar};
use crate::hash;
use crate::shake128;
use crate::sigma::{self, MINUS_ONE, ONE, coefficient, order_minus};

/// SHAKE128 known answers, through the protocol's sponge.
#[test]
fn shake128_known_answers() {
    let cases: [(&[u8], &str); 2] = [
        (
            b"",
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        ),
        (
            b"abc",
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
        ),
    ];
    for (msg, expected) in cases {
        let mut out = [0u8; 32];
        shake128::hash(&[msg], &mut out);
        assert_eq!(hex::encode(out), expected);
    }
    // Split absorbs see the same stream as one contiguous input.
    let mut out = [0u8; 200];
    shake128::hash(&[b"ab", b"c"], &mut out);
    let mut whole = [0u8; 200];
    shake128::hash(&[b"abc"], &mut whole);
    assert_eq!(out, whole);
}

#[test]
fn session_ids_and_tags() {
    let tag = sigma::tag(b"Spend", &[b"ctx"]).unwrap();
    assert_eq!(
        tag,
        b"EC-ACTv1-P256-SHA256-Spend-CMPT-with-sigma-proofs_Shake128_P256\x00\x03ctx"
    );
    assert_eq!(
        sigma::tag(b"IssueRequest", &[]).unwrap(),
        b"EC-ACTv1-P256-SHA256-IssueRequest-CMPT-with-sigma-proofs_Shake128_P256"
    );
    assert_eq!(
        sigma::tag(b"x", &[&[0u8; 65536]]).unwrap_err(),
        crate::Error::InvalidInput
    );
    // DeriveSessionID(tag) = SHAKE128(label || zeros(136) || tag)[..32].
    let mut expected = [0u8; 32];
    shake128::hash(
        &[b"irtf-cfrg-fiat-shamir/session-id", &[0u8; 136], &tag],
        &mut expected,
    );
    assert_eq!(sigma::session_id(&tag), expected);
}

fn coefficients<B: Backend>() {
    assert_eq!(ONE, B::Scalar::from(1).to_bytes());
    assert_eq!(MINUS_ONE, (-B::Scalar::from(1)).to_bytes());
    for value in [0u64, 1, 2, 255, 256, 1 << 63, u64::MAX] {
        assert_eq!(
            coefficient(value),
            B::Scalar::from(value).to_bytes(),
            "{value}"
        );
        assert_eq!(
            order_minus(value),
            (-B::Scalar::from(value)).to_bytes(),
            "{value}"
        );
    }
}

/// ACT's little-endian `DecodeUint` reduction agrees with the scalar
/// arithmetic and with the big-endian reduction of the reversed bytes.
fn reductions<B: Backend>() {
    let mut bytes = [0u8; 48];
    bytes[0] = 5;
    assert_eq!(hash::reduce_le_48::<B>(&bytes).to_bytes(), coefficient(5));
    let all = [0xffu8; 48];
    let expected = {
        // 2^384 - 1 = (2^192 - 1) * 2^192 + (2^192 - 1) mod n
        let mut half = [0u8; SCALAR_LENGTH];
        half[8..].fill(0xff);
        let half = B::Scalar::from_bytes(&half).unwrap();
        let mut two_192 = [0u8; SCALAR_LENGTH];
        two_192[7] = 1;
        let two_192 = B::Scalar::from_bytes(&two_192).unwrap();
        half * two_192 + half
    };
    assert_eq!(
        hash::reduce_le_48::<B>(&all).to_bytes(),
        expected.to_bytes()
    );
    let ascending: [u8; 48] = core::array::from_fn(|i| i as u8);
    let mut descending = ascending;
    descending.reverse();
    assert_eq!(
        hash::reduce_le_48::<B>(&ascending).to_bytes(),
        B::reduce_be_48(&descending).to_bytes()
    );
}

backend_tests!(coefficients, reductions);

/// With both backends enabled, every public output must agree.
#[cfg(all(feature = "rustcrypto", feature = "boringssl"))]
mod parity {
    use crate::backend::Point;
    use crate::backend::boringssl::BoringSsl;
    use crate::backend::rustcrypto::RustCrypto;

    #[test]
    fn generators_agree() {
        let rc = crate::Params::<RustCrypto>::new(8).unwrap();
        let bssl = crate::Params::<BoringSsl>::new(8).unwrap();
        let a = super::super::protocol::generators(&rc);
        let b = super::super::protocol::generators(&bssl);
        for (a, b) in a.iter().zip(&b) {
            assert_eq!(a.to_bytes(), b.to_bytes());
        }
    }

    #[test]
    fn spends_interoperate() {
        let rc = crate::Params::<RustCrypto>::new(6).unwrap();
        let bssl = crate::Params::<BoringSsl>::new(6).unwrap();
        let seed = [9u8; crate::SEED_LENGTH];
        let key_rc = crate::SecretKey::<RustCrypto>::from_seed(&seed).unwrap();
        let key_bssl = crate::SecretKey::<BoringSsl>::from_seed(&seed).unwrap();
        let pk_bssl =
            crate::PublicKey::<BoringSsl>::from_bytes(&key_rc.public_key().to_bytes()).unwrap();
        // Client on BoringSSL, Moderator on RustCrypto.
        let (state, request) = crate::issue_request(&bssl).unwrap();
        let request =
            crate::IssueRequestMessage::<RustCrypto>::from_bytes(&rc, &request.to_bytes()).unwrap();
        let response = crate::issue_response(
            &key_rc,
            b"ctx",
            40,
            crate::verify_issue_request(&rc, &request).unwrap(),
        )
        .unwrap();
        let response =
            crate::IssueResponseMessage::<BoringSsl>::from_bytes(&bssl, &response.to_bytes())
                .unwrap();
        let credential = crate::finalize_issue(&bssl, &pk_bssl, b"ctx", state, &response).unwrap();
        let (state, spend) = crate::prove_spend(&bssl, credential, b"ctx", 5, 3, b"chal").unwrap();
        let spend = crate::SpendMessage::<RustCrypto>::from_bytes(&rc, &spend.to_bytes()).unwrap();
        let verified = crate::verify_spend(&rc, &key_rc, b"ctx", b"chal", &spend).unwrap();
        let refund = crate::issue_refund(verified, 8).unwrap();
        let refund =
            crate::RefundMessage::<BoringSsl>::from_bytes(&bssl, &refund.to_bytes()).unwrap();
        let credential = crate::finalize_refund(&bssl, &pk_bssl, b"ctx", state, &refund).unwrap();
        assert_eq!(credential.balance(), 43);
        // And the other way around.
        let (state, spend) = {
            let credential =
                crate::Credential::<RustCrypto>::from_bytes(&rc, &credential.to_bytes()).unwrap();
            crate::prove_spend(&rc, credential, b"ctx", 43, 0, b"chal2").unwrap()
        };
        let spend = crate::SpendMessage::<BoringSsl>::from_bytes(&bssl, &spend.to_bytes()).unwrap();
        let verified = crate::verify_spend(&bssl, &key_bssl, b"ctx", b"chal2", &spend).unwrap();
        let refund = crate::issue_refund(verified, 0).unwrap();
        let refund =
            crate::RefundMessage::<RustCrypto>::from_bytes(&rc, &refund.to_bytes()).unwrap();
        let credential =
            crate::finalize_refund(&rc, &key_rc.public_key(), b"ctx", state, &refund).unwrap();
        assert_eq!(credential.balance(), 0);
    }
}
