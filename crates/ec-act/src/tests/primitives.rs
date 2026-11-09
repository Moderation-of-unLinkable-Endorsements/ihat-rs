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

//! Known answers for the primitives beneath the protocol.

use alloc::vec::Vec;

use ec_ihat::hash::{BackendHashExt, Error as HashError};
use shake::{ExtendableOutput, Shake128, Update, XofReader};

use crate::PROTOCOL_CONTEXT;
use crate::backend::{Backend, BackendFixedBaseExt, Point, SCALAR_LENGTH, Scalar};
use crate::hash::{self, XmdPrefix};
use crate::sigma::{self, MINUS_ONE, ONE, coefficient, order_minus};

/// RFC 9380, Appendix K.1: `expand_message_xmd(SHA-256)`.
fn expand_message_xmd_vectors<B: Backend>() {
    const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let cases: [(&[u8], usize, &str); 3] = [
        (
            b"",
            0x20,
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
        ),
        (
            b"abc",
            0x20,
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
        ),
        (
            b"",
            0x80,
            "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
        ),
    ];
    for (msg, len, expected) in cases {
        let mut out = alloc::vec![0u8; len];
        XmdPrefix::<B::Sha256>::new(&[]).expand_into(&[msg], &[DST], &mut out);
        assert_eq!(hex::encode(&out), expected);
        // The prefix split does not change the output.
        if !msg.is_empty() {
            XmdPrefix::<B::Sha256>::new(&[&msg[..1]]).expand_into(&[&msg[1..]], &[DST], &mut out);
            assert_eq!(hex::encode(&out), expected);
        }
    }
}

/// RFC 9380, Appendix J.1.1: `P256_XMD:SHA-256_SSWU_RO_`.
fn hash_to_curve_vectors<B: Backend>() {
    const DST: &[u8] = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
    let cases: [(&[u8], &str, &str); 3] = [
        (
            b"",
            "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
            "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
        ),
        (
            b"abc",
            "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
            "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
        ),
        (
            b"abcdef0123456789",
            "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
            "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
        ),
    ];
    for (msg, x, y) in cases {
        let point = B::hash_to_curve(&[msg], &[DST]).unwrap();
        let y = hex::decode(y).unwrap();
        let mut expected = alloc::vec![2 | (y[31] & 1)];
        expected.extend(hex::decode(x).unwrap());
        assert_eq!(point.to_bytes().unwrap().to_vec(), expected);
        // Message and tag parts concatenate.
        let split = B::hash_to_curve(
            &[&msg[..msg.len() / 2], &msg[msg.len() / 2..]],
            &[&DST[..10], &DST[10..]],
        )
        .unwrap();
        assert_eq!(split, point);
    }
}

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
        let mut sponge = Shake128::default();
        sponge.update(msg);
        let mut out = [0u8; 32];
        sponge.finalize_xof().read(&mut out);
        assert_eq!(hex::encode(out), expected);
    }
    // Split absorbs and split reads see one stream.
    let mut sponge = Shake128::default();
    sponge.update(b"ab");
    sponge.update(b"c");
    let mut reader = sponge.finalize_xof();
    let mut out = [0u8; 200];
    reader.read(&mut out[..7]);
    reader.read(&mut out[7..]);
    let mut sponge = Shake128::default();
    sponge.update(b"abc");
    let mut whole = [0u8; 200];
    sponge.finalize_xof().read(&mut whole);
    assert_eq!(out, whole);
}

#[test]
fn session_ids_and_tags() {
    let tag = sigma::tag(b"Spend", &[b"ctx"]).unwrap();
    assert_eq!(
        tag,
        b"ACTv1-P256-SHA256-Spend-CMPT-with-sigma-proofs_Shake128_P256\x00\x03ctx"
    );
    assert_eq!(
        sigma::tag(b"IssueRequest", &[]).unwrap(),
        b"ACTv1-P256-SHA256-IssueRequest-CMPT-with-sigma-proofs_Shake128_P256"
    );
    assert_eq!(
        sigma::tag(b"x", &[&[0u8; 65536]]).unwrap_err(),
        crate::Error::InvalidInput
    );
    // DeriveSessionID(tag) = SHAKE128(label || zeros(136) || tag)[..32].
    let mut sponge = Shake128::default();
    sponge.update(b"irtf-cfrg-fiat-shamir/session-id");
    sponge.update(&[0u8; 136]);
    sponge.update(&tag);
    let mut expected = [0u8; 32];
    sponge.finalize_xof().read(&mut expected);
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

fn scalar_arithmetic<B: Backend>() {
    let a = B::Scalar::from(7);
    let b = B::Scalar::from(6);
    let bytes = |s: B::Scalar| s.to_bytes();
    assert_eq!(bytes(a * b), bytes(B::Scalar::from(42)));
    assert_eq!(bytes(a + b), bytes(B::Scalar::from(13)));
    assert_eq!(bytes(a - b), bytes(B::Scalar::from(1)));
    assert_eq!(bytes(b - a), MINUS_ONE);
    assert_eq!(bytes(a + -a), bytes(B::Scalar::default()));
    assert_eq!(bytes(a * a.invert().unwrap()), ONE);
    assert!(bool::from(B::Scalar::default().invert().is_none()));
    assert!(bool::from(B::Scalar::default().is_zero()));
    assert!(!bool::from(a.is_zero()));
    // Canonical decoding admits order - 1 and rejects the order.
    assert!(bool::from(B::Scalar::from_bytes(&MINUS_ONE).is_some()));
    assert!(bool::from(
        B::Scalar::from_bytes(&crate::backend::ORDER).is_none()
    ));
    let mut above = crate::backend::ORDER;
    above[SCALAR_LENGTH - 1] += 1;
    assert!(bool::from(B::Scalar::from_bytes(&above).is_none()));
    assert!(bool::from(
        B::Scalar::from_bytes(&[0xff; SCALAR_LENGTH]).is_none()
    ));
    // (order - 1) + 1 wraps to zero, and (order - 1)^2 = 1.
    let max = B::Scalar::from_bytes(&MINUS_ONE).unwrap();
    assert!(bool::from((max + B::Scalar::from(1)).is_zero()));
    assert_eq!(bytes(max * max), ONE);
}

fn point_arithmetic<B: Backend>() {
    let g = B::Point::generator();
    let two = B::Scalar::from(2);
    let three = B::Scalar::from(3);
    assert_eq!(g.double(), g.add(&g));
    assert_eq!(g.mul(&two), g.double());
    assert_eq!(g.mul(&three), g.double().add(&g));
    assert_eq!(B::Point::mul_generator(&three), g.mul(&three));
    assert!(bool::from(
        g.mul(&-B::Scalar::from(1)).add(&g).is_identity()
    ));
    assert_eq!(
        B::Point::lincomb([(&g, &two), (&g.double(), &three)]),
        g.mul(&B::Scalar::from(8))
    );
    assert_eq!(
        B::Point::lincomb([(&g, &two), (&g, &-two)]),
        B::Point::identity()
    );
    assert_eq!(B::Point::identity().to_bytes(), None);
    assert_eq!(
        hex::encode(g.to_bytes().unwrap()),
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    );
    let decoded = B::Point::from_bytes(&g.to_bytes().unwrap()).unwrap();
    assert_eq!(decoded, g);
    assert!(bool::from(B::Point::from_bytes(&[0; 33]).is_none()));
    // Only the compressed prefixes decode: not 0x04 (uncompressed), 0x05
    // (the SEC1 compact tag), or any other.
    for prefix in (0..=u8::MAX).filter(|prefix| *prefix != 2 && *prefix != 3) {
        let mut other = g.to_bytes().unwrap();
        other[0] = prefix;
        assert!(
            bool::from(B::Point::from_bytes(&other).is_none()),
            "prefix {prefix:#04x}"
        );
    }
    let mut off_curve = g.to_bytes().unwrap();
    off_curve[32] ^= 1;
    // x + 1 may or may not be on the curve; only check that decoding is consistent.
    if let Some(point) = B::Point::from_bytes(&off_curve).into_option() {
        assert_eq!(point.to_bytes().unwrap(), off_curve);
    }
    let mut zeroized = g.clone();
    zeroized.zeroize();
    assert!(bool::from(zeroized.is_identity()));
}

fn fixed_base_tables<B: BackendFixedBaseExt>() {
    use crate::backend::FixedBase;
    // A generator computed directly, so that this test needs no SHAKE128
    // and can run under Miri.
    let h1 = B::hash_to_curve(&[b"GenH1"], &[hash::DST_HASH_TO_GROUP]).unwrap();
    let table = B::FixedBase::new(h1.clone());
    assert_eq!(table.point(), &h1);
    let mut scalars = alloc::vec![
        B::Scalar::default(),
        B::Scalar::from(1),
        B::Scalar::from(2),
        B::Scalar::from(15),
        B::Scalar::from(16),
        B::Scalar::from(u64::MAX),
        B::Scalar::from_bytes(&MINUS_ONE).unwrap(),
    ];
    // Interpretation under Miri is slow; a couple of hashed scalars suffice
    // there, since the fixed cases already cover every digit path.
    let hashed = if cfg!(miri) { 2 } else { 32 };
    for i in 0..hashed {
        scalars.push(B::hash_to_scalar_with_dst(&[&[i]], &[b"fixed-base-test"]));
    }
    for scalar in scalars {
        assert_eq!(
            table.mul(&scalar),
            h1.mul(&scalar),
            "{:?}",
            scalar.to_bytes()
        );
    }
}

fn derivations<B: Backend>() {
    for dst in [hash::DST_HASH_TO_GROUP, hash::DST_HASH_TO_SCALAR] {
        assert!(dst.ends_with(crate::PROTOCOL_CONTEXT));
    }
    let rand = [1u8; 48];
    let a = B::derive_scalars(PROTOCOL_CONTEXT, &rand, b"a", 3).unwrap();
    let b = B::derive_scalars(PROTOCOL_CONTEXT, &rand, b"b", 3).unwrap();
    assert_eq!(a.len(), 3);
    for (x, y) in a.iter().zip(b.iter()) {
        assert_ne!(x.to_bytes(), y.to_bytes());
        assert!(!bool::from(x.is_zero()));
    }
    // A change to any part of the input changes every derived scalar.
    let mut changed = rand;
    changed[47] ^= 1;
    let c = B::derive_scalars(PROTOCOL_CONTEXT, &changed, b"a", 3).unwrap();
    for (x, y) in a.iter().zip(c.iter()) {
        assert_ne!(x.to_bytes(), y.to_bytes());
    }
    let long = [1u8; 49];
    for wrong in [&long[..0], &long[..47], &long[..49]] {
        assert_eq!(
            B::derive_scalars(PROTOCOL_CONTEXT, wrong, b"a", 1).unwrap_err(),
            HashError::InvalidInput
        );
        assert_eq!(
            B::derive_nonces(PROTOCOL_CONTEXT, b"secret", b"e", &[b"x"], wrong, 1).unwrap_err(),
            HashError::InvalidInput
        );
    }
    assert_eq!(
        B::derive_scalars(PROTOCOL_CONTEXT, &rand, &[0u8; 65536], 1).unwrap_err(),
        HashError::InvalidInput
    );
    let seed = [1u8; 48];
    let nonce = B::derive_nonces(
        PROTOCOL_CONTEXT,
        b"secret",
        b"e",
        &[b"inst", b"ance"],
        &seed,
        2,
    )
    .unwrap();
    let joined =
        B::derive_nonces(PROTOCOL_CONTEXT, b"secret", b"e", &[b"instance"], &seed, 2).unwrap();
    assert_eq!(nonce[1].to_bytes(), joined[1].to_bytes());
    let other = B::derive_nonces(
        PROTOCOL_CONTEXT,
        b"secret",
        b"e",
        &[b"instance"],
        &[2u8; 48],
        2,
    )
    .unwrap();
    for (x, y) in nonce.iter().zip(other.iter()) {
        assert_ne!(x.to_bytes(), y.to_bytes());
    }
    let key = B::derive_key_scalar(PROTOCOL_CONTEXT, &seed, b"GenerateKeyPair").unwrap();
    assert!(!bool::from(key.is_zero()));
    assert_ne!(key.to_bytes(), a[0].to_bytes());
    // Little- and big-endian reductions agree with the scalar arithmetic.
    let mut bytes = [0u8; 48];
    bytes[47] = 5;
    assert_eq!(B::reduce_be_48(&bytes).to_bytes(), coefficient(5));
    bytes[47] = 0;
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
    assert_eq!(B::reduce_be_48(&all).to_bytes(), expected.to_bytes());
    assert_eq!(
        hash::reduce_le_48::<B>(&all).to_bytes(),
        expected.to_bytes()
    );
    let _: Vec<u8> = Vec::new();
}

backend_tests!(
    expand_message_xmd_vectors,
    hash_to_curve_vectors,
    coefficients,
    scalar_arithmetic,
    point_arithmetic,
    fixed_base_tables,
    derivations,
);

/// With both backends enabled, every public output must agree.
#[cfg(all(feature = "rustcrypto", feature = "boringssl"))]
mod parity {
    use crate::backend::boringssl::BoringSsl;
    use crate::backend::rustcrypto::RustCrypto;
    use crate::backend::{Point, Scalar};
    use ec_ihat::hash::BackendHashExt;

    #[test]
    fn generators_and_hashes_agree() {
        let rc = crate::Params::<RustCrypto>::new(8).unwrap();
        let bssl = crate::Params::<BoringSsl>::new(8).unwrap();
        let a = super::super::protocol::generators(&rc);
        let b = super::super::protocol::generators(&bssl);
        for (a, b) in a.iter().zip(&b) {
            assert_eq!(a.to_bytes(), b.to_bytes());
        }
        for msg in [&b""[..], b"ctx", &[7u8; 300]] {
            assert_eq!(
                RustCrypto::hash_to_scalar_with_dst(&[msg], &[b"dst"]).to_bytes(),
                BoringSsl::hash_to_scalar_with_dst(&[msg], &[b"dst"]).to_bytes()
            );
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
