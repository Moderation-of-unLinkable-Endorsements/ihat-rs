//! Known answers and properties of the primitives beneath the protocol.

use subtle::Choice;

use crate::backend::{Backend, FIELD_MODULUS, Point, SCALAR_LENGTH, Scalar};
use crate::commitment::depth;
use crate::hash::{self, XmdPrefix};
use crate::permutation::{
    is_valid_permutation_encoding, p, p_inv, permutation_pair, permute_bytes, select_bytes,
    unpermute_bytes,
};

const CTX: &[u8] = crate::PROTOCOL_CONTEXT;

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
        // Neither the prefix split nor the tag split changes the output.
        if !msg.is_empty() {
            XmdPrefix::<B::Sha256>::new(&[&msg[..1]]).expand_into(
                &[&msg[1..]],
                &[&DST[..5], &DST[5..]],
                &mut out,
            );
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
    }
}

fn point_arithmetic<B: Backend>() {
    let g = B::Point::generator();
    let three = B::Scalar::from(3);
    assert_eq!(g.neg().add(&g), B::Point::identity());
    assert_eq!(g.mul(&three).sub(&g), g.double());
    assert_eq!(g.neg(), g.mul(&-B::Scalar::from(1)));
    assert_eq!(B::Point::identity().neg(), B::Point::identity());
    assert_eq!(
        hex::encode(g.to_bytes().unwrap()),
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    );
    assert_eq!(
        hex::encode(g.neg().to_bytes().unwrap()),
        "026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    );
    assert!(bool::from(B::Point::from_bytes(&[0; 33]).is_none()));
    let mut zeroized = g.clone();
    zeroized.zeroize();
    assert!(bool::from(zeroized.is_identity()));
}

/// Whether `x` is a coordinate, by attempting to decode a point with it.
fn decodes<B: Backend>(x: &[u8; SCALAR_LENGTH]) -> bool {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    bytes[1..].copy_from_slice(x);
    bool::from(B::Point::from_bytes(&bytes).is_some())
}

/// The x-coordinate test agrees with point decoding, including at and
/// beyond the field modulus.
fn x_coordinate_test<B: Backend>() {
    let mut cases: alloc::vec::Vec<[u8; SCALAR_LENGTH]> = alloc::vec![
        [0; SCALAR_LENGTH],
        [0xff; SCALAR_LENGTH],
        FIELD_MODULUS,
        crate::backend::ORDER,
    ];
    let mut below = FIELD_MODULUS;
    below[SCALAR_LENGTH - 1] -= 1;
    cases.push(below);
    // p + 1: the low 96 bits of p are all ones.
    let mut above = FIELD_MODULUS;
    above[20..].fill(0);
    above[19] = 1;
    cases.push(above);
    // x and x + p, where x is a coordinate below 2^256 - p.
    let mut small = [0u8; SCALAR_LENGTH];
    small[SCALAR_LENGTH - 1] = 3;
    let mut wrapped = small;
    let mut carry = 0u16;
    for i in (0..SCALAR_LENGTH).rev() {
        let sum = u16::from(wrapped[i]) + u16::from(FIELD_MODULUS[i]) + carry;
        wrapped[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    cases.push(small);
    cases.push(wrapped);
    let mut one = [0; SCALAR_LENGTH];
    one[SCALAR_LENGTH - 1] = 1;
    cases.push(one);
    for i in 0..200u16 {
        let mut x = [0u8; SCALAR_LENGTH];
        XmdPrefix::<B::Sha256>::new(&[]).expand_into(&[&i.to_be_bytes()], &[b"x"], &mut x);
        cases.push(x);
    }
    let mut valid = 0;
    for x in &cases {
        let expected = decodes::<B>(x);
        assert_eq!(bool::from(B::Point::is_x_coordinate(x)), expected, "{x:?}");
        valid += usize::from(expected);
    }
    // About half of the random strings are coordinates.
    assert!(valid > 60 && valid < 150, "{valid}");
    // A point's own coordinate is one.
    let g = B::Point::generator().to_bytes().unwrap();
    assert!(bool::from(B::Point::is_x_coordinate(
        g[1..].try_into().unwrap()
    )));
}

fn permutation_properties<B: Backend>() {
    let mut buf = [0u8; 33];
    buf[0] = 1;
    buf[5] = 7;
    let original = buf;
    permute_bytes::<B>(&mut buf);
    assert_ne!(buf, original);
    assert!(buf[0] <= 1);
    unpermute_bytes::<B>(&mut buf);
    assert_eq!(buf, original);

    assert_eq!(select_bytes(&[1; 33], &[2; 33], Choice::from(0)), [1; 33]);
    assert_eq!(select_bytes(&[1; 33], &[2; 33], Choice::from(1)), [2; 33]);

    let g = B::Point::generator().to_bytes().unwrap();
    let mut encoding = g;
    encoding[0] -= 2;
    assert!(bool::from(is_valid_permutation_encoding::<B>(&encoding)));
    encoding[0] = 2;
    assert!(!bool::from(is_valid_permutation_encoding::<B>(&encoding)));

    for i in 0..8u64 {
        let secret = hash::hash_to_scalar::<B>(CTX, &[&i.to_be_bytes()]);
        let t = B::Point::mul_generator(&secret);
        assert_eq!(p_inv::<B>(&p::<B>(&t).unwrap()).unwrap(), t);
        assert_eq!(p::<B>(&p_inv::<B>(&t).unwrap()).unwrap(), t);
        // Binding left walks backwards from T = P(Q); binding right walks
        // forwards from T = Q.
        let (q, pq) = permutation_pair::<B>(&t, Choice::from(1)).unwrap();
        assert_eq!(pq, t);
        assert_eq!(p::<B>(&q).unwrap(), t);
        let (q, pq) = permutation_pair::<B>(&t, Choice::from(0)).unwrap();
        assert_eq!(q, t);
        assert_eq!(pq, p::<B>(&t).unwrap());
    }
    assert!(p::<B>(&B::Point::identity()).is_err());
}

fn derivations<B: Backend>() {
    let rand = [1u8; 48];
    let a = hash::derive_scalars::<B>(CTX, &rand, b"a", 3).unwrap();
    let b = hash::derive_scalars::<B>(CTX, &rand, b"b", 3).unwrap();
    assert_eq!(a.len(), 3);
    for (x, y) in a.iter().zip(b.iter()) {
        assert_ne!(x.to_bytes(), y.to_bytes());
    }
    // The protocol context separates derivations.
    let other = hash::derive_scalars::<B>(b"ACTv1-P256-SHA256", &rand, b"a", 3).unwrap();
    assert_ne!(a[0].to_bytes(), other[0].to_bytes());
    let long = [1u8; 49];
    for wrong in [&long[..0], &long[..47], &long[..49]] {
        assert_eq!(
            hash::derive_scalars::<B>(CTX, wrong, b"a", 1).unwrap_err(),
            crate::Error::InvalidInput
        );
        assert_eq!(
            hash::derive_nonces::<B>(CTX, b"secret", b"e", &[b"x"], wrong, 1).unwrap_err(),
            crate::Error::InvalidInput
        );
    }
    let seed = [1u8; 48];
    let split =
        hash::derive_nonces::<B>(CTX, b"secret", b"e", &[b"inst", b"ance"], &seed, 2).unwrap();
    let joined = hash::derive_nonces::<B>(CTX, b"secret", b"e", &[b"instance"], &seed, 2).unwrap();
    assert_eq!(split[1].to_bytes(), joined[1].to_bytes());
    // A changed byte of the randomness changes every nonce.
    let mut changed = seed;
    changed[47] ^= 1;
    let others =
        hash::derive_nonces::<B>(CTX, b"secret", b"e", &[b"instance"], &changed, 2).unwrap();
    for (x, y) in joined.iter().zip(others.iter()) {
        assert_ne!(x.to_bytes(), y.to_bytes());
    }
    let key = hash::derive_key_scalar::<B>(CTX, &seed, b"GenerateKeyPair").unwrap();
    assert!(!bool::from(key.is_zero()));
    assert!(hash::hash_to_group::<B>(CTX, &[b"x"]).is_ok());
}

#[test]
fn depths() {
    let expected = [
        (0, 0),
        (1, 0),
        (2, 1),
        (3, 2),
        (4, 2),
        (5, 3),
        (8, 3),
        (9, 4),
    ];
    for (n, q) in expected {
        assert_eq!(depth(n), q, "{n}");
    }
    assert_eq!(depth(65535), 16);
    assert_eq!(depth(usize::MAX), usize::BITS as usize);
}

backend_tests!(
    expand_message_xmd_vectors,
    hash_to_curve_vectors,
    point_arithmetic,
    x_coordinate_test,
    permutation_properties,
    derivations,
);

/// With both backends enabled, every output must agree.
#[cfg(all(feature = "rustcrypto", feature = "boringssl"))]
mod parity {
    use crate::backend::boringssl::BoringSsl;
    use crate::backend::rustcrypto::RustCrypto;
    use crate::backend::{Point, Scalar};
    use crate::{PublicKey, SecretKey};

    #[test]
    fn hashes_agree() {
        for msg in [&b""[..], b"ctx", &[7u8; 300]] {
            assert_eq!(
                crate::hash::hash_to_scalar::<RustCrypto>(super::CTX, &[msg]).to_bytes(),
                crate::hash::hash_to_scalar::<BoringSsl>(super::CTX, &[msg]).to_bytes()
            );
            assert_eq!(
                crate::hash::hash_to_group::<RustCrypto>(super::CTX, &[msg])
                    .unwrap()
                    .to_bytes(),
                crate::hash::hash_to_group::<BoringSsl>(super::CTX, &[msg])
                    .unwrap()
                    .to_bytes()
            );
        }
    }

    #[test]
    fn redemptions_interoperate() {
        let keys: [SecretKey<RustCrypto>; 3] =
            core::array::from_fn(|_| SecretKey::generate().unwrap());
        let anchor_rc: [PublicKey<RustCrypto>; 3] = core::array::from_fn(|i| keys[i].public_key());
        let anchor_bssl: [PublicKey<BoringSsl>; 3] =
            core::array::from_fn(|i| PublicKey::from_bytes(&anchor_rc[i].to_bytes()).unwrap());
        // The Anchor on RustCrypto, the Client on BoringSSL.
        let (state, commitment) = crate::commit::<RustCrypto>(b"iss", b"sid").unwrap();
        let commitment =
            crate::CommitMessage::<BoringSsl>::from_bytes(&commitment.to_bytes()).unwrap();
        let (client, challenge) =
            crate::challenge(&anchor_bssl[2], b"iss", b"red", &commitment).unwrap();
        let challenge =
            crate::ChallengeMessage::<RustCrypto>::from_bytes(&challenge.to_bytes()).unwrap();
        let response = crate::respond(&keys[2], state, &challenge).unwrap();
        let response =
            crate::ResponseMessage::<BoringSsl>::from_bytes(&response.to_bytes()).unwrap();
        let endorsement = crate::finalize(&anchor_bssl[2], client, &response).unwrap();
        let redemption =
            crate::redeem(&anchor_bssl, 2, endorsement, b"iss", b"red", b"digest").unwrap();
        // The Moderator on RustCrypto.
        let redemption =
            crate::Redemption::<RustCrypto>::from_bytes(&redemption.to_bytes(), 3).unwrap();
        crate::verify_redemption(&anchor_rc, &redemption, b"iss", b"red", b"digest").unwrap();
    }
}
