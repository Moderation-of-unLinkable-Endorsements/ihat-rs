//! Known answers and properties of the primitives beneath the protocol.

use alloc::vec::Vec;

use subtle::{Choice, ConditionallySelectable};

use crate::Error;
use crate::backend::{Backend, FIELD_MODULUS, ORDER, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::commitment::{
    Node, commit_val_at_place, depth, generate_vec_bind, hash_node, vec_commit, vec_equivocate,
};
use crate::hash::{self, BackendHashExt, XmdPrefix};
use crate::permutation::{
    is_valid_permutation_encoding, p, p_inv, permutation_pair, permute_bytes, select_bytes,
    unpermute_bytes,
};

const CTX: &[u8] = crate::PROTOCOL_CONTEXT;

#[test]
fn hash_errors_display_messages() {
    assert_eq!(
        alloc::format!("{}", hash::Error::InvalidInput),
        "input has an invalid length or count"
    );
    assert_eq!(
        alloc::format!("{}", hash::Error::Derive),
        "derivation failed to produce a usable scalar or group element"
    );
}

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

/// `ct_select` returns the entry at every index, and nothing out of range
/// or from a table that holds the identity.
fn point_selection<B: Backend>() {
    let g = B::Point::generator();
    let mut table: Vec<B::Point> = (1..=5)
        .map(|k| g.mul(&B::Scalar::from(k)))
        .chain([g.neg()])
        .collect();
    for (i, point) in table.iter().enumerate() {
        let selected = B::Point::ct_select(&table, i).into_option();
        assert_eq!(selected.as_ref(), Some(point), "index {i}");
    }
    assert!(bool::from(
        B::Point::ct_select(&table, table.len()).is_none()
    ));
    assert!(bool::from(
        B::Point::ct_select(core::iter::empty(), 0).is_none()
    ));

    table.insert(3, B::Point::identity());
    for i in 0..table.len() {
        let selected = B::Point::ct_select(&table, i);
        assert!(bool::from(selected.is_none()), "index {i}");
    }
}

/// Whether `x` is a coordinate, by attempting to decode a point with it.
fn decodes<B: Backend>(x: &[u8; SCALAR_LENGTH]) -> bool {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    bytes[1..].copy_from_slice(x);
    bool::from(B::Point::from_bytes(&bytes).is_some())
}

/// `x` as a big-endian field-sized integer.
fn small_x(x: u8) -> [u8; SCALAR_LENGTH] {
    let mut out = [0u8; SCALAR_LENGTH];
    out[SCALAR_LENGTH - 1] = x;
    out
}

/// `x + p`, for `x` below `2^256 - p`.
fn plus_modulus(x: &[u8; SCALAR_LENGTH]) -> [u8; SCALAR_LENGTH] {
    let mut out = *x;
    let mut carry = 0u16;
    for i in (0..SCALAR_LENGTH).rev() {
        let sum = u16::from(out[i]) + u16::from(FIELD_MODULUS[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    out
}

/// `p - k`, for `k` at most the low byte of the field modulus, `0xff`.
fn modulus_minus(k: u8) -> [u8; SCALAR_LENGTH] {
    let mut out = FIELD_MODULUS;
    out[SCALAR_LENGTH - 1] -= k;
    out
}

/// Known answers for the x-coordinate test, computed independently of
/// either backend (and checked against the draft's
/// `IsValidPermutationEncoding`). Unlike `x_coordinate_test`, these do not
/// consult point decoding, which for `p256` shares its code with the test.
fn x_coordinate_known_answers<B: Backend>() {
    let is_x = |x: &[u8; SCALAR_LENGTH]| bool::from(B::Point::is_x_coordinate(x));

    // `x^3 - 3x + b` is a square: the coordinates below 18, the largest
    // coordinate below p, and the generator's.
    let g = B::Point::generator().to_bytes().unwrap();
    let mut accepted: Vec<[u8; SCALAR_LENGTH]> = [0, 5, 6, 8, 9, 12, 13, 17].map(small_x).to_vec();
    accepted.push(modulus_minus(3));
    accepted.push(g[1..].try_into().unwrap());
    for x in &accepted {
        assert!(is_x(x), "{x:02x?} should be a coordinate");
    }

    // In range, but `x^3 - 3x + b` is not a square.
    let mut rejected: Vec<[u8; SCALAR_LENGTH]> =
        [1, 2, 3, 4, 7, 10, 11, 14, 15, 16].map(small_x).to_vec();
    rejected.extend([modulus_minus(1), modulus_minus(2)]);
    let mut half = [0u8; SCALAR_LENGTH];
    half[0] = 0x80;
    let mut order_minus_one = ORDER;
    order_minus_one[SCALAR_LENGTH - 1] -= 1;
    rejected.extend([half, ORDER, order_minus_one]);

    // Not below p, including `x + p` for coordinates `x`, which agree with
    // a coordinate modulo p and must not be reduced.
    let mut p_plus_one = FIELD_MODULUS;
    p_plus_one[20..].fill(0);
    p_plus_one[19] = 1;
    rejected.extend([FIELD_MODULUS, p_plus_one, [0xff; SCALAR_LENGTH]]);
    for x in [0, 5, 6, 8, 9] {
        rejected.push(plus_modulus(&small_x(x)));
    }
    for x in &rejected {
        assert!(!is_x(x), "{x:02x?} should not be a coordinate");
    }
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
    let small = small_x(5);
    assert!(decodes::<B>(&small));
    cases.push(small);
    cases.push(plus_modulus(&small));
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

/// `ORDER - k`, for `k` at most the low byte of the order, `0x51`.
fn order_minus(k: u8) -> [u8; SCALAR_LENGTH] {
    let mut out = ORDER;
    out[SCALAR_LENGTH - 1] -= k;
    out
}

/// Small values, values just below the order, and hashed values, on which
/// the arithmetic identities below are checked pairwise.
fn sample_scalars<B: Backend>() -> Vec<B::Scalar> {
    let mut scalars: Vec<B::Scalar> = [0, 1, 2, 3, u64::MAX]
        .into_iter()
        .map(B::Scalar::from)
        .collect();
    for k in [1, 2, 3] {
        scalars.push(B::Scalar::from_bytes(&order_minus(k)).unwrap());
    }
    for i in 0..8u64 {
        scalars.push(B::hash_to_scalar(CTX, &[b"sample", &i.to_be_bytes()]));
    }
    scalars
}

fn scalar_arithmetic<B: Backend>() {
    let bytes = |s: B::Scalar| s.to_bytes();
    let zero = B::Scalar::default();
    let one = B::Scalar::from(1);
    let max = B::Scalar::from_bytes(&order_minus(1)).unwrap();

    // Canonical encodings are exactly those below the order.
    for k in [1, 2, 0x51] {
        let encoding = order_minus(k);
        assert_eq!(
            B::Scalar::from_bytes(&encoding).unwrap().to_bytes(),
            encoding
        );
    }
    let mut above = ORDER;
    above[SCALAR_LENGTH - 1] += 1;
    for encoding in [ORDER, above, [0xff; SCALAR_LENGTH]] {
        assert!(bool::from(B::Scalar::from_bytes(&encoding).is_none()));
    }
    let mut expected = [0u8; SCALAR_LENGTH];
    expected[SCALAR_LENGTH - 8..].fill(0xff);
    assert_eq!(B::Scalar::from(u64::MAX).to_bytes(), expected);
    assert_eq!(bytes(zero), [0; SCALAR_LENGTH]);
    assert!(bool::from(zero.is_zero()) && !bool::from(one.is_zero()));

    // Reduction at the boundary of the order.
    assert_eq!(bytes(max + one), bytes(zero));
    assert_eq!(bytes(max + max), order_minus(2));
    assert_eq!(bytes(zero - one), bytes(max));
    assert_eq!(bytes(one - max), bytes(B::Scalar::from(2)));
    assert_eq!(bytes(-zero), bytes(zero));
    assert_eq!(bytes(-one), bytes(max));
    assert_eq!(bytes(max * max), bytes(one));
    assert_eq!(
        bytes(B::Scalar::from(u64::MAX) * B::Scalar::from(u64::MAX)),
        {
            // (2^64 - 1)^2 = 2^128 - 2^65 + 1, which is below the order.
            let mut square = [0u8; SCALAR_LENGTH];
            square[16..24].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
            square[31] = 1;
            square
        }
    );

    // Inversion.
    assert!(bool::from(zero.invert().is_none()));
    assert_eq!(bytes(one.invert().unwrap()), bytes(one));
    assert_eq!(bytes(max.invert().unwrap()), bytes(max));

    let scalars = sample_scalars::<B>();
    for &a in &scalars {
        assert_eq!(bytes(a + zero), bytes(a));
        assert_eq!(bytes(a * one), bytes(a));
        assert_eq!(bytes(a * zero), bytes(zero));
        assert_eq!(bytes(-a + a), bytes(zero));
        assert_eq!(bytes(-(-a)), bytes(a));
        assert_eq!(bytes(a * max), bytes(-a));
        if !bool::from(a.is_zero()) {
            let inverse = a.invert().unwrap();
            assert_eq!(bytes(a * inverse), bytes(one), "{a:?}");
            assert_eq!(bytes(inverse.invert().unwrap()), bytes(a));
        }
        for &b in &scalars {
            assert_eq!(bytes(a + b), bytes(b + a));
            assert_eq!(bytes(a * b), bytes(b * a));
            assert_eq!(bytes(a + b - b), bytes(a));
            assert_eq!(bytes(a - b), bytes(a + -b));
            assert_eq!(bytes(-(a - b)), bytes(b - a));
            for &c in &scalars[..6] {
                assert_eq!(bytes(a * (b + c)), bytes(a * b + a * c));
                assert_eq!(bytes((a * b) * c), bytes(a * (b * c)));
            }
        }
    }

    for choice in [0, 1] {
        let selected = B::Scalar::conditional_select(&one, &max, Choice::from(choice));
        assert_eq!(bytes(selected), bytes(if choice == 1 { max } else { one }));
    }
}

/// Scalar multiplication agrees with scalar arithmetic, and point addition
/// with doubling and the identity.
fn point_scalar_consistency<B: Backend>() {
    let g = B::Point::generator();
    let identity = B::Point::identity();
    let zero = B::Scalar::default();
    let max = B::Scalar::from_bytes(&order_minus(1)).unwrap();

    assert!(bool::from(B::Point::mul_generator(&zero).is_identity()));
    assert!(bool::from(g.mul(&zero).is_identity()));
    assert_eq!(B::Point::mul_generator(&max), g.neg());
    assert_eq!(identity.double(), identity);
    assert_eq!(identity.add(&identity), identity);
    assert!(identity.to_bytes().is_none());

    let scalars = sample_scalars::<B>();
    for &a in &scalars {
        let a_g = B::Point::mul_generator(&a);
        assert_eq!(a_g, g.mul(&a), "{a:?}");
        assert_eq!(identity.mul(&a), identity);
        assert_eq!(a_g.add(&identity), a_g);
        assert_eq!(identity.add(&a_g), a_g);
        // Equal operands take the doubling path of point addition.
        assert_eq!(a_g.add(&a_g), a_g.double());
        assert_eq!(a_g.double(), B::Point::mul_generator(&(a + a)));
        assert!(bool::from(a_g.sub(&a_g).is_identity()));
        assert_eq!(a_g.neg(), B::Point::mul_generator(&-a));
        if let Some(encoding) = a_g.to_bytes() {
            assert_eq!(B::Point::from_bytes(&encoding).unwrap(), a_g);
        } else {
            assert!(bool::from(a.is_zero()));
        }
        for &b in &scalars[..6] {
            let b_g = B::Point::mul_generator(&b);
            assert_eq!(a_g.add(&b_g), B::Point::mul_generator(&(a + b)));
            assert_eq!(a_g.sub(&b_g), B::Point::mul_generator(&(a - b)));
            assert_eq!(b_g.mul(&a), B::Point::mul_generator(&(a * b)));
            assert_eq!(
                B::Point::lincomb([(&a_g, &b), (&g, &a)]),
                B::Point::mul_generator(&(a * b + a))
            );
        }
    }
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
        let secret = B::hash_to_scalar(CTX, &[&i.to_be_bytes()]);
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
    let a = B::derive_scalars(CTX, &rand, b"a", 3).unwrap();
    let b = B::derive_scalars(CTX, &rand, b"b", 3).unwrap();
    assert_eq!(a.len(), 3);
    for (x, y) in a.iter().zip(b.iter()) {
        assert_ne!(x.to_bytes(), y.to_bytes());
    }
    // The protocol context separates derivations.
    let other = B::derive_scalars(b"ACTv1-P256-SHA256", &rand, b"a", 3).unwrap();
    assert_ne!(a[0].to_bytes(), other[0].to_bytes());
    let long = [1u8; 49];
    for wrong in [&long[..0], &long[..47], &long[..49]] {
        assert_eq!(
            B::derive_scalars(CTX, wrong, b"a", 1).unwrap_err(),
            hash::Error::InvalidInput
        );
        assert_eq!(
            B::derive_nonces(CTX, b"secret", b"e", &[b"x"], wrong, 1).unwrap_err(),
            hash::Error::InvalidInput
        );
    }
    let seed = [1u8; 48];
    let split = B::derive_nonces(CTX, b"secret", b"e", &[b"inst", b"ance"], &seed, 2).unwrap();
    let joined = B::derive_nonces(CTX, b"secret", b"e", &[b"instance"], &seed, 2).unwrap();
    assert_eq!(split[1].to_bytes(), joined[1].to_bytes());
    // A changed byte of the randomness changes every nonce.
    let mut changed = seed;
    changed[47] ^= 1;
    let others = B::derive_nonces(CTX, b"secret", b"e", &[b"instance"], &changed, 2).unwrap();
    for (x, y) in joined.iter().zip(others.iter()) {
        assert_ne!(x.to_bytes(), y.to_bytes());
    }
    let key = B::derive_key_scalar(CTX, &seed, b"GenerateKeyPair").unwrap();
    assert!(!bool::from(key.is_zero()));
    assert!(B::hash_to_group(CTX, &[b"x"]).is_ok());
}

/// Three leaves take two levels. A third key, trapdoor, or opening would
/// let the tree reach its root a level early, so each is rejected.
fn commitment_lengths<B: Backend>() {
    let index = 1;
    let trapdoors = [2, 3, 5].map(B::Scalar::from);
    let openings = [7, 11, 13].map(B::Scalar::from);
    let keys = generate_vec_bind::<B>(index, &trapdoors).unwrap();
    let leaves: Vec<Node> = (0..3).map(|i| [i; POINT_LENGTH]).collect();
    let invalid = Some(Error::InvalidInput);

    vec_commit::<B>(&leaves, &keys[..2], &openings[..2], Error::Derive).unwrap();
    for (keys, openings) in [(&keys[..], &openings[..]), (&keys[..2], &openings[..])] {
        assert_eq!(
            vec_commit::<B>(&leaves, keys, openings, Error::Derive).err(),
            invalid
        );
    }

    let first = commit_val_at_place::<B>(&keys[..2], 3, index, &leaves[1], &openings[..2]).unwrap();
    for (keys, openings) in [(&keys[..], &openings[..]), (&keys[..2], &openings[..])] {
        assert_eq!(
            commit_val_at_place::<B>(keys, 3, index, &leaves[1], openings).err(),
            invalid
        );
    }

    let new = || leaves.iter().map(|leaf| hash_node::<B>(leaf)).collect();
    vec_equivocate(
        &first,
        &keys[..2],
        &trapdoors[..2],
        &openings[..2],
        new(),
        index,
    )
    .unwrap();
    for (trapdoors, openings) in [
        (&trapdoors[..], &openings[..2]),
        (&trapdoors[..2], &openings[..]),
    ] {
        assert_eq!(
            vec_equivocate(&first, &keys[..2], trapdoors, openings, new(), index).err(),
            invalid
        );
    }
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
    point_selection,
    x_coordinate_test,
    x_coordinate_known_answers,
    scalar_arithmetic,
    point_scalar_consistency,
    permutation_properties,
    derivations,
    commitment_lengths,
);

/// With both backends enabled, every output must agree.
#[cfg(all(feature = "rustcrypto", feature = "boringssl"))]
mod parity {
    use alloc::vec::Vec;

    use crate::backend::boringssl::BoringSsl;
    use crate::backend::rustcrypto::RustCrypto;
    use crate::backend::{
        Backend, FIELD_MODULUS, ORDER, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar,
    };
    use crate::hash::{BackendHashExt, XmdPrefix};
    use crate::tests::{os_rng, random_key};
    use crate::{PublicKey, SecretKey};

    /// `count` pseudorandom strings of `N` bytes, the same on every run.
    fn strings<const N: usize>(label: &[u8], count: u16) -> Vec<[u8; N]> {
        (0..count)
            .map(|i| {
                let mut out = [0u8; N];
                XmdPrefix::<<RustCrypto as Backend>::Sha256>::new(&[]).expand_into(
                    &[&i.to_be_bytes()],
                    &[label],
                    &mut out,
                );
                out
            })
            .collect()
    }

    /// The outputs of every scalar and point operation on the given inputs,
    /// in order, as encodings; `None` where an operation has no result.
    fn transcript<B: Backend>(
        scalars: &[[u8; SCALAR_LENGTH]],
        coordinates: &[[u8; SCALAR_LENGTH]],
        points: &[[u8; POINT_LENGTH]],
    ) -> Vec<Option<Vec<u8>>> {
        let mut out = Vec::new();
        let scalar = |s: B::Scalar| Some(s.to_bytes().to_vec());
        let point = |p: B::Point| p.to_bytes().map(|b| b.to_vec());
        let decoded: Vec<Option<B::Scalar>> = scalars
            .iter()
            .map(|b| B::Scalar::from_bytes(b).into_option())
            .collect();
        out.extend(decoded.iter().map(|s| s.map(|s| s.to_bytes().to_vec())));
        let valid: Vec<B::Scalar> = decoded.into_iter().flatten().collect();
        for (&a, &b) in valid.iter().zip(valid.iter().cycle().skip(1)) {
            out.push(scalar(a + b));
            out.push(scalar(a - b));
            out.push(scalar(a * b));
            out.push(scalar(-a));
            out.push(a.invert().into_option().and_then(scalar));
            let a_g = B::Point::mul_generator(&a);
            let b_g = B::Point::mul_generator(&b);
            out.push(point(a_g.clone()));
            out.push(point(b_g.mul(&a)));
            out.push(point(a_g.add(&b_g)));
            out.push(point(a_g.sub(&b_g)));
            out.push(point(a_g.double()));
            out.push(point(a_g.neg()));
            out.push(point(B::Point::lincomb([(&a_g, &b), (&b_g, &a)])));
        }
        for x in coordinates {
            out.push(Some(alloc::vec![
                bool::from(B::Point::is_x_coordinate(x)).into()
            ]));
        }
        for p in points {
            out.push(B::Point::from_bytes(p).into_option().and_then(point));
        }
        out
    }

    /// Both backends compute the same scalar and point arithmetic, scalar
    /// and point decoding, and x-coordinate test, on random inputs and on
    /// values at the boundaries of the order and the field modulus.
    #[test]
    fn arithmetic_agrees() {
        let mut scalars = strings::<SCALAR_LENGTH>(b"scalar", 256);
        let mut one = [0u8; SCALAR_LENGTH];
        one[SCALAR_LENGTH - 1] = 1;
        let mut above = ORDER;
        above[SCALAR_LENGTH - 1] += 1;
        scalars.extend([
            [0; SCALAR_LENGTH],
            one,
            super::order_minus(1),
            super::order_minus(2),
            ORDER,
            above,
            [0xff; SCALAR_LENGTH],
        ]);
        // Random strings at or above the order are rare, so clear the top
        // bit of some and set every bit of the top 32 of others.
        for (i, s) in scalars.iter_mut().take(64).enumerate() {
            if i % 2 == 0 {
                s[0] &= 0x7f;
            } else {
                s[..4].fill(0xff);
            }
        }

        let mut coordinates = strings::<SCALAR_LENGTH>(b"coordinate", 256);
        let mut p_plus_one = FIELD_MODULUS;
        p_plus_one[20..].fill(0);
        p_plus_one[19] = 1;
        coordinates.extend([[0; SCALAR_LENGTH], one, FIELD_MODULUS, p_plus_one]);

        let mut points = strings::<POINT_LENGTH>(b"point", 256);
        for (i, p) in points.iter_mut().enumerate() {
            // Mostly compressed prefixes, with some of every other kind.
            if i % 8 != 0 {
                p[0] = 2 | (p[0] & 1);
            }
        }

        let rc = transcript::<RustCrypto>(&scalars, &coordinates, &points);
        let bssl = transcript::<BoringSsl>(&scalars, &coordinates, &points);
        assert_eq!(rc.len(), bssl.len());
        for (i, (x, y)) in rc.iter().zip(&bssl).enumerate() {
            assert_eq!(x, y, "output {i}");
        }
        // The inputs exercise both outcomes of every check.
        let some =
            |range: core::ops::Range<usize>| rc[range].iter().filter(|o| o.is_some()).count();
        let accepted = some(0..scalars.len());
        assert!(accepted > 0 && accepted < scalars.len());
        let decoded = some(rc.len() - points.len()..rc.len());
        assert!(decoded > 0 && decoded < points.len());
    }

    #[test]
    fn hashes_agree() {
        for msg in [&b""[..], b"ctx", &[7u8; 300]] {
            assert_eq!(
                RustCrypto::hash_to_scalar(super::CTX, &[msg]).to_bytes(),
                BoringSsl::hash_to_scalar(super::CTX, &[msg]).to_bytes()
            );
            assert_eq!(
                RustCrypto::hash_to_group(super::CTX, &[msg])
                    .unwrap()
                    .to_bytes(),
                BoringSsl::hash_to_group(super::CTX, &[msg])
                    .unwrap()
                    .to_bytes()
            );
        }
    }

    #[test]
    fn redemptions_interoperate() {
        let keys: [SecretKey<RustCrypto>; 3] =
            core::array::from_fn(|_| random_key(&mut os_rng::<RustCrypto>()));
        let anchor_rc: [PublicKey<RustCrypto>; 3] = core::array::from_fn(|i| keys[i].public_key());
        let anchor_bssl: [PublicKey<BoringSsl>; 3] =
            core::array::from_fn(|i| PublicKey::from_bytes(&anchor_rc[i].to_bytes()).unwrap());
        // The Anchor on RustCrypto, the Client on BoringSSL.
        let (state, commitment) = crate::commit::<RustCrypto>(b"iss").unwrap();
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
