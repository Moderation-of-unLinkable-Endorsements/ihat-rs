//! Properties of the permutation and the commitment tree.

use alloc::vec::Vec;

use subtle::Choice;

use crate::Error;
use crate::backend::{Backend, POINT_LENGTH, Point};
use crate::commitment::{
    Node, commit_val_at_place, depth, generate_vec_bind, hash_node, vec_commit, vec_equivocate,
};
use crate::permutation::{
    is_valid_permutation_encoding, p, p_inv, permutation_pair, permute_bytes, select_bytes,
    unpermute_bytes,
};
use mole_p256::hash::BackendHashExt;

const CTX: &[u8] = crate::PROTOCOL_CONTEXT;

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

backend_tests!(permutation_properties, commitment_lengths);
