//! Protocol behavior: issuance and redemption end to end at every position
//! of small Anchor Sets, the checks of each algorithm, and the encodings.

use alloc::vec::Vec;

use super::{Replay, os_rng};
use crate::Error;
use crate::backend::{Backend, POINT_LENGTH, Point, SCALAR_LENGTH, Scalar};
use crate::protocol::{
    ChallengeMessage, CommitMessage, Endorsement, PublicKey, Redemption, ResponseMessage,
    SecretKey, Signature, challenge_with, commit_with, finalize, redeem_with, respond, verify,
    verify_redemption,
};

const CTX_ISS: &[u8] = b"issuance context";
const CTX_RED: &[u8] = b"redemption context";
const DIGEST: &[u8] = b"challenge digest";

fn keys<B: Backend>(n: usize) -> (Vec<SecretKey<B>>, Vec<PublicKey<B>>) {
    let secret: Vec<SecretKey<B>> = (0..n)
        .map(|_| SecretKey::generate_with(&mut os_rng::<B>()).unwrap())
        .collect();
    let public = secret.iter().map(SecretKey::public_key).collect();
    (secret, public)
}

fn issue<B: Backend>(key: &SecretKey<B>, ctx_iss: &[u8], ctx_red: &[u8]) -> Endorsement<B> {
    let public_key = key.public_key();
    let (state, commitment) = commit_with::<B, _>(ctx_iss, b"sid", &mut os_rng::<B>()).unwrap();
    let (client, challenge) = challenge_with(
        &public_key,
        ctx_iss,
        ctx_red,
        &commitment,
        &mut os_rng::<B>(),
    )
    .unwrap();
    let response = respond(key, state, &challenge).unwrap();
    finalize(&public_key, client, &response).unwrap()
}

fn redemption<B: Backend>(
    anchor_set: &[PublicKey<B>],
    index: usize,
    endorsement: Endorsement<B>,
) -> Redemption<B> {
    redeem_with(
        anchor_set,
        index,
        endorsement,
        CTX_ISS,
        CTX_RED,
        DIGEST,
        &mut os_rng::<B>(),
    )
    .unwrap()
}

fn check<B: Backend>(anchor_set: &[PublicKey<B>], redemption: &Redemption<B>) -> Result<(), Error> {
    verify_redemption(anchor_set, redemption, CTX_ISS, CTX_RED, DIGEST).map(|_| ())
}

fn issue_and_redeem_everywhere<B: Backend>() {
    for n in 1..=9 {
        let (secret, public) = keys::<B>(n);
        for index in 0..n {
            let endorsement = issue(&secret[index], CTX_ISS, CTX_RED);
            verify(&public[index], &endorsement, CTX_ISS, CTX_RED).unwrap();
            let nf = *endorsement.nullifier();
            let redemption = redemption(&public, index, endorsement);
            let encoded = redemption.to_bytes();
            assert_eq!(encoded.len(), Redemption::<B>::encoded_len(n));
            let decoded = Redemption::<B>::from_bytes(&encoded, n).unwrap();
            assert_eq!(decoded.to_bytes(), encoded);
            assert_eq!(
                verify_redemption(&public, &decoded, CTX_ISS, CTX_RED, DIGEST).unwrap(),
                nf
            );
            assert_eq!(decoded.nullifier(), &nf);
        }
    }
}

fn redemption_rejections<B: Backend>() {
    let (secret, public) = keys::<B>(5);
    let endorsement = issue(&secret[3], CTX_ISS, CTX_RED);
    let stored = endorsement.to_bytes();
    let good = redemption(&public, 3, endorsement);
    check(&public, &good).unwrap();

    let reject = |redemption: &Redemption<B>| {
        assert_eq!(check(&public, redemption).unwrap_err(), Error::Verify);
    };
    let one = B::Scalar::from(1);
    let mut bad = good.clone();
    bad.x_hat = bad.x_hat.add(&B::Point::generator());
    reject(&bad);
    for field in 0..5 {
        let mut bad = good.clone();
        match field {
            0 => bad.shown.c = bad.shown.c + one,
            1 => bad.shown.s = bad.shown.s + one,
            2 => bad.shown.y = bad.shown.y + one,
            3 => bad.shown.t = bad.shown.t + one,
            _ => bad.shown.nf[0] ^= 1,
        }
        reject(&bad);
    }
    let mut bad = good.clone();
    bad.proof_challenge = bad.proof_challenge + one;
    reject(&bad);
    let mut bad = good.clone();
    bad.response = bad.response + one;
    reject(&bad);
    for j in 0..good.commitment_keys.len() {
        let mut bad = good.clone();
        bad.commitment_keys[j] = bad.commitment_keys[j].add(&B::Point::generator());
        reject(&bad);
        let mut bad = good.clone();
        bad.openings[j] = bad.openings[j] + one;
        reject(&bad);
    }
    let mut bad = good.clone();
    bad.openings.pop();
    reject(&bad);

    // Other contexts, digests, and Anchor Sets.
    for (ctx_iss, ctx_red, digest) in [
        (b"other".as_slice(), CTX_RED, DIGEST),
        (CTX_ISS, b"other".as_slice(), DIGEST),
        (CTX_ISS, CTX_RED, b"other".as_slice()),
    ] {
        assert_eq!(
            verify_redemption(&public, &good, ctx_iss, ctx_red, digest).unwrap_err(),
            Error::Verify
        );
    }
    let mut reordered = public.clone();
    reordered.swap(0, 1);
    assert_eq!(check(&reordered, &good).unwrap_err(), Error::Verify);
    assert_eq!(check(&public[..4], &good).unwrap_err(), Error::Verify);
    let mut longer = public.clone();
    longer.push(public[0].clone());
    assert_eq!(check(&longer, &good).unwrap_err(), Error::Verify);
    assert_eq!(check(&public[..1], &good).unwrap_err(), Error::Verify);

    // A branch commitment equal to the identity is rejected: with X_hat in
    // the Anchor Set and a zero response, that branch's commitment is
    // `proof_challenge * (X_hat - X_hat)`.
    let mut with_x_hat = public.clone();
    with_x_hat[0] = PublicKey {
        pk: good.x_hat.clone(),
    };
    let mut bad = good.clone();
    bad.response = B::Scalar::default();
    assert_eq!(check(&with_x_hat, &bad).unwrap_err(), Error::Verify);

    // The wrong index gives a key the Endorsement does not verify under.
    let endorsement = Endorsement::<B>::from_bytes(&stored).unwrap();
    let wrong = redemption(&public, 2, endorsement);
    assert_eq!(check(&public, &wrong).unwrap_err(), Error::Verify);

    // A one-key redemption verifies only against that key, and decodes only
    // against an Anchor Set of depth zero.
    let endorsement = Endorsement::<B>::from_bytes(&stored).unwrap();
    let single = redemption(&public[3..4], 0, endorsement);
    assert!(single.commitment_keys.is_empty() && single.openings.is_empty());
    check(&public[3..4], &single).unwrap();
    assert_eq!(check(&public[2..3], &single).unwrap_err(), Error::Verify);
    assert_eq!(check(&public[2..4], &single).unwrap_err(), Error::Verify);
    assert!(Redemption::<B>::from_bytes(&single.to_bytes(), 2).is_err());

    // An empty Anchor Set, and indices outside the set.
    let endorsement = Endorsement::<B>::from_bytes(&stored).unwrap();
    let error = redeem_with(
        &[],
        0,
        endorsement,
        CTX_ISS,
        CTX_RED,
        DIGEST,
        &mut os_rng::<B>(),
    )
    .unwrap_err();
    assert_eq!(error, Error::InvalidInput);
    assert_eq!(check(&[], &single).unwrap_err(), Error::Verify);
    let endorsement = Endorsement::<B>::from_bytes(&stored).unwrap();
    let error = redeem_with(
        &public,
        5,
        endorsement,
        CTX_ISS,
        CTX_RED,
        DIGEST,
        &mut os_rng::<B>(),
    )
    .unwrap_err();
    assert_eq!(error, Error::InvalidInput);
}

fn redemption_is_deterministic<B: Backend>() {
    let (secret, public) = keys::<B>(3);
    let stored = issue(&secret[1], CTX_ISS, CTX_RED).to_bytes();
    let rand = [7u8; 2 * 48];
    let run = || {
        let endorsement = Endorsement::<B>::from_bytes(&stored).unwrap();
        let mut rng = Replay::new(&rand);
        let redemption =
            redeem_with(&public, 1, endorsement, CTX_ISS, CTX_RED, DIGEST, &mut rng).unwrap();
        rng.finish();
        redemption
    };
    let first = run();
    assert_eq!(first.to_bytes(), run().to_bytes());
    check(&public, &first).unwrap();
}

fn issuance_rejections<B: Backend>() {
    let (secret, public) = keys::<B>(2);
    let mut rng = os_rng::<B>();

    // A challenge for another session.
    let (state, commitment) = commit_with::<B, _>(CTX_ISS, b"one", &mut rng).unwrap();
    let (_, mut challenge) =
        challenge_with(&public[0], CTX_ISS, CTX_RED, &commitment, &mut rng).unwrap();
    challenge.session_id = b"two".to_vec();
    assert_eq!(
        respond(&secret[0], state, &challenge).unwrap_err(),
        Error::Session
    );

    // A zero challenge.
    let (state, _) = commit_with::<B, _>(CTX_ISS, b"one", &mut rng).unwrap();
    let zero = ChallengeMessage::<B> {
        session_id: b"one".to_vec(),
        challenge: B::Scalar::default(),
    };
    assert_eq!(
        respond(&secret[0], state, &zero).unwrap_err(),
        Error::Verify
    );

    // Responses that do not open the commitment or do not verify under
    // the key.
    let one = B::Scalar::from(1);
    for case in 0..5 {
        let (state, commitment) = commit_with::<B, _>(CTX_ISS, b"sid", &mut rng).unwrap();
        let ctx_iss = if case == 3 {
            b"other".as_slice()
        } else {
            CTX_ISS
        };
        let (client, challenge) =
            challenge_with(&public[0], ctx_iss, CTX_RED, &commitment, &mut rng).unwrap();
        let mut response = respond(&secret[0], state, &challenge).unwrap();
        let key = if case == 4 { &public[1] } else { &public[0] };
        match case {
            0 => response.s = response.s + one,
            1 => response.t = response.t + one,
            2 => response.y = B::Scalar::default(),
            _ => {}
        }
        assert_eq!(
            finalize(key, client, &response).unwrap_err(),
            Error::Verify,
            "{case}"
        );
    }

    // An Endorsement verifies only under its key and contexts.
    let endorsement = issue(&secret[0], CTX_ISS, CTX_RED);
    verify(&public[0], &endorsement, CTX_ISS, CTX_RED).unwrap();
    for (key, ctx_iss, ctx_red) in [
        (&public[1], CTX_ISS, CTX_RED),
        (&public[0], b"other".as_slice(), CTX_RED),
        (&public[0], CTX_ISS, b"other".as_slice()),
    ] {
        assert_eq!(
            verify(key, &endorsement, ctx_iss, ctx_red).unwrap_err(),
            Error::Verify
        );
    }
    let mut bad = Endorsement::<B>::from_bytes(&endorsement.to_bytes()).unwrap();
    bad.signature.c = B::Scalar::default();
    assert_eq!(
        verify(&public[0], &bad, CTX_ISS, CTX_RED).unwrap_err(),
        Error::Verify
    );

    // A key whose discrete logarithm `x` the Client knows, and `s = c * y *
    // x`, reconstruct `A` as the identity, which is rejected.
    let x = SecretKey::<B>::generate_with(&mut rng).unwrap();
    let (c, y) = (B::Scalar::from(3), B::Scalar::from(5));
    let x_scalar = B::Scalar::from_bytes(&x.to_bytes()).unwrap();
    let forged = Endorsement::<B> {
        signature: Signature {
            c,
            s: c * y * x_scalar,
            y,
            t: one,
            nf: [0; 32],
        },
    };
    assert_eq!(
        verify(&x.public_key(), &forged, CTX_ISS, CTX_RED).unwrap_err(),
        Error::Verify
    );
}

fn input_limits<B: Backend>() {
    let (secret, public) = keys::<B>(2);
    let mut rng = os_rng::<B>();
    let long = alloc::vec![0u8; 65536];
    assert_eq!(
        commit_with::<B, _>(&long, b"sid", &mut rng).unwrap_err(),
        Error::InvalidInput
    );
    let (_, commitment) = commit_with::<B, _>(CTX_ISS, b"sid", &mut rng).unwrap();
    assert_eq!(
        challenge_with(&public[0], &long, CTX_RED, &commitment, &mut rng).unwrap_err(),
        Error::InvalidInput
    );
    // `ctx_red` is bounded by the length prefix of the whole message.
    let max = 65535 - 32 - 4;
    challenge_with(&public[0], CTX_ISS, &long[..max], &commitment, &mut rng).unwrap();
    assert_eq!(
        challenge_with(&public[0], CTX_ISS, &long[..max + 1], &commitment, &mut rng).unwrap_err(),
        Error::InvalidInput
    );
    let endorsement = issue(&secret[0], CTX_ISS, CTX_RED);
    assert_eq!(
        redeem_with(&public, 0, endorsement, CTX_ISS, CTX_RED, &long, &mut rng).unwrap_err(),
        Error::InvalidInput
    );
}

fn keys_encode<B: Backend>() {
    let key = SecretKey::<B>::generate_with(&mut os_rng::<B>()).unwrap();
    let decoded = SecretKey::<B>::from_bytes(&key.to_bytes()).unwrap();
    assert_eq!(decoded.public_key(), key.public_key());
    assert_eq!(
        SecretKey::<B>::from_bytes(&[0; SCALAR_LENGTH]).unwrap_err(),
        Error::Deserialize
    );
    let public = key.public_key();
    assert_eq!(
        PublicKey::<B>::from_bytes(&public.to_bytes()).unwrap(),
        public
    );
    assert_eq!(
        PublicKey::<B>::from_bytes(&[0; POINT_LENGTH]).unwrap_err(),
        Error::Deserialize
    );
    let from_seed = SecretKey::<B>::from_seed(&[3; 48], b"info").unwrap();
    assert_eq!(
        from_seed.to_bytes(),
        SecretKey::<B>::from_seed(&[3; 48], b"info")
            .unwrap()
            .to_bytes()
    );
}

fn encodings<B: Backend>() {
    let (secret, public) = keys::<B>(3);
    let mut rng = os_rng::<B>();
    let session_id = [9u8; 64];
    let (state, commitment) = commit_with::<B, _>(CTX_ISS, &session_id, &mut rng).unwrap();
    let encoded = commitment.to_bytes();
    // A 64-byte identifier takes a two-byte length prefix.
    assert_eq!(&encoded[..2], &[0x40, 64]);
    assert_eq!(
        CommitMessage::<B>::from_bytes(&encoded).unwrap(),
        commitment
    );
    let (client, challenge) =
        challenge_with(&public[0], CTX_ISS, CTX_RED, &commitment, &mut rng).unwrap();
    assert_eq!(challenge.session_id(), session_id);
    let encoded = challenge.to_bytes();
    assert_eq!(
        ChallengeMessage::<B>::from_bytes(&encoded)
            .unwrap()
            .to_bytes(),
        encoded
    );
    let response = respond(&secret[0], state, &challenge).unwrap();
    let encoded = response.to_bytes();
    assert_eq!(encoded.len(), ResponseMessage::<B>::LENGTH);
    assert_eq!(
        ResponseMessage::<B>::from_bytes(&encoded)
            .unwrap()
            .to_bytes(),
        encoded
    );
    let endorsement = finalize(&public[0], client, &response).unwrap();
    let stored = endorsement.to_bytes();
    let decoded = Endorsement::<B>::from_bytes(&stored).unwrap();
    assert_eq!(decoded.to_bytes(), stored);

    // Truncation and trailing bytes.
    type Decodes = fn(&[u8]) -> bool;
    let messages: [(Vec<u8>, Decodes); 4] = [
        (commitment.to_bytes(), |b| {
            CommitMessage::<B>::from_bytes(b).is_ok()
        }),
        (challenge.to_bytes(), |b| {
            ChallengeMessage::<B>::from_bytes(b).is_ok()
        }),
        (response.to_bytes().to_vec(), |b| {
            ResponseMessage::<B>::from_bytes(b).is_ok()
        }),
        (stored.to_vec(), |b| Endorsement::<B>::from_bytes(b).is_ok()),
    ];
    for (bytes, decodes) in &messages {
        assert!(decodes(bytes));
        assert!(!decodes(&bytes[..bytes.len() - 1]));
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(!decodes(&longer));
    }

    // A length prefix that is not the shortest.
    let mut long_prefix = alloc::vec![0x40, 3];
    long_prefix.extend_from_slice(b"sid");
    long_prefix.extend_from_slice(&commitment.to_bytes()[2 + 64..]);
    assert_eq!(
        CommitMessage::<B>::from_bytes(&long_prefix).unwrap_err(),
        Error::Deserialize
    );
    let mut short_prefix = alloc::vec![3];
    short_prefix.extend_from_slice(&long_prefix[2..]);
    assert!(CommitMessage::<B>::from_bytes(&short_prefix).is_ok());

    // The identity and non-canonical scalars.
    let mut identity = short_prefix.clone();
    identity[4..4 + POINT_LENGTH].fill(0);
    assert_eq!(
        CommitMessage::<B>::from_bytes(&identity).unwrap_err(),
        Error::Deserialize
    );
    let mut above_order = response.to_bytes();
    above_order[..SCALAR_LENGTH].fill(0xff);
    assert_eq!(
        ResponseMessage::<B>::from_bytes(&above_order).unwrap_err(),
        Error::Deserialize
    );

    // A redemption decodes only against an Anchor Set of its depth.
    let redemption = redemption(&public, 0, endorsement);
    let encoded = redemption.to_bytes();
    for n in [3, 4] {
        assert_eq!(
            Redemption::<B>::from_bytes(&encoded, n).unwrap().to_bytes(),
            encoded
        );
    }
    for n in [0, 1, 2, 5, 9] {
        assert_eq!(
            Redemption::<B>::from_bytes(&encoded, n).unwrap_err(),
            Error::Deserialize,
            "{n}"
        );
    }
    assert!(Redemption::<B>::from_bytes(&encoded[..encoded.len() - 1], 3).is_err());
    let mut longer = encoded.clone();
    longer.push(0);
    assert!(Redemption::<B>::from_bytes(&longer, 3).is_err());
}

fn identity_public_keys_are_rejected<B: Backend>() {
    use zeroize::Zeroize;

    let (secret, _) = keys::<B>(1);
    let endorsement = issue(&secret[0], CTX_ISS, CTX_RED);
    // A zeroized key has the identity as its public key.
    let mut zeroized = SecretKey::<B>::generate_with(&mut os_rng::<B>()).unwrap();
    zeroized.zeroize();
    let identity = zeroized.public_key();
    let (state, commitment) = commit_with::<B, _>(CTX_ISS, b"sid", &mut os_rng::<B>()).unwrap();
    assert_eq!(
        challenge_with(&identity, CTX_ISS, CTX_RED, &commitment, &mut os_rng::<B>()).unwrap_err(),
        Error::Verify
    );
    let public_key = secret[0].public_key();
    let (client, challenge) = challenge_with(
        &public_key,
        CTX_ISS,
        CTX_RED,
        &commitment,
        &mut os_rng::<B>(),
    )
    .unwrap();
    let response = respond(&secret[0], state, &challenge).unwrap();
    assert_eq!(
        finalize(&identity, client, &response).unwrap_err(),
        Error::Verify
    );
    assert_eq!(
        verify(&identity, &endorsement, CTX_ISS, CTX_RED).unwrap_err(),
        Error::Verify
    );
}

fn only_compressed_prefixes_decode<B: Backend>() {
    let (_, public) = keys::<B>(1);
    let mut bytes = public[0].to_bytes();
    assert!(PublicKey::<B>::from_bytes(&bytes).is_ok());
    for prefix in [0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff] {
        bytes[0] = prefix;
        assert!(
            PublicKey::<B>::from_bytes(&bytes).is_err(),
            "prefix {prefix:#04x}"
        );
    }
}

backend_tests!(
    issue_and_redeem_everywhere,
    redemption_rejections,
    redemption_is_deterministic,
    issuance_rejections,
    input_limits,
    keys_encode,
    encodings,
    identity_public_keys_are_rejected,
    only_compressed_prefixes_decode,
);
