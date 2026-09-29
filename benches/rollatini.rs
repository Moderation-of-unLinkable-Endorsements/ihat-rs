//! Benchmarks of every algorithm, per backend, with redemption at several
//! Anchor Set sizes.
//!
//! Run with `cargo bench` for the RustCrypto backend, or with
//! `--features boringssl` and the `bssl-sys` patch described in the README
//! for BoringSSL; both features together benchmark both.

use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use rollatini::backend::Backend;
use rollatini::{
    Endorsement, PublicKey, Redemption, SecretKey, challenge, commit, finalize, redeem, respond,
    verify, verify_redemption,
};

const CTX_ISS: &[u8] = b"benchmark-issuance-context";
const CTX_RED: &[u8] = b"benchmark-redemption-context";
const DIGEST: &[u8] = b"benchmark-challenge-digest";

fn bench_backend<B: Backend>(c: &mut Criterion, backend: &str) {
    let key = SecretKey::<B>::generate().unwrap();
    let public_key = key.public_key();
    let mut group = c.benchmark_group(format!("{backend}/issuance"));
    group
        .measurement_time(Duration::from_secs(3))
        .sample_size(20);

    group.bench_function("key_generation", |b| {
        b.iter(|| SecretKey::<B>::generate().unwrap())
    });
    group.bench_function("commit", |b| {
        b.iter(|| commit::<B>(CTX_ISS, b"session").unwrap())
    });
    let (_, commitment) = commit::<B>(CTX_ISS, b"session").unwrap();
    group.bench_function("challenge", |b| {
        b.iter(|| challenge(&public_key, CTX_ISS, CTX_RED, &commitment).unwrap())
    });
    group.bench_function("respond", |b| {
        b.iter_batched(
            || {
                let (state, commitment) = commit::<B>(CTX_ISS, b"session").unwrap();
                let (_, message) = challenge(&public_key, CTX_ISS, CTX_RED, &commitment).unwrap();
                (state, message)
            },
            |(state, message)| respond(&key, state, &message).unwrap(),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("finalize", |b| {
        b.iter_batched(
            || {
                let (state, commitment) = commit::<B>(CTX_ISS, b"session").unwrap();
                let (client, message) =
                    challenge(&public_key, CTX_ISS, CTX_RED, &commitment).unwrap();
                (client, respond(&key, state, &message).unwrap())
            },
            |(client, response)| finalize(&public_key, client, &response).unwrap(),
            BatchSize::SmallInput,
        )
    });
    let (state, commitment) = commit::<B>(CTX_ISS, b"session").unwrap();
    let (client, message) = challenge(&public_key, CTX_ISS, CTX_RED, &commitment).unwrap();
    let response = respond(&key, state, &message).unwrap();
    let endorsement = finalize(&public_key, client, &response).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| verify(&public_key, &endorsement, CTX_ISS, CTX_RED).unwrap())
    });
    group.finish();
    let stored = endorsement.to_bytes();

    let mut group = c.benchmark_group(format!("{backend}/redemption"));
    group
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for n in [2usize, 8, 32, 128] {
        let mut anchor_set: Vec<PublicKey<B>> = (0..n - 1)
            .map(|_| SecretKey::<B>::generate().unwrap().public_key())
            .collect();
        let index = n / 2;
        anchor_set.insert(index, public_key.clone());
        let fresh = || Endorsement::<B>::from_bytes(&stored).unwrap();
        group.bench_with_input(BenchmarkId::new("redeem", n), &n, |b, _| {
            b.iter_batched(
                fresh,
                |endorsement| {
                    redeem(&anchor_set, index, endorsement, CTX_ISS, CTX_RED, DIGEST).unwrap()
                },
                BatchSize::SmallInput,
            )
        });
        let redemption = redeem(&anchor_set, index, fresh(), CTX_ISS, CTX_RED, DIGEST).unwrap();
        let encoded = redemption.to_bytes();
        group.bench_with_input(BenchmarkId::new("decode_redemption", n), &n, |b, _| {
            b.iter(|| Redemption::<B>::from_bytes(&encoded, n).unwrap())
        });
        group.bench_with_input(BenchmarkId::new("verify_redemption", n), &n, |b, _| {
            b.iter(|| {
                verify_redemption(&anchor_set, &redemption, CTX_ISS, CTX_RED, DIGEST).unwrap()
            })
        });
    }
    group.finish();
}

fn benches(c: &mut Criterion) {
    #[cfg(feature = "rustcrypto")]
    bench_backend::<rollatini::backend::rustcrypto::RustCrypto>(c, "rustcrypto");
    #[cfg(feature = "boringssl")]
    bench_backend::<rollatini::backend::boringssl::BoringSsl>(c, "boringssl");
}

criterion_group!(rollatini, benches);
criterion_main!(rollatini);
