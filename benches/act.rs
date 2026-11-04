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

//! Benchmarks of every algorithm, per backend and balance width.
//!
//! Run with `cargo bench` for the RustCrypto backend, or with
//! `--features boringssl` and the `bssl-sys` patch described in the README
//! for BoringSSL; both features together benchmark both.

use std::time::Duration;

use act::backend::BackendFixedBaseExt;
use act::{
    ClientIssuanceState, ClientSpendState, Credential, Params, SecretKey, SpendMessage,
    finalize_issue, finalize_refund, issue_refund, issue_request, issue_response, prove_spend,
    verify_issue_request, verify_spend,
};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

const CTX_CRED: &[u8] = b"benchmark-context";
const CTX_SPEND: &[u8] = b"benchmark-challenge-digest";

/// The balance every benchmark starts from: one top-up below the maximum.
fn balance<B: BackendFixedBaseExt>(params: &Params<B>) -> u64 {
    params.max_amount() - 1
}

/// The four spend shapes as `(name, s, a, t)` for that balance.
fn shapes<B: BackendFixedBaseExt>(params: &Params<B>) -> [(&'static str, u64, u64, u64); 4] {
    let half = balance(params) / 2;
    [
        ("spend", half, 0, half / 2),
        ("refresh", 0, 0, 0),
        ("top_up", 0, 1, 1),
        ("spend_top_up", half, 1, half),
    ]
}

fn bench_backend<B: BackendFixedBaseExt>(c: &mut Criterion, backend: &str) {
    for l in [8u8, 16, 64] {
        let params = Params::<B>::new(l).unwrap();
        let key = SecretKey::<B>::from_seed(&B::generate_seed().unwrap()).unwrap();
        let public_key = key.public_key();
        let mut group = c.benchmark_group(format!("{backend}/L{l}"));
        group
            .measurement_time(Duration::from_secs(3))
            .sample_size(20);

        group.bench_function("params_new", |b| b.iter(|| Params::<B>::new(l).unwrap()));

        group.bench_function("key_generation", |b| {
            b.iter(|| SecretKey::<B>::from_seed(&B::generate_seed().unwrap()).unwrap())
        });
        group.bench_function("issue_request", |b| {
            b.iter(|| issue_request(&params).unwrap())
        });
        let (state, request) = issue_request(&params).unwrap();
        let balance = balance(&params);
        group.bench_function("issue_response", |b| {
            b.iter(|| {
                issue_response(
                    &key,
                    CTX_CRED,
                    balance,
                    verify_issue_request(&params, &request).unwrap(),
                )
                .unwrap()
            })
        });
        let response = issue_response(
            &key,
            CTX_CRED,
            balance,
            verify_issue_request(&params, &request).unwrap(),
        )
        .unwrap();
        let state_bytes = state.to_bytes();
        group.bench_function("finalize_issue", |b| {
            b.iter_batched(
                || ClientIssuanceState::<B>::from_bytes(&params, &state_bytes).unwrap(),
                |state| finalize_issue(&params, &public_key, CTX_CRED, state, &response).unwrap(),
                BatchSize::SmallInput,
            )
        });
        let credential = finalize_issue(&params, &public_key, CTX_CRED, state, &response).unwrap();
        let credential_bytes = credential.to_bytes();

        for (shape, s, a, t) in shapes(&params) {
            let fresh = || Credential::<B>::from_bytes(&params, &credential_bytes).unwrap();
            group.bench_with_input(BenchmarkId::new("prove_spend", shape), &shape, |b, _| {
                b.iter_batched(
                    fresh,
                    |credential| {
                        prove_spend(&params, credential, CTX_CRED, s, a, CTX_SPEND).unwrap()
                    },
                    BatchSize::SmallInput,
                )
            });
            group.bench_function(BenchmarkId::new("restore_prove_spend", shape), |b| {
                b.iter(|| prove_spend(&params, fresh(), CTX_CRED, s, a, CTX_SPEND).unwrap())
            });
            let (state, spend) = prove_spend(&params, fresh(), CTX_CRED, s, a, CTX_SPEND).unwrap();
            let spend_bytes = spend.to_bytes();
            group.bench_with_input(BenchmarkId::new("decode_spend", shape), &shape, |b, _| {
                b.iter(|| SpendMessage::<B>::from_bytes(&params, &spend_bytes).unwrap())
            });
            group.bench_with_input(BenchmarkId::new("verify_spend", shape), &shape, |b, _| {
                b.iter(|| verify_spend(&params, &key, CTX_CRED, CTX_SPEND, &spend).unwrap())
            });
            group.bench_with_input(BenchmarkId::new("issue_refund", shape), &shape, |b, _| {
                b.iter_batched(
                    || verify_spend(&params, &key, CTX_CRED, CTX_SPEND, &spend).unwrap(),
                    |verified| issue_refund(verified, t).unwrap(),
                    BatchSize::SmallInput,
                )
            });
            let verified = verify_spend(&params, &key, CTX_CRED, CTX_SPEND, &spend).unwrap();
            let refund = issue_refund(verified, t).unwrap();
            let state_bytes = state.to_bytes();
            group.bench_with_input(
                BenchmarkId::new("finalize_refund", shape),
                &shape,
                |b, _| {
                    b.iter_batched(
                        || ClientSpendState::<B>::from_bytes(&params, &state_bytes).unwrap(),
                        |state| {
                            finalize_refund(&params, &public_key, CTX_CRED, state, &refund).unwrap()
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
            group.bench_function(BenchmarkId::new("restore_finalize_refund", shape), |b| {
                b.iter(|| {
                    let state = ClientSpendState::<B>::from_bytes(&params, &state_bytes).unwrap();
                    finalize_refund(&params, &public_key, CTX_CRED, state, &refund).unwrap()
                })
            });
        }
        group.finish();
    }
}

fn benches(c: &mut Criterion) {
    #[cfg(feature = "rustcrypto")]
    bench_backend::<act::backend::rustcrypto::RustCrypto>(c, "rustcrypto");
    #[cfg(feature = "boringssl")]
    bench_backend::<act::backend::boringssl::BoringSsl>(c, "boringssl");
}

criterion_group!(act, benches);
criterion_main!(act);
