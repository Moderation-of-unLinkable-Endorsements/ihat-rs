# mole-p256-rs

Rust implementations of the MOLE cryptographic primitives over NIST P-256,
as a Cargo workspace:

| Crate                         | Implements |
|-------------------------------|------------|
| [`ec-ihat`](crates/ec-ihat)   | EC-IHAT, the issuer-hiding anonymous token of [draft-authors-mole-ec-ihat](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-ec-ihat.html) |
| [`ec-act`](crates/ec-act)    | Anonymous Credit Tokens of [draft-schlesinger-mole-ec-act](https://datatracker.ietf.org/doc/draft-schlesinger-mole-ec-act/) |
| [`mole-p256`](crates/mole-p256) | The P-256 group, hashing, and randomness that both protocols build on, with RustCrypto and BoringSSL backends |

Each crate's README describes its API, backends, design, and tests.

> **Warning:** This code has not been audited. Use it at your own risk.

## Building and testing

```sh
cargo test --workspace                       # RustCrypto backend
scripts/build-boringssl.sh                   # see the crate READMEs
export BORINGSSL_BUILD_DIR=$PWD/boringssl/build
cargo test --workspace --no-default-features --features boringssl --config boringssl/cargo-config.toml
cargo test --workspace --features backend-parity --config boringssl/cargo-config.toml
```

Continuous integration (`.github/workflows/ci.yml`) runs on every change,
over the whole workspace: format, clippy with warnings denied, tests and docs
on both backends, the feature powerset, the libraries on the minimum Rust
version (1.87), 32-bit and wasm targets, unused-dependency and `cargo deny`
checks, and mutation testing of the lines the change touches. A weekly
workflow (`.github/workflows/nightly.yml`) runs Miri over the pure-Rust
primitives and coverage; on demand, it also runs mutation testing of whole
modules. `.cargo/mutants.toml` lists what mutation testing skips, and why.
