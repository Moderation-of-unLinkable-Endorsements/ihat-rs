# mole-p256-rs

Rust implementations of the MOLE cryptographic primitives over NIST P-256,
as a Cargo workspace:

| Crate                         | Implements |
|-------------------------------|------------|
| [`ec-ihat`](crates/ec-ihat)   | EC-IHAT, the issuer-hiding anonymous token of [draft-authors-mole-ec-ihat](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-ec-ihat.html) |

Each crate's README describes its API, backends, design, and tests.

> **Warning:** This code has not been audited. Use it at your own risk.

## Building and testing

```sh
cargo test --workspace                       # RustCrypto backend
scripts/build-boringssl.sh                   # see the crate READMEs
export BORINGSSL_BUILD_DIR=$PWD/boringssl/build
cargo test --workspace --features rustcrypto,boringssl --config boringssl/cargo-config.toml
```

Continuous integration (`.github/workflows/ci.yml`) runs every check over
the whole workspace; `.github/workflows/nightly.yml` runs the slower ones.
