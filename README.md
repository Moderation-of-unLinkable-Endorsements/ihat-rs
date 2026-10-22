# act-rs

A Rust implementation of **Anonymous Credit Tokens (ACT)**, the MOLE
Credential scheme of
[draft-authors-mole-act](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-act.html),
for the `P256-SHA256` ciphersuite.

An ACT is a keyed-verification anonymous credential whose hidden state is a
balance of credits. A Moderator issues a Credential with an initial balance;
the Client later spends a public amount, proving in zero knowledge that the
Credential covers it and has not been spent before, and receives a refund for
the remainder plus a Moderator-chosen return amount. The Moderator never learns
the balance and cannot link a spend to the issuance or refund that produced
the Credential, nor two spends to each other.

The implementation tracks the draft, whose scalar derivation is that of
draft-authors-mole-rollatini, and reproduces its test vectors byte for byte.

## Usage

```rust
use act::{Backend, DefaultBackend, Params, SecretKey};

let params: Params = Params::new(8)?;       // balances below 2^8
let ctx_cred = b"epoch-42";                 // agreed out of band

let secret_key_seed = DefaultBackend::generate_seed()?;
let secret_key: SecretKey = SecretKey::from_seed(&secret_key_seed)?;
let public_key = secret_key.public_key();   // published

// Issuance
let (state, request) = act::issue_request(&params)?;
let verified = act::verify_issue_request(&params, &request)?;
let response = act::issue_response(&secret_key, ctx_cred, 100, verified)?;
let credential = act::finalize_issue(&params, &public_key, ctx_cred, state, &response)?;

// Spending 30 credits with no top-up allowance; the Moderator returns 5.
let ctx_spend = b"challenge-digest";
let (state, spend) = act::prove_spend(&params, credential, ctx_cred, 30, 0, ctx_spend)?;
let verified = act::verify_spend(&params, &secret_key, ctx_cred, ctx_spend, &spend)?;
// Grant verified.allowance(), then atomically record verified.nullifier()
// together with the refund.
let refund = act::issue_refund(verified, 5)?;
let credential = act::finalize_refund(&params, &public_key, ctx_cred, state, &refund)?;
assert_eq!(credential.balance(), 75);
# Ok::<(), act::Error>(())
```

Every message, the Credential, and both Client states have `to_bytes` and
`from_bytes`; the message encodings are those of the draft, and the others
are storage encodings that match the draft's test-vector representation,
returned as `Zeroizing<Vec<u8>>` because they hold secrets.
`examples/demo.rs` runs the four spend shapes through the encodings.

## Backends

Most cryptographic operations go through IHAT's `Backend` trait, re-exported
by this crate, following the design of the ATHM crate that Chromium builds. Two
implementations are provided, selected by Cargo feature:

| Feature       | Curve, SHA-256, hash-to-curve, randomness | SHAKE128 |
|---------------|-------------------------------------------|----------|
| `rustcrypto` (default) | `p256`, `sha2`, `getrandom`      | `shake`  |
| `boringssl`   | BoringSSL through `bssl-sys`              | `shake` (see below) |

Both backends encode scalars as 32-byte big-endian integers and points as
compressed SEC1, reject the identity, and produce identical outputs; with
both features enabled, the test suite checks that they interoperate and that
`boringssl` is the `DefaultBackend`. Every type takes the backend as a type
parameter that defaults to it.

ACT uses SHAKE128 from the RustCrypto `shake` crate for both backends.
BoringSSL implements Keccak but does not export it through a public header,
so the `boringssl` configuration uses RustCrypto's implementation until
BoringSSL exposes it through a public header and the `bssl-sys` bindings.
The sponge only ever absorbs public data; see `src/sigma.rs` for its use.

### Building the BoringSSL backend

`bssl-sys` is not published on crates.io (the registry entry is a
placeholder), so it must be patched to a BoringSSL checkout built with Rust
bindings for the host. `scripts/build-boringssl.sh` does that at the commit
this crate is tested against (`5112448a`, September 2026; `bssl-sys` moves in
lockstep with BoringSSL) and writes a Cargo config with the patch:

```sh
cargo install bindgen-cli          # plus git, cmake, ninja, and clang
scripts/build-boringssl.sh         # clones and builds into ./boringssl

export BORINGSSL_BUILD_DIR=$PWD/boringssl/build
cargo test --features boringssl --config boringssl/cargo-config.toml
```

### Chromium

Chromium builds crates with GN rather than Cargo, listing sources and
features explicitly. The `boringssl` backend needs only `bssl_sys`, `subtle`,
`zeroize`, and `shake` (plus its `keccak` and `digest` dependencies). A
target along the lines of Chromium's ATHM rule:

```gn
rust_static_library("act") {
  crate_name = "act"
  crate_root = "src/lib.rs"
  sources = [ ... every file under src/ except src/backend/rustcrypto.rs ... ]
  edition = "2024"
  allow_unsafe = true  # bssl_sys FFI in src/backend/boringssl.rs, one volatile write elsewhere
  features = [ "boringssl" ]
  deps = [
    "//third_party/boringssl:bssl_sys",
    "//third_party/rust/shake/v0_1:lib",
    "//third_party/rust/subtle/v2:lib",
    "//third_party/rust/zeroize/v1:lib",
  ]
}
```

The crate is `no_std` with `alloc`; the `std` feature only enables the
precomputed generator tables of `p256`.

## Design

The proofs are compact NARG strings of `draft-irtf-cfrg-sigma-protocols-03`
under the Fiat-Shamir transform of `draft-irtf-cfrg-fiat-shamir-03`. Rather
than a generic sparse-relation engine, each of the three relations of the
draft is a fixed-shape statement (`src/statements.rs`) that writes its own
`SerializeLinearRelation` bytes and evaluates its own equations. The wire
format is unchanged; the specialization lets the code:

* merge terms on a shared base, so `sum_j w[j] s[j] * H3` is one
  multiplication;
* fold the verifier's `-challenge * Com[j]` into the term `Com[j]` already
  carries;
* compute `sum_j w[j] Com[j]` once and reuse it for the balance commitment;
* multiply the ciphersuite generators through fixed-base tables built once
  per `Params` (the `rustcrypto` backend; 72 KiB per generator, 288 KiB
  for the four), and
  evaluate the remaining terms as one multi-scalar multiplication where the
  backend offers it;
* cache the session identifiers of the fixed tags.

The identity checks that `ValidateInstance` requires of a verifier are made
explicitly in each statement's `validate`, with the check they implement
named alongside.

## Security

* Operations on the Client's balance and blinding factors, and on the
  Moderator's signing key, are constant time in those values; both backends
  use constant-time scalar and point arithmetic, and `Bits` selects with
  `subtle`. The exception is point addition in the BoringSSL backend: BoringSSL
  exports no complete constant-time addition, and `EC_POINT_add` branches
  when its operands are equal or negatives of each other. When a secret
  operand is random and independent of the other, the branch is taken with
  negligible probability.
* `prove_spend` consumes the Credential, and `finalize_issue` and
  `finalize_refund` consume their state, so no value is used twice within a
  process. Persisted copies are the wallet's responsibility.
* Secrets are zeroized on drop.
* Decoding rejects non-canonical scalars and points, the identity element,
  amounts at or above `2^L`, and spend messages whose shape does not match
  their amounts.
* `verify_issue_request` returns an opaque `VerifiedIssueRequest`, and
  `issue_response` only accepts this value, so a Moderator can check a request
  before committing other state and sign only afterwards.
* `verify_spend` returns an opaque, non-cloneable `VerifiedSpend` bound to the
  exact message, key, configuration, and contexts it checked. `issue_refund`
  only accepts this value, so it cannot sign a raw, unverified spend.
* The Moderator must grant the verified allowance, reject a repeated
  nullifier, and record the nullifier atomically with the refund; the crate
  leaves the store to the deployment.

## Performance

Criterion medians on an Apple M-series laptop, one core, `L = 8` and
`L = 64`, for an ordinary spend (`s > 0`, `a = 0`); a spend with a top-up
roughly doubles the spend and verify times, and a refresh (`s = a = 0`)
is independent of `L`.

| Operation           | BoringSSL, L = 8 | RustCrypto, L = 8 | BoringSSL, L = 64 | RustCrypto, L = 64 |
|---------------------|-----------------:|------------------:|------------------:|-------------------:|
| `issue_request`     |           104 µs |            108 µs |            105 µs |             108 µs |
| `issue_response`    |           199 µs |            429 µs |            202 µs |             423 µs |
| `finalize_issue`    |           133 µs |            305 µs |            135 µs |             304 µs |
| `prove_spend`       |          1.78 ms |           2.59 ms |           10.2 ms |            14.6 ms |
| `verify_spend`      |          1.38 ms |           2.62 ms |            8.1 ms |            16.6 ms |
| `issue_refund`      |           124 µs |            277 µs |            137 µs |             316 µs |
| `finalize_refund`   |           133 µs |            293 µs |            135 µs |             304 µs |
| `prove_spend` (refresh) | 640 µs       |            935 µs |            643 µs |             970 µs |

Relative to the same code without the fixed-base tables, the RustCrypto
prover is about 1.6x faster, issuance requests 2.2x, refunds 1.25x, and
verification 5 to 13 percent; BoringSSL, whose public API exposes tables
only for the generator, is unchanged. Building a `Params` costs about
1.5 ms on RustCrypto for the four tables (288 KiB of heap per `Params`), and
40 µs on BoringSSL, which builds no tables.

The BoringSSL profile at `L = 8` is roughly half scalar multiplications,
a fifth point compression for the transcript, and the rest scalar field
operations and nonce derivation. A constant-time multi-scalar
multiplication would be the next lever there, but BoringSSL does not
export one.

## Testing

```sh
cargo test                                   # RustCrypto
cargo test --features boringssl ...          # BoringSSL, see above
cargo test --features rustcrypto,boringssl   # both, plus interoperability
cargo bench                                  # criterion, per backend and L
```

`tests/vectors/draft-L4.txt` is the draft's test-vector appendix; the other
files there were generated from the draft's Python reference implementation
at `L` = 1, 2, 8, 16, and 64, covering every spend shape and the `uint64`
boundary (`tests/vectors/generate.py` records how). Every `rand` entry is
replayed in place of the random number generator, so every key, message,
state, and Credential must match byte for byte. Further tests cover
tampering, misdirected messages, amount and shape bounds, the identity checks
of every statement, and RFC 9380 known answers for the primitives.

Continuous integration (`.github/workflows/ci.yml`) runs on every change:
format, clippy with warnings denied, tests and docs on both backends, the
feature powerset, the library on the minimum Rust version (1.85), 32-bit and
wasm targets, unused-dependency and `cargo deny` checks, and mutation testing
of the lines the change touches. A weekly workflow
(`.github/workflows/nightly.yml`) runs Miri over the pure-Rust primitives and
coverage; on demand, it also runs mutation testing of the proof and encoding
modules. `.cargo/mutants.toml` lists what mutation testing skips, and why.

## License

Apache License 2.0; see [LICENSE](LICENSE).

## Disclaimer

This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).
