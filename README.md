# rollatini-rs

A Rust implementation of **Rollatini**, the issuer-hiding anonymous token of
[draft-authors-mole-rollatini](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-rollatini.html),
for the `P256-SHA256` ciphersuite.

An Anchor issues an Endorsement to a Client in a three-move partially blind
signature: the Anchor learns neither the Endorsement nor the redemption
context bound into it. The Client later redeems the Endorsement at a
Moderator that accepts a list of Anchors, its Anchor Set. The redemption shows
the signature under a rerandomized key and proves, in size logarithmic in the
Anchor Set, that the key is a shift of one of the Anchor Set's keys. The
Moderator learns the Endorsement's nullifier, which it uses to reject a second
redemption, and nothing about which Anchor issued it.

The implementation tracks the draft at commit
[`e4690fc`](https://github.com/Moderation-of-unLinkable-Endorsements/internet-drafts/commit/e4690fcbb192b39a94664268917b5335aaf89779)
of the drafts repository and reproduces its test vectors byte for byte.

> **Warning:** This code has not been audited. Use it at your own risk.

## Usage

```rust
use rollatini::{PublicKey, SecretKey};

let secret_key: SecretKey = SecretKey::generate()?;  // Anchor
let public_key = secret_key.public_key();            // published
let ctx_iss = b"epoch-42";                           // agreed out of band
let ctx_red = b"moderator.example";                  // chosen by the Client

// Issuance: Commit, Challenge, Respond, Finalize.
let (anchor_state, commitment) = rollatini::commit(ctx_iss, b"session-1")?;
let (client_state, challenge) =
    rollatini::challenge(&public_key, ctx_iss, ctx_red, &commitment)?;
let response = rollatini::respond(&secret_key, anchor_state, &challenge)?;
let endorsement = rollatini::finalize(&public_key, client_state, &response)?;

// Redemption against the Moderator's Anchor Set, in which this Anchor's key
// is at index 1.
let other: PublicKey = SecretKey::generate()?.public_key();
let anchor_set = [other, public_key];
let digest = b"moderator challenge digest";
let redemption = rollatini::redeem(&anchor_set, 1, endorsement, ctx_iss, ctx_red, digest)?;
let nf = rollatini::verify_redemption(&anchor_set, &redemption, ctx_iss, ctx_red, digest)?;
// reject a repeated nf, and record it before granting anything
# let _ = nf;
# Ok::<(), rollatini::Error>(())
```

`CommitMessage`, `ChallengeMessage`, `ResponseMessage`, `Endorsement`, and
`Redemption` have `to_bytes` and `from_bytes` with the encodings of the
draft; a redemption is decoded against the size of the Anchor Set.
`examples/demo.rs` issues from several Anchors and redeems through the
encodings.

## Backends

All group and hash operations go through the [`Backend`](src/backend/mod.rs)
trait, as in act-rs, the Rust implementation of the MoLE Anonymous Credit
Tokens. Two implementations are provided, selected by Cargo feature:

| Feature                | Curve, SHA-256, hash-to-curve, randomness |
|------------------------|-------------------------------------------|
| `rustcrypto` (default) | `p256`, `sha2`, `getrandom`               |
| `boringssl`            | BoringSSL through `bssl-sys`              |

Both backends encode scalars as 32-byte big-endian integers and points as
compressed SEC1, reject the identity, and produce identical outputs; with
both features enabled, the test suite checks that they interoperate and
`boringssl` is the `DefaultBackend`. Every type takes the backend as a type
parameter that defaults to it.

The permutation `P` needs a constant-time test of whether a 32-byte string
is the x-coordinate of a point. The `rustcrypto` backend runs `p256`'s
constant-time decompression; the `boringssl` backend computes
`(x^3 - 3x + b)^((p+1)/4)` with BoringSSL's constant-time Montgomery
arithmetic and compares its square.

### Building the BoringSSL backend

`bssl-sys` is not published on crates.io (the registry entry is a
placeholder), so it must be patched to a BoringSSL checkout built with Rust
bindings for the host. `scripts/build-boringssl.sh` does that at the commit
this crate is tested against (`5112448a`, September 2026, the same as
act-rs) and writes a Cargo config with the patch:

```sh
cargo install bindgen-cli          # plus git, cmake, ninja, a C++ compiler
scripts/build-boringssl.sh         # clones and builds into ./boringssl

export BORINGSSL_BUILD_DIR=$PWD/boringssl/build
cargo test --features boringssl --config boringssl/cargo-config.toml
```

A BoringSSL tree already built for act-rs works too: pass its
`cargo-config.toml` and build directory instead. The patch rewrites
`Cargo.lock`; restore it before committing.

The crate is `no_std` with `alloc`. The `std` feature enables the standard
library in `p256` and `getrandom`, and the precomputed generator tables of
`p256`.

## Design

* **Hashing and derivation** (`src/hash.rs`) are act-rs's functions with the
  protocol context as a parameter: `expand_message_xmd`, `HashToScalar`,
  `HashToGroup`, and the draft's `DeriveScalars`, `SeedsToScalars`,
  `DeriveNonces`, and `DeriveKeyPair`. Together with the backend and the
  random source they are meant to move into a crate shared with act-rs,
  `mole-p256`.
* **The permutation** (`src/permutation.rs`) implements `PermuteBytes`,
  `UnpermuteBytes`, `P`, `Pinv`, and `PermutationPair`. `PermutationPair`
  computes both one-step permutations on each iteration, selects one with
  `subtle`, and stops at the first valid encoding, so its schedule depends
  only on the public key it outputs.
* **The commitment tree** (`src/commitment.rs`) is computed over the hashes
  of its nodes, since every node enters a commitment through `HashToScalar`.
  The prover computes every node of every level, selects the binding leaf and
  each level's sibling by constant-time scans, and selects the opening of an
  odd last node in constant time, so no branch or memory access depends on
  the Anchor's index.
* **Redemption** forms `X_hat` as `delta * B + sum_i [i = index] * pkA_i`,
  multiplying every key by a selected 0 or 1, rather than indexing the
  Anchor Set by the secret index. Branch commitments are computed as
  `(c * X_hat + z * B) - c * pkA_i`, one multiplication per key.

## Security

* The Anchor's signing key and session state, the Client's blinding factors
  and nullifier, and the redemption's `delta`, index, trapdoors, and first
  openings are handled in constant time and zeroized after use. On the
  `boringssl` backend, point addition takes a separate path when its operands
  are equal or negatives of each other, which for a uniformly random secret
  operand independent of the other happens with negligible probability.
  Values that fail to decode are not wiped; their bytes remain the caller's
  to wipe.
* `respond` consumes the Anchor's state, `finalize` the Client's, and
  `redeem` the Endorsement, so none is used twice within a process. An
  Anchor must also refuse a second challenge for a session it has answered,
  which the application's session store enforces; `respond` returns
  `Error::Session` for a challenge that carries another session's
  identifier.
* Decoding rejects non-canonical scalars and points, the identity element,
  non-minimal length prefixes, trailing bytes, and redemptions whose vectors
  do not match the depth of the Anchor Set.
* `redeem` refuses Anchor Sets of fewer than two keys, and
  `verify_redemption` rejects them.
* The Moderator must reject a repeated nullifier and record it before
  granting anything; the crate returns the nullifier and leaves the store to
  the deployment.

## Testing

```sh
cargo test                                   # RustCrypto
cargo test --features boringssl ...          # BoringSSL, see above
cargo test --features rustcrypto,boringssl   # both, plus interoperability
cargo bench                                  # criterion, per backend
```

`tests/vectors/draft.txt` is the draft's Test Vectors section with the
fences and headings removed. `tests/vectors/extended.txt` was generated from
the draft's Python reference implementation by `tests/vectors/generate.py`,
with redemptions against Anchor Sets of 2, 3, 4, 6, 7, 8, 9, 16, and 33 keys
at the first, last, and interior positions, and `P` and `Pinv` of further
points. Every `rand` entry is replayed in place of the random number
generator, so every key, message, state, Endorsement, and redemption must
match byte for byte. Further tests cover issuance and redemption at every
position of Anchor Sets of 2 to 9 keys, tampering with every field of a
redemption, other contexts, digests, and Anchor Sets, the identity checks of
`Verify` and `VerifyIssuer`, the x-coordinate test against point decoding,
and RFC 9380 known answers for the primitives.

Continuous integration (`.github/workflows/ci.yml`) runs format, clippy with
warnings denied, tests and docs on both backends, the feature powerset, the
library on the minimum Rust version (1.85), 32-bit and wasm targets, and
unused-dependency and `cargo deny` checks. A weekly workflow
(`.github/workflows/nightly.yml`) runs Miri over the pure-Rust primitives,
mutation testing, and coverage.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option, except the files that carry a
Google LLC Apache 2.0 header, which are adapted from act-rs and are under
the Apache License, Version 2.0 only.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
