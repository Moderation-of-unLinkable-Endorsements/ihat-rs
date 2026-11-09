# Repository notes

This is a Cargo workspace of three crates under `crates/`:

* `mole-p256` holds the code the protocols share: the `backend` module (the
  `Backend` trait, its RustCrypto and BoringSSL implementations, and the
  fixed-base extension `BackendFixedBaseExt`), the `hash` module (hashing and
  derivation under a protocol context, provided by the blanket-implemented
  `hash::BackendHashExt` trait), the `random` module, and the shared `Error`
  and `SEED_LENGTH`.
* `ec-ihat` implements EC-IHAT and `ec-act` implements ACT. Each re-exports
  `mole_p256::backend` as its own `backend` module and keeps only
  protocol-specific code: `ec-act`'s SHAKE128 sponge, tags, and little-endian
  scalar decoding, for instance.

Put code that both protocols could use in `mole-p256` rather than
duplicating it in a protocol crate, and test it there: mutation testing runs
only the tests of the crate it mutates.
