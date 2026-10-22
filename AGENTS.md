# Repository notes

The cryptographic code shared by `act-rs` and `ihat-rs` is hosted in `ihat-rs`:
common backend implementations live in its `backend` module. Shared hashing
and derivation routines live in its public `hash` module, provided by the
blanket-implemented `hash::BackendHashExt` trait. ACT re-exports IHAT's
`Backend` directly and extends it with `backend::BackendFixedBaseExt` for
ACT-specific fixed-base multiplication. ACT uses the `shake` crate for its
protocol-specific SHAKE128 computations. Reuse the shared implementations
rather than duplicating common code here.
