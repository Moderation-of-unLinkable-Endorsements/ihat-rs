# Repository notes

This crate hosts the cryptographic code shared by `ihat-rs` and `act-rs`:
common backend implementations live in the `backend` module. Shared hashing
and derivation routines live in the public `hash` module, provided by the
blanket-implemented `hash::BackendHashExt` trait. `act-rs` depends on and
extends this code with functionality specific to ACT, including fixed-base
multiplication via its `backend::BackendFixedBaseExt` trait. ACT’s
protocol-specific backend extensions live in
[act-rs](https://github.com/Moderation-of-unLinkable-Endorsements/act-rs).
