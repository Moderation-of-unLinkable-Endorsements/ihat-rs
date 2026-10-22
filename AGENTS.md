# Repository notes

The `backend` module in this crate hosts the cryptographic backend code shared
by `ihat-rs` and `act-rs`. Keep common backend implementations here; `act-rs`
depends on and extends them with functionality specific to ACT. ACT’s
protocol-specific backend extensions live in
[act-rs](https://github.com/Moderation-of-unLinkable-Endorsements/act-rs).
