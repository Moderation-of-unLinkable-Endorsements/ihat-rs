# Test vectors

`draft.txt` is the Test Vectors section of draft-authors-mole-rollatini at
commit 03d3069fd0a4080b8c3d7ba026f63178796adfe8, with the fences and headings
removed. `extended.txt` was generated from the draft's Python reference
implementation at the same commit by `generate.py`, which documents the
invocation: it holds the same entries from a different random stream, with
redemptions against Anchor Sets of 2, 3, 4, 6, 7, 8, 9, 16, 33, and 1 keys,
and `perm<i>` entries giving `P` and `Pinv` of eight derived points.
`src/tests/vectors.rs` replays every `rand` entry in place of the random
number generator and checks each key, message, state, Endorsement, and
redemption byte for byte, on every backend.

`draft.txt` is reproduced from the Internet-Draft, whose test vectors are
subject to the IETF Trust's legal provisions; the generated file is covered
by this repository's license.
