# Test vectors

`draft-schlesinger-mole-ec-act-00.txt` is copied from the artwork blocks in
[Appendix A of draft-schlesinger-mole-ec-act-00](https://datatracker.ietf.org/doc/html/draft-schlesinger-mole-ec-act-00#appendix-A),
with only the XML wrappers removed. `src/tests/vectors.rs` replays every
`rand` entry in place of the random number generator and checks each key,
message, state, and Credential byte for byte, on every backend.

The vector is reproduced from the Internet-Draft and is subject to the IETF
Trust's legal provisions.
