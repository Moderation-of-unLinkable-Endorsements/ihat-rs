"""Generate the extended Rollatini test vectors from the draft's reference
implementation, in the draft's `key = value` format.

Run from the `poc/` directory of the internet-drafts repository at commit
e4690fcbb192b39a94664268917b5335aaf89779, with its virtual environment set
up as its README describes:

    .venv/bin/python /path/to/generate.py > extended.txt

The output has the entries of the draft's Test Vectors section, from a
different random stream, with redemptions against Anchor Sets of the sizes
and at the indices in REDEMPTIONS, followed by `perm<i>` entries giving
`P` and `Pinv` of derived points.

Randomness is served from SHAKE128 of a fixed label so that every entry is
reproducible; each `rand` entry records the bytes the algorithm consumed.
"""

from rollatini import protocol as rollatini, vectors

LABEL = b"Rollatiniv1-P256-SHA256 extended vectors"
# Anchor Set sizes and the position of the issuing Anchor in each: the
# first and last positions, odd sizes that carry a node up at several
# levels, and powers of two.
REDEMPTIONS = [(2, 0), (3, 2), (4, 1), (6, 5), (7, 6), (8, 5), (9, 8), (16, 9), (33, 32)]
PERMUTATION_POINTS = 8


class ExtendedSource(vectors.Source):
    def __init__(self, label: bytes) -> None:
        super().__init__(LABEL)


def main() -> None:
    vectors.Source = ExtendedSource
    vectors.REDEMPTIONS = REDEMPTIONS
    text = vectors.render()
    lines = text.splitlines(keepends=True)
    out = "".join(
        line
        for line in lines
        if line.strip() and not line.startswith(("## ", "~~~"))
    )
    G = rollatini.G
    for i in range(PERMUTATION_POINTS):
        _, point = G.DeriveKeyPair(bytes([i]) * rollatini.Nseed, b"permutation vectors")
        out += vectors.entry(f"perm{i}.point", G.SerializeElement(point))
        out += vectors.entry(f"perm{i}.P", G.SerializeElement(G.P(point)))
        out += vectors.entry(f"perm{i}.Pinv", G.SerializeElement(G.Pinv(point)))
    print(out, end="")


if __name__ == "__main__":
    main()
