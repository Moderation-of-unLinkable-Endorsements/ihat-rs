//! Test-vector access to shared protocol computations.

use super::{
    AnchorState, Backend, BackendHashExt, CTX, ClientState, Error, NSEED, NULLIFIER_LENGTH, Point,
    Scalar, Vec, compute_challenge, context_base,
};

// ---------------------------------------------------------------------------
// Test access
// ---------------------------------------------------------------------------

#[cfg(test)]
impl<B: Backend> AnchorState<B> {
    /// `SerializeScalar(a) || SerializeScalar(y) || SerializeScalar(t)`, the
    /// `commit.state` entry of the test vectors.
    pub(crate) fn vector_bytes(&self) -> Vec<u8> {
        [self.a, self.y, self.t]
            .iter()
            .flat_map(|scalar| scalar.to_bytes())
            .collect()
    }
}

#[cfg(test)]
impl<B: Backend> ClientState<B> {
    /// `nf || r1 || r2 || gamma1 || gamma2 || c`, the `challenge.state`
    /// entry of the test vectors.
    pub(crate) fn vector_bytes(&self) -> Vec<u8> {
        let mut out = self.nf.to_vec();
        for scalar in [self.r1, self.r2, self.gamma1, self.gamma2, self.c] {
            out.extend_from_slice(&scalar.to_bytes());
        }
        out
    }
}

#[cfg(test)]
pub(crate) fn context_base_for_tests<B: Backend>(ctx_iss: &[u8]) -> B::Point {
    context_base::<B>(ctx_iss).unwrap_or_else(|_| B::Point::identity())
}

#[cfg(test)]
pub(crate) fn delta_for_tests<B: Backend>(rand: &[u8]) -> B::Scalar {
    B::derive_scalars(CTX, &rand[..NSEED], b"delta", 1)
        .map(|scalars| scalars[0])
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn compute_challenge_for_tests<B: Backend>(
    ctx_iss: &[u8],
    a: &B::Point,
    c: &B::Point,
    nf: &[u8; NULLIFIER_LENGTH],
    ctx_red: &[u8],
) -> Result<B::Scalar, Error> {
    compute_challenge::<B>(ctx_iss, a, c, nf, ctx_red)
}
