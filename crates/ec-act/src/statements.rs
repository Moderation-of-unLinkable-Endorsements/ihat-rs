// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The three relations of the draft as fixed-shape statements.
//!
//! Each `impl` documents the compiled index layout of its `Relation` block:
//! elements are numbered in declaration order with the generator at 0, and
//! witness scalars likewise. The serialization written here must match
//! `SerializeLinearRelation` of that compiled relation byte for byte, which
//! the test vectors pin.
//!
//! Terms on the ciphersuite generators go through the backend's fixed-base
//! multiplication; terms on statement-specific points use `Point::lincomb`.

use alloc::vec::Vec;

use crate::Error;
use crate::backend::{Backend, BackendFixedBaseExt, FixedBase, Point, Scalar};
use crate::protocol::Generators;
use crate::sigma::{MINUS_ONE, ONE, RelationWriter, Statement, coefficient};

/// Rejects the identity element among statement elements or images.
fn nonidentity<P: Point>(point: &P) -> Result<(), Error> {
    if bool::from(point.is_identity()) {
        Err(Error::Verify)
    } else {
        Ok(())
    }
}

/// `sum_i scalar_i * base_i` over precomputed bases.
pub(crate) fn fixed<B: BackendFixedBaseExt, const N: usize>(
    terms: [(&B::FixedBase, &B::Scalar); N],
) -> B::Point {
    let mut terms = terms.into_iter();
    let Some((base, scalar)) = terms.next() else {
        return B::Point::identity();
    };
    terms.fold(base.mul(scalar), |acc, (base, scalar)| {
        acc.add(&base.mul(scalar))
    })
}

/// The positive weights whose bit subsets cover exactly `[0, m]`.
pub(crate) fn range_weights(l: usize, m: u64) -> Result<Vec<u64>, Error> {
    let max = u64::MAX >> (64 - l);
    if m > max {
        return Err(Error::Amount);
    }
    let n = (u64::BITS - m.leading_zeros()) as usize;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut weights = Vec::with_capacity(n);
    weights.extend((0..n - 1).map(|j| 1u64 << j));
    weights.push(m - (1u64 << (n - 1)) + 1);
    Ok(weights)
}

/// The spend weights fixed by the public amounts. A refresh has none.
pub(crate) fn spend_weights(l: usize, s: u64, a: u64) -> Result<Vec<u64>, Error> {
    let max = u64::MAX >> (64 - l);
    let total = u128::from(s) + u128::from(a);
    if total > u128::from(max) {
        return Err(Error::Amount);
    }
    if total == 0 {
        return Ok(Vec::new());
    }
    range_weights(l, (u128::from(max) - total) as u64)
}

/// `sum_j weights[j] * scalars[j]`, in constant time in the scalars.
///
/// [`range_weights`] makes every weight except possibly the last a power of
/// two. A single Horner pass over the public weight bits avoids field
/// multiplications altogether.
pub(crate) fn weighted_scalars<S: Scalar>(scalars: &[S], weights: &[u64]) -> S {
    debug_assert_eq!(scalars.len(), weights.len());
    let Some((last, prefix)) = scalars.split_last() else {
        return S::default();
    };
    let Some((&last_weight, prefix_weights)) = weights.split_last() else {
        return S::default();
    };
    debug_assert!(
        prefix_weights
            .iter()
            .enumerate()
            .all(|(j, weight)| *weight == 1u64 << j)
    );

    (0..=prefix.len()).rev().fold(S::default(), |acc, bit| {
        let mut acc = acc + acc;
        if bit < prefix.len() {
            acc = acc + prefix[bit];
        }
        if last_weight & (1u64 << bit) != 0 {
            acc = acc + *last;
        }
        acc
    })
}

/// `sum_j weights[j] * points[j]` for public points and weights.
///
/// As above, one Horner pass replaces scalar multiplications with point
/// doublings and additions. Its control flow depends only on public weights.
pub(crate) fn weighted_points<P: Point>(points: &[P], weights: &[u64]) -> P {
    debug_assert_eq!(points.len(), weights.len());
    let Some((last, prefix)) = points.split_last() else {
        return P::identity();
    };
    let Some((&last_weight, prefix_weights)) = weights.split_last() else {
        return P::identity();
    };
    debug_assert!(
        prefix_weights
            .iter()
            .enumerate()
            .all(|(j, weight)| *weight == 1u64 << j)
    );

    (0..=prefix.len()).rev().fold(P::identity(), |acc, bit| {
        let mut acc = acc.double();
        if bit < prefix.len() {
            acc = acc.add(&prefix[bit]);
        }
        if last_weight & (1u64 << bit) != 0 {
            acc = acc.add(last);
        }
        acc
    })
}

// ---------------------------------------------------------------------------
// Relation Commitment(H2, H3, K): Witness k, r; K = k * H2 + r * H3
//   elements: G 0, H2 1, H3 2, K 3      scalars: k 0, r 1
// ---------------------------------------------------------------------------

/// The `Commitment` relation of the issuance request.
pub(crate) struct Commitment<'a, B: BackendFixedBaseExt> {
    pub(crate) gens: &'a Generators<B>,
    pub(crate) k: &'a B::Point,
}

impl<B: BackendFixedBaseExt> Statement<B> for Commitment<'_, B> {
    fn num_scalars(&self) -> usize {
        2
    }

    fn num_equations(&self) -> usize {
        1
    }

    fn validate(&self) -> Result<(), Error> {
        nonidentity(self.k)
    }

    fn serialize(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = RelationWriter::new(out);
        w.equations(self.num_equations());
        w.image(&[(3, &ONE)]);
        w.terms(&[(0, 1, &ONE), (1, 2, &ONE)]);
        w.element(self.gens.h2.point())?;
        w.element(self.gens.h3.point())?;
        w.element(self.k)
    }

    fn commit(&self, n: &[B::Scalar], out: &mut Vec<B::Point>) {
        out.push(fixed::<B, 2>([
            (&self.gens.h2, &n[0]),
            (&self.gens.h3, &n[1]),
        ]));
    }

    fn simulate(&self, c: &B::Scalar, z: &[B::Scalar], out: &mut Vec<B::Point>) {
        let generators = fixed::<B, 2>([(&self.gens.h2, &z[0]), (&self.gens.h3, &z[1])]);
        out.push(generators.add(&self.k.mul(&-*c)));
    }
}

// ---------------------------------------------------------------------------
// Relation Signature(A, X_A, X_G): Witness x; X_A = x * A, X_G = x * G
//   elements: G 0, A 1, X_A 2, X_G 3     scalars: x 0
// ---------------------------------------------------------------------------

/// The `Signature` relation of the issuance response and the refund.
pub(crate) struct Signature<'a, B: Backend> {
    pub(crate) a: &'a B::Point,
    pub(crate) x_a: &'a B::Point,
    pub(crate) x_g: &'a B::Point,
}

impl<B: Backend> Statement<B> for Signature<'_, B> {
    fn num_scalars(&self) -> usize {
        1
    }

    fn num_equations(&self) -> usize {
        2
    }

    fn validate(&self) -> Result<(), Error> {
        nonidentity(self.a)?;
        nonidentity(self.x_a)?;
        nonidentity(self.x_g)
    }

    fn serialize(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = RelationWriter::new(out);
        w.equations(self.num_equations());
        w.image(&[(2, &ONE)]);
        w.terms(&[(0, 1, &ONE)]);
        w.image(&[(3, &ONE)]);
        w.terms(&[(0, 0, &ONE)]);
        w.element(self.a)?;
        w.element(self.x_a)?;
        w.element(self.x_g)
    }

    fn commit(&self, n: &[B::Scalar], out: &mut Vec<B::Point>) {
        out.push(self.a.mul(&n[0]));
        out.push(B::Point::mul_generator(&n[0]));
    }

    fn simulate(&self, c: &B::Scalar, z: &[B::Scalar], out: &mut Vec<B::Point>) {
        let minus_c = -*c;
        out.push(B::Point::lincomb([(self.a, &z[0]), (self.x_a, &minus_c)]));
        out.push(B::Point::mul_generator(&z[0]).add(&self.x_g.mul(&minus_c)));
    }
}

// ---------------------------------------------------------------------------
// Relation Spend(H1, H2, H3, A_prime, B_bar, A_bar, H1_prime, K_n, s, a,
//                w[0..n], Com1[0..n] (s + a > 0) | Com_c (s + a = 0))
//   elements: G 0, H1 1, H2 2, H3 3, A_prime 4, B_bar 5, A_bar 6,
//             H1_prime 7, K_n 8, Com1[j] 9+j | Com_c 9
//   scalars:  e 0, r2 1, r3 2, c 3, r 4, kstar 5, rn 6,
//             b1[j] 7+j, s1[j] 7+n+j, u1[j] 7+2n+j | rc 7
//   equations, in order:
//     A_bar    = -e * A_prime + r2 * B_bar
//     H1_prime = r3 * B_bar - c * H1 - r * H3
//     K_n      = kstar * H2 + rn * H3
//     s + a > 0: for j: Com1[j] = b1[j] * H1 + s1[j] * H3
//                        Com1[j] = b1[j] * Com1[j] + u1[j] * H3
//                  K_n + s * H1 + sum w[j] * Com1[j]
//                    = c * H1 + kstar * H2 + rn * H3
//                      + sum w[j] * s1[j] * H3
//     s + a = 0: Com_c = c * H1 + rc * H3
// ---------------------------------------------------------------------------

/// Witness index of `e`.
const E: usize = 0;
const R2: usize = 1;
const R3: usize = 2;
const C: usize = 3;
const R: usize = 4;
const KSTAR: usize = 5;
const RN: usize = 6;
/// First witness index after the seven fixed scalars.
const FIXED_SCALARS: usize = 7;

/// Element indices of the fixed statement elements.
const EL_H1: usize = 1;
const EL_H2: usize = 2;
const EL_H3: usize = 3;
const EL_A_PRIME: usize = 4;
const EL_B_BAR: usize = 5;
const EL_A_BAR: usize = 6;
const EL_H1_PRIME: usize = 7;
const EL_K_N: usize = 8;
const FIXED_ELEMENTS: usize = 9;

/// The witness length of the spend relation, `Nw`.
pub(crate) fn spend_witness_count(l: usize, s: u64, a: u64) -> Result<usize, Error> {
    let weights = spend_weights(l, s, a)?;
    Ok(FIXED_SCALARS
        + if s == 0 && a == 0 {
            1
        } else {
            3 * weights.len()
        })
}

/// The single weighted range block of a non-refresh spend.
struct Range<'a, B: Backend> {
    /// Commitments `Com[j]`.
    com: &'a [B::Point],
    /// Public positive weights whose subsets cover exactly the allowed range.
    weights: Vec<u64>,
    /// `sum_j weights[j] * Com[j]`.
    sum: B::Point,
    /// The public spent amount in the sum equation.
    s: u64,
}

impl<B: Backend> Range<'_, B> {
    fn len(&self) -> usize {
        self.com.len()
    }

    fn bits(&self) -> core::ops::Range<usize> {
        FIXED_SCALARS..FIXED_SCALARS + self.len()
    }

    fn blindings(&self) -> core::ops::Range<usize> {
        FIXED_SCALARS + self.len()..FIXED_SCALARS + 2 * self.len()
    }

    fn products(&self) -> core::ops::Range<usize> {
        FIXED_SCALARS + 2 * self.len()..FIXED_SCALARS + 3 * self.len()
    }
}

/// How the remainder `c - s` is committed to: a weighted range proof for a
/// non-refresh, or one commitment to the already-ranged balance for a refresh.
enum Remainder<'a, B: Backend> {
    Bits(Range<'a, B>),
    Single(&'a B::Point),
}

/// The `Spend` relation.
pub(crate) struct Spend<'a, B: BackendFixedBaseExt> {
    gens: &'a Generators<B>,
    a_prime: &'a B::Point,
    b_bar: &'a B::Point,
    a_bar: &'a B::Point,
    h1_prime: &'a B::Point,
    k_n: &'a B::Point,
    remainder: Remainder<'a, B>,
}

impl<'a, B: BackendFixedBaseExt> Spend<'a, B> {
    /// Builds the statement, rejecting a shape that does not match `s` and
    /// `a` or the balance width `l`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        gens: &'a Generators<B>,
        l: usize,
        a_prime: &'a B::Point,
        b_bar: &'a B::Point,
        a_bar: &'a B::Point,
        h1_prime: &'a B::Point,
        k_n: &'a B::Point,
        s: u64,
        a: u64,
        com1: &'a [B::Point],
        com_c: Option<&'a B::Point>,
    ) -> Result<Self, Error> {
        let refresh = s == 0 && a == 0;
        let weights = spend_weights(l, s, a)?;
        if com1.len() != weights.len() || com_c.is_some() != refresh {
            return Err(Error::Verify);
        }
        let remainder = match com_c {
            None => Remainder::Bits(Range {
                com: com1,
                sum: weighted_points(com1, &weights),
                weights,
                s,
            }),
            Some(com_c) => Remainder::Single(com_c),
        };
        Ok(Self {
            gens,
            a_prime,
            b_bar,
            a_bar,
            h1_prime,
            k_n,
            remainder,
        })
    }

    /// `BalanceCommitment(proof)`: `K_n + V1`, reusing the weighted sum
    /// already computed while constructing the statement.
    pub(crate) fn balance_commitment(&self) -> B::Point {
        let v1 = match &self.remainder {
            Remainder::Bits(range) => &range.sum,
            Remainder::Single(com_c) => com_c,
        };
        self.k_n.add(v1)
    }

    fn serialize_range(&self, w: &mut RelationWriter<'_>, range: &Range<'_, B>) {
        let l = range.len();
        for j in 0..l {
            let com = FIXED_ELEMENTS + j;
            w.image(&[(com, &ONE)]);
            w.terms(&[
                (FIXED_SCALARS + j, EL_H1, &ONE),
                (FIXED_SCALARS + l + j, EL_H3, &ONE),
            ]);
            w.image(&[(com, &ONE)]);
            w.terms(&[
                (FIXED_SCALARS + j, com, &ONE),
                (FIXED_SCALARS + 2 * l + j, EL_H3, &ONE),
            ]);
        }
        w.begin(2 + l);
        w.image_term(EL_K_N, &ONE);
        w.image_term(EL_H1, &coefficient(range.s));
        for j in 0..l {
            w.image_term(FIXED_ELEMENTS + j, &coefficient(range.weights[j]));
        }
        w.begin(3 + l);
        w.term(C, EL_H1, &ONE);
        w.term(KSTAR, EL_H2, &ONE);
        w.term(RN, EL_H3, &ONE);
        for j in 0..l {
            w.term(FIXED_SCALARS + l + j, EL_H3, &coefficient(range.weights[j]));
        }
    }

    fn commit_range(
        &self,
        range: &Range<'_, B>,
        n: &[B::Scalar],
        k_n_commitment: B::Point,
        out: &mut Vec<B::Point>,
    ) {
        let (h1, h3) = (&self.gens.h1, &self.gens.h3);
        let bits = &n[range.bits()];
        let blindings = &n[range.blindings()];
        let products = &n[range.products()];
        // Reuse the commitment to `K_n = kstar * H2 + rn * H3` in the sum
        // equation, adding only the terms that are not already in it.
        let h3_scalar = weighted_scalars(blindings, &range.weights);
        let sum_commitment = k_n_commitment.add(&fixed::<B, 2>([(h1, &n[C]), (h3, &h3_scalar)]));
        out.push(k_n_commitment);
        for j in 0..range.len() {
            out.push(fixed::<B, 2>([(h1, &bits[j]), (h3, &blindings[j])]));
            out.push(range.com[j].mul(&bits[j]).add(&h3.mul(&products[j])));
        }
        out.push(sum_commitment);
    }

    fn simulate_range(
        &self,
        range: &Range<'_, B>,
        c: &B::Scalar,
        z: &[B::Scalar],
        k_n_commitment: B::Point,
        out: &mut Vec<B::Point>,
    ) {
        let (h1, h3) = (&self.gens.h1, &self.gens.h3);
        let minus_c = -*c;
        let bits = &z[range.bits()];
        let blindings = &z[range.blindings()];
        let products = &z[range.products()];
        // As in `commit_range`, reuse the simulated `K_n` equation.
        let h1_scalar = z[C] - *c * B::Scalar::from(range.s);
        let h3_scalar = weighted_scalars(blindings, &range.weights);
        let generators = fixed::<B, 2>([(h1, &h1_scalar), (h3, &h3_scalar)]);
        let sum_commitment = k_n_commitment
            .add(&generators)
            .add(&range.sum.mul(&minus_c));
        out.push(k_n_commitment);
        for j in 0..range.len() {
            let com = &range.com[j];
            let generators = fixed::<B, 2>([(h1, &bits[j]), (h3, &blindings[j])]);
            out.push(generators.add(&com.mul(&minus_c)));
            // -c * Com[j] folds into the term that Com[j] already carries.
            out.push(com.mul(&(bits[j] - *c)).add(&h3.mul(&products[j])));
        }
        // Subtract the challenge times `K_n + s * H1 + sum w[j] * Com1[j]`.
        out.push(sum_commitment);
    }
}

impl<B: BackendFixedBaseExt> Statement<B> for Spend<'_, B> {
    fn num_scalars(&self) -> usize {
        match &self.remainder {
            Remainder::Bits(range) => FIXED_SCALARS + 3 * range.len(),
            Remainder::Single(_) => FIXED_SCALARS + 1,
        }
    }

    fn num_equations(&self) -> usize {
        match &self.remainder {
            Remainder::Bits(range) => 4 + 2 * range.len(),
            Remainder::Single(_) => 4,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        // Check 8: no statement element is the identity. The generators are
        // fixed and the commitments were deserialized; `A_bar` and
        // `H1_prime` are computed.
        for point in [
            self.a_prime,
            self.b_bar,
            self.a_bar,
            self.h1_prime,
            self.k_n,
        ] {
            nonidentity(point)?;
        }
        if let Remainder::Bits(range) = &self.remainder {
            for com in range.com {
                nonidentity(com)?;
            }
            // Check 9: the image `K_n + s * H1 + sum w[j] * Com1[j]`.
            nonidentity(
                &self
                    .k_n
                    .add(&self.gens.h1.mul(&B::Scalar::from(range.s)))
                    .add(&range.sum),
            )?;
        }
        if let Remainder::Single(com_c) = self.remainder {
            nonidentity(com_c)?;
        }
        // Check 10 holds structurally: every witness scalar multiplies a
        // fixed generator or a deserialized element with a nonzero coefficient.
        Ok(())
    }

    fn serialize(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = RelationWriter::new(out);
        w.equations(self.num_equations());

        w.image(&[(EL_A_BAR, &ONE)]);
        w.terms(&[(E, EL_A_PRIME, &MINUS_ONE), (R2, EL_B_BAR, &ONE)]);
        w.image(&[(EL_H1_PRIME, &ONE)]);
        w.terms(&[
            (R3, EL_B_BAR, &ONE),
            (C, EL_H1, &MINUS_ONE),
            (R, EL_H3, &MINUS_ONE),
        ]);
        w.image(&[(EL_K_N, &ONE)]);
        w.terms(&[(KSTAR, EL_H2, &ONE), (RN, EL_H3, &ONE)]);
        match &self.remainder {
            Remainder::Bits(range) => self.serialize_range(&mut w, range),
            Remainder::Single(_) => {
                w.image(&[(FIXED_ELEMENTS, &ONE)]);
                w.terms(&[(C, EL_H1, &ONE), (FIXED_SCALARS, EL_H3, &ONE)]);
            }
        }
        for base in [&self.gens.h1, &self.gens.h2, &self.gens.h3] {
            w.element(base.point())?;
        }
        for point in [
            self.a_prime,
            self.b_bar,
            self.a_bar,
            self.h1_prime,
            self.k_n,
        ] {
            w.element(point)?;
        }
        match &self.remainder {
            Remainder::Bits(range) => range.com.iter().try_for_each(|com| w.element(com))?,
            Remainder::Single(com_c) => w.element(*com_c)?,
        }
        Ok(())
    }

    fn commit(&self, n: &[B::Scalar], out: &mut Vec<B::Point>) {
        let gens = self.gens;
        out.push(B::Point::lincomb([
            (self.a_prime, &-n[E]),
            (self.b_bar, &n[R2]),
        ]));
        let generators = fixed::<B, 2>([(&gens.h1, &-n[C]), (&gens.h3, &-n[R])]);
        out.push(self.b_bar.mul(&n[R3]).add(&generators));
        let k_n_commitment = fixed::<B, 2>([(&gens.h2, &n[KSTAR]), (&gens.h3, &n[RN])]);
        match &self.remainder {
            Remainder::Bits(range) => self.commit_range(range, n, k_n_commitment, out),
            Remainder::Single(_) => {
                out.push(k_n_commitment);
                out.push(fixed::<B, 2>([
                    (&gens.h1, &n[C]),
                    (&gens.h3, &n[FIXED_SCALARS]),
                ]));
            }
        }
    }

    fn simulate(&self, c: &B::Scalar, z: &[B::Scalar], out: &mut Vec<B::Point>) {
        let gens = self.gens;
        let minus_c = -*c;
        out.push(B::Point::lincomb([
            (self.a_prime, &-z[E]),
            (self.b_bar, &z[R2]),
            (self.a_bar, &minus_c),
        ]));
        let generators = fixed::<B, 2>([(&gens.h1, &-z[C]), (&gens.h3, &-z[R])]);
        out.push(
            B::Point::lincomb([(self.b_bar, &z[R3]), (self.h1_prime, &minus_c)]).add(&generators),
        );
        let generators = fixed::<B, 2>([(&gens.h2, &z[KSTAR]), (&gens.h3, &z[RN])]);
        let k_n_commitment = generators.add(&self.k_n.mul(&minus_c));
        match &self.remainder {
            Remainder::Bits(range) => self.simulate_range(range, c, z, k_n_commitment, out),
            Remainder::Single(com_c) => {
                out.push(k_n_commitment);
                let generators = fixed::<B, 2>([(&gens.h1, &z[C]), (&gens.h3, &z[FIXED_SCALARS])]);
                out.push(generators.add(&com_c.mul(&minus_c)));
            }
        }
    }
}
