//! The partially binding vector commitment of the issuer-hiding proof: a
//! tree of pair commitments, one key and one opening per level.
//!
//! Every value in the tree enters a commitment through `HashToScalar`, so
//! the tree is computed over those hashes: a leaf or interior node is
//! represented by the hash of its encoding, and an odd last node is carried
//! up as it is. The prover's functions are constant time in the binding
//! index: every node of every level is computed, and the index selects
//! values only through constant-time selection.

use alloc::vec::Vec;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::{Backend, POINT_LENGTH, Point};
use crate::hash;
use crate::permutation;
use crate::{Error, PROTOCOL_CONTEXT};

/// The encoding of a commitment node.
pub(crate) type Node = [u8; POINT_LENGTH];

/// `Depth(n)`: the number of levels of a tree over `n` leaves, the least
/// `q` with `2^q >= n`.
pub(crate) fn depth(n: usize) -> usize {
    (usize::BITS - n.saturating_sub(1).leading_zeros()) as usize
}

/// `G.HashToScalar(value)`.
pub(crate) fn hash_node<B: Backend>(value: &[u8]) -> B::Scalar {
    hash::hash_to_scalar::<B>(PROTOCOL_CONTEXT, &[value])
}

/// A level's commitment key `Q`, with `P(Q)`.
#[derive(Clone, Debug)]
pub(crate) struct Key<B: Backend> {
    pub(crate) q: B::Point,
    pub(crate) pq: B::Point,
}

impl<B: Backend> Key<B> {
    /// A key received from the prover, with `P(Q)` computed from it.
    pub(crate) fn public(q: B::Point) -> Result<Self, Error> {
        let pq = permutation::p::<B>(&q)?;
        Ok(Self { q, pq })
    }

    /// `GenerateStep(bind_left, secret)`: the key whose position opposite
    /// `bind_left` has the discrete logarithm `secret`.
    pub(crate) fn generate(bind_left: Choice, secret: &B::Scalar) -> Result<Self, Error> {
        let mut t = B::Point::mul_generator(secret);
        let pair = permutation::permutation_pair::<B>(&t, bind_left);
        t.zeroize();
        let (q, pq) = pair?;
        Ok(Self { q, pq })
    }
}

/// `CommitStep(Q, left, right, randomness)`, given the hashes of `left` and
/// `right`.
///
/// The encoding of the identity does not exist; a node equal to it is
/// reported as `error`.
fn commit_step<B: Backend>(
    key: &Key<B>,
    left: &B::Scalar,
    right: &B::Scalar,
    randomness: &B::Scalar,
    error: Error,
) -> Result<Node, Error> {
    let commitment = B::Point::mul_generator(randomness)
        .add(&B::Point::lincomb([(&key.q, left), (&key.pq, right)]));
    commitment.to_bytes().ok_or(error)
}

/// The next level of the tree: each pair committed under `key` and
/// `opening`, and an odd last node carried up.
///
/// Returns the hashes of the new level, or, for a level of two nodes, the
/// encoding of the root in place of a hash.
fn next_level<B: Backend>(
    level: &[B::Scalar],
    key: &Key<B>,
    opening: &B::Scalar,
    error: Error,
) -> Result<Level<B>, Error> {
    if let [left, right] = level {
        return Ok(Level::Root(commit_step(key, left, right, opening, error)?));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(level.len().div_ceil(2)));
    for pair in level.chunks(2) {
        match pair {
            [left, right] => out.push(hash_node::<B>(&commit_step(
                key, left, right, opening, error,
            )?)),
            [carried] => out.push(*carried),
            _ => return Err(Error::InvalidInput),
        }
    }
    Ok(Level::Hashes(out))
}

enum Level<B: Backend> {
    Hashes(Zeroizing<Vec<B::Scalar>>),
    Root(Node),
}

/// `VecCommit(V, Qi, rands)` for `V` of at least two values, given their
/// hashes: the root, the last commitment computed.
pub(crate) fn vec_commit<B: Backend>(
    leaves: Zeroizing<Vec<B::Scalar>>,
    keys: &[Key<B>],
    openings: &[B::Scalar],
    error: Error,
) -> Result<Node, Error> {
    if leaves.len() < 2 || keys.len() != depth(leaves.len()) || openings.len() != keys.len() {
        return Err(Error::InvalidInput);
    }
    let mut level = leaves;
    for (key, opening) in keys.iter().zip(openings) {
        match next_level(&level, key, opening, error)? {
            Level::Hashes(next) => level = next,
            Level::Root(root) => return Ok(root),
        }
    }
    Err(Error::InvalidInput)
}

/// `GenerateVecBind(index, trapdoors)`: level `j` binds the side of bit `j`
/// of `index`. Constant time in `index` and the trapdoors.
pub(crate) fn generate_vec_bind<B: Backend>(
    index: u16,
    trapdoors: &[B::Scalar],
) -> Result<Vec<Key<B>>, Error> {
    let mut keys = Vec::with_capacity(trapdoors.len());
    for (j, trapdoor) in trapdoors.iter().enumerate() {
        let bit = Choice::from(((u32::from(index) >> j) & 1) as u8);
        keys.push(Key::generate(!bit, trapdoor)?);
    }
    Ok(keys)
}

/// The first move of the proof, `CommitValAtPlace`, with the state that
/// `VecEquivocate` needs.
pub(crate) struct FirstMove<B: Backend> {
    /// The hashes of every level below the root.
    levels: Vec<Zeroizing<Vec<B::Scalar>>>,
    /// The root.
    pub(crate) root: Node,
}

/// `CommitValAtPlace(keys, n, index, value, openings)` for `n >= 2`: `value`
/// at leaf `index` and the empty string at every other leaf. Constant time
/// in `index` and `value`.
pub(crate) fn commit_val_at_place<B: Backend>(
    keys: &[Key<B>],
    n: usize,
    index: u16,
    value: &Node,
    openings: &[B::Scalar],
) -> Result<FirstMove<B>, Error> {
    if n < 2 || keys.len() != depth(n) || openings.len() != keys.len() {
        return Err(Error::InvalidInput);
    }
    let empty = hash_node::<B>(b"");
    let mut held = hash_node::<B>(value);
    let mut leaves = Zeroizing::new(Vec::with_capacity(n));
    for i in 0..n {
        let at = (i as u64).ct_eq(&u64::from(index));
        leaves.push(B::Scalar::conditional_select(&empty, &held, at));
    }
    held.zeroize();
    let mut levels = Vec::with_capacity(keys.len());
    let mut level = leaves;
    for (key, opening) in keys.iter().zip(openings) {
        match next_level(&level, key, opening, Error::Derive)? {
            Level::Hashes(next) => levels.push(core::mem::replace(&mut level, next)),
            Level::Root(root) => {
                levels.push(level);
                return Ok(FirstMove { levels, root });
            }
        }
    }
    Err(Error::InvalidInput)
}

/// `VecEquivocateFromZero(keys, trapdoors, openings, new, index)`, given
/// the first move and the hashes of `new`: the openings under which `new`
/// commits to the root of the first move.
///
/// At level `j` the sibling of the binding path takes its new value, and
/// the opening shifts by the difference of its hashes times the trapdoor;
/// an odd last node on the path keeps its opening. Constant time in
/// `index`, the trapdoors, and the first openings.
pub(crate) fn vec_equivocate<B: Backend>(
    first: &FirstMove<B>,
    keys: &[Key<B>],
    trapdoors: &[B::Scalar],
    openings: &[B::Scalar],
    new: Vec<B::Scalar>,
    index: u16,
) -> Result<Vec<B::Scalar>, Error> {
    let q = keys.len();
    if first.levels.len() != q || trapdoors.len() != q || openings.len() != q {
        return Err(Error::InvalidInput);
    }
    let mut result = Vec::with_capacity(q);
    let mut path = u64::from(index);
    let mut new = Zeroizing::new(new);
    for (j, old) in first.levels.iter().enumerate() {
        let m = old.len();
        if new.len() != m {
            return Err(Error::InvalidInput);
        }
        let partner = path ^ 1;
        let mut old_partner = B::Scalar::default();
        let mut new_partner = B::Scalar::default();
        for (k, (old, new)) in old.iter().zip(new.iter()).enumerate() {
            let at = (k as u64).ct_eq(&partner);
            old_partner.conditional_assign(old, at);
            new_partner.conditional_assign(new, at);
        }
        let carried = path.ct_eq(&(m as u64 - 1)) & Choice::from((m & 1) as u8);
        let mut shifted = openings[j] + (old_partner - new_partner) * trapdoors[j];
        let opening = B::Scalar::conditional_select(&shifted, &openings[j], carried);
        old_partner.zeroize();
        new_partner.zeroize();
        shifted.zeroize();
        result.push(opening);
        if j + 1 < q {
            match next_level(&new, &keys[j], &opening, Error::Derive)? {
                Level::Hashes(next) => new = next,
                Level::Root(_) => return Err(Error::InvalidInput),
            }
        }
        path >>= 1;
    }
    Ok(result)
}
