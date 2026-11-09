//! The permutation `P` of the group and its inverse `Pinv`: an eight-round
//! Feistel network over compressed encodings, walked until the result
//! decodes. [`p`] and [`p_inv`] are for public points; [`permutation_pair`]
//! derives a commitment key from a secret without revealing the direction
//! of the walk.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::Error;
use crate::backend::{Backend, POINT_LENGTH, Point, SCALAR_LENGTH, Sha256};

/// An encoding with its prefix `0x02` or `0x03` replaced by its low bit.
type Encoding = [u8; POINT_LENGTH];

/// Length of the left half, which carries the prefix bit.
const LEFT: usize = 17;

/// `_sha256(half || label || digit)`, for a round label `"left round i"` or
/// `"right round i"`.
fn round<B: Backend>(half: &[u8], label: &[u8], i: u8) -> [u8; 32] {
    let mut hasher = B::Sha256::new();
    hasher.update(half);
    hasher.update(label);
    hasher.update(&[b'0' + i]);
    hasher.finalize()
}

/// The left round `i`: `left ^= _sha256(right || "left round i")[0:17]`,
/// then keep only the low bit of the first byte.
fn left_round<B: Backend>(buf: &mut Encoding, i: u8) {
    let (left, right) = buf.split_at_mut(LEFT);
    let mut mask = round::<B>(right, b"left round ", i);
    for (byte, m) in left.iter_mut().zip(mask.iter()) {
        *byte ^= m;
    }
    left[0] &= 0x01;
    mask.zeroize();
}

/// The right round `i`: `right ^= _sha256(left || "right round i")[0:16]`.
fn right_round<B: Backend>(buf: &mut Encoding, i: u8) {
    let (left, right) = buf.split_at_mut(LEFT);
    let mut mask = round::<B>(left, b"right round ", i);
    for (byte, m) in right.iter_mut().zip(mask.iter()) {
        *byte ^= m;
    }
    mask.zeroize();
}

/// `PermuteBytes`.
pub(crate) fn permute_bytes<B: Backend>(buf: &mut Encoding) {
    for i in 0..4 {
        left_round::<B>(buf, i);
        right_round::<B>(buf, i);
    }
}

/// `UnpermuteBytes`, the inverse of [`permute_bytes`] on strings whose
/// first byte is 0 or 1.
pub(crate) fn unpermute_bytes<B: Backend>(buf: &mut Encoding) {
    for i in (0..4).rev() {
        right_round::<B>(buf, i);
        left_round::<B>(buf, i);
    }
}

/// `SelectBytes(left, right, choose_right)`, in constant time.
pub(crate) fn select_bytes(left: &Encoding, right: &Encoding, choose_right: Choice) -> Encoding {
    let mut out = [0u8; POINT_LENGTH];
    for ((out, a), b) in out.iter_mut().zip(left).zip(right) {
        *out = u8::conditional_select(a, b, choose_right);
    }
    out
}

/// `IsValidPermutationEncoding(buf)`: whether `buf` becomes the encoding of
/// a point once `0x02` is added to its first byte. Constant time in `buf`.
pub(crate) fn is_valid_permutation_encoding<B: Backend>(buf: &Encoding) -> Choice {
    let prefix = buf[0].ct_eq(&0) | buf[0].ct_eq(&1);
    let mut x = [0u8; SCALAR_LENGTH];
    x.copy_from_slice(&buf[1..]);
    let valid = prefix & B::Point::is_x_coordinate(&x);
    x.zeroize();
    valid
}

/// `SerializeElement(point)` with the prefix reduced to its low bit.
fn to_encoding<B: Backend>(point: &B::Point) -> Result<Encoding, Error> {
    let mut buf = point.to_bytes().ok_or(Error::InvalidInput)?;
    buf[0] -= 0x02;
    Ok(buf)
}

/// Decodes an encoding whose first byte is 0 or 1.
fn from_encoding<B: Backend>(buf: &Encoding) -> Option<B::Point> {
    let mut bytes = *buf;
    bytes[0] += 0x02;
    B::Point::from_bytes(&bytes).into_option()
}

/// Applies `step` to the encoding of `point` until the result decodes.
/// Not constant time; for public points only.
fn walk<B: Backend>(point: &B::Point, step: fn(&mut Encoding)) -> Result<B::Point, Error> {
    let mut buf = to_encoding::<B>(point)?;
    // The walk follows a cycle of a permutation of the encodings, which
    // returns to the start, so it ends.
    loop {
        step(&mut buf);
        if let Some(point) = from_encoding::<B>(&buf) {
            return Ok(point);
        }
    }
}

/// `G.P(point)`, for a public point other than the identity.
pub(crate) fn p<B: Backend>(point: &B::Point) -> Result<B::Point, Error> {
    walk::<B>(point, permute_bytes::<B>)
}

/// `G.Pinv(point)`, for a public point other than the identity. The
/// protocol walks backwards only inside [`permutation_pair`]; the tests
/// check this against the vectors.
#[cfg(test)]
pub(crate) fn p_inv<B: Backend>(point: &B::Point) -> Result<B::Point, Error> {
    walk::<B>(point, unpermute_bytes::<B>)
}

/// `G.PermutationPair(element, bind_left)`: `(Q, P(Q))` with
/// `P(Q) = element` if `bind_left` and `Q = element` otherwise.
///
/// Each iteration computes both one-step permutations and selects one in
/// constant time, and the loop ends at the first valid encoding, so the
/// operation schedule depends only on the output `Q`. `element` must not be
/// the identity.
pub(crate) fn permutation_pair<B: Backend>(
    element: &B::Point,
    bind_left: Choice,
) -> Result<(B::Point, B::Point), Error> {
    let mut start = to_encoding::<B>(element)?;
    let mut buf = start;
    loop {
        let mut forward = buf;
        permute_bytes::<B>(&mut forward);
        let mut backward = buf;
        unpermute_bytes::<B>(&mut backward);
        buf = select_bytes(&forward, &backward, bind_left);
        forward.zeroize();
        backward.zeroize();
        if bool::from(is_valid_permutation_encoding::<B>(&buf)) {
            break;
        }
    }
    let mut left = select_bytes(&start, &buf, bind_left);
    let mut right = select_bytes(&buf, &start, bind_left);
    start.zeroize();
    buf.zeroize();
    // Both ends are valid encodings: `start` of `element`, and `buf` by
    // the test that ended the loop.
    let q = from_encoding::<B>(&left).ok_or(Error::Derive);
    let pq = from_encoding::<B>(&right).ok_or(Error::Derive);
    left.zeroize();
    right.zeroize();
    Ok((q?, pq?))
}
