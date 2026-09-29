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

//! Hashing and derivation under a protocol context: RFC 9380's
//! `expand_message_xmd` over SHA-256, and the group's `HashToGroup`,
//! `HashToScalar`, `DeriveScalars`, `SeedsToScalars`, `DeriveNonces`, and
//! `DeriveKeyPair`.
//!
//! These are the functions of act-rs's `hash` module, taking the protocol
//! context `ctx` as their first parameter and forming each domain
//! separation tag as a label followed by it, so that one copy can serve
//! both protocols. They are to move into a `mole-p256` crate shared with
//! act-rs; see the TODO in `lib.rs`.

use alloc::vec::Vec;

use subtle::CtOption;
use zeroize::{Zeroize, Zeroizing};

use crate::Error;
use crate::backend::{Backend, SCALAR_LENGTH, Scalar, Sha256};

/// The seed length `Nseed`.
pub(crate) const NSEED: usize = crate::SEED_LENGTH;

/// Output length of the `expand_message_xmd` calls that produce seeds and
/// scalars.
const XMD_LENGTH: usize = 48;

/// Length of the keys of `SeedsToScalars`, the hash output length `Nh`.
const NH: usize = 32;

/// `expand_message_xmd` with SHA-256 (RFC 9380, Section 5.3.1), with the
/// message split into a prefix absorbed once and a suffix supplied per call.
/// The domain separation tag is the concatenation of `dst`.
pub(crate) struct XmdPrefix<H: Sha256> {
    hasher: H,
}

impl<H: Sha256> XmdPrefix<H> {
    /// Absorbs `Z_pad || prefix`.
    pub(crate) fn new(prefix: &[&[u8]]) -> Self {
        let mut hasher = H::new();
        hasher.update(&[0u8; 64]);
        for part in prefix {
            hasher.update(part);
        }
        Self { hasher }
    }

    /// `expand_message_xmd(prefix || suffix, dst, XMD_LENGTH)`.
    pub(crate) fn expand(&self, suffix: &[&[u8]], dst: &[&[u8]]) -> [u8; XMD_LENGTH] {
        let mut out = [0u8; XMD_LENGTH];
        self.expand_into(suffix, dst, &mut out);
        out
    }

    /// `expand_message_xmd(prefix || suffix, dst, len(out))`.
    ///
    /// `dst` is at most 255 bytes and `out` at most `255 * 32` bytes; the
    /// tags of this crate are short and every output is 32 or 48 bytes.
    pub(crate) fn expand_into(&self, suffix: &[&[u8]], dst: &[&[u8]], out: &mut [u8]) {
        let dst_len = dst.iter().map(|part| part.len()).sum::<usize>();
        debug_assert!(dst_len <= 255 && out.len() <= 255 * 32);
        let dst_prime_tail = [dst_len as u8];
        let absorb_dst = |hasher: &mut H| {
            for part in dst {
                hasher.update(part);
            }
            hasher.update(&dst_prime_tail);
        };
        let mut hasher = self.hasher.clone();
        for part in suffix {
            hasher.update(part);
        }
        hasher.update(&(out.len() as u16).to_be_bytes());
        hasher.update(&[0]);
        absorb_dst(&mut hasher);
        let mut b0 = hasher.finalize();

        let mut previous = [0u8; 32];
        for (i, chunk) in out.chunks_mut(32).enumerate() {
            // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime); for
            // i = 1 the previous block is zero, so the xor leaves b_0.
            let mut block = b0;
            for (byte, prev) in block.iter_mut().zip(previous) {
                *byte ^= prev;
            }
            let mut hasher = H::new();
            hasher.update(&block);
            block.zeroize();
            hasher.update(&[i as u8 + 1]);
            absorb_dst(&mut hasher);
            previous = hasher.finalize();
            chunk.copy_from_slice(&previous[..chunk.len()]);
        }
        b0.zeroize();
        previous.zeroize();
    }
}

/// A scalar from a 24-byte big-endian integer, which is below the order.
fn scalar_from_u192<B: Backend>(bytes: &[u8]) -> B::Scalar {
    let mut padded = [0u8; SCALAR_LENGTH];
    padded[8..].copy_from_slice(bytes);
    let scalar = B::Scalar::from_bytes(&padded).unwrap_or(B::Scalar::default());
    padded.zeroize();
    scalar
}

/// The scalar `2^192`.
fn two_to_192<B: Backend>() -> B::Scalar {
    let mut bytes = [0u8; SCALAR_LENGTH];
    bytes[7] = 1;
    B::Scalar::from_bytes(&bytes).unwrap_or(B::Scalar::default())
}

/// Reduces a 48-byte big-endian integer modulo the order, in constant time,
/// as `hi * 2^192 + lo` over two canonical halves.
pub(crate) fn reduce_be_48<B: Backend>(bytes: &[u8; XMD_LENGTH]) -> B::Scalar {
    let (hi, lo) = bytes.split_at(24);
    scalar_from_u192::<B>(hi) * two_to_192::<B>() + scalar_from_u192::<B>(lo)
}

/// `G.HashToScalar(msg)`: `hash_to_field` with `L = 48` under the tag
/// `"HashToScalar-" || ctx`. `msg` is hashed as the concatenation of its
/// parts.
pub(crate) fn hash_to_scalar<B: Backend>(ctx: &[u8], msg: &[&[u8]]) -> B::Scalar {
    let mut uniform = XmdPrefix::<B::Sha256>::new(&[]).expand(msg, &[b"HashToScalar-", ctx]);
    let scalar = reduce_be_48::<B>(&uniform);
    uniform.zeroize();
    scalar
}

/// `G.HashToGroup(msg)`: `P256_XMD:SHA-256_SSWU_RO_` under the tag
/// `"HashToGroup-" || ctx`.
pub(crate) fn hash_to_group<B: Backend>(ctx: &[u8], msg: &[&[u8]]) -> Result<B::Point, Error> {
    B::hash_to_curve(msg, &[b"HashToGroup-", ctx]).ok_or(Error::Derive)
}

/// `G.DeriveScalars(rand, info)`: one scalar from each `Nseed` bytes of
/// `rand`, under a key that `info` determines.
pub(crate) fn derive_scalars<B: Backend>(
    ctx: &[u8],
    rand: &[u8],
    info: &[u8],
) -> Result<Zeroizing<Vec<B::Scalar>>, Error> {
    let info_len = u16::try_from(info.len()).map_err(|_| Error::InvalidInput)?;
    let mut key = [0u8; NH];
    XmdPrefix::<B::Sha256>::new(&[]).expand_into(
        &[&info_len.to_be_bytes(), info],
        &[b"DeriveScalars-", ctx],
        &mut key,
    );
    seeds_to_scalars::<B>(ctx, &key, rand)
}

/// `G.DeriveNonces(secret, label, instance, rand)`: one nonce from each
/// `Nseed` bytes of `rand`, under a key derived from the secret and the
/// operation. `instance` is supplied in parts and hashed as their
/// concatenation.
pub(crate) fn derive_nonces<B: Backend>(
    ctx: &[u8],
    secret: &[u8],
    label: &[u8],
    instance: &[&[u8]],
    rand: &[u8],
) -> Result<Zeroizing<Vec<B::Scalar>>, Error> {
    let label_len = u16::try_from(label.len()).map_err(|_| Error::InvalidInput)?;
    let secret_len = u32::try_from(secret.len()).map_err(|_| Error::InvalidInput)?;
    let instance_len = instance.iter().map(|part| part.len()).sum::<usize>();
    let instance_len = u32::try_from(instance_len).map_err(|_| Error::InvalidInput)?;
    let (label_len, secret_len, instance_len) = (
        label_len.to_be_bytes(),
        secret_len.to_be_bytes(),
        instance_len.to_be_bytes(),
    );
    let mut parts: Vec<&[u8]> = alloc::vec![&label_len, label, &secret_len, secret, &instance_len];
    parts.extend_from_slice(instance);
    let mut key = [0u8; NH];
    XmdPrefix::<B::Sha256>::new(&[]).expand_into(&parts, &[b"DeriveNonces-", ctx], &mut key);
    let nonces = seeds_to_scalars::<B>(ctx, &key, rand);
    key.zeroize();
    nonces
}

/// `G.SeedsToScalars(key, rand)`: a four-round Feistel network over all of
/// `rand`, keyed by `key`, then each `Nseed`-byte piece of the result
/// reduced modulo the order. The network is a permutation for every key, so
/// uniform input gives scalars each within about `2^-128` of uniform. With
/// the round functions modeled as random oracles, a change to any part of an
/// input chosen without reference to them changes every scalar, except with
/// negligible probability.
pub(crate) fn seeds_to_scalars<B: Backend>(
    ctx: &[u8],
    key: &[u8; NH],
    rand: &[u8],
) -> Result<Zeroizing<Vec<B::Scalar>>, Error> {
    if rand.is_empty() || rand.len() % NSEED != 0 {
        return Err(Error::InvalidInput);
    }
    let half = rand.len() / 2;
    let mut left = Zeroizing::new(rand[..half].to_vec());
    let mut right = Zeroizing::new(rand[half..].to_vec());
    let mut mask = Zeroizing::new(alloc::vec![0u8; half.div_ceil(XMD_LENGTH) * XMD_LENGTH]);
    for i in 0..4u8 {
        for (j, chunk) in mask.chunks_exact_mut(XMD_LENGTH).enumerate() {
            let j = u32::try_from(j).map_err(|_| Error::InvalidInput)?;
            XmdPrefix::<B::Sha256>::new(&[key, &[i], &j.to_be_bytes(), &right]).expand_into(
                &[],
                &[b"SeedsToScalars-", ctx],
                chunk,
            );
        }
        for (byte, m) in left.iter_mut().zip(mask.iter()) {
            *byte ^= m;
        }
        core::mem::swap(&mut left, &mut right);
    }
    // Copy into a buffer allocated at full size, so that no reallocation
    // frees secret bytes before they are wiped.
    let mut permuted = Zeroizing::new(Vec::with_capacity(rand.len()));
    permuted.extend_from_slice(&left);
    permuted.extend_from_slice(&right);
    let mut scalars = Zeroizing::new(Vec::with_capacity(permuted.len() / NSEED));
    let mut result = Ok(());
    for piece in permuted.chunks_exact(NSEED) {
        let piece: &[u8; XMD_LENGTH] = piece.try_into().map_err(|_| Error::InvalidInput)?;
        let scalar = reduce_be_48::<B>(piece);
        if bool::from(scalar.is_zero()) {
            result = Err(Error::Derive);
        }
        scalars.push(scalar);
    }
    result.map(|()| scalars)
}

/// The secret scalar of `G.DeriveKeyPair(seed, info)`, as in RFC 9497,
/// Section 3.2.1, under the tag `"DeriveKeyPair-" || ctx`.
///
/// The counter loop exits on the first nonzero output, a branch taken with
/// probability about `2^-256`; the draft specifies it.
pub(crate) fn derive_key_scalar<B: Backend>(
    ctx: &[u8],
    seed: &[u8; NSEED],
    info: &[u8],
) -> Result<B::Scalar, Error> {
    let info_len = u16::try_from(info.len()).map_err(|_| Error::InvalidInput)?;
    let prefix = XmdPrefix::<B::Sha256>::new(&[seed, &info_len.to_be_bytes(), info]);
    for counter in 0..=u8::MAX {
        let mut uniform = prefix.expand(&[&[counter]], &[b"DeriveKeyPair-", ctx]);
        let scalar = reduce_be_48::<B>(&uniform);
        uniform.zeroize();
        if !bool::from(scalar.is_zero()) {
            return Ok(scalar);
        }
    }
    Err(Error::Derive)
}

/// Checks that a `CtOption` holds a value, mapping absence to `error`.
pub(crate) fn require<T>(value: CtOption<T>, error: Error) -> Result<T, Error> {
    value.into_option().ok_or(error)
}
