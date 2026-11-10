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

//! Known answers from an independent oracle, `tests/vectors/generate.py`,
//! which computes `expand_message_xmd` and the derivations with Python's
//! `hashlib` and integers and checks itself against RFC 9380, Appendix K.1;
//! and the limits of `expand_message_xmd`.

use crate::Error;
use crate::backend::{Backend, Point, Scalar};
use crate::hash::{BackendHashExt, XmdPrefix};

include!("../../tests/vectors/derivations.rs");

/// Every derivation, under the contexts of both protocols and under one
/// long enough that every tag exceeds 255 bytes.
fn oracle_derivations<B: Backend>() {
    let seed: [u8; 48] = core::array::from_fn(|i| i as u8);
    let secret: [u8; 32] = core::array::from_fn(|i| i as u8);
    let hex = |scalar: &B::Scalar| hex::encode(scalar.to_bytes());
    for vector in &DERIVATION_VECTORS {
        let context = vector.context.len();
        assert_eq!(
            hex(&B::hash_to_scalar(vector.context, &[b"example"])),
            vector.scalar,
            "{context}-byte context"
        );
        let scalars = B::derive_scalars(vector.context, &seed, b"test", 3).unwrap();
        assert_eq!(
            scalars.iter().map(hex).collect::<alloc::vec::Vec<_>>(),
            vector.scalars,
            "{context}-byte context"
        );
        let nonces = B::derive_nonces(
            vector.context,
            &secret,
            b"nonce",
            &[b"review-", b"fixture"],
            &seed,
            3,
        )
        .unwrap();
        assert_eq!(
            nonces.iter().map(hex).collect::<alloc::vec::Vec<_>>(),
            vector.nonces,
            "{context}-byte context"
        );
        assert_eq!(
            hex(&B::derive_key_scalar(vector.context, &seed, b"GenerateKeyPair").unwrap()),
            vector.key,
            "{context}-byte context"
        );
    }
}

/// Tags at and beyond 255 bytes, which RFC 9380, Section 5.3.3 shortens by
/// hashing, with the message and the tag each split across parts.
fn oversized_tags<B: Backend>() {
    for (length, expected) in TAG_VECTORS {
        let dst = alloc::vec![b'x'; length];
        let mut out = [0u8; 48];
        XmdPrefix::<B::Sha256>::new(&[b"a"]).expand_into(
            &[b"bc"],
            &[&dst[..200], &dst[200..]],
            &mut out,
        );
        assert_eq!(hex::encode(out), expected, "{length}-byte tag");
    }
    // Hash-to-curve shortens a long tag the same way. The drafts' Python
    // reference implementation, `G.HashToGroup(b"abc", DST=b"x" * 300)`.
    assert_eq!(
        hex::encode(
            B::hash_to_curve(&[b"abc"], &[&[b'x'; 300]])
                .unwrap()
                .to_bytes()
                .unwrap()
        ),
        "02dd38ff88d296b1ef65f2cf670395ef004a4d6a397b30bb293aafecd3e8bba7d0"
    );
}

/// The longest output is produced; a longer one is refused and its buffer
/// left untouched.
fn output_limits<B: Backend>() {
    const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let mut maximum = alloc::vec![0u8; 255 * 32];
    assert_eq!(
        XmdPrefix::<B::Sha256>::new(&[]).try_expand_into(&[], &[DST], &mut maximum),
        Ok(())
    );
    // The last block of the longest output is the 255th.
    assert_ne!(maximum[255 * 32 - 32..], [0; 32]);
    let mut too_long = alloc::vec![0x55u8; 255 * 32 + 1];
    assert_eq!(
        XmdPrefix::<B::Sha256>::new(&[]).try_expand_into(&[], &[DST], &mut too_long),
        Err(Error::InvalidInput)
    );
    assert!(too_long.iter().all(|byte| *byte == 0x55));
}

/// Panics as `expand_into` documents.
fn oversized_output<B: Backend>() {
    let mut out = alloc::vec![0u8; 255 * 32 + 1];
    XmdPrefix::<B::Sha256>::new(&[]).expand_into(&[], &[b"x"], &mut out);
}

backend_tests!(oracle_derivations, oversized_tags, output_limits);

#[cfg(feature = "rustcrypto")]
#[test]
#[should_panic(expected = "XMD length exceeds RFC 9380 limit")]
fn rustcrypto_oversized_output_panics() {
    oversized_output::<crate::backend::rustcrypto::RustCrypto>();
}

#[cfg(feature = "boringssl")]
#[test]
#[should_panic(expected = "XMD length exceeds RFC 9380 limit")]
fn boringssl_oversized_output_panics() {
    oversized_output::<crate::backend::boringssl::BoringSsl>();
}
