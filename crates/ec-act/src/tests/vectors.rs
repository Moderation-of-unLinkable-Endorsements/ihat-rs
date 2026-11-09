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

//! Replays the draft's test vectors, and vectors generated from the
//! reference implementation at other balance widths, against every
//! algorithm and encoding. Every `rand` entry is served in place of
//! `random`, so each output must match byte for byte.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::Replay;
use crate::backend::{BackendFixedBaseExt, Point, Scalar};
use crate::protocol::{
    ClientIssuanceState, ClientSpendState, Credential, IssueRequestMessage, IssueResponseMessage,
    Params, RefundMessage, SecretKey, SpendMessage, finalize_issue, finalize_refund,
    issue_refund_with, issue_request_with, issue_response_with, prove_spend_with,
    verify_issue_request, verify_spend,
};

/// The draft's vectors, `L = 4`.
const DRAFT_L4: &str = include_str!("../../tests/vectors/draft-L4.txt");
const EXTENDED: [(&str, &str); 5] = [
    ("L1", include_str!("../../tests/vectors/act-L1.txt")),
    ("L2", include_str!("../../tests/vectors/act-L2.txt")),
    ("L8", include_str!("../../tests/vectors/act-L8.txt")),
    ("L16", include_str!("../../tests/vectors/act-L16.txt")),
    ("L64", include_str!("../../tests/vectors/act-L64.txt")),
];

/// Parses the draft's `key = value` blocks, joining continuation lines.
fn parse(text: &str) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("    ") {
            let (_, value) = current.as_mut().expect("continuation without key");
            value.push_str(rest.trim());
        } else if let Some((key, value)) = line.split_once(" =") {
            if let Some((key, value)) = current.take() {
                entries.insert(key, value);
            }
            current = Some((key.trim().to_string(), value.trim().to_string()));
        }
    }
    if let Some((key, value)) = current {
        entries.insert(key, value);
    }
    entries
}

struct Vectors(BTreeMap<String, String>);

impl Vectors {
    fn hex(&self, key: &str) -> Vec<u8> {
        hex::decode(self.0.get(key).unwrap_or_else(|| panic!("missing {key}"))).expect(key)
    }

    fn int(&self, key: &str) -> u64 {
        self.0
            .get(key)
            .unwrap_or_else(|| panic!("missing {key}"))
            .parse()
            .expect(key)
    }

    fn has(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }
}

fn replay<B: BackendFixedBaseExt>(text: &str) {
    let v = Vectors(parse(text));
    let params = Params::<B>::new(v.int("suite.L") as u8).unwrap();
    let ctx_cred = v.hex("suite.ctx_cred");

    if v.has("suite.H1") {
        assert_eq!(v.hex("suite.identifier"), crate::CIPHERSUITE_IDENTIFIER);
        assert_eq!(v.hex("suite.ctx_proto"), crate::PROTOCOL_CONTEXT);
        let gens = crate::tests::protocol::generators(&params);
        for (name, point) in ["H1", "H2", "H3", "H4"].into_iter().zip(gens) {
            let expected = v.hex(&alloc::format!("suite.{name}"));
            assert_eq!(point.to_bytes().unwrap().to_vec(), expected, "{name}");
        }
        let ctx = crate::tests::protocol::context_scalar::<B>(&ctx_cred);
        assert_eq!(ctx.to_vec(), v.hex("suite.ctx"));
    }

    let seed: [u8; crate::SEED_LENGTH] = v.hex("key.rand").try_into().unwrap();
    let key = SecretKey::<B>::from_seed(&seed).unwrap();
    assert_eq!(key.sk.to_bytes().to_vec(), v.hex("key.skM"));
    assert_eq!(key.public_key().to_bytes().to_vec(), v.hex("key.pkM"));
    let public_key = key.public_key();

    let mut rng = Replay::new(&v.hex("issue.request.rand"));
    let (state, request) = issue_request_with(&params, &mut rng).unwrap();
    rng.finish();
    assert_eq!(*state.to_bytes(), v.hex("issue.request.state"));
    assert_eq!(state.to_bytes().len(), ClientIssuanceState::<B>::LENGTH);
    let encoded = request.to_bytes();
    assert_eq!(encoded, v.hex("issue.request.message"));
    assert_eq!(encoded.len(), IssueRequestMessage::<B>::LENGTH);
    let request = IssueRequestMessage::from_bytes(&params, &encoded).unwrap();

    let c = v.int("issue.response.c");
    let mut rng = Replay::new(&v.hex("issue.response.rand"));
    let response = issue_response_with(
        &key,
        &ctx_cred,
        c,
        verify_issue_request(&params, &request).unwrap(),
        &mut rng,
    )
    .unwrap();
    rng.finish();
    let encoded = response.to_bytes();
    assert_eq!(encoded, v.hex("issue.response.message"));
    assert_eq!(encoded.len(), IssueResponseMessage::<B>::LENGTH);
    let response = IssueResponseMessage::from_bytes(&params, &encoded).unwrap();
    assert_eq!(response.balance(), c);

    let mut credential = finalize_issue(&params, &public_key, &ctx_cred, state, &response).unwrap();
    assert_eq!(*credential.to_bytes(), v.hex("issue.credential"));
    assert_eq!(credential.to_bytes().len(), Credential::<B>::LENGTH);
    assert_eq!(credential.balance(), c);

    for index in 1.. {
        let key_prefix = alloc::format!("spend{index}");
        if !v.has(&alloc::format!("{key_prefix}.s")) {
            assert!(index > 1, "no spends");
            break;
        }
        let s = v.int(&alloc::format!("{key_prefix}.s"));
        let a = v.int(&alloc::format!("{key_prefix}.a"));
        let ctx_spend = v.hex(&alloc::format!("{key_prefix}.ctx_spend"));
        let balance = credential.balance();

        let mut rng = Replay::new(&v.hex(&alloc::format!("{key_prefix}.rand")));
        let (state, spend) =
            prove_spend_with(&params, credential, &ctx_cred, s, a, &ctx_spend, &mut rng).unwrap();
        rng.finish();
        assert_eq!(
            *state.to_bytes(),
            v.hex(&alloc::format!("{key_prefix}.state"))
        );
        assert_eq!(state.remainder(), balance - s);
        assert_eq!(state.to_bytes().len(), ClientSpendState::<B>::LENGTH);
        let state = ClientSpendState::from_bytes(&params, &state.to_bytes()).unwrap();
        let encoded = spend.to_bytes();
        assert_eq!(encoded, v.hex(&alloc::format!("{key_prefix}.message")));
        assert_eq!(
            encoded.len(),
            SpendMessage::<B>::encoded_len(&params, s, a).unwrap()
        );
        let spend = SpendMessage::from_bytes(&params, &encoded).unwrap();
        assert_eq!((spend.amount(), spend.allowance()), (s, a));
        let verified = verify_spend(&params, &key, &ctx_cred, &ctx_spend, &spend).unwrap();

        let t = v.int(&alloc::format!("{key_prefix}.refund.t"));
        let mut rng = Replay::new(&v.hex(&alloc::format!("{key_prefix}.refund.rand")));
        let refund = issue_refund_with(verified, t, &mut rng).unwrap();
        rng.finish();
        let encoded = refund.to_bytes();
        assert_eq!(
            encoded,
            v.hex(&alloc::format!("{key_prefix}.refund.message"))
        );
        assert_eq!(encoded.len(), RefundMessage::<B>::LENGTH);
        let refund = RefundMessage::from_bytes(&params, &encoded).unwrap();
        assert_eq!(refund.return_amount(), t);

        credential = finalize_refund(&params, &public_key, &ctx_cred, state, &refund).unwrap();
        assert_eq!(
            *credential.to_bytes(),
            v.hex(&alloc::format!("{key_prefix}.credential"))
        );
        assert_eq!(credential.balance(), balance - s + t);
        let decoded = Credential::from_bytes(&params, &credential.to_bytes()).unwrap();
        assert_eq!(decoded.to_bytes(), credential.to_bytes());
    }
}

fn draft_l4<B: BackendFixedBaseExt>() {
    replay::<B>(DRAFT_L4);
}

fn extended<B: BackendFixedBaseExt>() {
    for (_name, text) in EXTENDED {
        replay::<B>(text);
    }
}

backend_tests!(draft_l4, extended);
