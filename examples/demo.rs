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

//! Issues a Credential and runs the four spend shapes with their refunds,
//! printing the message sizes and balances.

use act::{
    Backend, Credential, DefaultBackend, IssueRequestMessage, IssueResponseMessage, Params,
    RefundMessage, SecretKey, SpendMessage, finalize_issue, finalize_refund, issue_refund,
    issue_request, issue_response, prove_spend, verify_issue_request, verify_spend,
};

fn main() -> Result<(), act::Error> {
    let params: Params = Params::new(8)?;
    let ctx_cred = b"epoch-1";
    let key_seed = DefaultBackend::generate_seed()?;
    let key = SecretKey::from_seed(&key_seed)?;
    let public_key = key.public_key();

    // Issuance, through the wire encodings.
    let (state, request) = issue_request(&params)?;
    let request = IssueRequestMessage::from_bytes(&params, &request.to_bytes())?;
    let response = issue_response(&key, ctx_cred, 10, verify_issue_request(&params, &request)?)?;
    let response = IssueResponseMessage::from_bytes(&params, &response.to_bytes())?;
    let mut credential: Credential =
        finalize_issue(&params, &public_key, ctx_cred, state, &response)?;
    println!("issued: balance {}", credential.balance());

    // The Moderator's nullifier store, checked and updated atomically with
    // verification and the refund.
    let mut seen = std::collections::HashSet::new();

    for (name, s, a, t) in [
        ("ordinary spend", 3, 0, 1),
        ("refresh", 0, 0, 0),
        ("pure top-up", 0, 2, 2),
        ("spend with top-up", 3, 2, 5),
    ] {
        let ctx_spend = format!("challenge-{name}");
        let (state, spend) =
            prove_spend(&params, credential, ctx_cred, s, a, ctx_spend.as_bytes())?;
        let encoded = spend.to_bytes();
        let spend = SpendMessage::from_bytes(&params, &encoded)?;

        let verified = verify_spend(&params, &key, ctx_cred, ctx_spend.as_bytes(), &spend)?;
        assert!(seen.insert(verified.nullifier()), "nullifier reused");
        let refund = issue_refund(verified, t)?;

        let refund = RefundMessage::from_bytes(&params, &refund.to_bytes())?;
        credential = finalize_refund(&params, &public_key, ctx_cred, state, &refund)?;
        println!(
            "{name}: {} bytes, balance {}",
            encoded.len(),
            credential.balance()
        );
    }
    Ok(())
}
