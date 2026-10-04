use rollatini::{AnchorState, ClientState, DefaultBackend, PROTOCOL_CONTEXT, SecretKey};

fn anchor(bytes: &[u8]) -> bool {
    AnchorState::<DefaultBackend>::from_bytes(bytes).is_ok()
}

fn client(bytes: &[u8]) -> bool {
    ClientState::<DefaultBackend>::from_bytes(bytes).is_ok()
}

#[test]
fn restored_continuations_complete_and_reject_malformed_blobs() {
    let key: SecretKey = SecretKey::generate().unwrap();
    let (anchor_state, commitment) = rollatini::commit(b"epoch", b"session").unwrap();
    let (client_state, challenge) =
        rollatini::challenge(&key.public_key(), b"epoch", b"scope", &commitment).unwrap();
    let a = anchor_state.to_bytes();
    let c = client_state.to_bytes();
    drop(anchor_state);
    drop(client_state);
    let anchor_state = AnchorState::from_bytes(&a).unwrap();
    assert_eq!(anchor_state.session_id(), b"session");
    let client_state = ClientState::from_bytes(&c).unwrap();
    assert_eq!(*a, *anchor_state.to_bytes());
    assert_eq!(*c, *client_state.to_bytes());
    let response = rollatini::respond(&key, anchor_state, &challenge).unwrap();
    let endorsement = rollatini::finalize(&key.public_key(), client_state, &response).unwrap();
    rollatini::verify(&key.public_key(), &endorsement, b"epoch", b"scope").unwrap();

    let anchor_header = [b"AnchorState-", PROTOCOL_CONTEXT].concat();
    let client_header = [b"ClientState-", PROTOCOL_CONTEXT].concat();
    assert!(a.starts_with(&anchor_header));
    assert!(c.starts_with(&client_header));
    assert!(!anchor(&c) && !client(&a));

    for blob in [&a, &c] {
        for length in 0..blob.len() {
            assert!(!anchor(&blob[..length]) && !client(&blob[..length]));
        }
        let mut bad = blob.to_vec();
        bad.push(0);
        assert!(!anchor(&bad) && !client(&bad));
        bad.pop();
        bad[0] ^= 1;
        assert!(!anchor(&bad) && !client(&bad));
        bad[0] ^= 1;
        bad[anchor_header.len() - 1] ^= 1; // Another ciphersuite or version.
        assert!(!anchor(&bad) && !client(&bad));
    }

    // Scalars are last: a noncanonical one, then a zero one.
    for (blob, ok) in [(&a, anchor as fn(&[u8]) -> bool), (&c, client)] {
        let mut bad = blob.to_vec();
        let start = bad.len() - 32;
        bad[start..].fill(255);
        assert!(!ok(&bad));
        bad[start..].fill(0);
        assert!(!ok(&bad));
        // Two zero scalars, which must not cancel out.
        bad[start - 32..].fill(0);
        assert!(!ok(&bad));
    }

    let mut bad = c.to_vec();
    let point = client_header.len() + 32 + 1 + b"epoch".len();
    bad[point..point + 33].fill(0);
    assert!(!client(&bad));

    let mut bad = a.to_vec();
    bad[anchor_header.len()] = 0x40;
    bad.insert(anchor_header.len() + 1, 7); // A two-byte encoding of 7 is nonminimal.
    assert!(!anchor(&bad));
}
