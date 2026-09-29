//! Issues Endorsements from several Anchors and redeems each at a Moderator
//! whose Anchor Set lists them all, printing the message sizes.

use rollatini::{
    ChallengeMessage, CommitMessage, Endorsement, PublicKey, Redemption, ResponseMessage,
    SecretKey, challenge, commit, finalize, redeem, respond, verify, verify_redemption,
};

fn main() -> Result<(), rollatini::Error> {
    let ctx_iss = b"epoch-1";
    let ctx_red = b"moderator.example";

    // Eight Anchors; the Moderator accepts Endorsements from any of them.
    let anchors: Vec<SecretKey> = (0..8)
        .map(|_| SecretKey::generate())
        .collect::<Result<_, _>>()?;
    let anchor_set: Vec<PublicKey> = anchors.iter().map(SecretKey::public_key).collect();

    // The Moderator's nullifier store.
    let mut seen = std::collections::HashSet::new();

    for (index, anchor) in anchors.iter().enumerate().step_by(3) {
        let public_key = anchor.public_key();

        // Issuance, through the wire encodings.
        let session_id = format!("session-{index}");
        let (state, commitment) = commit(ctx_iss, session_id.as_bytes())?;
        let commitment = CommitMessage::from_bytes(&commitment.to_bytes())?;
        let (client, challenge_message) = challenge(&public_key, ctx_iss, ctx_red, &commitment)?;
        let challenge_message = ChallengeMessage::from_bytes(&challenge_message.to_bytes())?;
        let response = respond(anchor, state, &challenge_message)?;
        let response = ResponseMessage::from_bytes(&response.to_bytes())?;
        let endorsement: Endorsement = finalize(&public_key, client, &response)?;
        verify(&public_key, &endorsement, ctx_iss, ctx_red)?;

        // Redemption against the whole Anchor Set.
        let challenge_digest = format!("moderator-challenge-{index}");
        let redemption = redeem(
            &anchor_set,
            index,
            endorsement,
            ctx_iss,
            ctx_red,
            challenge_digest.as_bytes(),
        )?;
        let encoded = redemption.to_bytes();
        let redemption = Redemption::from_bytes(&encoded, anchor_set.len())?;
        let nf = verify_redemption(
            &anchor_set,
            &redemption,
            ctx_iss,
            ctx_red,
            challenge_digest.as_bytes(),
        )?;
        assert!(seen.insert(nf), "nullifier reused");
        println!(
            "Endorsement from Anchor {index}: redemption of {} bytes against {} Anchors",
            encoded.len(),
            anchor_set.len()
        );
    }
    Ok(())
}
