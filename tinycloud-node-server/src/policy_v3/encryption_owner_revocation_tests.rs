//! TC-3858: the wallet that owns an encryption network revokes a grant its
//! session key issued on the network, one of its keys or a key prefix, over
//! the generic `POST /revoke` (SIWE), directly or through an exact-CID revoke
//! control it issues. The delegatee and other wallets are still refused.

use super::test_harness::*;
use super::*;
use serde_json::json;

const DECRYPT: &str = "tinycloud.encryption/decrypt";
const REVOKE: &str = "tinycloud.delegation/revoke";
const UNAUTHORIZED_REVOKER: &str = "Unauthorized Revoker";

async fn the_network_owner_wallet_revokes_its_session_keys_encryption_grants(
    backend: Backend,
) -> anyhow::Result<()> {
    // Named keys on needs a deletion ledger path.
    let ledger_dir = tempfile::tempdir()?;
    let ledger_path = ledger_dir.path().join("deletion-ledger.jsonl");
    let Some(h) = Harness::new_with(
        backend,
        Shape::PkhSession,
        "the_network_owner_wallet_revokes_its_session_keys_encryption_grants",
        |config| {
            config.encryption_network.named_keys_v1 = true;
            config.encryption_network.deletion_ledger_path = Some(ledger_path);
        },
    )
    .await?
    else {
        return Ok(());
    };
    let resources = [
        h.network.clone(),
        format!("{}/secrets/x", h.network),
        format!("{}/secrets/", h.network),
    ];
    let session = h
        .grant_owner_with(
            &resources
                .iter()
                .map(|resource| (resource.clone(), DECRYPT))
                .collect::<Vec<_>>(),
            Window::until(now() + Duration::days(1)),
        )
        .await?;
    let stranger = Signer::pkh();
    for resource in &resources {
        // The session key delegates decrypt on `resource` to a child.
        let issue = |child: &Signer| -> anyhow::Result<String> {
            h.owner.delegate(
                child.did(),
                &[(resource.clone(), DECRYPT)],
                Window::until(now() + Duration::hours(1)),
                &[session.parse()?],
            )
        };

        let child = Signer::key();
        let grant = h.import(issue(&child)?).await?;
        for (label, signer) in [("another wallet", &stranger), ("the delegatee", &child)] {
            assert_eq!(
                h.post_revoke(signer.revoke(&grant)?).await,
                (Status::Forbidden, UNAUTHORIZED_REVOKER.to_owned()),
                "{resource}: {label}"
            );
        }
        assert_eq!(
            h.delegation_status(&h.owner, &grant).await?["status"],
            json!("active"),
            "{resource}"
        );
        h.revoke(&h.space_owner, &grant).await?;
        assert_eq!(
            h.delegation_status(&h.owner, &grant).await?["status"],
            json!("revoked"),
            "{resource}"
        );

        // The wallet hands revocation of exactly one such grant to a device.
        let child = Signer::key();
        let grant = h.import(issue(&child)?).await?;
        let device = Signer::key();
        let control = h
            .import(h.space_owner.delegate(
                device.did(),
                &[(format!("urn:cid:{grant}"), REVOKE)],
                Window::until(now() + Duration::hours(1)),
                &[],
            )?)
            .await?;
        let (status, body) = h
            .post_revoke(device.revoke_citing(&grant, &[control.parse()?])?)
            .await;
        assert_eq!(status, Status::Ok, "{resource} via control: {body}");
        assert_eq!(
            h.delegation_status(&h.owner, &grant).await?["status"],
            json!("revoked"),
            "{resource} via control"
        );
    }
    Ok(())
}
on_both_backends!(the_network_owner_wallet_revokes_its_session_keys_encryption_grants);
