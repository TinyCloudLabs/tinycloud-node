//! A network this node holds a threshold member key for is never created as a
//! plain one: `POST /encryption/networks` answers 409
//! `pending_threshold_member` while any member key record for it exists, and
//! key routes see no network.

use super::encryption_keys::{create, invocation, owner_did, post_json};
use super::*;
use crate::threshold_member::{LocalIdentity, MemberHoldings, MemberKeys, PENDING_KEY_TTL};
use rocket::http::Status;
use serde_json::{json, Value};
use std::time::{Duration, SystemTime};
use tinycloud_core::encryption_network::{
    canonical::canonical_hash,
    protocol::{NETWORK_ADMIN_TYPE, NETWORK_CREATE_ACTION},
    NetworkId,
};

struct HoldsNothing;

impl MemberHoldings for HoldsNothing {
    fn holds_share_or_candidate(&self, _: &NetworkId) -> anyhow::Result<bool> {
        Ok(false)
    }
}

fn identity() -> LocalIdentity {
    LocalIdentity {
        app_id: "0b1c3a7e9f2d4c6b8a0e1f2d3c4b5a6978877665".into(),
        instance_id: "5f4e3d2c1b0a99887766554433221100ffeeddcc".into(),
    }
}

/// POST a valid plain create of `network`.
async fn create_network(fixture: &KvSyncFixture, network: &NetworkId) -> Result<(Status, String)> {
    let body = json!({"name": network.name(), "ownerDid": network.owner_did()});
    let id = network.to_string();
    let auth = invocation(
        fixture,
        &fixture.node_did,
        &[(id.as_str(), NETWORK_CREATE_ACTION)],
        vec![json!({
            "type": NETWORK_ADMIN_TYPE,
            "targetNode": fixture.node_did,
            "networkId": id,
            "action": NETWORK_CREATE_ACTION,
            "bodyHash": canonical_hash(&body),
        })],
    )?;
    Ok(post_json(&fixture.client, "/encryption/networks", &auth, &body).await)
}

#[tokio::test]
async fn a_plain_create_is_refused_while_a_member_key_exists() -> Result<()> {
    let share = tempfile::tempdir()?;
    let mut config = Config::default();
    config.encryption_network.named_keys_v1 = true;
    let fixture = KvSyncFixture::new_configured(config, |rocket| {
        rocket
            .mount(
                "/",
                rocket::routes![
                    crate::routes::encryption::create_network,
                    crate::routes::encryption::create_encryption_key,
                ],
            )
            .manage(MemberKeys::new(share.path()))
    })
    .await?;
    let keys = fixture
        .client
        .rocket()
        .state::<MemberKeys>()
        .expect("MemberKeys is managed");
    let network = NetworkId::new(owner_did(&fixture), "vault".to_string())?;
    let now = SystemTime::now();
    keys.admit(&network, &identity(), &HoldsNothing, now, &mut Vec::new())?;

    let (status, body) = create_network(&fixture, &network).await?;
    assert_eq!(status, Status::Conflict, "{body}");
    assert!(body.contains("pending_threshold_member"), "{body}");
    // Key routes see no network N.
    let (status, body) = create(&fixture, &network.to_string(), "docs/a", false).await?;
    assert_eq!(status, Status::NotFound, "{body}");

    // Once the pending key expires, the plain create succeeds.
    let mut audit = Vec::new();
    keys.expire_pending(
        &HoldsNothing,
        &identity(),
        now + PENDING_KEY_TTL + Duration::from_secs(1),
        &mut audit,
    )?;
    assert_eq!(audit.len(), 1);
    let (status, body) = create_network(&fixture, &network).await?;
    assert_eq!(status, Status::Ok, "{body}");
    let created: Value = serde_json::from_str(&body)?;
    assert_eq!(created["descriptor"]["state"], "active");
    Ok(())
}
