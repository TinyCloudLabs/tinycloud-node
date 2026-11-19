//! A half-created network (a network row with no member, left by an earlier
//! create) answers as a missing network on every lookup, and a create through
//! the route completes it in place.

use super::encryption_keys::{invocation, owner_did, post_json};
use super::*;
use rocket::http::Status;
use serde_json::{json, Value};
use tinycloud_core::encryption_network::{
    canonical::canonical_hash,
    protocol::{NETWORK_ADMIN_TYPE, NETWORK_CREATE_ACTION},
    CreateNetworkRequest, EncryptionService, NetworkId, Threshold,
};
use tinycloud_core::models::{encryption_ceremony, encryption_network, encryption_network_member};
use tinycloud_core::sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, PaginatorTrait};

async fn get(fixture: &KvSyncFixture, uri: &str) -> (Status, String) {
    let response = fixture
        .client
        .get(uri.to_string())
        .remote("127.0.0.1:0".parse().expect("valid socket address"))
        .dispatch()
        .await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

#[tokio::test]
async fn half_created_network_is_missing_until_a_create_completes_it() -> Result<()> {
    let fixture = KvSyncFixture::new_configured(Config::default(), |rocket| {
        rocket.mount(
            "/",
            rocket::routes![
                crate::routes::encryption::create_network,
                crate::routes::encryption::get_network,
                crate::routes::encryption::well_known_network,
            ],
        )
    })
    .await?;
    let service = fixture
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed");
    let owner = owner_did(&fixture);
    let id = NetworkId::new(owner.clone(), "half".to_string())?;

    // What the earlier create left: the network row and a started ceremony,
    // no member.
    let generated = service
        .create_one_of_one_network(CreateNetworkRequest {
            name: "donor".to_string(),
            owner_did: owner.clone(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let donor = encryption_network::Entity::find_by_id(generated.network_id.to_string())
        .one(&fixture.conn)
        .await?
        .expect("donor row");
    encryption_network::ActiveModel {
        network_id: Set(id.to_string()),
        owner_did: Set(owner.clone()),
        name: Set("half".to_string()),
        alg: Set(donor.alg),
        key_version: Set(1),
        public_key: Set(donor.public_key),
        state: Set("active".to_string()),
        threshold_n: Set(1),
        threshold_t: Set(1),
        key_backend: Set(donor.key_backend),
        sealed_private_key: Set(donor.sealed_private_key),
        created_at: Set("2026-01-01T00:00:00Z".to_string()),
        updated_at: Set("2026-01-01T00:00:00Z".to_string()),
    }
    .insert(&fixture.conn)
    .await?;
    encryption_ceremony::ActiveModel {
        ceremony_id: Set("ceremony:old".to_string()),
        network_id: Set(id.to_string()),
        kind: Set("initial".to_string()),
        state: Set("started".to_string()),
        transcript_hash: Set(None),
        started_at: Set("2026-01-01T00:00:00Z".to_string()),
        completed_at: Set(None),
        failure: Set(None),
    }
    .insert(&fixture.conn)
    .await?;

    let by_id = format!("/encryption/networks/{id}");
    let well_known = format!("/.well-known/encryption/network/half?ownerDid={owner}");
    let missing = NetworkId::new(owner.clone(), "nope".to_string())?;
    let missing_by_id = get(&fixture, &format!("/encryption/networks/{missing}")).await;
    assert_eq!(missing_by_id.0, Status::NotFound);

    // The same answer as a network that does not exist.
    let (status, body) = get(&fixture, &by_id).await;
    assert_eq!(status, Status::NotFound);
    assert_eq!(body, missing_by_id.1);
    let missing_wk = get(
        &fixture,
        &format!("/.well-known/encryption/network/nope?ownerDid={owner}"),
    )
    .await;
    let (status, wk_body) = get(&fixture, &well_known).await;
    assert_eq!(status, Status::NotFound);
    assert_eq!(status, missing_wk.0);
    assert_eq!(wk_body, missing_wk.1);

    // A create completes it in place.
    let body = json!({"name": "half", "ownerDid": owner});
    let network = id.to_string();
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(network.as_str(), NETWORK_CREATE_ACTION)],
        vec![json!({
            "type": NETWORK_ADMIN_TYPE,
            "targetNode": fixture.node_did,
            "networkId": network,
            "action": NETWORK_CREATE_ACTION,
            "bodyHash": canonical_hash(&body),
        })],
    )?;
    let (status, created) = post_json(&fixture.client, "/encryption/networks", &auth, &body).await;
    assert_eq!(status, Status::Ok, "{created}");
    let created: Value = serde_json::from_str(&created)?;
    assert_eq!(created["descriptor"]["state"], "active");

    let (status, got) = get(&fixture, &by_id).await;
    assert_eq!(status, Status::Ok, "{got}");
    let got: Value = serde_json::from_str(&got)?;
    assert_eq!(got["descriptor"]["state"], "active");
    assert_eq!(
        got["descriptor"]["members"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(get(&fixture, &well_known).await.0, Status::Ok);
    let members = encryption_network_member::Entity::find()
        .count(&fixture.conn)
        .await?;
    assert_eq!(members, 2); // donor + repaired
    Ok(())
}
