//! TC-2381: a revocation refusal carries a stable machine-readable `code`
//! next to the human text, so clients never match the text.
//!
//! `delegation_revoked`: the delegation the invocation cites. `parent_revoked`:
//! a direct parent of the delegation being invoked or registered.
//! `ancestor_revoked`: a higher ancestor.

use super::*;
use rocket::http::{Header, Status};
use serde_json::Value;
use tinycloud_auth::{
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::hash::Hash;

impl KvSyncFixture {
    /// A `kv/sync` chain `owner -> device` of `depth` grants, each citing the
    /// one before. Returns the ids from root to leaf.
    async fn sync_chain(&self, label: &str, depth: usize) -> Result<Vec<Hash>> {
        let owner = self.space.did().to_string();
        let device = self.device_did();
        let mut chain: Vec<Hash> = Vec::new();
        for level in 0..depth {
            let (delegator, parents) = match chain.last() {
                Some(parent) => (device.as_str(), vec![*parent]),
                None => (owner.as_str(), vec![]),
            };
            chain.push(
                self.grant(
                    &format!("{label}-{level}"),
                    delegator,
                    &device,
                    &[("notes/", "tinycloud.kv/sync")],
                    None,
                    Some(whole_seconds_from_now(3600)),
                    &parents,
                )
                .await?,
            );
        }
        Ok(chain)
    }

    /// POST a delegation `issuer -> audience` of `kv/get` citing `proof`.
    async fn post_delegation(
        &self,
        label: &str,
        issuer: (&JWK, &str),
        audience: &str,
        proof: &[Hash],
    ) -> Result<(SyncReply, Option<Hash>)> {
        let mut capabilities = Capabilities::new();
        capabilities.with_action(
            self.kv_resource("")?.as_uri(),
            "tinycloud.kv/get".parse::<UcanAbility>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
        let token = Payload {
            issuer: issuer.1.parse::<DIDURLBuf>()?,
            audience: audience.parse::<DIDBuf>()?,
            not_before: None,
            expiration: NumericDate::try_from_seconds(
                whole_seconds_from_now(3000).unix_timestamp() as f64,
            )?,
            nonce: Some(format!("urn:uuid:tc2381-{label}")),
            facts: Some(Vec::<Value>::new()),
            proof: proof.iter().map(|id| id.to_cid(0x55)).collect(),
            attenuation: capabilities,
        }
        .sign(issuer.0.get_algorithm().unwrap_or_default(), issuer.0)?
        .encode()?;
        let response = self
            .client
            .post("/delegate")
            .header(Header::new("Authorization", token))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let json: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let cid = json["cid"]
            .as_str()
            .and_then(|cid| cid.parse::<tinycloud_auth::ipld_core::cid::Cid>().ok())
            .map(Hash::from);
        Ok((SyncReply { status, body, json }, cid))
    }
}

#[tokio::test]
async fn invoking_a_revoked_delegation_is_delegation_revoked() -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let chain = fixture.sync_chain("invoked", 1).await?;
    assert_eq!(
        fixture.sync("notes/", chain[0], &[]).await?.status,
        Status::Ok
    );
    fixture.revoke("tc2381-invoked", chain[0]).await?;
    let reply = fixture.sync("notes/", chain[0], &[]).await?;
    assert_code(&reply, "delegation_revoked");
    Ok(())
}

#[tokio::test]
async fn invoking_under_a_revoked_parent_is_parent_revoked() -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let chain = fixture.sync_chain("parent", 2).await?;
    assert_eq!(
        fixture.sync("notes/", chain[1], &[]).await?.status,
        Status::Ok
    );
    fixture.revoke("tc2381-parent", chain[0]).await?;
    let reply = fixture.sync("notes/", chain[1], &[]).await?;
    assert_code(&reply, "parent_revoked");
    Ok(())
}

#[tokio::test]
async fn invoking_under_a_revoked_higher_ancestor_is_ancestor_revoked() -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let chain = fixture.sync_chain("ancestor", 3).await?;
    assert_eq!(
        fixture.sync("notes/", chain[2], &[]).await?.status,
        Status::Ok
    );
    fixture.revoke("tc2381-ancestor", chain[0]).await?;
    let reply = fixture.sync("notes/", chain[2], &[]).await?;
    assert_code(&reply, "ancestor_revoked");
    Ok(())
}

#[tokio::test]
async fn a_refusal_that_is_not_a_revocation_has_no_code() -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let chain = fixture.sync_chain("plain", 1).await?;
    let header = fixture.device_invocation(&[("notes/", "tinycloud.kv/put")], chain[0])?;
    let reply = fixture.dispatch(header, &[]).await;
    assert_eq!(reply.status, Status::Unauthorized, "{}", reply.body);
    assert!(reply.json["code"].is_null(), "{}", reply.body);
    Ok(())
}

#[tokio::test]
async fn delegating_under_a_revoked_parent_is_parent_revoked() -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let root = fixture
        .signed_root_grant(
            "tc2381-parent",
            "tinycloud.kv/get",
            whole_seconds_from_now(3600),
            false,
        )
        .await?;
    let device = (&fixture.device, fixture.device_vm.as_str());
    let (reply, _) = fixture
        .post_delegation(
            "live-child",
            device,
            &fixture.space.did().to_string(),
            &[root],
        )
        .await?;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    fixture.revoke("tc2381-parent-revoke", root).await?;
    let (reply, _) = fixture
        .post_delegation(
            "dead-child",
            device,
            &fixture.space.did().to_string(),
            &[root],
        )
        .await?;
    assert_code(&reply, "parent_revoked");
    Ok(())
}

#[tokio::test]
async fn delegating_under_a_revoked_higher_ancestor_is_ancestor_revoked() -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let owner_did = fixture.space.did().to_string();
    let root = fixture
        .signed_root_grant(
            "tc2381-ancestor",
            "tinycloud.kv/get",
            whole_seconds_from_now(3600),
            false,
        )
        .await?;
    // device -> device, then device -> owner: the root is the grandparent.
    // (A delegation issued by the space owner needs no proof, so the leaf
    // must come from the device.)
    let device = (&fixture.device, fixture.device_vm.as_str());
    let (reply, middle) = fixture
        .post_delegation("middle", device, &fixture.device_did(), &[root])
        .await?;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    let middle = middle.expect("middle delegation cid");
    fixture.revoke("tc2381-ancestor-revoke", root).await?;
    let (reply, _) = fixture
        .post_delegation("leaf", device, &owner_did, &[middle])
        .await?;
    assert_code(&reply, "ancestor_revoked");
    Ok(())
}

// Every other route that refuses a revoked grant with a 401 carries the same
// code. A grant is revoked before it is used, so each request is refused on
// revocation whatever else it asks for.

use rocket::http::ContentType;
use serde_json::json;
use tinycloud_core::encryption_network::{
    CreateNetworkRequest, EncryptionService, Threshold, DECRYPT_ACTION, KEY_BLOCK_ACTION,
    KEY_CREATE_ACTION, KEY_UNBLOCK_ACTION,
};

impl KvSyncFixture {
    /// A device invocation to `audience` of `caps` (resource URI, ability)
    /// citing `proof`.
    fn invocation_citing(
        &self,
        audience: &str,
        caps: &[(String, &str)],
        proof: Hash,
    ) -> Result<String> {
        let mut capabilities = Capabilities::new();
        for (uri, action) in caps {
            capabilities.with_action(
                uri.parse()?,
                action.parse::<UcanAbility>()?,
                [std::collections::BTreeMap::<String, Value>::new()],
            );
        }
        Ok(Payload {
            issuer: self.device_vm.parse::<DIDURLBuf>()?,
            audience: audience.parse::<DIDBuf>()?,
            not_before: None,
            expiration: test_invocation_expiration(),
            nonce: Some(self.next_nonce()),
            facts: Some(Vec::<Value>::new()),
            proof: vec![proof.to_cid(0x55)],
            attenuation: capabilities,
        }
        .sign(
            self.device.get_algorithm().unwrap_or_default(),
            &self.device,
        )?
        .encode()?)
    }

    async fn revoked_grant(&self) -> Result<Hash> {
        let chain = self.sync_chain("route", 1).await?;
        self.revoke("tc2381-route", chain[0]).await?;
        Ok(chain[0])
    }

    async fn post_with(&self, uri: &str, auth: String, body: Option<Value>) -> Result<SyncReply> {
        let mut request = self
            .client
            .post(uri.to_string())
            .header(Header::new("Authorization", auth));
        if let Some(body) = body {
            request = request.header(ContentType::JSON).body(body.to_string());
        }
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);
        Ok(SyncReply { status, body, json })
    }
}

fn assert_code(reply: &SyncReply, code: &str) {
    assert_eq!(reply.status, Status::Unauthorized, "{}", reply.body);
    assert_eq!(reply.json["code"], Value::from(code), "{}", reply.body);
}

async fn encryption_fixture() -> Result<(KvSyncFixture, String)> {
    let fixture = KvSyncFixture::new_with(|rocket| {
        rocket
            .mount(
                "/",
                rocket::routes![
                    crate::routes::encryption::create_network,
                    crate::routes::encryption::revoke_network,
                    crate::routes::encryption::create_encryption_key,
                    crate::routes::encryption::describe_encryption_key,
                    crate::routes::encryption::block_encryption_key,
                    crate::routes::encryption::unblock_encryption_key,
                    crate::routes::encryption::decrypt,
                ],
            )
            .manage(crate::routes::public::RateLimiter::new(
                &crate::config::PublicSpacesConfig::default(),
            ))
    })
    .await?;
    let network = fixture
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed")
        .create_one_of_one_network(CreateNetworkRequest {
            name: "net".to_string(),
            owner_did: super::encryption_keys::owner_did(&fixture),
            threshold: Threshold::one_of_one(),
        })
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?
        .network_id
        .to_string();
    Ok((fixture, network))
}

#[tokio::test]
async fn signed_kv_url_under_a_revoked_grant_is_delegation_revoked() -> Result<()> {
    let fixture = KvSyncFixture::new_with(|rocket| {
        rocket
            .mount("/", rocket::routes![create_signed_kv_url])
            .manage(crate::signed_urls::SignedUrlRuntime::new([33; 32]))
    })
    .await?;
    let grant = fixture.revoked_grant().await?;
    let auth = fixture.device_invocation(&[("notes/a", "tinycloud.kv/get")], grant)?;
    let reply = fixture
        .post_with(
            "/signed/kv",
            auth,
            Some(json!({ "space": fixture.space.to_string(), "path": "notes/a" })),
        )
        .await?;
    assert_code(&reply, "delegation_revoked");
    Ok(())
}

#[tokio::test]
async fn encryption_create_network_under_a_revoked_grant_is_delegation_revoked() -> Result<()> {
    let (fixture, _) = encryption_fixture().await?;
    let grant = fixture.revoked_grant().await?;
    let auth = fixture.invocation_citing(
        &fixture.node_did,
        &[(
            fixture.kv_resource("notes/a")?.as_uri().to_string(),
            "tinycloud.kv/get",
        )],
        grant,
    )?;
    let reply = fixture
        .post_with("/encryption/networks", auth, Some(json!({})))
        .await?;
    assert_code(&reply, "delegation_revoked");
    Ok(())
}

#[tokio::test]
async fn encryption_revoke_network_under_a_revoked_grant_is_delegation_revoked() -> Result<()> {
    let (fixture, network) = encryption_fixture().await?;
    let grant = fixture.revoked_grant().await?;
    let auth = fixture.invocation_citing(
        &fixture.node_did,
        &[(network.clone(), "tinycloud.encryption/revoke")],
        grant,
    )?;
    let reply = fixture
        .post_with(
            &format!("/encryption/networks/{network}/revoke"),
            auth,
            None,
        )
        .await?;
    assert_code(&reply, "delegation_revoked");
    Ok(())
}

async fn key_route_refusal(
    fixture: &KvSyncFixture,
    network: &str,
    uri: String,
    ability: &str,
    body: Value,
) -> Result<SyncReply> {
    let grant = fixture.revoked_grant().await?;
    let auth = fixture.invocation_citing(
        &fixture.node_did,
        &[(format!("{network}/docs/a"), ability)],
        grant,
    )?;
    fixture.post_with(&uri, auth, Some(body)).await
}

#[tokio::test]
async fn encryption_create_key_under_a_revoked_grant_is_delegation_revoked() -> Result<()> {
    let (fixture, network) = encryption_fixture().await?;
    let reply = key_route_refusal(
        &fixture,
        &network,
        format!("/encryption/networks/{network}/keys"),
        KEY_CREATE_ACTION,
        json!({"keyPath": "docs/a", "deletable": false}),
    )
    .await?;
    assert_code(&reply, "delegation_revoked");
    Ok(())
}

#[tokio::test]
async fn encryption_block_key_under_a_revoked_grant_is_delegation_revoked() -> Result<()> {
    let (fixture, network) = encryption_fixture().await?;
    let reply = key_route_refusal(
        &fixture,
        &network,
        format!("/encryption/networks/{network}/key-actions/block"),
        KEY_BLOCK_ACTION,
        json!({"keyPath": "docs/a"}),
    )
    .await?;
    assert_code(&reply, "delegation_revoked");
    Ok(())
}

#[tokio::test]
async fn encryption_unblock_key_under_a_revoked_grant_is_delegation_revoked() -> Result<()> {
    let (fixture, network) = encryption_fixture().await?;
    let reply = key_route_refusal(
        &fixture,
        &network,
        format!("/encryption/networks/{network}/key-actions/unblock"),
        KEY_UNBLOCK_ACTION,
        json!({"keyPath": "docs/a"}),
    )
    .await?;
    assert_code(&reply, "delegation_revoked");
    Ok(())
}

#[tokio::test]
async fn encryption_describe_key_under_a_revoked_grant_is_delegation_revoked() -> Result<()> {
    let (fixture, network) = encryption_fixture().await?;
    let grant = fixture.revoked_grant().await?;
    let auth = fixture.invocation_citing(
        &fixture.node_did,
        &[(format!("{network}/docs/a"), KEY_CREATE_ACTION)],
        grant,
    )?;
    let response = fixture
        .client
        .get(format!("/encryption/networks/{network}/keys/docs/a"))
        .remote("127.0.0.1:0".parse()?)
        .header(Header::new("Authorization", auth))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    let json = serde_json::from_str(&body).unwrap_or(Value::Null);
    assert_code(&SyncReply { status, body, json }, "delegation_revoked");
    Ok(())
}

#[tokio::test]
async fn encryption_decrypt_under_a_revoked_grant_is_delegation_revoked() -> Result<()> {
    let (fixture, network) = encryption_fixture().await?;
    let grant = fixture.revoked_grant().await?;
    let auth = fixture.invocation_citing(
        &fixture.node_did,
        &[(network.clone(), DECRYPT_ACTION)],
        grant,
    )?;
    let reply = fixture
        .post_with(
            &format!("/encryption/networks/{network}/decrypt"),
            auth,
            Some(json!({"networkId": network})),
        )
        .await?;
    assert_code(&reply, "delegation_revoked");
    Ok(())
}
