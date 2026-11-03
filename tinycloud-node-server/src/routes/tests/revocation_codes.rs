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

fn assert_revoked(reply: &SyncReply, code: &str, text: &str) {
    assert_eq!(reply.status, Status::Unauthorized, "{}", reply.body);
    assert_eq!(reply.json["code"], Value::from(code), "{}", reply.body);
    // The human text stays, whole, next to the code.
    let error = reply.json["error"].as_str().unwrap_or_default();
    assert!(error.starts_with(text), "{}", reply.body);
}

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
    assert_revoked(&reply, "delegation_revoked", "delegation-revoked: ");
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
    assert_revoked(&reply, "parent_revoked", "delegation-ancestor-revoked: ");
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
    assert_revoked(&reply, "ancestor_revoked", "delegation-ancestor-revoked: ");
    Ok(())
}

#[tokio::test]
async fn a_refusal_that_is_not_a_revocation_has_no_code() -> Result<()> {
    let fixture = KvSyncFixture::new().await?;
    let chain = fixture.sync_chain("plain", 1).await?;
    let header = fixture.device_invocation(&[("notes/", "tinycloud.kv/put")], chain[0])?;
    let reply = fixture.dispatch(header, &[]).await;
    assert_eq!(reply.status, Status::Unauthorized, "{}", reply.body);
    assert!(
        reply.body.starts_with("Unauthorized Action"),
        "{}",
        reply.body
    );
    assert_eq!(reply.json, Value::Null);
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
    assert_revoked(&reply, "parent_revoked", "delegation-parent-revoked: ");
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
    assert_revoked(&reply, "ancestor_revoked", "delegation-ancestor-revoked: ");
    Ok(())
}
