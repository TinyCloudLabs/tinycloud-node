use super::*;
use rocket::http::{Header, Status};
use tinycloud_auth::{
    ipld_core::cid::Cid,
    ssi::{claims::jwt::NumericDate, dids::DIDURLBuf, ucan::Payload},
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::Hash,
    models::{abilities as ability_model, delegation, revocation},
    sea_orm::{ActiveModelTrait, ActiveValue::Set, PaginatorTrait},
};

async fn stored_revoked(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    target: &Hash,
) -> Result<bool> {
    Ok(revocation::Entity::find()
        .filter(revocation::Column::Revoked.eq(*target))
        .one(conn)
        .await?
        .is_some())
}

async fn scoped_fixture() -> Result<KvSyncFixture> {
    KvSyncFixture::new_with(|rocket| rocket.mount("/", routes![revoke])).await
}

#[tokio::test]
async fn owner_space_revoke_proof_cannot_revoke_another_space_of_same_owner() -> Result<()> {
    use rocket::http::{Header, Status};
    use tinycloud_auth::ssi::{
        dids::{DIDBuf, DIDURLBuf},
        ucan::Payload,
    };
    use tinycloud_auth::ucan_capabilities_object::Capabilities;
    use tinycloud_core::models::{actor, space as space_model};
    use tinycloud_core::sea_orm::{ActiveModelTrait, ActiveValue::Set};
    use tinycloud_core::types::SpaceIdWrap;

    let fixture = scoped_fixture().await?;
    let other_space = SpaceId::new(fixture.space.did().to_string().parse()?, "other".parse()?);
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(other_space.clone())),
    }
    .insert(&fixture.conn)
    .await?;
    let owner_did = fixture.space.did().to_string();
    let device_did = fixture.device_did();
    let target_in_other = fixture
        .grant_in(
            "cross-space-revoke-target",
            &owner_did,
            &device_did,
            &[(&other_space, "notes/", "tinycloud.kv/get")],
            None,
            Some(whole_seconds_from_now(3600)),
            &[],
        )
        .await?;
    let foreign = JWK::generate_ed25519()?;
    let foreign_did = KvSyncFixture::did_of(&tc341_verification_method(&foreign)?);
    actor::ActiveModel {
        id: Set(foreign_did.clone()),
    }
    .insert(&fixture.conn)
    .await?;
    let parent_in_other = fixture
        .grant_in(
            "cross-space-import-parent",
            &owner_did,
            &foreign_did,
            &[(&other_space, "notes/", "tinycloud.kv/get")],
            None,
            Some(whole_seconds_from_now(3600)),
            &[],
        )
        .await?;
    let imported_target_in_other = fixture
        .grant_in(
            "cross-space-import-target",
            &foreign_did,
            &device_did,
            &[(&other_space, "notes/", "tinycloud.kv/get")],
            None,
            Some(whole_seconds_from_now(3600)),
            &[parent_in_other],
        )
        .await?;
    let target_in_control_space = fixture
        .grant(
            "same-space-revoke-target",
            &owner_did,
            &device_did,
            &[("notes/", "tinycloud.kv/get")],
            None,
            Some(whole_seconds_from_now(3600)),
            &[],
        )
        .await?;
    let outside_owner = JWK::generate_ed25519()?;
    let outside_did = KvSyncFixture::did_of(&tc341_verification_method(&outside_owner)?);
    actor::ActiveModel {
        id: Set(outside_did.clone()),
    }
    .insert(&fixture.conn)
    .await?;
    let outside_space = SpaceId::new(outside_did.parse()?, "files".parse()?);
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(outside_space.clone())),
    }
    .insert(&fixture.conn)
    .await?;
    let outside_target = fixture
        .grant_in(
            "foreign-owner-revoke-target",
            &outside_did,
            &device_did,
            &[(&outside_space, "notes/", "tinycloud.kv/get")],
            None,
            Some(whole_seconds_from_now(3600)),
            &[],
        )
        .await?;

    let mut control_caps = Capabilities::new();
    control_caps.with_action(
        fixture
            .resource_in(&fixture.space, "delegation", "")?
            .as_uri(),
        "tinycloud.delegation/revoke".parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );
    let control = Payload {
        issuer: fixture.owner_vm.parse::<DIDURLBuf>()?,
        audience: device_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: test_invocation_expiration(),
        nonce: Some(fixture.next_nonce()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![],
        attenuation: control_caps,
    }
    .sign(
        fixture.owner.get_algorithm().unwrap_or_default(),
        &fixture.owner,
    )?
    .encode()?;
    let activated = fixture
        .client
        .post("/delegate")
        .header(Header::new("Authorization", control))
        .dispatch()
        .await;
    let status = activated.status();
    let body = activated.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "{body}");
    let control_cid = serde_json::from_str::<serde_json::Value>(&body)?["cid"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing control CID"))?
        .parse::<tinycloud_auth::ipld_core::cid::Cid>()?;

    for (target, expected) in [
        (target_in_control_space, Status::Ok),
        (outside_target, Status::Forbidden),
        (imported_target_in_other, Status::Forbidden),
        (target_in_other, Status::Forbidden),
    ] {
        let mut caps = Capabilities::new();
        caps.with_action(
            format!("urn:cid:{}", target.to_cid(0x55)).parse()?,
            "tinycloud.delegation/revoke".parse::<UcanAbility>()?,
            [std::collections::BTreeMap::<String, serde_json::Value>::new()],
        );
        let token = Payload {
            issuer: fixture.device_vm.parse::<DIDURLBuf>()?,
            audience: fixture.device_did().parse::<DIDBuf>()?,
            not_before: None,
            expiration: test_invocation_expiration(),
            nonce: Some(fixture.next_nonce()),
            facts: Some(Vec::<serde_json::Value>::new()),
            proof: vec![control_cid],
            attenuation: caps,
        }
        .sign(
            fixture.device.get_algorithm().unwrap_or_default(),
            &fixture.device,
        )?
        .encode()?;
        let before = revocation::Entity::find().count(&fixture.conn).await?;
        let response = fixture
            .client
            .post("/revoke")
            .header(Header::new("Authorization", token))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(status, expected, "target {target:?}: {body}");
        if expected == Status::Forbidden {
            assert_eq!(
                revocation::Entity::find().count(&fixture.conn).await?,
                before
            );
            assert!(!stored_revoked(&fixture.conn, &target).await?);
        }
        if status == Status::Ok {
            let receipt: serde_json::Value = serde_json::from_str(&body)?;
            assert_eq!(receipt["revoked"], true);
            assert_eq!(receipt["cid"], target.to_cid(0x55).to_string());
        }
    }
    assert!(!stored_revoked(&fixture.conn, &target_in_other).await?);
    assert!(!stored_revoked(&fixture.conn, &imported_target_in_other).await?);
    assert!(stored_revoked(&fixture.conn, &target_in_control_space).await?);
    assert!(!stored_revoked(&fixture.conn, &outside_target).await?);
    Ok(())
}

impl KvSyncFixture {
    #[allow(clippy::too_many_arguments)]
    fn signed_scope_token(
        &self,
        signer: &JWK,
        signer_vm: &str,
        audience: &str,
        resource: &str,
        action: &str,
        expiry: OffsetDateTime,
        proofs: &[Cid],
    ) -> Result<String> {
        let mut capabilities = Capabilities::new();
        capabilities.with_action(
            resource.parse()?,
            action.parse::<UcanAbility>()?,
            [std::collections::BTreeMap::<String, serde_json::Value>::new()],
        );
        Ok(Payload {
            issuer: signer_vm.parse::<DIDURLBuf>()?,
            audience: audience.parse::<DIDBuf>()?,
            not_before: None,
            expiration: NumericDate::try_from_seconds(expiry.unix_timestamp() as f64)?,
            nonce: Some(self.next_nonce()),
            facts: Some(Vec::<serde_json::Value>::new()),
            proof: proofs.to_vec(),
            attenuation: capabilities,
        }
        .sign(signer.get_algorithm().unwrap_or_default(), signer)?
        .encode()?)
    }

    async fn activate_scope(&self, resource: &str, action: &str) -> Result<(Hash, String)> {
        let header = self.signed_scope_token(
            &self.owner,
            &self.owner_vm,
            &self.device_did(),
            resource,
            action,
            whole_seconds_from_now(3600),
            &[],
        )?;
        let response = self
            .client
            .post("/delegate")
            .header(Header::new("Authorization", header.clone()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(status, Status::Ok, "control activation: {body}");
        let receipt: serde_json::Value = serde_json::from_str(&body)?;
        let cid: Cid = receipt["cid"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing control CID"))?
            .parse()?;
        Ok((Hash::from(cid), header))
    }

    fn scoped_revoke_header(&self, target: Hash, control: Option<Hash>) -> Result<String> {
        self.signed_scope_token(
            &self.device,
            &self.device_vm,
            &self.device_did(),
            &format!("urn:cid:{}", target.to_cid(0x55)),
            "tinycloud.delegation/revoke",
            whole_seconds_from_now(3600),
            &control.map(|id| vec![id.to_cid(0x55)]).unwrap_or_default(),
        )
    }

    async fn assert_scope_denied(&self, target: Hash, header: String) -> Result<()> {
        assert!(!stored_revoked(&self.conn, &target).await?);
        let before = revocation::Entity::find().count(&self.conn).await?;
        let response = self
            .client
            .post("/revoke")
            .header(Header::new("Authorization", header))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(status, Status::Forbidden, "scope denial: {body}");
        assert_eq!(revocation::Entity::find().count(&self.conn).await?, before);
        assert!(!stored_revoked(&self.conn, &target).await?);
        Ok(())
    }
}

#[tokio::test]
async fn space_control_cannot_revoke_a_legacy_target_without_resource_scope() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let (control, _) = fixture
        .activate_scope(
            fixture
                .resource_in(&fixture.space, "delegation", "")?
                .as_uri()
                .as_ref(),
            "tinycloud.delegation/revoke",
        )
        .await?;
    let target = fixture
        .grant(
            "legacy-no-resource",
            &fixture.space.did().to_string(),
            &fixture.device_did(),
            &[],
            None,
            None,
            &[],
        )
        .await?;
    fixture
        .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
        .await
}

#[tokio::test]
async fn space_control_cannot_revoke_a_grant_with_an_uncovered_space() -> Result<()> {
    use tinycloud_core::models::space as space_model;
    use tinycloud_core::types::SpaceIdWrap;
    let fixture = scoped_fixture().await?;
    let other = SpaceId::new(fixture.space.did().to_string().parse()?, "other".parse()?);
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(other.clone())),
    }
    .insert(&fixture.conn)
    .await?;
    let (control, _) = fixture
        .activate_scope(
            fixture
                .resource_in(&fixture.space, "delegation", "")?
                .as_uri()
                .as_ref(),
            "tinycloud.delegation/revoke",
        )
        .await?;
    let target = fixture
        .grant_in(
            "mixed-space-target",
            &fixture.space.did().to_string(),
            &fixture.device_did(),
            &[
                (&fixture.space, "notes/", "tinycloud.kv/get"),
                (&other, "notes/", "tinycloud.kv/get"),
            ],
            None,
            None,
            &[],
        )
        .await?;
    fixture
        .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
        .await
}

#[tokio::test]
async fn narrowed_control_path_or_action_cannot_revoke_a_target() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let target = fixture
        .device_grant("narrowed-control-target", &["tinycloud.kv/get"])
        .await?;
    for (path, action) in [
        ("notes/", "tinycloud.delegation/revoke"),
        ("", "tinycloud.delegation/status"),
    ] {
        let (control, _) = fixture
            .activate_scope(
                fixture
                    .resource_in(&fixture.space, "delegation", path)?
                    .as_uri()
                    .as_ref(),
                action,
            )
            .await?;
        fixture
            .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn revoked_control_retry_does_not_reapply_a_revocation() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let target = fixture
        .device_grant("revoked-control-retry-target", &["tinycloud.kv/get"])
        .await?;
    let (control, _) = fixture
        .activate_scope(
            fixture
                .resource_in(&fixture.space, "delegation", "")?
                .as_uri()
                .as_ref(),
            "tinycloud.delegation/revoke",
        )
        .await?;
    let header = fixture.scoped_revoke_header(target, Some(control))?;
    let first = fixture
        .client
        .post("/revoke")
        .header(Header::new("Authorization", header.clone()))
        .dispatch()
        .await;
    assert_eq!(first.status(), Status::Ok);
    let owner_header = fixture.signed_scope_token(
        &fixture.owner,
        &fixture.owner_vm,
        &fixture.space.did().to_string(),
        &format!("urn:cid:{}", control.to_cid(0x55)),
        "tinycloud.delegation/revoke",
        whole_seconds_from_now(3600),
        &[],
    )?;
    let revoked = fixture
        .client
        .post("/revoke")
        .header(Header::new("Authorization", owner_header))
        .dispatch()
        .await;
    assert_eq!(revoked.status(), Status::Ok);
    let before = revocation::Entity::find().count(&fixture.conn).await?;
    let retry = fixture
        .client
        .post("/revoke")
        .header(Header::new("Authorization", header))
        .dispatch()
        .await;
    let status = retry.status();
    let body = retry.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Forbidden, "revoked control retry: {body}");
    assert_eq!(
        revocation::Entity::find().count(&fixture.conn).await?,
        before
    );
    assert!(stored_revoked(&fixture.conn, &target).await?);
    Ok(())
}

#[tokio::test]
async fn expired_control_retry_does_not_reapply_a_revocation() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let target = fixture
        .device_grant("expired-control-retry-target", &["tinycloud.kv/get"])
        .await?;
    let (control, _) = fixture
        .activate_scope(
            fixture
                .resource_in(&fixture.space, "delegation", "")?
                .as_uri()
                .as_ref(),
            "tinycloud.delegation/revoke",
        )
        .await?;
    let header = fixture.scoped_revoke_header(target, Some(control))?;
    let first = fixture
        .client
        .post("/revoke")
        .header(Header::new("Authorization", header.clone()))
        .dispatch()
        .await;
    assert_eq!(first.status(), Status::Ok);
    delegation::Entity::update_many()
        .col_expr(
            delegation::Column::Expiry,
            tinycloud_core::sea_orm::sea_query::Expr::value(whole_seconds_from_now(-1)),
        )
        .filter(delegation::Column::Id.eq(control))
        .exec(&fixture.conn)
        .await?;
    let before = revocation::Entity::find().count(&fixture.conn).await?;
    let retry = fixture
        .client
        .post("/revoke")
        .header(Header::new("Authorization", header))
        .dispatch()
        .await;
    let status = retry.status();
    let body = retry.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Forbidden, "expired control retry: {body}");
    assert_eq!(
        revocation::Entity::find().count(&fixture.conn).await?,
        before
    );
    assert!(stored_revoked(&fixture.conn, &target).await?);
    Ok(())
}

async fn import_signed_scope(fixture: &KvSyncFixture, header: &str) -> Result<Hash> {
    let response = fixture
        .client
        .post("/delegate")
        .header(Header::new("Authorization", header.to_string()))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "signed grant import: {body}");
    let receipt: serde_json::Value = serde_json::from_str(&body)?;
    Ok(Hash::from(
        receipt["cid"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing imported CID"))?
            .parse::<Cid>()?,
    ))
}

#[tokio::test]
async fn signed_import_and_reimport_do_not_widen_control_scope() -> Result<()> {
    use tinycloud_core::models::space as space_model;
    use tinycloud_core::types::SpaceIdWrap;
    let fixture = scoped_fixture().await?;
    let owner = fixture.space.did().to_string();
    let other = SpaceId::new(owner.parse()?, "other".parse()?);
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(other.clone())),
    }
    .insert(&fixture.conn)
    .await?;
    let (control, _) = fixture
        .activate_scope(
            fixture
                .resource_in(&fixture.space, "delegation", "")?
                .as_uri()
                .as_ref(),
            "tinycloud.delegation/revoke",
        )
        .await?;
    let foreign = JWK::generate_ed25519()?;
    let foreign_vm = tc341_verification_method(&foreign)?;
    let foreign_did = KvSyncFixture::did_of(&foreign_vm);
    let resource = fixture
        .resource_in(&other, "kv", "notes/")?
        .as_uri()
        .to_string();
    let parent = fixture.signed_scope_token(
        &fixture.owner,
        &fixture.owner_vm,
        &foreign_did,
        &resource,
        "tinycloud.kv/get",
        whole_seconds_from_now(3600),
        &[],
    )?;
    let parent = import_signed_scope(&fixture, &parent).await?;
    let imported = fixture.signed_scope_token(
        &foreign,
        &foreign_vm,
        &fixture.device_did(),
        &resource,
        "tinycloud.kv/get",
        whole_seconds_from_now(1800),
        &[parent.to_cid(0x55)],
    )?;
    let target = import_signed_scope(&fixture, &imported).await?;
    assert_eq!(import_signed_scope(&fixture, &imported).await?, target);
    fixture
        .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
        .await?;
    Ok(())
}

#[tokio::test]
async fn historical_out_of_scope_revocation_replay_is_denied_without_rewriting_history(
) -> Result<()> {
    use tinycloud_auth::authorization::TinyCloudRevocation;
    use tinycloud_core::{events::Revocation, models::space as space_model, types::SpaceIdWrap};
    let fixture = scoped_fixture().await?;
    let other = SpaceId::new(fixture.space.did().to_string().parse()?, "other".parse()?);
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(other.clone())),
    }
    .insert(&fixture.conn)
    .await?;
    let (control, _) = fixture
        .activate_scope(
            fixture
                .resource_in(&fixture.space, "delegation", "")?
                .as_uri()
                .as_ref(),
            "tinycloud.delegation/revoke",
        )
        .await?;
    let target = fixture
        .grant_in(
            "historical-replay-target",
            &fixture.space.did().to_string(),
            &fixture.device_did(),
            &[(&other, "notes/", "tinycloud.kv/get")],
            None,
            None,
            &[],
        )
        .await?;
    let header = fixture.scoped_revoke_header(target, Some(control))?;
    let event = Revocation::from_header_ser::<TinyCloudRevocation>(&header)?;
    // Seed the exact signed event shape retained by the old authorization
    // path. Denying its replay must not erase or rewrite prior history.
    let historical = revocation::Model {
        id: event.content_hash(),
        revoker: fixture.device_did(),
        revoked: target,
        serialization: event.serialized_bytes().to_vec(),
        revoked_at: Some(OffsetDateTime::now_utc()),
    };
    revocation::ActiveModel::from(historical.clone())
        .insert(&fixture.conn)
        .await?;
    let before = revocation::Entity::find().count(&fixture.conn).await?;
    let response = fixture
        .client
        .post("/revoke")
        .header(Header::new("Authorization", header))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Forbidden, "historical replay: {body}");
    assert_eq!(
        revocation::Entity::find().count(&fixture.conn).await?,
        before
    );
    assert_eq!(
        revocation::Entity::find_by_id(historical.id)
            .one(&fixture.conn)
            .await?,
        Some(historical)
    );
    assert!(stored_revoked(&fixture.conn, &target).await?);
    Ok(())
}

#[tokio::test]
async fn exact_cid_control_cannot_revoke_another_target() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let allowed = fixture
        .device_grant("cid-allowed-target", &["tinycloud.kv/get"])
        .await?;
    let denied = fixture
        .device_grant("cid-denied-target", &["tinycloud.kv/get"])
        .await?;
    // A persisted exact-CID grant, as supplied by historical graph imports.
    let control = fixture
        .grant(
            "historical-cid-control",
            &fixture.space.did().to_string(),
            &fixture.device_did(),
            &[],
            None,
            None,
            &[],
        )
        .await?;
    ability_model::ActiveModel {
        delegation: Set(control),
        resource: Set(Resource::Other(
            format!("urn:cid:{}", allowed.to_cid(0x55)).parse()?,
        )),
        ability: Set(Ability::try_from(
            "tinycloud.delegation/revoke".to_string(),
        )?),
        caveats: Set(tinycloud_core::types::Caveats(Default::default())),
    }
    .insert(&fixture.conn)
    .await?;
    fixture
        .assert_scope_denied(denied, fixture.scoped_revoke_header(denied, Some(control))?)
        .await?;
    let response = fixture
        .client
        .post("/revoke")
        .header(Header::new(
            "Authorization",
            fixture.scoped_revoke_header(allowed, Some(control))?,
        ))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "exact-CID grant: {body}");
    assert!(stored_revoked(&fixture.conn, &allowed).await?);
    assert!(!stored_revoked(&fixture.conn, &denied).await?);
    Ok(())
}

#[tokio::test]
async fn status_control_preserves_the_full_granted_space() -> Result<()> {
    use tinycloud_core::{db::DelegationStatus, models::space as space_model, types::SpaceIdWrap};
    let fixture = scoped_fixture().await?;
    let other = SpaceId::new(fixture.space.did().to_string().parse()?, "other".parse()?);
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(other.clone())),
    }
    .insert(&fixture.conn)
    .await?;
    let own = fixture
        .device_grant("status-same-space", &["tinycloud.kv/get"])
        .await?;
    let outside = fixture
        .grant_in(
            "status-other-space",
            &fixture.space.did().to_string(),
            &fixture.device_did(),
            &[(&other, "notes/", "tinycloud.kv/get")],
            None,
            None,
            &[],
        )
        .await?;
    let (control, _) = fixture
        .activate_scope(
            fixture
                .resource_in(&fixture.space, "delegation", "")?
                .as_uri()
                .as_ref(),
            "tinycloud.delegation/status",
        )
        .await?;
    let state = fixture
        .client
        .rocket()
        .state::<TinyCloud>()
        .expect("managed TinyCloud");
    assert_eq!(
        state
            .delegation_status(own, &fixture.device_did(), &[control.to_cid(0x55)])
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        Some(DelegationStatus::Active)
    );
    assert_eq!(
        state
            .delegation_status(outside, &fixture.device_did(), &[control.to_cid(0x55)])
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        None
    );
    assert!(!stored_revoked(&fixture.conn, &outside).await?);
    Ok(())
}

#[tokio::test]
async fn owner_signed_target_revocation_preserves_cross_space_account_control() -> Result<()> {
    use tinycloud_core::{models::space as space_model, types::SpaceIdWrap};
    let fixture = scoped_fixture().await?;
    let owner = fixture.space.did().to_string();
    let other = SpaceId::new(owner.parse()?, "other".parse()?);
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(other.clone())),
    }
    .insert(&fixture.conn)
    .await?;
    let target_header = fixture.signed_scope_token(
        &fixture.owner,
        &fixture.owner_vm,
        &fixture.device_did(),
        fixture
            .resource_in(&other, "kv", "notes/")?
            .as_uri()
            .as_ref(),
        "tinycloud.kv/get",
        whole_seconds_from_now(3600),
        &[],
    )?;
    let target = import_signed_scope(&fixture, &target_header).await?;
    let (control, _) = fixture
        .activate_scope(
            fixture
                .resource_in(&fixture.space, "delegation", "")?
                .as_uri()
                .as_ref(),
            "tinycloud.delegation/revoke",
        )
        .await?;
    fixture
        .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
        .await?;
    let direct = fixture.signed_scope_token(
        &fixture.owner,
        &fixture.owner_vm,
        &owner,
        &format!("urn:cid:{}", target.to_cid(0x55)),
        "tinycloud.delegation/revoke",
        whole_seconds_from_now(3600),
        &[],
    )?;
    let response = fixture
        .client
        .post("/revoke")
        .header(Header::new("Authorization", direct))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "owner-signed target revocation: {body}");
    let receipt: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(receipt["cid"], target.to_cid(0x55).to_string());
    assert_eq!(receipt["revoked"], true);
    assert!(stored_revoked(&fixture.conn, &target).await?);
    Ok(())
}

/// A key that can sign UCANs and appear in persisted delegation rows.
async fn registered_key(fixture: &KvSyncFixture) -> Result<(JWK, String, String)> {
    use tinycloud_core::models::actor;
    let jwk = JWK::generate_ed25519()?;
    let vm = tc341_verification_method(&jwk)?;
    let did = KvSyncFixture::did_of(&vm);
    actor::ActiveModel {
        id: Set(did.clone()),
    }
    .insert(&fixture.conn)
    .await?;
    Ok((jwk, vm, did))
}

/// Persist an exact-CID `tinycloud.delegation/revoke` control grant.
async fn exact_cid_revoke_control(
    fixture: &KvSyncFixture,
    label: &str,
    grantor: &str,
    holder: &str,
    target: Hash,
) -> Result<Hash> {
    let control = fixture
        .grant(label, grantor, holder, &[], None, None, &[])
        .await?;
    ability_model::ActiveModel {
        delegation: Set(control),
        resource: Set(Resource::Other(
            format!("urn:cid:{}", target.to_cid(0x55)).parse()?,
        )),
        ability: Set(Ability::try_from(
            "tinycloud.delegation/revoke".to_string(),
        )?),
        caveats: Set(tinycloud_core::types::Caveats(Default::default())),
    }
    .insert(&fixture.conn)
    .await?;
    Ok(control)
}

async fn assert_revoked_ok(fixture: &KvSyncFixture, target: Hash, header: String) -> Result<()> {
    let response = fixture
        .client
        .post("/revoke")
        .header(Header::new("Authorization", header))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "authorized revocation: {body}");
    let receipt: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(receipt["revoked"], true);
    assert_eq!(receipt["cid"], target.to_cid(0x55).to_string());
    assert!(stored_revoked(&fixture.conn, &target).await?);
    Ok(())
}

#[tokio::test]
async fn recipient_cannot_revoke_a_grant_it_only_received() -> Result<()> {
    use tinycloud_core::db::DelegationStatus;
    let fixture = scoped_fixture().await?;
    let target = fixture
        .device_grant("received-only-target", &["tinycloud.kv/get"])
        .await?;
    // The recipient keeps read access to the grant's status.
    let state = fixture
        .client
        .rocket()
        .state::<TinyCloud>()
        .expect("managed TinyCloud");
    assert_eq!(
        state
            .delegation_status(target, &fixture.device_did(), &[])
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        Some(DelegationStatus::Active)
    );
    // A proof-less revocation signed by the recipient alone is refused.
    fixture
        .assert_scope_denied(target, fixture.scoped_revoke_header(target, None)?)
        .await?;
    // The grantor (here the space owner) still revokes it.
    let owner = fixture.signed_scope_token(
        &fixture.owner,
        &fixture.owner_vm,
        &fixture.space.did().to_string(),
        &format!("urn:cid:{}", target.to_cid(0x55)),
        "tinycloud.delegation/revoke",
        whole_seconds_from_now(3600),
        &[],
    )?;
    assert_revoked_ok(&fixture, target, owner).await
}

#[tokio::test]
async fn recipient_cannot_grant_revocation_of_a_grant_it_only_received() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let target = fixture
        .device_grant("received-only-control-target", &["tinycloud.kv/get"])
        .await?;
    let (helper, helper_vm, helper_did) = registered_key(&fixture).await?;
    // The recipient issues an exact-CID revoke control for its own grant.
    let control = exact_cid_revoke_control(
        &fixture,
        "recipient-issued-control",
        &fixture.device_did(),
        &helper_did,
        target,
    )
    .await?;
    let header = fixture.signed_scope_token(
        &helper,
        &helper_vm,
        &helper_did,
        &format!("urn:cid:{}", target.to_cid(0x55)),
        "tinycloud.delegation/revoke",
        whole_seconds_from_now(3600),
        &[control.to_cid(0x55)],
    )?;
    fixture.assert_scope_denied(target, header).await
}

#[tokio::test]
async fn issuing_delegator_and_owner_revoke_a_descendant_its_recipient_cannot() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let device_did = fixture.device_did();
    let parent = fixture
        .device_grant("reshare-parent", &["tinycloud.kv/get"])
        .await?;
    let (holder, holder_vm, holder_did) = registered_key(&fixture).await?;
    let mut children = Vec::new();
    for label in ["reshare-child-1", "reshare-child-2", "reshare-child-3"] {
        children.push(
            fixture
                .grant(
                    label,
                    &device_did,
                    &holder_did,
                    &[("notes/", "tinycloud.kv/get")],
                    None,
                    Some(whole_seconds_from_now(1800)),
                    &[parent],
                )
                .await?,
        );
    }
    let holder_revokes = |target: Hash| {
        fixture.signed_scope_token(
            &holder,
            &holder_vm,
            &holder_did,
            &format!("urn:cid:{}", target.to_cid(0x55)),
            "tinycloud.delegation/revoke",
            whole_seconds_from_now(3600),
            &[],
        )
    };
    // The re-share's recipient cannot revoke it.
    fixture
        .assert_scope_denied(children[0], holder_revokes(children[0])?)
        .await?;
    // The intermediate delegator that issued it can.
    assert_revoked_ok(
        &fixture,
        children[0],
        fixture.scoped_revoke_header(children[0], None)?,
    )
    .await?;
    // So can a key the issuing delegator handed an exact-CID revoke control.
    let (helper, helper_vm, helper_did) = registered_key(&fixture).await?;
    let control = exact_cid_revoke_control(
        &fixture,
        "delegator-issued-control",
        &device_did,
        &helper_did,
        children[1],
    )
    .await?;
    let helper_header = fixture.signed_scope_token(
        &helper,
        &helper_vm,
        &helper_did,
        &format!("urn:cid:{}", children[1].to_cid(0x55)),
        "tinycloud.delegation/revoke",
        whole_seconds_from_now(3600),
        &[control.to_cid(0x55)],
    )?;
    assert_revoked_ok(&fixture, children[1], helper_header).await?;
    // The space owner revokes a descendant it did not issue directly.
    let owner = fixture.signed_scope_token(
        &fixture.owner,
        &fixture.owner_vm,
        &fixture.space.did().to_string(),
        &format!("urn:cid:{}", children[2].to_cid(0x55)),
        "tinycloud.delegation/revoke",
        whole_seconds_from_now(3600),
        &[],
    )?;
    assert_revoked_ok(&fixture, children[2], owner).await?;
    assert!(!stored_revoked(&fixture.conn, &parent).await?);
    Ok(())
}

/// POST `/delegate` and return the status, body and receipt CID.
async fn activate(fixture: &KvSyncFixture, header: String) -> (Status, String, Option<Hash>) {
    let response = fixture
        .client
        .post("/delegate")
        .header(Header::new("Authorization", header))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    let cid = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|receipt| {
            receipt["cid"]
                .as_str()
                .and_then(|cid| cid.parse::<Cid>().ok())
        })
        .map(Hash::from);
    (status, body, cid)
}

#[tokio::test]
async fn owner_activates_a_parentless_exact_cid_revoke_grant() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let target = fixture
        .device_grant("owner-cid-control-target", &["tinycloud.kv/get"])
        .await?;
    let (helper, helper_vm, helper_did) = registered_key(&fixture).await?;
    let resource = format!("urn:cid:{}", target.to_cid(0x55));
    let control = fixture.signed_scope_token(
        &fixture.owner,
        &fixture.owner_vm,
        &helper_did,
        &resource,
        "tinycloud.delegation/revoke",
        whole_seconds_from_now(3600),
        &[],
    )?;
    let (status, body, control) = activate(&fixture, control).await;
    assert_eq!(status, Status::Ok, "owner exact-CID control: {body}");
    let control = control.expect("control receipt CID");
    let header = fixture.signed_scope_token(
        &helper,
        &helper_vm,
        &helper_did,
        &resource,
        "tinycloud.delegation/revoke",
        whole_seconds_from_now(3600),
        &[control.to_cid(0x55)],
    )?;
    assert_revoked_ok(&fixture, target, header).await
}

#[tokio::test]
async fn only_an_owner_of_the_target_space_activates_a_parentless_exact_cid_revoke_grant(
) -> Result<()> {
    let fixture = scoped_fixture().await?;
    let owner_did = fixture.space.did().to_string();
    let device_did = fixture.device_did();
    let target = fixture
        .device_grant("owner-only-cid-target", &["tinycloud.kv/get"])
        .await?;
    let (helper, helper_vm, helper_did) = registered_key(&fixture).await?;
    let reshare = fixture
        .grant(
            "owner-only-cid-reshare",
            &device_did,
            &helper_did,
            &[("notes/", "tinycloud.kv/get")],
            None,
            Some(whole_seconds_from_now(1800)),
            &[target],
        )
        .await?;
    let empty = fixture
        .grant(
            "owner-only-cid-no-abilities",
            &owner_did,
            &device_did,
            &[],
            None,
            Some(whole_seconds_from_now(3600)),
            &[],
        )
        .await?;
    let unknown = tinycloud_core::hash::hash(b"owner-only-cid-unknown");
    let foreign = JWK::generate_ed25519()?;
    let foreign_vm = tc341_verification_method(&foreign)?;
    for (label, key, vm, cid) in [
        ("unrelated signer", &foreign, foreign_vm.as_str(), target),
        (
            "target delegatee",
            &fixture.device,
            fixture.device_vm.as_str(),
            target,
        ),
        ("re-share delegatee", &helper, helper_vm.as_str(), reshare),
        (
            "intermediate delegator, not an owner",
            &fixture.device,
            fixture.device_vm.as_str(),
            reshare,
        ),
        (
            "owner, unknown target",
            &fixture.owner,
            fixture.owner_vm.as_str(),
            unknown,
        ),
        (
            "owner, target without abilities",
            &fixture.owner,
            fixture.owner_vm.as_str(),
            empty,
        ),
    ] {
        let header = fixture.signed_scope_token(
            key,
            vm,
            &helper_did,
            &format!("urn:cid:{}", cid.to_cid(0x55)),
            "tinycloud.delegation/revoke",
            whole_seconds_from_now(3600),
            &[],
        )?;
        let (status, body, _) = activate(&fixture, header).await;
        assert_eq!(status, Status::Unauthorized, "{label}: {body}");
    }
    for cid in [target, reshare, empty] {
        assert!(!stored_revoked(&fixture.conn, &cid).await?);
    }
    Ok(())
}
