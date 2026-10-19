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
        self.signed_caps_token(
            signer,
            signer_vm,
            audience,
            &[(resource, action)],
            expiry,
            proofs,
        )
    }

    fn signed_caps_token(
        &self,
        signer: &JWK,
        signer_vm: &str,
        audience: &str,
        grants: &[(&str, &str)],
        expiry: OffsetDateTime,
        proofs: &[Cid],
    ) -> Result<String> {
        let mut capabilities = Capabilities::new();
        for (resource, action) in grants {
            capabilities.with_action(
                resource.parse()?,
                action.parse::<UcanAbility>()?,
                [std::collections::BTreeMap::<String, serde_json::Value>::new()],
            );
        }
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
        self.activate_caps(&[(resource, action)]).await
    }

    /// The owner signs a control to the device and imports it through
    /// `/delegate`, which must accept it.
    async fn activate_caps(&self, grants: &[(&str, &str)]) -> Result<(Hash, String)> {
        let header = self.signed_caps_token(
            &self.owner,
            &self.owner_vm,
            &self.device_did(),
            grants,
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
    let resource = format!("urn:cid:{}", target.to_cid(0x55));
    let control = fixture
        .grant(label, grantor, holder, &[], None, None, &[])
        .await?;
    add_raw_abilities(
        fixture,
        control,
        &[(resource.as_str(), "tinycloud.delegation/revoke")],
    )
    .await?;
    Ok(control)
}

/// Persist `(resource, action)` rows whose resource is not a space resource
/// (encryption networks, exact CIDs), byte-for-byte as given.
async fn add_raw_abilities(
    fixture: &KvSyncFixture,
    delegation: Hash,
    rows: &[(&str, &str)],
) -> Result<()> {
    for (resource, action) in rows {
        let resource: Resource = resource.parse()?;
        assert!(matches!(resource, Resource::Other(_)), "{resource}");
        ability_model::ActiveModel {
            delegation: Set(delegation),
            resource: Set(resource),
            ability: Set(Ability::try_from(action.to_string())?),
            caveats: Set(tinycloud_core::types::Caveats(Default::default())),
        }
        .insert(&fixture.conn)
        .await?;
    }
    Ok(())
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

// N4': revoke and status controls that name an encryption network (TC-1423).

const REVOKE: &str = "tinycloud.delegation/revoke";
const STATUS: &str = "tinycloud.delegation/status";
const DECRYPT: &str = "tinycloud.encryption/decrypt";

fn network_urn(owner: &str, name: &str) -> String {
    format!("urn:tinycloud:encryption:{owner}:{name}")
}

impl KvSyncFixture {
    fn owner_did(&self) -> String {
        self.space.did().to_string()
    }

    fn share_network(&self) -> String {
        network_urn(&self.owner_did(), "share")
    }

    /// The one-approval kill-all control: `action` on the space's delegation
    /// root and on the owner's `:share` network, owner -> device.
    async fn kill_all_control(&self, action: &str) -> Result<Hash> {
        let space_root = self
            .resource_in(&self.space, "delegation", "")?
            .as_uri()
            .to_string();
        let share = self.share_network();
        Ok(self
            .activate_caps(&[(space_root.as_str(), action), (share.as_str(), action)])
            .await?
            .0)
    }

    /// A share root as Share signs it: kv on the space plus decrypt on
    /// `network`.
    async fn share_root(
        &self,
        label: &str,
        delegator: &str,
        delegatee: &str,
        network: &str,
    ) -> Result<Hash> {
        let root = self
            .grant(
                label,
                delegator,
                delegatee,
                &[("notes/", "tinycloud.kv/get")],
                None,
                Some(whole_seconds_from_now(3600)),
                &[],
            )
            .await?;
        add_raw_abilities(self, root, &[(network, DECRYPT)]).await?;
        Ok(root)
    }

    /// A grant whose only rows are the given raw (network or CID) rows.
    async fn raw_grant(
        &self,
        label: &str,
        delegator: &str,
        delegatee: &str,
        rows: &[(&str, &str)],
    ) -> Result<Hash> {
        let id = self
            .grant(
                label,
                delegator,
                delegatee,
                &[],
                None,
                Some(whole_seconds_from_now(3600)),
                &[],
            )
            .await?;
        add_raw_abilities(self, id, rows).await?;
        Ok(id)
    }

    async fn status_with(
        &self,
        target: Hash,
        invoker: &str,
        proofs: &[Hash],
    ) -> Result<Option<tinycloud_core::db::DelegationStatus>> {
        let proofs = proofs.iter().map(|id| id.to_cid(0x55)).collect::<Vec<_>>();
        self.client
            .rocket()
            .state::<TinyCloud>()
            .expect("managed TinyCloud")
            .delegation_status(target, invoker, &proofs)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }
}

#[tokio::test]
async fn network_control_revokes_a_share_root_and_its_links() -> Result<()> {
    use tinycloud_core::db::DelegationStatus;
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let control = fixture.kill_all_control(REVOKE).await?;
    let (_, _, share_key) = registered_key(&fixture).await?;
    let (_, _, recipient) = registered_key(&fixture).await?;
    let root = fixture
        .share_root(
            "n4-share-root",
            &owner,
            &share_key,
            &fixture.share_network(),
        )
        .await?;
    let link = fixture
        .grant(
            "n4-share-link",
            &share_key,
            &recipient,
            &[("notes/", "tinycloud.kv/get")],
            None,
            Some(whole_seconds_from_now(1800)),
            &[root],
        )
        .await?;
    assert_eq!(
        fixture.status_with(link, &owner, &[]).await?,
        Some(DelegationStatus::Active)
    );
    assert_revoked_ok(
        &fixture,
        root,
        fixture.scoped_revoke_header(root, Some(control))?,
    )
    .await?;
    assert_eq!(
        fixture.status_with(link, &owner, &[]).await?,
        Some(DelegationStatus::Revoked)
    );
    Ok(())
}

#[tokio::test]
async fn network_control_cannot_revoke_default_network_grants() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let default = network_urn(&owner, "default");
    let control = fixture.kill_all_control(REVOKE).await?;
    let (_, _, agent) = registered_key(&fixture).await?;
    // An agent root with secrets access, and a decrypt-only `:default` grant.
    let agent_root = fixture
        .share_root("n4-agent-root", &owner, &agent, &default)
        .await?;
    let secrets = fixture
        .raw_grant("n4-agent-secrets", &owner, &agent, &[(&default, DECRYPT)])
        .await?;
    for target in [agent_root, secrets] {
        fixture
            .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn network_control_cannot_revoke_other_networks_or_another_owners_share() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let device = fixture.device_did();
    let control = fixture.kill_all_control(REVOKE).await?;
    let (_, _, key) = registered_key(&fixture).await?;
    let (_, _, stranger) = registered_key(&fixture).await?;
    let stranger_share = network_urn(&stranger, "share");
    let other_network = fixture
        .raw_grant(
            "n4-other-network",
            &owner,
            &key,
            &[(&network_urn(&owner, "other"), DECRYPT)],
        )
        .await?;
    let stranger_root = fixture
        .raw_grant(
            "n4-stranger-root",
            &stranger,
            &key,
            &[(&stranger_share, DECRYPT)],
        )
        .await?;
    // The owner re-delegates decrypt on the stranger's network.
    let owner_issued_stranger = fixture
        .raw_grant(
            "n4-owner-issued-stranger",
            &owner,
            &key,
            &[(&stranger_share, DECRYPT)],
        )
        .await?;
    // A persisted control in which the owner names the stranger's network.
    let names_stranger = fixture
        .raw_grant(
            "n4-names-stranger-control",
            &owner,
            &device,
            &[(&stranger_share, REVOKE)],
        )
        .await?;
    for (target, control) in [
        (other_network, control),
        (stranger_root, control),
        (owner_issued_stranger, control),
        (stranger_root, names_stranger),
        (owner_issued_stranger, names_stranger),
    ] {
        fixture
            .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn network_control_must_cover_every_row_of_the_target() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let share = fixture.share_network();
    let default = network_urn(&owner, "default");
    let (share_only, _) = fixture.activate_caps(&[(share.as_str(), REVOKE)]).await?;
    let kill_all = fixture.kill_all_control(REVOKE).await?;
    let (_, _, key) = registered_key(&fixture).await?;
    // The space row of a share root is not covered by a `:share`-only control.
    let root = fixture
        .share_root("n4-partial-root", &owner, &key, &share)
        .await?;
    fixture
        .assert_scope_denied(root, fixture.scoped_revoke_header(root, Some(share_only))?)
        .await?;
    // `:share` is covered, `:default` is not.
    let mixed = fixture
        .raw_grant(
            "n4-partial-networks",
            &owner,
            &key,
            &[(&share, DECRYPT), (&default, DECRYPT)],
        )
        .await?;
    fixture
        .assert_scope_denied(mixed, fixture.scoped_revoke_header(mixed, Some(kill_all))?)
        .await?;
    // Full coverage by the network alone.
    let decrypt_only = fixture
        .raw_grant("n4-share-decrypt-only", &owner, &key, &[(&share, DECRYPT)])
        .await?;
    assert_revoked_ok(
        &fixture,
        decrypt_only,
        fixture.scoped_revoke_header(decrypt_only, Some(share_only))?,
    )
    .await
}

#[tokio::test]
async fn network_only_control_never_acts_as_an_exact_cid_control() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let device = fixture.device_did();
    let share = fixture.share_network();
    let (revoke_control, _) = fixture.activate_caps(&[(share.as_str(), REVOKE)]).await?;
    let (status_control, _) = fixture.activate_caps(&[(share.as_str(), STATUS)]).await?;
    // Grants the control's grantor issued that touch nothing the control names.
    let kv_only = fixture
        .device_grant("n4-kv-only-target", &["tinycloud.kv/get"])
        .await?;
    let no_rows = fixture
        .grant("n4-no-rows-target", &owner, &device, &[], None, None, &[])
        .await?;
    for target in [kv_only, no_rows] {
        fixture
            .assert_scope_denied(
                target,
                fixture.scoped_revoke_header(target, Some(revoke_control))?,
            )
            .await?;
        assert_eq!(
            fixture
                .status_with(target, &device, &[status_control])
                .await?,
            None
        );
    }
    Ok(())
}

#[tokio::test]
async fn session_issued_network_sub_control_is_denied() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let share = fixture.share_network();
    let (control, _) = fixture.activate_caps(&[(share.as_str(), REVOKE)]).await?;
    let (helper, helper_vm, helper_did) = registered_key(&fixture).await?;
    let sub_control = fixture.signed_scope_token(
        &fixture.device,
        &fixture.device_vm,
        &helper_did,
        &share,
        REVOKE,
        whole_seconds_from_now(1800),
        &[control.to_cid(0x55)],
    )?;
    let sub_control = import_signed_scope(&fixture, &sub_control).await?;
    let (_, _, key) = registered_key(&fixture).await?;
    let target = fixture
        .raw_grant("n4-sub-control-target", &owner, &key, &[(&share, DECRYPT)])
        .await?;
    let via_sub_control = fixture.signed_scope_token(
        &helper,
        &helper_vm,
        &helper_did,
        &format!("urn:cid:{}", target.to_cid(0x55)),
        REVOKE,
        whole_seconds_from_now(1800),
        &[sub_control.to_cid(0x55)],
    )?;
    fixture.assert_scope_denied(target, via_sub_control).await?;
    assert_revoked_ok(
        &fixture,
        target,
        fixture.scoped_revoke_header(target, Some(control))?,
    )
    .await
}

#[tokio::test]
async fn cid_and_network_control_keeps_each_scope_exact() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let device = fixture.device_did();
    let share = fixture.share_network();
    let (_, _, key) = registered_key(&fixture).await?;
    let named = fixture
        .device_grant("n4-cid-named", &["tinycloud.kv/get"])
        .await?;
    let unnamed = fixture
        .device_grant("n4-cid-unnamed", &["tinycloud.kv/get"])
        .await?;
    let share_grant = fixture
        .raw_grant("n4-cid-share-grant", &owner, &key, &[(&share, DECRYPT)])
        .await?;
    let named_cid = format!("urn:cid:{}", named.to_cid(0x55));
    let control = fixture
        .raw_grant(
            "n4-cid-and-network-control",
            &owner,
            &device,
            &[(&named_cid, REVOKE), (&share, REVOKE)],
        )
        .await?;
    // Another target: the CID row is dropped and only `:share` coverage applies.
    fixture
        .assert_scope_denied(
            unnamed,
            fixture.scoped_revoke_header(unnamed, Some(control))?,
        )
        .await?;
    assert_revoked_ok(
        &fixture,
        share_grant,
        fixture.scoped_revoke_header(share_grant, Some(control))?,
    )
    .await?;
    // The named target: the exact-CID branch applies.
    assert_revoked_ok(
        &fixture,
        named,
        fixture.scoped_revoke_header(named, Some(control))?,
    )
    .await
}

#[tokio::test]
async fn network_scope_matches_the_parsed_network_id() -> Result<()> {
    use tinycloud_core::models::actor;
    const CHECKSUM: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const OTHER_ADDRESS: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
    let fixture = scoped_fixture().await?;
    let device = fixture.device_did();
    let owner = format!("did:pkh:eip155:1:{CHECKSUM}");
    actor::ActiveModel {
        id: Set(owner.clone()),
    }
    .insert(&fixture.conn)
    .await?;
    let lower_owner = format!("did:pkh:eip155:1:{}", CHECKSUM.to_lowercase());
    let checksum = network_urn(&owner, "share");
    let lower = network_urn(&lower_owner, "share");
    let (_, _, key) = registered_key(&fixture).await?;
    // Both spellings of the owner's address name the same network.
    for (label, control_urn, target_urn) in [
        ("lower-lower", &lower, &lower),
        ("lower-checksum", &lower, &checksum),
        ("checksum-lower", &checksum, &lower),
        ("checksum-checksum", &checksum, &checksum),
    ] {
        let control = fixture
            .raw_grant(
                &format!("n4-pkh-control-{label}"),
                &owner,
                &device,
                &[(control_urn, REVOKE)],
            )
            .await?;
        let target = fixture
            .raw_grant(
                &format!("n4-pkh-root-{label}"),
                &owner,
                &key,
                &[(target_urn, DECRYPT)],
            )
            .await?;
        assert_revoked_ok(
            &fixture,
            target,
            fixture.scoped_revoke_header(target, Some(control))?,
        )
        .await?;
    }
    // A different network name, owner address or chain id is another network.
    let control = fixture
        .raw_grant("n4-pkh-control-share", &owner, &device, &[(&lower, REVOKE)])
        .await?;
    for (label, network) in [
        ("name", network_urn(&lower_owner, "default")),
        (
            "address",
            network_urn(&format!("did:pkh:eip155:1:{OTHER_ADDRESS}"), "share"),
        ),
        (
            "chain",
            network_urn(
                &format!("did:pkh:eip155:137:{}", CHECKSUM.to_lowercase()),
                "share",
            ),
        ),
    ] {
        let target = fixture
            .raw_grant(
                &format!("n4-pkh-other-{label}"),
                &owner,
                &key,
                &[(&network, DECRYPT)],
            )
            .await?;
        fixture
            .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn network_control_never_covers_an_unrecognized_target_row() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let share = fixture.share_network();
    let control = fixture.kill_all_control(REVOKE).await?;
    let (_, _, key) = registered_key(&fixture).await?;
    let unknown = "urn:example:unknown";
    // An address that is not 20 bytes: not a network id.
    let malformed = "urn:tinycloud:encryption:did:pkh:eip155:1:0xabc:share";
    let with_unknown = fixture
        .share_root("n4-unknown-row-root", &owner, &key, &share)
        .await?;
    add_raw_abilities(&fixture, with_unknown, &[(unknown, DECRYPT)]).await?;
    let with_malformed = fixture
        .raw_grant(
            "n4-malformed-network-row",
            &owner,
            &key,
            &[(&share, DECRYPT), (malformed, DECRYPT)],
        )
        .await?;
    let only_unknown = fixture
        .raw_grant("n4-only-unknown-row", &owner, &key, &[(unknown, DECRYPT)])
        .await?;
    for target in [with_unknown, with_malformed, only_unknown] {
        fixture
            .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn control_of_only_unrecognized_rows_is_denied() -> Result<()> {
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let device = fixture.device_did();
    let share = fixture.share_network();
    let (_, _, key) = registered_key(&fixture).await?;
    let (_, _, stranger) = registered_key(&fixture).await?;
    let elsewhere = fixture
        .device_grant("n4-junk-elsewhere", &["tinycloud.kv/get"])
        .await?;
    let elsewhere_cid = format!("urn:cid:{}", elsewhere.to_cid(0x55));
    let stranger_share = network_urn(&stranger, "share");
    let foreign_chain_share = network_urn(
        "did:pkh:eip155:137:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        "share",
    );
    let junk = [
        ("urn:example:junk", REVOKE),
        (
            "urn:tinycloud:encryption:did:pkh:eip155:1:0xabc:share",
            REVOKE,
        ),
        (elsewhere_cid.as_str(), REVOKE),
        (stranger_share.as_str(), REVOKE),
        (foreign_chain_share.as_str(), REVOKE),
        (share.as_str(), STATUS),
    ];
    let control = fixture
        .raw_grant("n4-junk-control", &owner, &device, &junk)
        .await?;
    let share_grant = fixture
        .raw_grant("n4-junk-share-target", &owner, &key, &[(&share, DECRYPT)])
        .await?;
    let kv_grant = fixture
        .device_grant("n4-junk-kv-target", &["tinycloud.kv/get"])
        .await?;
    for target in [share_grant, kv_grant] {
        fixture
            .assert_scope_denied(target, fixture.scoped_revoke_header(target, Some(control))?)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn network_revoke_control_grants_no_decrypt() -> Result<()> {
    use tinycloud_core::{models::invocation, util::Capability};
    let fixture = scoped_fixture().await?;
    let share = fixture.share_network();
    let (control, _) = fixture.activate_caps(&[(share.as_str(), REVOKE)]).await?;
    let capability = |action: &str| -> Result<Capability> {
        Ok(Capability {
            resource: share.parse()?,
            ability: Ability::try_from(action.to_string())?,
            caveats: Default::default(),
        })
    };
    // Invocation (and Policy/v3 owner-authority) rules: the control proves
    // the revoke ability it names and nothing else on the network.
    let proofs = [control.to_cid(0x55)];
    let now = OffsetDateTime::now_utc();
    let device = fixture.device_did();
    assert!(invocation::authorize_holder(
        &fixture.conn,
        &device,
        &[capability(REVOKE)?],
        &proofs,
        now
    )
    .await
    .is_ok());
    assert!(invocation::authorize_holder(
        &fixture.conn,
        &device,
        &[capability(DECRYPT)?],
        &proofs,
        now
    )
    .await
    .is_err());
    Ok(())
}

#[tokio::test]
async fn network_status_control_follows_the_revoke_scope() -> Result<()> {
    use tinycloud_core::db::DelegationStatus;
    let fixture = scoped_fixture().await?;
    let owner = fixture.owner_did();
    let device = fixture.device_did();
    let control = fixture.kill_all_control(STATUS).await?;
    let (_, _, key) = registered_key(&fixture).await?;
    let root = fixture
        .share_root("n4-status-root", &owner, &key, &fixture.share_network())
        .await?;
    let agent_root = fixture
        .share_root(
            "n4-status-agent-root",
            &owner,
            &key,
            &network_urn(&owner, "default"),
        )
        .await?;
    let kv_only = fixture
        .device_grant("n4-status-kv-only", &["tinycloud.kv/get"])
        .await?;
    assert_eq!(
        fixture.status_with(root, &device, &[control]).await?,
        Some(DelegationStatus::Active)
    );
    assert_eq!(
        fixture.status_with(kv_only, &device, &[control]).await?,
        Some(DelegationStatus::Active)
    );
    assert_eq!(
        fixture.status_with(agent_root, &device, &[control]).await?,
        None
    );
    Ok(())
}
