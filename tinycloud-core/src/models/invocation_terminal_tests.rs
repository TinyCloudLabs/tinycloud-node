use super::*;
use crate::events::{Delegation, Invocation, TinyCloudDelegation, TinyCloudInvocation};
use crate::keys::StaticSecret;
use crate::models::{invocation, policy_v3_root, space};
use crate::storage::{
    memory::{MemoryStaging, MemoryStore},
    HashBuffer,
};
use crate::types::{DelegationQuery, Metadata, SpaceIdWrap};
use crate::SpaceDatabase;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection, PaginatorTrait};
use sea_orm_migration::MigratorTrait;
use std::collections::{BTreeMap, HashMap};
use tinycloud_auth::{
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

fn identity() -> (JWK, String) {
    let key = JWK::generate_ed25519().unwrap();
    let did = DID_METHODS.generate(&key, "key").unwrap().to_string();
    (key, did)
}
fn signed(
    key: &JWK,
    issuer: &str,
    audience: &str,
    resource: &str,
    ability: &str,
    proofs: Vec<Cid>,
    policy: bool,
) -> String {
    let mut caps = Capabilities::<serde_json::Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        ability.parse().unwrap(),
        [BTreeMap::new()],
    );
    let facts = policy.then(|| {
        vec![serde_json::json!({
            "role":"policy-authority", "mode":"policy-source", "ownerDid":issuer,
            "policyId":"scope-probe", "policyDigestHex":"digest", "policyCid":"policy-cid",
            "contentSourceDigestHex":"source", "capabilityCeilingHashHex":"ceiling",
            "nativeProjectionHashHex":"projection", "nodeAudience":audience
        })]
    });
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Payload {
        issuer: issuer.parse().unwrap(),
        audience: audience.parse().unwrap(),
        expiration: NumericDate::try_from_seconds((now + 3600) as f64).unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 1) as f64).unwrap()),
        nonce: None,
        facts,
        proof: proofs,
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, key)
    .unwrap()
    .encode()
    .unwrap()
}
fn delegation_event(encoded: &str) -> Delegation {
    Delegation::from_header_ser::<TinyCloudDelegation>(encoded).unwrap()
}
fn invocation_event(encoded: &str) -> Invocation {
    Invocation::from_header_ser::<TinyCloudInvocation>(encoded).unwrap()
}
async fn connection(
    pg: bool,
) -> Option<(
    DatabaseConnection,
    Option<crate::test_support::PostgresTestSchema>,
)> {
    if pg {
        let fixture = crate::test_support::PostgresTestSchema::new("tc2939_scope_review").await?;
        Some((fixture.conn.clone(), Some(fixture)))
    } else {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        Some((db, None))
    }
}
async fn persist_root(
    db: &DatabaseConnection,
    key: &JWK,
    holder: &str,
    resource: &str,
    ability: &str,
) -> Cid {
    let plain = delegation_event(&signed(
        key,
        holder,
        holder,
        resource,
        ability,
        vec![],
        false,
    ));
    assert!(
        delegation::process(db, &plain, None).await.is_err(),
        "ordinary non-owner root must refuse"
    );
    let policy = delegation_event(&signed(
        key,
        holder,
        holder,
        resource,
        ability,
        vec![],
        true,
    ));
    assert!(policy.0.parents.is_empty());
    assert_ne!(
        policy.0.capabilities[0]
            .resource
            .space()
            .map(|s| s.did().as_str()),
        Some(holder)
    );
    let cid = policy.content_hash().to_cid(0x55);
    delegation::process(db, &policy, None).await.unwrap();
    assert!(policy_v3_root::Entity::find_by_id(cid.to_string())
        .one(db)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(Hash::from(cid)))
            .count(db)
            .await
            .unwrap(),
        0
    );
    cid
}

async fn register_root(db: &DatabaseConnection, cid: Cid) {
    policy_v3_root::ActiveModel {
        root_cid: Set(cid.to_string()),
        policy_cid: Set("policy-cid".into()),
        role: Set("policy-authority".into()),
        authorization_bytes: Set(vec![]),
        status_checkpoint_bytes: Set(None),
        previous_checkpoint_digest_hex: Set(None),
        status_sequence: Set(1),
        admission_epoch: Set(0),
        status_checked_at: Set(None),
        status_fresh_until: Set(None),
        revoked_at: Set(None),
        revocation_bytes: Set(None),
    }
    .insert(db)
    .await
    .unwrap();
}

#[tokio::test]
async fn policy_terminal_kv_operations() {
    for pg in [false, true] {
        let Some((db, _fixture)) = connection(pg).await else {
            continue;
        };
        let store = SpaceDatabase::new(
            db.clone(),
            MemoryStore::default(),
            StaticSecret::new(vec![0; 32]).unwrap(),
        )
        .await
        .unwrap();
        let (owner_key, owner) = identity();
        let (holder_key, holder) = identity();
        let space_id = SpaceId::new(owner.parse().unwrap(), "files".parse().unwrap()).unwrap();
        space::ActiveModel {
            id: Set(SpaceIdWrap(space_id.clone())),
        }
        .insert(&db)
        .await
        .unwrap();
        let resource = format!("{space_id}/kv/docs/secret");
        let path: tinycloud_auth::resource::Path = "docs/secret".parse().unwrap();
        let mut body = HashBuffer::new(Vec::new());
        body.write_all(b"owner-private-original").await.unwrap();
        let owner_put = invocation_event(&signed(
            &owner_key,
            &owner,
            &owner,
            &resource,
            "tinycloud.kv/put",
            vec![],
            false,
        ));
        store
            .invoke::<MemoryStaging>(
                owner_put,
                HashMap::from([(
                    (space_id.clone(), path.clone()),
                    (Metadata(Default::default()), body),
                )]),
            )
            .await
            .map_err(|e| e.to_string())
            .unwrap();
        for action in ["get", "metadata", "list", "put", "del"] {
            let ability = format!("tinycloud.kv/{action}");
            let target = if action == "list" {
                format!("{space_id}/kv/docs/")
            } else {
                resource.clone()
            };
            let root = persist_root(&db, &holder_key, &holder, &target, &ability).await;
            let invoke = invocation_event(&signed(
                &holder_key,
                &holder,
                &owner,
                &target,
                &ability,
                vec![root],
                false,
            ));
            assert!(
                invocation::verify_and_authorize(&db, &invoke.0, OffsetDateTime::now_utc())
                    .await
                    .is_err()
            );
            let mut allowed_outcomes = None;
            for registered in [false, true] {
                if registered {
                    let grant = delegation_event(&signed(
                        &owner_key,
                        &owner,
                        &holder,
                        &target,
                        &ability,
                        vec![],
                        false,
                    ));
                    delegation::process(&db, &grant, None).await.unwrap();
                    register_root(&db, root).await;
                }
                let mut inputs = HashMap::new();
                if action == "put" {
                    let mut replacement = HashBuffer::new(Vec::new());
                    replacement.write_all(b"holder-replacement").await.unwrap();
                    inputs.insert(
                        (space_id.clone(), path.clone()),
                        (Metadata(Default::default()), replacement),
                    );
                }
                let result = store.invoke::<MemoryStaging>(invoke.clone(), inputs).await;
                if registered {
                    allowed_outcomes = Some(result.map_err(|e| e.to_string()).unwrap().1);
                } else {
                    assert!(
                        result.is_err(),
                        "unregistered terminal must refuse KV {action}"
                    );
                    assert!(store.kv_get(&space_id, &path).await.unwrap().is_some());
                }
            }
            let outcomes = allowed_outcomes.unwrap();
            if action == "get" {
                let mut outcomes = outcomes.into_iter();
                let crate::InvocationOutcome::KvRead(Some((_, _, mut content))) =
                    outcomes.next().unwrap()
                else {
                    panic!("expected private data")
                };
                let mut bytes = Vec::new();
                content.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"owner-private-original");
            }
            if action == "put" {
                let (_, _, mut content) = store.kv_get(&space_id, &path).await.unwrap().unwrap();
                let mut bytes = Vec::new();
                content.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"holder-replacement");
            }
            if action == "del" {
                assert!(store.kv_get(&space_id, &path).await.unwrap().is_none());
            }
        }
    }
}

#[tokio::test]
async fn policy_terminal_special_controls() {
    for pg in [false, true] {
        let Some((db, _fixture)) = connection(pg).await else {
            continue;
        };
        let store = SpaceDatabase::new(
            db.clone(),
            MemoryStore::default(),
            StaticSecret::new(vec![0; 32]).unwrap(),
        )
        .await
        .unwrap();
        let (owner_key, owner) = identity();
        let (_victim_key, victim) = identity();
        let (holder_key, holder) = identity();
        let space_id = SpaceId::new(owner.parse().unwrap(), "files".parse().unwrap()).unwrap();
        let target_event = delegation_event(&signed(
            &owner_key,
            &owner,
            &victim,
            &format!("{space_id}/kv/docs/secret"),
            "tinycloud.kv/get",
            vec![],
            false,
        ));
        delegation::process(&db, &target_event, None).await.unwrap();
        let target = target_event.content_hash();
        let target_row = delegation::Entity::find_by_id(target)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        let target_abilities = abilities::Entity::find()
            .filter(abilities::Column::Delegation.eq(target))
            .all(&db)
            .await
            .unwrap();
        for action in [
            ControlAction::Revoke,
            ControlAction::Status,
            ControlAction::Renew,
        ] {
            for resource in [
                format!("{space_id}/delegation"),
                format!("urn:cid:{}", target.to_cid(0x55)),
            ] {
                let root =
                    persist_root(&db, &holder_key, &holder, &resource, action.ability()).await;
                let decision = control_proof_decision(&db, &holder, &[root], action, &target)
                    .await
                    .unwrap();
                match &decision {
                    ControlProofDecision::Scoped(control) => {
                        assert!(!control.authorizes_target(
                            &target,
                            &target_row,
                            &target_abilities
                        ));
                        assert!(!control.directly_authorizes_cid(&target, &target_row));
                    }
                    ControlProofDecision::Ungranted | ControlProofDecision::Denied => {}
                    _ => panic!("proof must not become direct authority: {decision:?}"),
                }
                assert!(
                    !revoker_is_authorized(&db, &target_row, &target, &holder, &[root])
                        .await
                        .unwrap()
                );
                assert!(store
                    .delegation_status(target, &holder, &[root])
                    .await
                    .map_err(|e| e.to_string())
                    .unwrap()
                    .is_none());
                assert!(matches!(
                    crate::renewal::renewal_history(
                        &db,
                        &target.to_cid(0x55).to_string(),
                        &holder,
                        &[root]
                    )
                    .await,
                    Err(crate::renewal::RenewalStoreError::Unauthorized)
                ));
            }
        }
        for list_principal in [
            owner.clone(),
            "did:pkh:eip155:1:0x1111111111111111111111111111111111111111".to_string(),
        ] {
            let list_space =
                SpaceId::new(list_principal.parse().unwrap(), "files".parse().unwrap()).unwrap();
            let list_resource = format!("{list_space}/delegation");
            let root = persist_root(
                &db,
                &holder_key,
                &holder,
                &list_resource,
                "tinycloud.delegation/list",
            )
            .await;
            let inv = invocation_event(&signed(
                &holder_key,
                &holder,
                &owner,
                &list_resource,
                "tinycloud.delegation/list",
                vec![root],
                false,
            ));
            assert!(matches!(
                store
                    .query_account_delegations(&inv.0, &DelegationQuery::default())
                    .await,
                Err(crate::db::AccountDelegationQueryError::Unauthorized)
            ));
        }
        // Positive control: actual owner control on the foreign target is recognized.
        let grant = delegation_event(&signed(
            &owner_key,
            &owner,
            &holder,
            &format!("{space_id}/delegation"),
            "tinycloud.delegation/revoke",
            vec![],
            false,
        ));
        delegation::process(&db, &grant, None).await.unwrap();
        assert!(revoker_is_authorized(
            &db,
            &target_row,
            &target,
            &holder,
            &[grant.content_hash().to_cid(0x55)]
        )
        .await
        .unwrap());
    }
}

#[tokio::test]
async fn policy_terminal_capabilities_read() {
    for pg in [false, true] {
        let Some((db, _fixture)) = connection(pg).await else {
            continue;
        };
        let store = SpaceDatabase::new(
            db.clone(),
            MemoryStore::default(),
            StaticSecret::new(vec![0; 32]).unwrap(),
        )
        .await
        .unwrap();
        let (owner_key, owner) = identity();
        let (_victim_key, victim) = identity();
        let (holder_key, holder) = identity();
        let space_id = SpaceId::new(owner.parse().unwrap(), "files".parse().unwrap()).unwrap();
        space::ActiveModel {
            id: Set(SpaceIdWrap(space_id.clone())),
        }
        .insert(&db)
        .await
        .unwrap();
        let target_event = delegation_event(&signed(
            &owner_key,
            &owner,
            &victim,
            &format!("{space_id}/kv/docs/secret"),
            "tinycloud.kv/get",
            vec![],
            false,
        ));
        delegation::process(&db, &target_event, None).await.unwrap();
        let resource = format!("{space_id}/capabilities/all");
        let root = persist_root(
            &db,
            &holder_key,
            &holder,
            &resource,
            "tinycloud.capabilities/read",
        )
        .await;
        let inv = invocation_event(&signed(
            &holder_key,
            &holder,
            &owner,
            &resource,
            "tinycloud.capabilities/read",
            vec![root],
            false,
        ));
        assert!(store
            .invoke::<MemoryStaging>(inv.clone(), HashMap::new())
            .await
            .is_err());
        let grant = delegation_event(&signed(
            &owner_key,
            &owner,
            &holder,
            &resource,
            "tinycloud.capabilities/read",
            vec![],
            false,
        ));
        delegation::process(&db, &grant, None).await.unwrap();
        register_root(&db, root).await;
        let (_, outcomes) = store
            .invoke::<MemoryStaging>(inv, HashMap::new())
            .await
            .map_err(|e| e.to_string())
            .unwrap();
        let crate::InvocationOutcome::OpenSessions(rows) = outcomes.into_iter().next().unwrap()
        else {
            panic!("expected delegation bytes")
        };
        assert_eq!(
            rows.get(&target_event.content_hash())
                .unwrap()
                .serialized_bytes(),
            target_event.serialized_bytes()
        );
    }
}
