//! Replay the unchanged frozen bytes at their published verifier time.
use super::*;
use sea_orm::{Database, TransactionTrait};
use sea_orm_migration::MigratorTrait;

#[tokio::test]
async fn frozen_proofless_owner_lease_registers_active_generation_one() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tinycloud-node-server/tests/fixtures/renewal-lease-v1.json"
    ))
    .unwrap();
    let db = Database::connect("sqlite::memory:").await.unwrap();
    crate::migrations::Migrator::up(&db, None).await.unwrap();
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let seed = secret.derive_key(RENEWER_KEY_CONTEXT);
    let (_, epoch, _) = initialize_renewal_identity(&db, seed).await.unwrap();
    let tx = db.begin().await.unwrap();
    for name in ["ownerDid", "holderDid", "renewerDid"] {
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO actor (id) VALUES ($1)",
            [Value::String(Some(Box::new(
                fixture[name].as_str().unwrap().into(),
            )))],
        ))
        .await
        .unwrap();
    }
    for field in ["originalToken", "leaseToken"] {
        let bytes = fixture[field].as_str().unwrap().as_bytes();
        let info = signed_delegation_info(bytes).unwrap();
        let id = crate::hash::hash(bytes);
        tx.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO delegation (id,delegator,delegatee,expiry,issued_at,not_before,facts,serialization,serialization_format) VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,0)",
            [Vec::<u8>::from(id).into(),info.delegator.into(),info.delegate.into(),
             Value::TimeDateTime(Some(Box::new(db_datetime(info.expiry.unwrap().unix_timestamp()).unwrap()))),bytes.to_vec().into()])).await.unwrap();
        tx.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO delegation_cid_alias (id,canonical,encrypted) VALUES ($1,$1,FALSE)",
            [Vec::<u8>::from(id).into()],
        ))
        .await
        .unwrap();
    }
    let lease_id = canonical_cid(fixture["leaseCid"].as_str().unwrap())
        .unwrap()
        .1;
    tx.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
        "INSERT INTO ability (delegation,resource,ability,caveats) VALUES ($1,$2,'tinycloud.delegation/renew',$3)",
        [Vec::<u8>::from(lease_id).into(),fixture["renewResource"].as_str().unwrap().into(),
         Value::Json(Some(Box::new(serde_json::json!({}))))])).await.unwrap();
    let lease = crate::events::Delegation::from_header_ser::<
        tinycloud_auth::authorization::TinyCloudDelegation,
    >(fixture["leaseToken"].as_str().unwrap())
    .unwrap();
    assert!(lease.0.parents.is_empty());
    register_lease_at(
        &tx,
        &lease,
        seed,
        epoch,
        fixture["nodeIdentityDid"].as_str().unwrap(),
        None,
        fixture["issuedAt"].as_i64().unwrap() + 1,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let row = db
        .query_one(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT state,generation FROM renewal_lease",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<String>("", "state").unwrap(), "active");
    assert_eq!(row.try_get::<i64>("", "generation").unwrap(), 1);
}
