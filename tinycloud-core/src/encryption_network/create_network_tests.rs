//! One-transaction network creation and repair of half-created networks.

use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, Database, DatabaseConnection,
    EntityTrait, PaginatorTrait, QueryFilter,
};
use sea_orm_migration::MigratorTrait;

use crate::encryption::ColumnEncryption;
use crate::encryption_network::backend::LocalOneOfOneBackend;
use crate::encryption_network::network_id::NetworkId;
use crate::encryption_network::service::{
    CreateNetworkRequest, EncryptionService, EncryptionServiceError,
};
use crate::encryption_network::types::{NetworkState, Threshold};
use crate::migrations::Migrator;
use crate::models::{encryption_ceremony, encryption_network, encryption_network_member};
use crate::test_support::PostgresTestSchema;

const NODE_DID: &str = "did:key:z6MkNodeTest";
const OWNER: &str = "did:key:z6MkOwnerTest";

async fn fresh_db() -> DatabaseConnection {
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .expect("connect sqlite");
    Migrator::up(&db, None).await.expect("migrate");
    db
}

fn service(db: DatabaseConnection) -> EncryptionService {
    let backend = Arc::new(LocalOneOfOneBackend::new(ColumnEncryption::new(
        [0xABu8; 32],
    )));
    EncryptionService::new(db, NODE_DID.to_string(), backend)
}

fn request() -> CreateNetworkRequest {
    CreateNetworkRequest {
        name: "default".to_string(),
        owner_did: OWNER.to_string(),
        threshold: Threshold::one_of_one(),
    }
}

async fn row_counts(db: &DatabaseConnection) -> (u64, u64, u64) {
    (
        encryption_network::Entity::find().count(db).await.unwrap(),
        encryption_network_member::Entity::find()
            .count(db)
            .await
            .unwrap(),
        encryption_ceremony::Entity::find().count(db).await.unwrap(),
    )
}

#[tokio::test]
async fn failure_between_inserts_leaves_no_rows_and_creation_can_be_retried() {
    // 1: after the ceremony row, 2: after the network row, 3: after the member row.
    for stage in 1..=3u8 {
        let db = fresh_db().await;
        let svc = service(db.clone());
        svc.create_faults.fail_after_stage.store(stage, SeqCst);

        let err = svc.create_one_of_one_network(request()).await.unwrap_err();
        assert!(
            matches!(err, EncryptionServiceError::Db(_)),
            "stage {stage}"
        );
        assert_eq!(row_counts(&db).await, (0, 0, 0), "stage {stage}");

        let created = svc.create_one_of_one_network(request()).await.unwrap();
        assert_eq!(created.state, NetworkState::Active);
        assert_eq!(row_counts(&db).await, (1, 1, 1), "stage {stage}");
    }
}

/// A network row written by the earlier non-transactional create, whose member
/// insert never ran.
async fn insert_half_created(db: &DatabaseConnection, svc: &EncryptionService) -> NetworkId {
    let network_id = NetworkId::new(OWNER.to_string(), "default".to_string()).unwrap();
    let generated = svc.backend.generate().unwrap();
    encryption_network::ActiveModel {
        network_id: Set(network_id.to_string()),
        owner_did: Set(OWNER.to_string()),
        name: Set("default".to_string()),
        alg: Set(generated.alg),
        key_version: Set(1),
        public_key: Set(generated.public_key),
        state: Set("active".to_string()),
        threshold_n: Set(1),
        threshold_t: Set(1),
        key_backend: Set(svc.backend.kind().as_str().to_string()),
        sealed_private_key: Set(Some(generated.sealed_private_key)),
        created_at: Set("2026-01-01T00:00:00Z".to_string()),
        updated_at: Set("2026-01-01T00:00:00Z".to_string()),
    }
    .insert(db)
    .await
    .unwrap();
    encryption_ceremony::ActiveModel {
        ceremony_id: Set("ceremony:old".to_string()),
        network_id: Set(network_id.to_string()),
        kind: Set("initial".to_string()),
        state: Set("started".to_string()),
        transcript_hash: Set(None),
        started_at: Set("2026-01-01T00:00:00Z".to_string()),
        completed_at: Set(None),
        failure: Set(None),
    }
    .insert(db)
    .await
    .unwrap();
    network_id
}

#[tokio::test]
async fn half_created_network_answers_as_missing_and_is_not_used_as_active() {
    let db = fresh_db().await;
    let svc = service(db.clone());
    let id = insert_half_created(&db, &svc).await;

    assert!(matches!(
        svc.get_network(&id).await,
        Err(EncryptionServiceError::NetworkNotFound)
    ));
    assert!(matches!(
        svc.get_network_by_name("default", None).await,
        Err(EncryptionServiceError::NetworkNotFound)
    ));
    assert!(matches!(
        svc.get_network_by_name("default", Some(OWNER)).await,
        Err(EncryptionServiceError::NetworkNotFound)
    ));
}

#[tokio::test]
async fn create_repairs_a_half_created_network_in_place() {
    let db = fresh_db().await;
    let svc = service(db.clone());
    let id = insert_half_created(&db, &svc).await;
    let before = encryption_network::Entity::find_by_id(id.to_string())
        .one(&db)
        .await
        .unwrap()
        .unwrap();

    let repaired = svc.create_one_of_one_network(request()).await.unwrap();
    assert_eq!(repaired.state, NetworkState::Active);
    assert_eq!(repaired.members.len(), 1);
    // The existing key is kept, not regenerated.
    assert_eq!(repaired.public_encryption_key, before.public_key);
    assert_eq!(row_counts(&db).await, (1, 1, 1));
    let ceremony = encryption_ceremony::Entity::find()
        .filter(encryption_ceremony::Column::NetworkId.eq(id.to_string()))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ceremony.state, "completed");

    // A second create is a plain duplicate.
    assert!(matches!(
        svc.create_one_of_one_network(request()).await,
        Err(EncryptionServiceError::NetworkAlreadyExists)
    ));
}

/// Concurrent creates and repairs on PostgreSQL: exactly one writer wins and
/// every other one is answered as a duplicate, never a raw key violation.
#[tokio::test]
async fn concurrent_creates_and_repairs_on_postgres_leave_one_winner() {
    let Some(schema) = PostgresTestSchema::new("concurrent_network_create").await else {
        return;
    };
    for round in 0..5 {
        for half_created in [false, true] {
            let name = format!("net{round}{half_created}");
            let req = |n: &str| CreateNetworkRequest {
                name: n.to_string(),
                owner_did: OWNER.to_string(),
                threshold: Threshold::one_of_one(),
            };
            let services: Vec<_> = (0..4).map(|_| service(schema.conn.clone())).collect();
            if half_created {
                let id = NetworkId::new(OWNER.to_string(), name.clone()).unwrap();
                let generated = services[0].backend.generate().unwrap();
                encryption_network::ActiveModel {
                    network_id: Set(id.to_string()),
                    owner_did: Set(OWNER.to_string()),
                    name: Set(name.clone()),
                    alg: Set(generated.alg),
                    key_version: Set(1),
                    public_key: Set(generated.public_key),
                    state: Set("active".to_string()),
                    threshold_n: Set(1),
                    threshold_t: Set(1),
                    key_backend: Set(services[0].backend.kind().as_str().to_string()),
                    sealed_private_key: Set(Some(generated.sealed_private_key)),
                    created_at: Set("2026-01-01T00:00:00Z".to_string()),
                    updated_at: Set("2026-01-01T00:00:00Z".to_string()),
                }
                .insert(&schema.conn)
                .await
                .unwrap();
            }
            let results = futures::future::join_all(
                services
                    .iter()
                    .map(|svc| svc.create_one_of_one_network(req(&name))),
            )
            .await;
            let won = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(won, 1, "{name}: {results:?}");
            for r in results.iter().filter(|r| r.is_err()) {
                assert!(
                    matches!(r, Err(EncryptionServiceError::NetworkAlreadyExists)),
                    "{name}: {r:?}"
                );
            }
            let id = NetworkId::new(OWNER.to_string(), name.clone()).unwrap();
            let members = encryption_network_member::Entity::find()
                .filter(encryption_network_member::Column::NetworkId.eq(id.to_string()))
                .count(&schema.conn)
                .await
                .unwrap();
            assert_eq!(members, 1, "{name}");
        }
    }
}
