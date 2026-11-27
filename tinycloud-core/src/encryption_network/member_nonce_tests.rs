//! `consume_unexpired_invocation_nonce`, the only nonce primitive exposed
//! outside this crate.

use std::sync::Arc;

use sea_orm::{ConnectOptions, Database, EntityTrait, PaginatorTrait};
use sea_orm_migration::MigratorTrait;
use time::{Duration, OffsetDateTime};

use crate::encryption::ColumnEncryption;
use crate::encryption_network::{EncryptionService, EncryptionServiceError, LocalOneOfOneBackend};
use crate::migrations::Migrator;
use crate::models::encryption_nonce;

const INVOKER: &str = "did:key:z6MkTestSigner";

async fn service() -> EncryptionService {
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .expect("connect sqlite");
    Migrator::up(&db, None).await.expect("migrate");
    let backend = Arc::new(LocalOneOfOneBackend::new(ColumnEncryption::new([0xAB; 32])));
    EncryptionService::new(db, "did:key:z6MkNodeTest".to_string(), backend)
}

async fn rows(service: &EncryptionService) -> u64 {
    encryption_nonce::Entity::find()
        .count(&service.db)
        .await
        .expect("count nonces")
}

#[tokio::test]
async fn an_expired_invocation_is_refused_before_its_nonce_is_written() {
    let service = service().await;
    let now = OffsetDateTime::now_utc();
    for expires_at in [now - Duration::seconds(1), now] {
        let err = service
            .consume_unexpired_invocation_nonce(
                INVOKER,
                "nonce-1",
                expires_at.unix_timestamp(),
                now,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, EncryptionServiceError::Expired), "{err}");
    }
    assert_eq!(rows(&service).await, 0);
}

#[tokio::test]
async fn a_repeated_invoker_and_nonce_is_refused() {
    let service = service().await;
    let now = OffsetDateTime::now_utc();
    let exp = (now + Duration::seconds(60)).unix_timestamp();
    service
        .consume_unexpired_invocation_nonce(INVOKER, "nonce-1", exp, now)
        .await
        .unwrap();
    let err = service
        .consume_unexpired_invocation_nonce(INVOKER, "nonce-1", exp, now)
        .await
        .unwrap_err();
    assert!(matches!(err, EncryptionServiceError::NonceReplay), "{err}");
    service
        .consume_unexpired_invocation_nonce("did:key:z6MkSecondSigner", "nonce-1", exp, now)
        .await
        .unwrap();
    assert_eq!(rows(&service).await, 2);
}
