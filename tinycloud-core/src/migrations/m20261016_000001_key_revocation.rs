use sea_orm_migration::prelude::*;

use crate::models::key_revocation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(key_revocation::target::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(key_revocation::target::Column::TargetDid)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(key_revocation::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(key_revocation::Column::TargetDid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(key_revocation::Column::ScopeKey)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(key_revocation::Column::RevokedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(key_revocation::Column::TargetDid)
                            .col(key_revocation::Column::ScopeKey),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(key_revocation::nonce::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(key_revocation::nonce::Column::IssuerDid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(key_revocation::nonce::Column::Nonce)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(key_revocation::nonce::Column::AuthorizationHash)
                            .binary_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(key_revocation::nonce::Column::TargetDid)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(key_revocation::nonce::Column::ReceiptBytes)
                            .blob()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(key_revocation::nonce::Column::IssuerDid)
                            .col(key_revocation::nonce::Column::Nonce),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(key_revocation::nonce::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(key_revocation::Entity).to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(key_revocation::target::Entity)
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database, EntityTrait,
    };

    struct MySqlDatabase {
        url: String,
        name: String,
    }

    impl Drop for MySqlDatabase {
        fn drop(&mut self) {
            let (url, name) = (self.url.clone(), self.name.clone());
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        let admin = Database::connect(ConnectOptions::new(url)).await.unwrap();
                        admin
                            .execute_unprepared(&format!("DROP DATABASE IF EXISTS {name}"))
                            .await
                            .unwrap();
                    })
            })
            .join()
            .unwrap();
        }
    }

    #[tokio::test]
    async fn mysql_nonce_migration_persists_real_digest_and_replay_receipt() {
        let url = match std::env::var("TINYCLOUD_TEST_MYSQL_URL") {
            Ok(url) if !url.trim().is_empty() => url,
            _ => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "MySQL nonce migration requires TINYCLOUD_TEST_MYSQL_URL in CI"
                );
                eprintln!("skipping MySQL nonce migration: TINYCLOUD_TEST_MYSQL_URL is unset");
                return;
            }
        };
        let name = format!(
            "tc1149_nonce_{}_{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let database = MySqlDatabase {
            url: url.clone(),
            name: name.clone(),
        };
        let admin = Database::connect(ConnectOptions::new(url.clone()))
            .await
            .expect("connect to disposable MySQL");
        admin
            .execute_unprepared(&format!("CREATE DATABASE {name}"))
            .await
            .expect("create isolated MySQL database");
        admin.close().await.unwrap();
        let database_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
        let conn = Database::connect(ConnectOptions::new(database_url))
            .await
            .expect("connect to isolated MySQL database");
        Migration.up(&SchemaManager::new(&conn)).await.unwrap();

        let target = "did:key:tc1149-mysql-test-principal".to_owned();
        let receipt = key_revocation::KeyRevokeReceipt {
            revoked: true,
            target_did: target.clone(),
            scope: key_revocation::KeyRevokeScope::Global,
            revoked_at: 1_000,
        };
        let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        assert!(
            receipt_bytes.len() > 1,
            "real signed receipt exceeds BINARY(1)"
        );
        let digest = vec![0x42; 32];
        let nonce = "mysql-nonce-roundtrip".to_owned();
        key_revocation::nonce::ActiveModel {
            issuer_did: Set(target.clone()),
            nonce: Set(nonce.clone()),
            authorization_hash: Set(digest.clone()),
            target_did: Set(target.clone()),
            receipt_bytes: Set(receipt_bytes.clone()),
        }
        .insert(&conn)
        .await
        .expect("persist full-width signed digest and durable receipt on MySQL");
        let stored = key_revocation::nonce::Entity::find_by_id((target, nonce))
            .one(&conn)
            .await
            .unwrap()
            .expect("committed replay receipt");
        assert_eq!(stored.authorization_hash, digest);
        assert_eq!(stored.receipt_bytes, receipt_bytes);
        assert_eq!(
            serde_json::from_slice::<key_revocation::KeyRevokeReceipt>(&stored.receipt_bytes)
                .unwrap(),
            receipt,
        );
        conn.close().await.unwrap();
        drop(database);
    }
}
