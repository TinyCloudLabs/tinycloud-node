use sea_orm_migration::prelude::*;
pub mod m20230510_101010_init_tables;
pub mod m20260218_sql_database;
pub mod m20260409_000000_hook_tables;
pub mod m20260512_000000_signed_kv_tickets;
pub mod m20260516_000000_database_artifacts;
pub mod m20260601_000000_encryption_networks;
pub mod m20260602_000000_rename_encryption_owner_did;
pub mod m20260715_000000_policy_authority;
pub mod m20260715_000000_revocation_timestamp;
pub mod m20260719_000000_share_email_protocol;
pub mod m20260719_000001_share_policy_presentation_jti;
pub mod m20260719_000002_policy_status_freshness;
pub mod m20260724_000000_database_artifact_deltas;
pub mod m20260724_000000_invocation_replay;
pub mod m20260724_010000_current_kv;
pub mod m20260725_000000_request_path_indexes;
pub mod m20260726_000000_owner_share_policy;
pub mod m20260726_000001_owner_share_policy_proof;
pub mod m20260726_000002_owner_share_enforcement_bytes;
pub mod m20260731_000000_policy_v3;
pub mod m20260915_000000_meeting_legacy_write_guard;
pub mod m20261005_000000_current_kv_sync_order;
pub mod m20261005_000000_deactivate_hook_subscriptions;
pub mod m20261007_000000_database_alias;
pub mod m20261007_010000_database_identity_fence;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230510_101010_init_tables::Migration),
            Box::new(m20260218_sql_database::Migration),
            Box::new(m20260409_000000_hook_tables::Migration),
            Box::new(m20260512_000000_signed_kv_tickets::Migration),
            Box::new(m20260516_000000_database_artifacts::Migration),
            Box::new(m20260601_000000_encryption_networks::Migration),
            Box::new(m20260602_000000_rename_encryption_owner_did::Migration),
            Box::new(m20260715_000000_revocation_timestamp::Migration),
            Box::new(m20260715_000000_policy_authority::Migration),
            Box::new(m20260719_000000_share_email_protocol::Migration),
            Box::new(m20260719_000001_share_policy_presentation_jti::Migration),
            Box::new(m20260719_000002_policy_status_freshness::Migration),
            Box::new(m20260724_000000_invocation_replay::Migration),
            Box::new(m20260724_010000_current_kv::Migration),
            Box::new(m20260724_000000_database_artifact_deltas::Migration),
            Box::new(m20260725_000000_request_path_indexes::Migration),
            Box::new(m20260726_000000_owner_share_policy::Migration),
            Box::new(m20260726_000001_owner_share_policy_proof::Migration),
            Box::new(m20260726_000002_owner_share_enforcement_bytes::Migration),
            Box::new(m20260731_000000_policy_v3::Migration),
            Box::new(m20260915_000000_meeting_legacy_write_guard::Migration),
            Box::new(m20261005_000000_current_kv_sync_order::Migration),
            Box::new(m20261005_000000_deactivate_hook_subscriptions::Migration),
            Box::new(m20261007_000000_database_alias::Migration),
            Box::new(m20261007_010000_database_identity_fence::Migration),
        ]
    }
}

#[cfg(test)]
mod release_line_tests {
    use super::*;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};

    #[tokio::test]
    async fn postgres_fresh_and_release_line_upgrade_apply_n3_last() {
        let Some(url) = crate::test_support::postgres_test_url(
            "postgres_fresh_and_release_line_upgrade_apply_n3_last",
        ) else {
            return;
        };
        let admin = Database::connect(url.clone()).await.unwrap();
        let base_count = (Migrator::migrations().len() - 2) as u32;
        for path in ["fresh", "release"] {
            let schema = format!(
                "tc780_{path}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            admin
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    format!("CREATE SCHEMA {schema}"),
                ))
                .await
                .unwrap();
            let mut options = ConnectOptions::new(url.clone());
            options.set_schema_search_path(schema.clone());
            let db = Database::connect(options).await.unwrap();
            if path == "release" {
                Migrator::up(&db, Some(base_count)).await.unwrap();
                let applied = db
                    .query_all(Statement::from_string(
                        DbBackend::Postgres,
                        "SELECT version FROM seaql_migrations".to_string(),
                    ))
                    .await
                    .unwrap();
                assert_eq!(applied.len(), base_count as usize);
                let versions: Vec<String> = applied
                    .iter()
                    .map(|row| row.try_get("", "version").unwrap())
                    .collect();
                for required in [
                    "m20260915_000000_meeting_legacy_write_guard",
                    "m20261005_000000_current_kv_sync_order",
                    "m20261005_000000_deactivate_hook_subscriptions",
                ] {
                    assert!(versions.iter().any(|version| version == required));
                }
            }
            Migrator::up(&db, None).await.unwrap();
            let applied = db
                .query_all(Statement::from_string(
                    DbBackend::Postgres,
                    "SELECT version FROM seaql_migrations".to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(applied.len(), Migrator::migrations().len());
            let versions: Vec<String> = applied
                .iter()
                .map(|row| row.try_get("", "version").unwrap())
                .collect();
            assert!(versions.contains(&"m20261007_000000_database_alias".to_string()));
            assert!(versions.contains(&"m20261007_010000_database_identity_fence".to_string()));
            drop(db);
            admin
                .execute(Statement::from_string(
                    DbBackend::Postgres,
                    format!("DROP SCHEMA {schema} CASCADE"),
                ))
                .await
                .unwrap();
        }
    }
}
