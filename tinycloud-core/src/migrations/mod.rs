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
        ]
    }
}
