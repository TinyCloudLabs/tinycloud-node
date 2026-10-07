//! TC-541: deactivate every webhook subscription registered before hooks
//! routes verified the registering invocation.
//!
//! `hook_subscription` stores no delegation reference, so rows written while
//! `/hooks/webhooks` trusted claimed capabilities cannot be re-verified. The
//! dispatcher already dead-letters deliveries for inactive subscriptions with
//! "subscription inactive"; legitimate owners re-register under the verified
//! route.

use std::collections::BTreeSet;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
use sea_orm_migration::prelude::*;

use crate::models::hook_subscription;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let owners: BTreeSet<(String, String)> = hook_subscription::Entity::find()
            .select_only()
            .column(hook_subscription::Column::SpaceId)
            .column(hook_subscription::Column::SubscriberDid)
            .filter(hook_subscription::Column::Active.eq(true))
            .into_tuple::<(String, String)>()
            .all(db)
            .await?
            .into_iter()
            .collect();
        let deactivated = hook_subscription::Entity::update_many()
            .col_expr(hook_subscription::Column::Active, Expr::value(false))
            .filter(hook_subscription::Column::Active.eq(true))
            .exec(db)
            .await?
            .rows_affected;

        // Callback URLs and secrets are deliberately not logged.
        tracing::warn!(
            deactivated,
            owners = owners.len(),
            "deactivated webhook subscriptions; owners must re-register"
        );
        for (space_id, subscriber_did) in &owners {
            tracing::warn!(
                space_id = %space_id,
                subscriber_did = %subscriber_did,
                "webhook subscription deactivated"
            );
        }
        Ok(())
    }

    /// Irreversible: which rows were active is not retained, and reactivating
    /// unverified registrations is exactly what this migration prevents.
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ConnectOptions, Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;

    fn subscription(
        id: &str,
        space: &str,
        subscriber: &str,
        active: bool,
    ) -> hook_subscription::Model {
        hook_subscription::Model {
            id: id.to_string(),
            subscriber_did: subscriber.to_string(),
            space_id: space.to_string(),
            target_service: "kv".to_string(),
            path_prefix: Some("documents".to_string()),
            abilities_json: None,
            callback_url: "https://hooks.example/callback".to_string(),
            encrypted_secret: vec![1, 2, 3],
            secret_key_id: "primary".to_string(),
            active,
            created_at: "2026-04-09T00:00:00Z".to_string(),
        }
    }

    /// Applies every migration before this one, mirroring a node that was
    /// running the release this migration ships in.
    async fn database_before_this_migration() -> DatabaseConnection {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        let this_migration = Migration.name();
        let before_this = Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == this_migration)
            .unwrap_or_else(|| panic!("{this_migration} must be registered in Migrator"))
            as u32;
        Migrator::up(&db, Some(before_this)).await.unwrap();
        db
    }

    #[tokio::test]
    async fn deactivates_every_existing_subscription() {
        let db = database_before_this_migration().await;
        hook_subscription::Entity::insert_many(
            [
                subscription("sub_a", "tinycloud:space-a", "did:key:a", true),
                subscription("sub_b", "tinycloud:space-a", "did:key:a", true),
                subscription("sub_c", "tinycloud:space-b", "did:key:b", true),
                subscription("sub_d", "tinycloud:space-b", "did:key:b", false),
            ]
            .map(hook_subscription::ActiveModel::from),
        )
        .exec(&db)
        .await
        .unwrap();

        Migrator::up(&db, None).await.unwrap();

        let rows = hook_subscription::Entity::find().all(&db).await.unwrap();
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|row| !row.active));
        assert!(Migrator::get_pending_migrations(&db)
            .await
            .unwrap()
            .is_empty());
    }
}
