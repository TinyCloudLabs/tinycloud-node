use sea_orm::{ConnectionTrait, EntityTrait, FromQueryResult, QueryOrder, Schema};
use sea_orm_migration::prelude::*;

use crate::models::{current_kv, kv_delete, kv_write};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(current_kv::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_current_kv_space_deleted_key")
                    .table(current_kv::Entity)
                    .col(current_kv::Column::Space)
                    .col(current_kv::Column::Deleted)
                    .col(current_kv::Column::Key)
                    .to_owned(),
            )
            .await?;
        backfill_and_validate(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(current_kv::Entity).to_owned())
            .await
    }
}

fn latest_writes() -> SelectStatement {
    let write = Alias::new("candidate");
    let newer = Alias::new("newer");
    let tombstone = Alias::new("tombstone");

    let newer_order = Condition::any()
        .add(
            Expr::col((newer.clone(), kv_write::Column::Seq))
                .gt(Expr::col((write.clone(), kv_write::Column::Seq))),
        )
        .add(
            Condition::all()
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Seq))
                        .equals((write.clone(), kv_write::Column::Seq)),
                )
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Epoch))
                        .gt(Expr::col((write.clone(), kv_write::Column::Epoch))),
                ),
        )
        .add(
            Condition::all()
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Seq))
                        .equals((write.clone(), kv_write::Column::Seq)),
                )
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Epoch))
                        .equals((write.clone(), kv_write::Column::Epoch)),
                )
                .add(
                    Expr::col((newer.clone(), kv_write::Column::EpochSeq))
                        .gt(Expr::col((write.clone(), kv_write::Column::EpochSeq))),
                ),
        );
    let newer_write = Query::select()
        .expr(Expr::val(1))
        .from_as(kv_write::Entity, newer.clone())
        .cond_where(
            Condition::all()
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Space))
                        .equals((write.clone(), kv_write::Column::Space)),
                )
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Key))
                        .equals((write.clone(), kv_write::Column::Key)),
                )
                .add(newer_order),
        )
        .to_owned();
    let exact_tombstone = Query::select()
        .expr(Expr::val(1))
        .from_as(kv_delete::Entity, tombstone.clone())
        .cond_where(
            Condition::all()
                .add(
                    Expr::col((tombstone.clone(), kv_delete::Column::Space))
                        .equals((write.clone(), kv_write::Column::Space)),
                )
                .add(
                    Expr::col((tombstone.clone(), kv_delete::Column::Key))
                        .equals((write.clone(), kv_write::Column::Key)),
                )
                .add(
                    Expr::col((tombstone.clone(), kv_delete::Column::DeletedInvocationId))
                        .equals((write.clone(), kv_write::Column::Invocation)),
                ),
        )
        .to_owned();

    let mut query = Query::select();
    query
        .columns([
            (write.clone(), kv_write::Column::Space),
            (write.clone(), kv_write::Column::Key),
            (write.clone(), kv_write::Column::Invocation),
            (write.clone(), kv_write::Column::Seq),
            (write.clone(), kv_write::Column::Epoch),
            (write.clone(), kv_write::Column::EpochSeq),
            (write.clone(), kv_write::Column::Value),
            (write.clone(), kv_write::Column::Metadata),
        ])
        .expr_as(Expr::exists(exact_tombstone), current_kv::Column::Deleted)
        .from_as(kv_write::Entity, write)
        .cond_where(Condition::all().not().add(Expr::exists(newer_write)));
    query.to_owned()
}

async fn backfill_and_validate(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let conn = manager.get_connection();
    let backend = manager.get_database_backend();
    let expected_select = latest_writes();
    let mut insert = Query::insert();
    insert
        .into_table(current_kv::Entity)
        .columns([
            current_kv::Column::Space,
            current_kv::Column::Key,
            current_kv::Column::Invocation,
            current_kv::Column::Seq,
            current_kv::Column::Epoch,
            current_kv::Column::EpochSeq,
            current_kv::Column::Value,
            current_kv::Column::Metadata,
            current_kv::Column::Deleted,
        ])
        .select_from(expected_select.clone())
        .map_err(|error| DbErr::Migration(error.to_string()))?;
    conn.execute(backend.build(&insert)).await?;

    let mut expected = current_kv::Model::find_by_statement(backend.build(&expected_select))
        .all(conn)
        .await?;
    let mut actual = current_kv::Entity::find()
        .order_by_asc(current_kv::Column::Space)
        .order_by_asc(current_kv::Column::Key)
        .all(conn)
        .await?;
    expected.sort_by(|a, b| (&a.space, &a.key).cmp(&(&b.space, &b.key)));
    actual.sort_by(|a, b| (&a.space, &a.key).cmp(&(&b.space, &b.key)));

    if actual.len() != expected.len() || actual != expected {
        return Err(DbErr::Migration(format!(
            "current_kv backfill validation mismatch: expected {} rows, found {}",
            expected.len(),
            actual.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash;
    use crate::migrations::Migrator;
    use crate::models::{actor, epoch, invocation, space};
    use crate::relationships::event_order;
    use crate::types::{Metadata, SpaceIdWrap};
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, PaginatorTrait};
    use sea_orm_migration::MigratorTrait;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        resource::SpaceId,
        ssi::{dids::DIDBuf, jwk::JWK},
    };

    async fn insert_write(
        db: &sea_orm::DatabaseConnection,
        space_id: &SpaceId,
        key: &str,
        label: &str,
        seq: i64,
    ) -> kv_write::Model {
        let invocation_id = hash(format!("invocation-{label}").as_bytes());
        let epoch_id = hash(format!("epoch-{label}").as_bytes());
        invocation::ActiveModel {
            id: Set(invocation_id),
            invoker: Set("did:key:migration".to_string()),
            issued_at: Set(OffsetDateTime::now_utc()),
            facts: Set(None),
            serialization: Set(label.as_bytes().to_vec()),
        }
        .insert(db)
        .await
        .unwrap();
        epoch::ActiveModel {
            seq: Set(seq),
            id: Set(epoch_id),
            space: Set(SpaceIdWrap(space_id.clone())),
        }
        .insert(db)
        .await
        .unwrap();
        event_order::ActiveModel {
            seq: Set(seq),
            epoch: Set(epoch_id),
            epoch_seq: Set(0),
            event: Set(invocation_id),
            space: Set(SpaceIdWrap(space_id.clone())),
        }
        .insert(db)
        .await
        .unwrap();
        let write = kv_write::Model {
            space: SpaceIdWrap(space_id.clone()),
            key: key
                .parse::<tinycloud_auth::resource::Path>()
                .unwrap()
                .into(),
            invocation: invocation_id,
            seq,
            epoch: epoch_id,
            epoch_seq: 0,
            value: hash(format!("value-{label}").as_bytes()),
            metadata: Metadata(BTreeMap::from([("label".to_string(), label.to_string())])),
        };
        kv_write::ActiveModel::from(write.clone())
            .insert(db)
            .await
            .unwrap();
        write
    }

    #[tokio::test]
    async fn backfill_preserves_latest_live_and_deleted_watermarks() {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, Some(13)).await.unwrap();
        let did: DIDBuf = DID_METHODS
            .generate(&JWK::generate_ed25519().unwrap(), "key")
            .unwrap();
        let space_id = SpaceId::new(did, "migration".parse().unwrap());
        actor::ActiveModel {
            id: Set("did:key:migration".to_string()),
        }
        .insert(&db)
        .await
        .unwrap();
        space::ActiveModel {
            id: Set(SpaceIdWrap(space_id.clone())),
        }
        .insert(&db)
        .await
        .unwrap();

        let _live_old = insert_write(&db, &space_id, "live", "live-old", 1).await;
        let live_latest = insert_write(&db, &space_id, "live", "live-latest", 2).await;
        let _deleted_old = insert_write(&db, &space_id, "deleted-latest", "deleted-old", 1).await;
        let deleted_latest =
            insert_write(&db, &space_id, "deleted-latest", "deleted-latest", 2).await;
        let tombstoned_old =
            insert_write(&db, &space_id, "old-tombstone", "old-tombstone", 1).await;
        let live_after_old =
            insert_write(&db, &space_id, "old-tombstone", "live-after-old", 2).await;

        for (label, key, deleted) in [
            ("delete-latest", "deleted-latest", &deleted_latest),
            ("delete-old", "old-tombstone", &tombstoned_old),
        ] {
            let delete_invocation = hash(label.as_bytes());
            invocation::ActiveModel {
                id: Set(delete_invocation),
                invoker: Set("did:key:migration".to_string()),
                issued_at: Set(OffsetDateTime::now_utc()),
                facts: Set(None),
                serialization: Set(label.as_bytes().to_vec()),
            }
            .insert(&db)
            .await
            .unwrap();
            kv_delete::ActiveModel {
                invocation_id: Set(delete_invocation),
                space: Set(SpaceIdWrap(space_id.clone())),
                key: Set(key
                    .parse::<tinycloud_auth::resource::Path>()
                    .unwrap()
                    .into()),
                deleted_invocation_id: Set(deleted.invocation),
            }
            .insert(&db)
            .await
            .unwrap();
        }

        Migration.up(&SchemaManager::new(&db)).await.unwrap();
        let rows = current_kv::Entity::find()
            .order_by_asc(current_kv::Column::Key)
            .all(&db)
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);
        let deleted = rows
            .iter()
            .find(|row| row.key.0.as_str() == "deleted-latest")
            .unwrap();
        assert!(deleted.deleted);
        assert_eq!(deleted.invocation, deleted_latest.invocation);
        let live = rows
            .iter()
            .find(|row| row.key.0.as_str() == "live")
            .unwrap();
        assert!(!live.deleted);
        assert_eq!(live.invocation, live_latest.invocation);
        let old_tombstone = rows
            .iter()
            .find(|row| row.key.0.as_str() == "old-tombstone")
            .unwrap();
        assert!(!old_tombstone.deleted);
        assert_eq!(old_tombstone.invocation, live_after_old.invocation);
        assert_eq!(
            kv_write::Entity::find().count(&db).await.unwrap(),
            6,
            "backfill must preserve immutable write history"
        );
        assert_eq!(
            kv_delete::Entity::find().count(&db).await.unwrap(),
            2,
            "backfill must preserve immutable delete history"
        );
    }
}
