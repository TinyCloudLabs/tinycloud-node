//! Canonical revocation identities without rewriting signed delegation history.

use std::borrow::Cow;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use sea_orm::{
    entity::prelude::*, sea_query::Query, ActiveValue::Set, ConnectionTrait, JoinType, QueryOrder,
    QuerySelect,
};
use sea_orm_migration::{seaql_migrations, MigrationName};
use tinycloud_auth::authorization::{HeaderEncode, TinyCloudDelegation};

use crate::encryption::{maybe_decrypt, ColumnEncryption};
use crate::hash::{hash, Hash};
use crate::migrations::m20261014_000000_delegation_cid_alias::Migration;
use crate::models::delegation;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "delegation_cid_alias")]
pub struct Model {
    /// Hash of the exact plaintext serialization persisted in `delegation`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Hash,
    /// Hash of current ingestion's canonical bytes; it need not be a stored row.
    pub canonical: Hash,
    /// Whether the original stored serialization requires the column key.
    pub encrypted: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "delegation::Entity",
        from = "Column::Id",
        to = "delegation::Column::Id"
    )]
    Delegation,
}

impl Related<delegation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Delegation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// Derive the same identity as current delegation ingestion, without changing
/// the stored serialization. UCAN JWT bytes remain exact; CACAO goes through
/// the public header decoder, including all current canonicalization rules.
/// Decoder rejection is fatal: a guessed self-alias could hide a revocation.
pub(crate) fn canonical_hash(serialization: &[u8]) -> Result<Hash, DbErr> {
    let decoded = match std::str::from_utf8(serialization) {
        Ok(token) if token.contains('.') => TinyCloudDelegation::decode(token),
        _ => TinyCloudDelegation::decode(&URL_SAFE.encode(serialization)),
    };
    let (_, canonical) = decoded.map_err(|_| {
        DbErr::Custom("delegation CID alias backfill: delegation decoding failed".into())
    })?;
    Ok(hash(&canonical))
}

/// Validate one indexed encrypted record on every boot, including after the
/// backfill is complete. A completed index must not permit keyless restarts.
async fn validate_encryption<C: ConnectionTrait>(
    db: &C,
    encryption: Option<&ColumnEncryption>,
) -> Result<(), DbErr> {
    let Some((id, stored)) = delegation::Entity::find()
        .select_only()
        .column(delegation::Column::Id)
        .column(delegation::Column::Serialization)
        .join_rev(JoinType::InnerJoin, Relation::Delegation.def())
        .filter(Column::Encrypted.eq(true))
        .into_tuple::<(Hash, Vec<u8>)>()
        .one(db)
        .await?
    else {
        return Ok(());
    };
    let encryption = encryption.ok_or_else(|| {
        DbErr::Custom(
            "delegation CID alias backfill: encrypted delegation requires a column encryption key"
                .into(),
        )
    })?;
    let plaintext = encryption
        .decrypt(&stored)
        .map_err(|_| DbErr::Custom("delegation CID alias backfill: decryption failed".into()))?;
    if hash(&plaintext) != id {
        return Err(DbErr::Custom(
            "delegation CID alias backfill: plaintext content hash does not match stored ID".into(),
        ));
    }
    Ok(())
}

/// Backfill only persisted delegations with no alias, in bounded keyset pages.
/// The caller must use its boot transaction so any failure rolls back all
/// aliases written by this call. Encrypted rows require the configured key;
/// decryption, plaintext content-hash, and decoder failures abort startup.
/// Original IDs, serializations, proof edges, and revocation targets are never
/// updated. Completed restarts validate only one indexed encrypted record.
pub(crate) async fn backfill<C: ConnectionTrait>(
    db: &C,
    encryption: Option<&ColumnEncryption>,
) -> Result<(), DbErr> {
    const PAGE_SIZE: u64 = 128;
    if db.get_database_backend() != sea_orm::DbBackend::Sqlite {
        // Serialize boot transactions before the first history read. In
        // particular, MySQL must not establish a stale repeatable-read snapshot
        // before waiting for another boot's aliases. SQLite's caller already
        // holds its BEGIN IMMEDIATE writer lock.
        let migration = seaql_migrations::Entity::find_by_id(Migration.name())
            .select_only()
            .column(seaql_migrations::Column::AppliedAt)
            .lock_exclusive()
            .into_tuple::<i64>()
            .one(db)
            .await?;
        if migration.is_none() {
            return Err(DbErr::Custom(
                "delegation CID alias backfill: migration record is missing".into(),
            ));
        }
    }
    let mut after = None;
    loop {
        let mut query = delegation::Entity::find()
            .select_only()
            .column(delegation::Column::Id)
            .column(delegation::Column::Serialization)
            .filter(
                Expr::exists(
                    Query::select()
                        .expr(Expr::value(1))
                        .from(Entity)
                        .and_where(
                            Expr::col((Entity, Column::Id))
                                .equals((delegation::Entity, delegation::Column::Id)),
                        )
                        .to_owned(),
                )
                .not(),
            )
            .order_by_asc(delegation::Column::Id)
            .limit(PAGE_SIZE);
        if let Some(id) = after {
            query = query.filter(delegation::Column::Id.gt(id));
        }
        let rows = query.into_tuple::<(Hash, Vec<u8>)>().all(db).await?;
        if rows.is_empty() {
            return validate_encryption(db, encryption).await;
        }

        let mut aliases = Vec::with_capacity(rows.len());
        for (id, stored) in rows {
            // This is ColumnEncryption's version marker. Borrow legacy
            // plaintext instead of copying it through the passthrough helper.
            let serialization = if stored.first() == Some(&0x01) {
                let encryption = encryption.ok_or_else(|| {
                    DbErr::Custom(
                        "delegation CID alias backfill: encrypted delegation requires a column encryption key"
                            .into(),
                    )
                })?;
                Cow::Owned(maybe_decrypt(Some(encryption), &stored).map_err(|_| {
                    DbErr::Custom("delegation CID alias backfill: decryption failed".into())
                })?)
            } else {
                Cow::Borrowed(stored.as_slice())
            };
            if hash(serialization.as_ref()) != id {
                return Err(DbErr::Custom(
                    "delegation CID alias backfill: plaintext content hash does not match stored ID"
                        .into(),
                ));
            }
            aliases.push(ActiveModel {
                id: Set(id),
                canonical: Set(canonical_hash(serialization.as_ref())?),
                encrypted: Set(stored.first() == Some(&0x01)),
            });
            after = Some(id);
        }
        Entity::insert_many(aliases).exec(db).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::models::actor;
    use crate::test_support::did_resolution::signed_ucan;
    use sea_orm::{ActiveModelTrait, Database, DbConn, TransactionTrait};
    use sea_orm_migration::MigratorTrait;
    use tinycloud_auth::ssi::jwk::{Algorithm, JWK};

    const ACTOR: &str = "did:key:cid-alias-fixture";

    fn ucan_serialization() -> Vec<u8> {
        signed_ucan(ACTOR, &JWK::generate_ed25519().unwrap(), Algorithm::EdDSA)
            .encode()
            .unwrap()
            .into_bytes()
    }

    async fn database() -> DbConn {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        actor::ActiveModel {
            id: Set(ACTOR.into()),
        }
        .insert(&db)
        .await
        .unwrap();
        db
    }

    async fn insert_delegation(db: &DbConn, id: Hash, serialization: Vec<u8>) {
        delegation::ActiveModel {
            id: Set(id),
            delegator: Set(ACTOR.into()),
            delegatee: Set(ACTOR.into()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(serialization),
        }
        .insert(db)
        .await
        .unwrap();
    }

    #[test]
    fn ucan_canonical_identity_preserves_exact_jwt_bytes() {
        let serialization = ucan_serialization();
        assert_eq!(
            canonical_hash(&serialization).unwrap(),
            hash(&serialization)
        );
    }

    #[tokio::test]
    async fn encrypted_backfill_preserves_storage_and_restart_requires_the_key() {
        let db = database().await;
        let encryption = ColumnEncryption::new([0x42; 32]);
        let serialization = ucan_serialization();
        let id = hash(&serialization);
        let stored = encryption.encrypt(&serialization);
        insert_delegation(&db, id, stored.clone()).await;

        backfill(&db, Some(&encryption)).await.unwrap();
        assert_eq!(
            Entity::find_by_id(id).one(&db).await.unwrap().unwrap(),
            Model {
                id,
                canonical: id,
                encrypted: true
            }
        );
        assert_eq!(
            delegation::Entity::find_by_id(id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .serialization,
            stored
        );
        assert!(backfill(&db, None).await.is_err());
        assert!(backfill(&db, Some(&ColumnEncryption::new([0x43; 32])))
            .await
            .is_err());
        backfill(&db, Some(&encryption)).await.unwrap();
    }

    #[tokio::test]
    async fn encrypted_backfill_requires_the_correct_key() {
        let db = database().await;
        let encryption = ColumnEncryption::new([0x42; 32]);
        let serialization = ucan_serialization();
        insert_delegation(
            &db,
            hash(&serialization),
            encryption.encrypt(&serialization),
        )
        .await;

        assert!(backfill(&db, None).await.is_err());
        let wrong = ColumnEncryption::new([0x43; 32]);
        assert!(backfill(&db, Some(&wrong)).await.is_err());
        assert_eq!(Entity::find().count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn mismatched_plaintext_hash_is_not_aliased() {
        let db = database().await;
        insert_delegation(&db, hash(b"different content"), ucan_serialization()).await;
        assert!(backfill(&db, None).await.is_err());
        assert_eq!(Entity::find().count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn undecodable_cacao_aborts_without_a_self_alias() {
        let db = database().await;
        let serialization = vec![0xa0];
        insert_delegation(&db, hash(&serialization), serialization).await;
        let transaction = db.begin().await.unwrap();
        assert!(backfill(&transaction, None).await.is_err());
        transaction.rollback().await.unwrap();
        assert_eq!(Entity::find().count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn keyset_backfill_indexes_more_than_one_page() {
        let db = database().await;
        for _ in 0..129 {
            let serialization = ucan_serialization();
            let id = hash(&serialization);
            insert_delegation(&db, id, serialization).await;
        }

        backfill(&db, None).await.unwrap();
        assert_eq!(Entity::find().count(&db).await.unwrap(), 129);
        backfill(&db, None).await.unwrap();
        assert_eq!(Entity::find().count(&db).await.unwrap(), 129);
    }

    #[tokio::test]
    async fn postgres_concurrent_historical_backfills_produce_ready_databases() {
        use std::time::Duration;

        use crate::{
            db::{DelegationStatus, SpaceDatabase},
            keys::StaticSecret,
            models::{abilities, revocation, space},
            relationships::parent_delegations,
            storage::memory::MemoryStore,
            test_support::PostgresTestSchema,
        };
        use sea_orm::{IntoActiveModel, Statement};
        use tinycloud_auth::authorization::Cid;

        let Some(fixture) = PostgresTestSchema::new(
            "postgres_concurrent_historical_backfills_produce_ready_databases",
        )
        .await
        else {
            return;
        };
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tc1071/generated");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(source.join("manifest.json")).unwrap()).unwrap();
        let historical = manifest
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["database"] == "revoked-v0.sqlite")
            .unwrap();
        let old = Database::connect(format!(
            "sqlite:{}?mode=ro",
            source.join("revoked-v0.sqlite").display()
        ))
        .await
        .unwrap();
        macro_rules! copy_records {
            ($entity:path) => {
                let records = <$entity>::find().all(&old).await.unwrap();
                if !records.is_empty() {
                    <$entity>::insert_many(records.into_iter().map(|row| row.into_active_model()))
                        .exec(&fixture.conn)
                        .await
                        .unwrap();
                }
            };
        }
        copy_records!(actor::Entity);
        copy_records!(space::Entity);
        copy_records!(delegation::Entity);
        copy_records!(abilities::Entity);
        copy_records!(parent_delegations::Entity);
        copy_records!(revocation::Entity);
        old.close().await.unwrap();
        let original = delegation::Entity::find()
            .order_by_asc(delegation::Column::Id)
            .all(&fixture.conn)
            .await
            .unwrap();

        // Force both constructors into overlapping database work. Following
        // the blocker graph permits either a serialized backfill or a
        // conflict-safe insert, without pinning the implementation's lock.
        let blocker = fixture.conn.begin().await.unwrap();
        let blocker_pid: i32 = blocker
            .query_one(Statement::from_string(
                sea_orm::DbBackend::Postgres,
                "SELECT pg_backend_pid() AS pid",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "pid")
            .unwrap();
        blocker
            .execute_unprepared("LOCK TABLE delegation_cid_alias IN EXCLUSIVE MODE")
            .await
            .unwrap();
        let workers = std::array::from_fn::<_, 2, _>(|_| {
            let connection = fixture.conn.clone();
            tokio::spawn(async move {
                SpaceDatabase::new(
                    connection,
                    MemoryStore::default(),
                    StaticSecret::new(vec![31; 32]).unwrap(),
                )
                .await
            })
        });
        let waiting = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let blocked: i64 = fixture
                    .conn
                    .query_one(Statement::from_sql_and_values(
                        sea_orm::DbBackend::Postgres,
                        "WITH RECURSIVE blocked(pid) AS (SELECT $1::int UNION SELECT activity.pid FROM pg_stat_activity AS activity INNER JOIN blocked ON blocked.pid = ANY(pg_blocking_pids(activity.pid))) SELECT COUNT(*) AS blocked FROM blocked WHERE pid <> $1",
                        [blocker_pid.into()],
                    ))
                    .await?
                    .ok_or_else(|| DbErr::Custom("missing PostgreSQL wait observation".into()))?
                    .try_get("", "blocked")?;
                if blocked == 2 {
                    return Ok::<(), DbErr>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        blocker.commit().await.unwrap();
        let [first, second] = workers;
        let results = [first.await.unwrap(), second.await.unwrap()];
        let roots = historical["rows"].as_array().unwrap();
        let mut statuses = Vec::with_capacity(roots.len() * results.len());
        let mut errors = Vec::with_capacity(results.len());
        for result in results {
            match result {
                Ok(db) => {
                    for row in roots {
                        let cid: Cid = row["raw_cid"].as_str().unwrap().parse().unwrap();
                        statuses.push(
                            db.delegation_status(
                                Hash::from(cid),
                                historical["issuer"].as_str().unwrap(),
                                &[],
                            )
                            .await,
                        );
                    }
                }
                Err(error) => errors.push(error),
            }
        }
        let current = delegation::Entity::find()
            .order_by_asc(delegation::Column::Id)
            .all(&fixture.conn)
            .await;
        fixture.conn.clone().close().await.unwrap();
        waiting
            .expect("both constructors must overlap under the database blocker")
            .unwrap();
        assert!(errors.is_empty(), "concurrent startup failed: {errors:?}");
        for status in statuses {
            assert!(
                matches!(status, Ok(Some(DelegationStatus::Revoked))),
                "each historical equivalent must remain revoked after concurrent startup",
            );
        }
        assert_eq!(
            current.unwrap(),
            original,
            "concurrent startup must preserve every historical signed row",
        );
    }
}
