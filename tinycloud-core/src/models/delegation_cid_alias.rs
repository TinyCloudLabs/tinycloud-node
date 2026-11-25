//! Canonical revocation identities without rewriting signed delegation history.

use std::borrow::Cow;

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use sea_orm::{
    entity::prelude::*, sea_query::Query, ActiveValue::Set, ConnectionTrait, JoinType, QueryOrder,
    QuerySelect,
};
use sea_orm_migration::{seaql_migrations, MigrationName};
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation},
    ssi::{jwk::Algorithm, ucan::Ucan},
};

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
/// the stored serialization. CACAO goes through the public header decoder,
/// including all current canonicalization rules. A UCAN keeps its exact JWT
/// bytes as its ID; its canonical form is [`ucan_canonical`].
/// Decoder rejection is fatal: a guessed self-alias could hide a revocation.
pub(crate) fn canonical_hash(serialization: &[u8]) -> Result<Hash, DbErr> {
    Ok(match decode_stored(serialization)? {
        (TinyCloudDelegation::Ucan(ucan), token) => hash(&ucan_canonical(&ucan, &token)),
        (TinyCloudDelegation::Cacao(_), canonical) => hash(&canonical),
    })
}

/// [`canonical_hash`], and for an ECDSA UCAN also the hash of its other
/// encoding ([`ucan_twin`]). A tombstone written before TC-4366 names only the
/// stored id of the encoding it purged, which for a high-S UCAN is not the
/// canonical hash of the low-S one; registration checks both.
pub(crate) fn canonical_and_twin_hash(serialization: &[u8]) -> Result<(Hash, Option<Hash>), DbErr> {
    Ok(match decode_stored(serialization)? {
        (TinyCloudDelegation::Ucan(ucan), token) => (
            hash(&ucan_canonical(&ucan, &token)),
            ucan_twin(&ucan, &token).map(|twin| hash(&twin)),
        ),
        (TinyCloudDelegation::Cacao(_), canonical) => (hash(&canonical), None),
    })
}

fn decode_stored(serialization: &[u8]) -> Result<(TinyCloudDelegation, Vec<u8>), DbErr> {
    match std::str::from_utf8(serialization) {
        Ok(token) if token.contains('.') => TinyCloudDelegation::decode(token),
        _ => TinyCloudDelegation::decode(&URL_SAFE.encode(serialization)),
    }
    .map_err(|_| DbErr::Custom("delegation CID alias backfill: delegation decoding failed".into()))
}

/// The canonical bytes of a UCAN JWT: its ECDSA signature `(r, s)` with `s`
/// in the lower half of the group order. `(r, s)` and `(r, n - s)` verify
/// alike, so both encodings must name one delegation. Every other algorithm,
/// and a signature that does not parse, keeps the exact bytes.
fn ucan_canonical<'a>(ucan: &Ucan, token: &'a [u8]) -> Cow<'a, [u8]> {
    let signature = ucan.signature().as_bytes();
    let low_s = match ucan.header().algorithm {
        Algorithm::ES256 | Algorithm::ESBlake2b => p256::ecdsa::Signature::from_slice(signature)
            .ok()
            .and_then(|signature| signature.normalize_s())
            .map(|signature| signature.to_bytes().to_vec()),
        Algorithm::ES256K => k256::ecdsa::Signature::from_slice(signature)
            .ok()
            .and_then(|signature| signature.normalize_s())
            .map(|signature| signature.to_bytes().to_vec()),
        _ => None,
    };
    match low_s {
        Some(low_s) => with_signature(token, &low_s).map_or(Cow::Borrowed(token), Cow::Owned),
        None => Cow::Borrowed(token),
    }
}

/// The other encoding of an ECDSA UCAN JWT: the same header and payload with
/// signature `(r, n - s)`. `None` for every other algorithm and for a
/// signature that does not parse.
fn ucan_twin(ucan: &Ucan, token: &[u8]) -> Option<Vec<u8>> {
    let signature = ucan.signature().as_bytes();
    let other = match ucan.header().algorithm {
        Algorithm::ES256 | Algorithm::ESBlake2b => {
            let (r, s) = p256::ecdsa::Signature::from_slice(signature)
                .ok()?
                .split_scalars();
            p256::ecdsa::Signature::from_scalars(r, -s)
                .ok()?
                .to_bytes()
                .to_vec()
        }
        Algorithm::ES256K => {
            let (r, s) = k256::ecdsa::Signature::from_slice(signature)
                .ok()?
                .split_scalars();
            k256::ecdsa::Signature::from_scalars(r, -s)
                .ok()?
                .to_bytes()
                .to_vec()
        }
        _ => return None,
    };
    with_signature(token, &other)
}

/// `token` with its JWS signature segment replaced by `signature`.
fn with_signature(token: &[u8], signature: &[u8]) -> Option<Vec<u8>> {
    let dot = token.iter().rposition(|byte| *byte == b'.')?;
    let mut replaced = token[..=dot].to_vec();
    replaced.extend_from_slice(URL_SAFE_NO_PAD.encode(signature).as_bytes());
    Some(replaced)
}

/// Validate indexed encrypted and plaintext records on every boot, including
/// after the backfill is complete, so keyless and strict restarts stay checked.
async fn validate_encryption<C: ConnectionTrait>(
    db: &C,
    encryption: Option<&ColumnEncryption>,
) -> Result<(), DbErr> {
    for encrypted in [true, false] {
        let Some((id, stored, format)) = delegation::Entity::find()
            .select_only()
            .column(delegation::Column::Id)
            .column(delegation::Column::Serialization)
            .column(delegation::Column::SerializationFormat)
            .join_rev(JoinType::InnerJoin, Relation::Delegation.def())
            .filter(Column::Encrypted.eq(encrypted))
            .into_tuple::<(Hash, Vec<u8>, i16)>()
            .one(db)
            .await?
        else {
            continue;
        };
        let plaintext = stored_plaintext(encryption, id, &stored, format)?;
        if hash(&plaintext) != id {
            return Err(DbErr::Custom(
                "delegation CID alias backfill: plaintext content hash does not match stored ID"
                    .into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn stored_plaintext<'a>(
    encryption: Option<&ColumnEncryption>,
    id: Hash,
    stored: &'a [u8],
    format: i16,
) -> Result<Cow<'a, [u8]>, DbErr> {
    let encrypted = matches!(stored.first(), Some(0x01 | 0x02));
    if encryption.is_none() {
        if encrypted || format != 0 {
            return Err(DbErr::Custom(
                "delegation CID alias backfill: encrypted delegation requires a column encryption key"
                    .into(),
            ));
        }
        return Ok(Cow::Borrowed(stored));
    }
    maybe_decrypt(
        encryption,
        stored,
        crate::encryption::RowBinding::new("delegation", "serialization", &[&Vec::<u8>::from(id)]),
        format,
    )
    .map(Cow::Owned)
    .map_err(|_| DbErr::Custom("delegation CID alias backfill: decryption failed".into()))
}

/// Backfill only persisted delegations with no alias, in bounded keyset pages.
/// The caller must use its boot transaction so any failure rolls back all
/// aliases written by this call. Encrypted rows require the configured key;
/// decryption, plaintext content-hash, and decoder failures abort startup.
/// Original IDs, serializations, proof edges, and revocation targets are never
/// updated. Completed restarts validate indexed encrypted and plaintext records.
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
            .column(delegation::Column::SerializationFormat)
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
        let rows = query.into_tuple::<(Hash, Vec<u8>, i16)>().all(db).await?;
        if rows.is_empty() {
            return validate_encryption(db, encryption).await;
        }

        let mut aliases = Vec::with_capacity(rows.len());
        for (id, stored, format) in rows {
            let serialization = stored_plaintext(encryption, id, &stored, format)?;
            if hash(serialization.as_ref()) != id {
                return Err(DbErr::Custom(
                    "delegation CID alias backfill: plaintext content hash does not match stored ID"
                        .into(),
                ));
            }
            aliases.push(ActiveModel {
                id: Set(id),
                canonical: Set(canonical_hash(serialization.as_ref())?),
                encrypted: Set(matches!(stored.first(), Some(0x01 | 0x02))),
            });
            after = Some(id);
        }
        Entity::insert_many(aliases).exec(db).await?;
    }
}

/// The revision of [`canonical_hash`] stored UCAN aliases follow, recorded in
/// `delegation_cid_alias_rule` once [`recompute`] has applied it.
const CANONICAL_RULE: i32 = 1;

/// Rows per [`recompute`] page.
const RECOMPUTE_PAGE_SIZE: u64 = 128;

/// One keyset page of [`recompute`] after `after`, bounded on both tables.
fn recompute_page(after: Option<Hash>) -> Select<delegation::Entity> {
    let query = delegation::Entity::find()
        .select_only()
        .column(delegation::Column::Id)
        .column(delegation::Column::Serialization)
        .column(delegation::Column::SerializationFormat)
        .column(Column::Canonical)
        .join_rev(JoinType::InnerJoin, Relation::Delegation.def())
        .order_by_asc(delegation::Column::Id)
        .limit(RECOMPUTE_PAGE_SIZE);
    match after {
        Some(id) => query
            .filter(delegation::Column::Id.gt(id))
            .filter(Column::Id.gt(id)),
        None => query,
    }
}

/// Bring every stored UCAN alias to the current [`canonical_hash`], once per
/// rule revision. Run in the boot transaction after [`backfill`], which
/// serializes concurrent boots; any failure rolls back every update.
///
/// Only `canonical` changes, and only where the current rule gives another
/// value: IDs, serializations, proof edges and revocations are never
/// written. CACAO aliases are left as they are. Encrypted rows require the
/// configured key; decryption and content-hash failures abort startup, as in
/// [`backfill`]. A stored UCAN the current decoder rejects keeps its alias
/// (what every older image computed) and is counted in the log.
pub(crate) async fn recompute<C: ConnectionTrait>(
    db: &C,
    encryption: Option<&ColumnEncryption>,
) -> Result<(), DbErr> {
    use crate::migrations::m20261125_010000_delegation_cid_alias_rule::DelegationCidAliasRule as Rule;
    let backend = db.get_database_backend();
    let applied = Query::select()
        .expr(Expr::value(1))
        .from(Rule::Table)
        .and_where(Expr::col(Rule::Revision).eq(CANONICAL_RULE))
        .to_owned();
    if db.query_one(backend.build(&applied)).await?.is_some() {
        return Ok(());
    }
    let (mut checked, mut changed, mut undecodable) = (0u64, 0u64, 0u64);
    let mut after = None;
    loop {
        let rows = recompute_page(after)
            .into_tuple::<(Hash, Vec<u8>, i16, Hash)>()
            .all(db)
            .await?;
        if rows.is_empty() {
            break;
        }
        for (id, stored, format, stored_canonical) in rows {
            after = Some(id);
            let serialization = stored_plaintext(encryption, id, &stored, format)?;
            if hash(serialization.as_ref()) != id {
                return Err(DbErr::Custom(
                    "delegation CID alias recompute: plaintext content hash does not match stored ID"
                        .into(),
                ));
            }
            // The same dispatch as `canonical_hash`: a CACAO is not UTF-8 text
            // with a dot.
            let Some(token) = std::str::from_utf8(serialization.as_ref())
                .ok()
                .filter(|token| token.contains('.'))
            else {
                continue;
            };
            checked += 1;
            let Ok((TinyCloudDelegation::Ucan(ucan), bytes)) = TinyCloudDelegation::decode(token)
            else {
                undecodable += 1;
                continue;
            };
            let canonical = hash(&ucan_canonical(&ucan, &bytes));
            if canonical == stored_canonical {
                continue;
            }
            Entity::update_many()
                .col_expr(Column::Canonical, Expr::value(canonical))
                .filter(Column::Id.eq(id))
                .filter(Column::Canonical.eq(stored_canonical))
                .exec(db)
                .await?;
            changed += 1;
        }
    }
    let record = Query::insert()
        .into_table(Rule::Table)
        .columns([Rule::Revision, Rule::AppliedAt])
        .values_panic([CANONICAL_RULE.into(), Expr::current_timestamp().into()])
        .to_owned();
    db.execute(backend.build(&record)).await?;
    tracing::info!(
        rule = CANONICAL_RULE,
        checked,
        changed,
        undecodable,
        "delegation CID alias recompute applied"
    );
    Ok(())
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
            serialization_format: Set(0),
            first_seen_at: Default::default(),
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
        let stored = encryption.encrypt_legacy(&serialization);
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
            encryption.encrypt_legacy(&serialization),
        )
        .await;

        assert!(backfill(&db, None).await.is_err());
        let wrong = ColumnEncryption::new([0x43; 32]);
        assert!(backfill(&db, Some(&wrong)).await.is_err());
        assert_eq!(Entity::find().count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn recorded_v2_backfill_rejects_plaintext_and_legacy_ciphertext() {
        let encryption = ColumnEncryption::new([0x42; 32]);
        let serialization = ucan_serialization();
        for stored in [
            serialization.clone(),
            encryption.encrypt_legacy(&serialization),
        ] {
            let db = database().await;
            let id = hash(&serialization);
            insert_delegation(&db, id, stored).await;
            delegation::Entity::update_many()
                .col_expr(delegation::Column::SerializationFormat, Expr::value(2))
                .exec(&db)
                .await
                .unwrap();
            assert!(backfill(&db, Some(&encryption)).await.is_err());
            assert!(backfill(&db, None).await.is_err());
            assert_eq!(Entity::find().count(&db).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn v2_backfill_preserves_binding_and_records_encrypted_alias() {
        let encryption = ColumnEncryption::new([0x42; 32]);
        let serialization = ucan_serialization();
        let id = hash(&serialization);
        let stored = encryption.encrypt(
            &serialization,
            crate::encryption::RowBinding::new(
                "delegation",
                "serialization",
                &[&Vec::<u8>::from(id)],
            ),
        );
        let db = database().await;
        insert_delegation(&db, id, stored.clone()).await;
        delegation::Entity::update_many()
            .col_expr(delegation::Column::SerializationFormat, Expr::value(2))
            .exec(&db)
            .await
            .unwrap();
        backfill(&db, Some(&encryption)).await.unwrap();
        assert!(
            Entity::find_by_id(id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .encrypted
        );
        assert!(backfill(&db, None).await.is_err());
        assert_eq!(
            delegation::Entity::find_by_id(id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .serialization,
            stored,
        );
        let compatibility = database().await;
        insert_delegation(&compatibility, id, stored.clone()).await;
        backfill(&compatibility, Some(&encryption)).await.unwrap();
        assert!(
            Entity::find_by_id(id)
                .one(&compatibility)
                .await
                .unwrap()
                .unwrap()
                .encrypted
        );

        let moved = database().await;
        insert_delegation(&moved, hash(b"other row"), stored).await;
        assert!(backfill(&moved, Some(&encryption)).await.is_err());
        assert_eq!(Entity::find().count(&moved).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn strict_backfill_refuses_legacy_plaintext() {
        let db = database().await;
        let serialization = ucan_serialization();
        insert_delegation(&db, hash(&serialization), serialization).await;
        let encryption = ColumnEncryption::new([0x42; 32]).with_strict(true);
        assert!(backfill(&db, Some(&encryption)).await.is_err());
        assert_eq!(Entity::find().count(&db).await.unwrap(), 0);
        backfill(&db, None).await.unwrap();
        assert!(backfill(&db, Some(&encryption)).await.is_err());
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
        let delegations = delegation::Entity::find()
            .from_raw_sql(Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT *, 0 AS serialization_format FROM delegation",
            ))
            .all(&old)
            .await
            .unwrap();
        delegation::Entity::insert_many(delegations.into_iter().map(|row| row.into_active_model()))
            .exec(&fixture.conn)
            .await
            .unwrap();
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

    // TC-4366: `recompute` brings stored UCAN aliases to the current rule.

    /// `(low_s, high_s)` encodings of a fresh UCAN signed with `algorithm`.
    fn encodings(jwk: &JWK, algorithm: Algorithm) -> (Vec<u8>, Vec<u8>) {
        let token = signed_ucan(ACTOR, jwk, algorithm).encode().unwrap();
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
        let (low, high) = match algorithm {
            Algorithm::ES256 => {
                let signature = p256::ecdsa::Signature::from_slice(&signature).unwrap();
                let (r, s) = signature.split_scalars();
                let twin = p256::ecdsa::Signature::from_scalars(r, -s).unwrap();
                match signature.normalize_s() {
                    None => (signature.to_vec(), twin.to_vec()),
                    Some(_) => (twin.to_vec(), signature.to_vec()),
                }
            }
            Algorithm::ES256K => {
                let signature = k256::ecdsa::Signature::from_slice(&signature).unwrap();
                let (r, s) = signature.split_scalars();
                let twin = k256::ecdsa::Signature::from_scalars(r, -s).unwrap();
                match signature.normalize_s() {
                    None => (signature.to_vec(), twin.to_vec()),
                    Some(_) => (twin.to_vec(), signature.to_vec()),
                }
            }
            other => panic!("no second encoding for {other:?}"),
        };
        let encode = |signature: Vec<u8>| {
            format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature)).into_bytes()
        };
        (encode(low), encode(high))
    }

    async fn insert_alias(db: &DbConn, id: Hash, canonical: Hash, encrypted: bool) {
        ActiveModel {
            id: Set(id),
            canonical: Set(canonical),
            encrypted: Set(encrypted),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn aliases(db: &DbConn) -> std::collections::HashMap<Hash, Hash> {
        Entity::find()
            .all(db)
            .await
            .unwrap()
            .into_iter()
            .map(|alias| (alias.id, alias.canonical))
            .collect()
    }

    async fn delegations(db: &DbConn) -> Vec<delegation::Model> {
        delegation::Entity::find()
            .order_by_asc(delegation::Column::Id)
            .all(db)
            .await
            .unwrap()
    }

    /// A database as an older image left it: every UCAN aliased to the hash of
    /// its exact bytes, a historical CACAO alias to another hash.
    async fn recompute_rekeys_only_the_two_high_s_aliases_once(db: &DbConn) {
        let (es256_low, es256_high) = encodings(&JWK::generate_p256(), Algorithm::ES256);
        let (es256k_low, es256k_high) = encodings(&JWK::generate_secp256k1(), Algorithm::ES256K);
        // A second P-256 UCAN stored only in its low-S encoding.
        let (lone_low, _) = encodings(&JWK::generate_p256(), Algorithm::ES256);
        let eddsa = ucan_serialization();
        // CACAO rows are DAG-CBOR, not UTF-8 text.
        let cacao = vec![0xa3, 0xff, 0x00, 0x2e, 0x01];
        let mut expected = std::collections::HashMap::new();
        for serialization in [
            &es256_low,
            &es256_high,
            &es256k_low,
            &es256k_high,
            &lone_low,
            &eddsa,
        ] {
            let id = hash(serialization);
            insert_delegation(db, id, serialization.clone()).await;
            insert_alias(db, id, id, false).await;
            expected.insert(id, id);
        }
        let cacao_id = hash(&cacao);
        insert_delegation(db, cacao_id, cacao).await;
        insert_alias(db, cacao_id, hash(b"historical canonical"), false).await;
        expected.insert(cacao_id, hash(b"historical canonical"));
        let stored = delegations(db).await;
        assert_eq!(aliases(db).await, expected);

        recompute(db, None).await.unwrap();
        expected.insert(hash(&es256_high), hash(&es256_low));
        expected.insert(hash(&es256k_high), hash(&es256k_low));
        assert_eq!(aliases(db).await, expected, "only the high-S aliases move");
        assert_eq!(delegations(db).await, stored, "signed rows are untouched");

        // A second boot reads the recorded rule and writes nothing, even where
        // an alias disagrees with it.
        Entity::update_many()
            .col_expr(Column::Canonical, Expr::value(hash(&es256_high)))
            .filter(Column::Id.eq(hash(&es256_high)))
            .exec(db)
            .await
            .unwrap();
        recompute(db, None).await.unwrap();
        let mut unchanged = expected.clone();
        unchanged.insert(hash(&es256_high), hash(&es256_high));
        assert_eq!(aliases(db).await, unchanged);

        // Applying the migration again (after a rollback deleted its record)
        // clears the rule, so the next boot recomputes.
        sea_orm_migration::MigrationTrait::up(
            &crate::migrations::m20261125_010000_delegation_cid_alias_rule::Migration,
            &sea_orm_migration::SchemaManager::new(db),
        )
        .await
        .unwrap();
        recompute(db, None).await.unwrap();
        assert_eq!(aliases(db).await, expected);
        assert_eq!(delegations(db).await, stored);
    }

    #[tokio::test]
    async fn sqlite_recompute_rekeys_only_the_two_high_s_aliases_once() {
        recompute_rekeys_only_the_two_high_s_aliases_once(&database().await).await;
    }

    #[tokio::test]
    async fn postgres_recompute_rekeys_only_the_two_high_s_aliases_once() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_recompute_rekeys_only_the_two_high_s_aliases_once",
        )
        .await
        else {
            return;
        };
        actor::ActiveModel {
            id: Set(ACTOR.into()),
        }
        .insert(&fixture.conn)
        .await
        .unwrap();
        recompute_rekeys_only_the_two_high_s_aliases_once(&fixture.conn).await;
    }

    #[tokio::test]
    async fn recompute_reads_encrypted_rows_only_with_the_key() {
        let db = database().await;
        let encryption = ColumnEncryption::new([0x42; 32]);
        let (low, high) = encodings(&JWK::generate_p256(), Algorithm::ES256);
        let id = hash(&high);
        let stored = encryption.encrypt(
            &high,
            crate::encryption::RowBinding::new(
                "delegation",
                "serialization",
                &[&Vec::<u8>::from(id)],
            ),
        );
        insert_delegation(&db, id, stored.clone()).await;
        delegation::Entity::update_many()
            .col_expr(delegation::Column::SerializationFormat, Expr::value(2))
            .exec(&db)
            .await
            .unwrap();
        insert_alias(&db, id, id, true).await;

        assert!(recompute(&db, None).await.is_err());
        assert!(recompute(&db, Some(&ColumnEncryption::new([0x43; 32])))
            .await
            .is_err());
        recompute(&db, Some(&encryption)).await.unwrap();
        assert_eq!(
            Entity::find_by_id(id).one(&db).await.unwrap().unwrap(),
            Model {
                id,
                canonical: hash(&low),
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
    }

    /// Both encodings stored by an older image, each its own identity, and
    /// the high-S one revoked: after the next boot the low-S one is revoked
    /// too, in the revocation read authorization uses and in the status route.
    async fn earlier_twin_reads_revoked_after_boot(db: &DbConn, jwk: JWK, algorithm: Algorithm) {
        use crate::{
            db::{DelegationStatus, SpaceDatabase},
            keys::StaticSecret,
            models::revocation,
            storage::memory::MemoryStore,
        };
        let (low, high) = encodings(&jwk, algorithm);
        let (low, high) = ((hash(&low), low.clone()), (hash(&high), high.clone()));
        for (id, serialization) in [&low, &high] {
            insert_delegation(db, *id, serialization.clone()).await;
            insert_alias(db, *id, *id, false).await;
        }
        revocation::ActiveModel {
            id: Set(hash(format!("{algorithm:?} revocation").as_bytes())),
            revoker: Set(ACTOR.into()),
            revoked: Set(high.0),
            serialization: Set(b"revocation".to_vec()),
            revoked_at: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        assert!(revocation::is_revoked(db, &high.0).await.unwrap());
        assert!(
            !revocation::is_revoked(db, &low.0).await.unwrap(),
            "{algorithm:?}: before the boot the older aliases do not link the two"
        );

        let space = SpaceDatabase::new(
            db.clone(),
            MemoryStore::default(),
            StaticSecret::new(vec![31; 32]).unwrap(),
        )
        .await
        .unwrap();
        assert!(
            revocation::is_revoked(db, &low.0).await.unwrap(),
            "{algorithm:?}: after the boot the low-S encoding is revoked"
        );
        assert!(matches!(
            space.delegation_status(low.0, ACTOR, &[]).await,
            Ok(Some(DelegationStatus::Revoked))
        ));
    }

    #[tokio::test]
    async fn sqlite_an_earlier_p256_twin_reads_revoked_after_boot() {
        earlier_twin_reads_revoked_after_boot(
            &database().await,
            JWK::generate_p256(),
            Algorithm::ES256,
        )
        .await;
    }

    #[tokio::test]
    async fn sqlite_an_earlier_secp256k1_twin_reads_revoked_after_boot() {
        earlier_twin_reads_revoked_after_boot(
            &database().await,
            JWK::generate_secp256k1(),
            Algorithm::ES256K,
        )
        .await;
    }

    #[tokio::test]
    async fn postgres_an_earlier_p256_twin_reads_revoked_after_boot() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_an_earlier_p256_twin_reads_revoked_after_boot",
        )
        .await
        else {
            return;
        };
        actor::ActiveModel {
            id: Set(ACTOR.into()),
        }
        .insert(&fixture.conn)
        .await
        .unwrap();
        earlier_twin_reads_revoked_after_boot(
            &fixture.conn,
            JWK::generate_p256(),
            Algorithm::ES256,
        )
        .await;
    }

    /// Each recompute page reads only its own range of the alias index,
    /// however deep into history the page starts.
    #[tokio::test]
    async fn postgres_recompute_page_reads_a_bounded_alias_range() {
        use sea_orm::{DbBackend, QueryTrait, Statement};

        fn alias_rows_read(node: &serde_json::Value) -> f64 {
            let own = if node["Relation Name"] == "delegation_cid_alias" {
                (node["Actual Rows"].as_f64().unwrap()
                    + node["Rows Removed by Filter"].as_f64().unwrap_or(0.0))
                    * node["Actual Loops"].as_f64().unwrap()
            } else {
                0.0
            };
            own + node["Plans"]
                .as_array()
                .into_iter()
                .flatten()
                .map(alias_rows_read)
                .sum::<f64>()
        }

        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_recompute_page_reads_a_bounded_alias_range",
        )
        .await
        else {
            return;
        };
        let db = &fixture.conn;
        actor::ActiveModel {
            id: Set(ACTOR.into()),
        }
        .insert(db)
        .await
        .unwrap();
        const ROWS: u64 = 4096;
        db.execute_unprepared(&format!(
            "INSERT INTO delegation (id, delegator, delegatee, serialization) \
             SELECT '\\x1e20'::bytea || sha256(i::text::bytea), '{ACTOR}', '{ACTOR}', '\\x00'::bytea \
             FROM generate_series(1, {ROWS}) AS i; \
             INSERT INTO delegation_cid_alias (id, canonical, encrypted) \
             SELECT id, id, false FROM delegation; \
             ANALYZE delegation; ANALYZE delegation_cid_alias;"
        ))
        .await
        .unwrap();
        let after = delegation::Entity::find()
            .order_by_asc(delegation::Column::Id)
            .offset(ROWS / 2)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .id;

        let page = recompute_page(Some(after)).build(DbBackend::Postgres);
        let plan = db
            .query_one(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("EXPLAIN (ANALYZE, FORMAT JSON) {}", page.sql),
                page.values.map(|values| values.0).unwrap_or_default(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<serde_json::Value>("", "QUERY PLAN")
            .unwrap();
        let read = alias_rows_read(&plan[0]["Plan"]);
        assert!(read > 0.0, "no alias scan in the plan: {plan}");
        assert!(
            read <= (2 * RECOMPUTE_PAGE_SIZE) as f64,
            "a page {} rows deep read {read} alias rows: {plan}",
            ROWS / 2
        );
    }
}
