//! Canonical revocation identities without rewriting signed delegation history.

use std::borrow::Cow;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use sea_orm::{
    entity::prelude::*, sea_query::Query, ActiveValue::Set, ConnectionTrait, QueryOrder,
    QuerySelect,
};
use tinycloud_auth::authorization::{HeaderEncode, TinyCloudDelegation};

use crate::encryption::{maybe_decrypt, ColumnEncryption};
use crate::hash::{hash, Hash};
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
    let encrypted_id = Query::select()
        .column(Column::Id)
        .from(Entity)
        .and_where(Expr::col(Column::Encrypted).eq(true))
        .limit(1)
        .to_owned();
    let Some((id, stored)) = delegation::Entity::find()
        .select_only()
        .column(delegation::Column::Id)
        .column(delegation::Column::Serialization)
        .filter(delegation::Column::Id.in_subquery(encrypted_id))
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

        let missing = backfill(&db, None).await.unwrap_err();
        assert!(missing
            .to_string()
            .contains("requires a column encryption key"));
        let wrong = ColumnEncryption::new([0x43; 32]);
        let rejected = backfill(&db, Some(&wrong)).await.unwrap_err();
        assert!(rejected.to_string().contains("decryption failed"));
        assert_eq!(Entity::find().count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn mismatched_plaintext_hash_is_not_aliased() {
        let db = database().await;
        insert_delegation(&db, hash(b"different content"), ucan_serialization()).await;
        let error = backfill(&db, None).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("plaintext content hash does not match stored ID"));
        assert_eq!(Entity::find().count(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn undecodable_cacao_aborts_without_a_self_alias() {
        let db = database().await;
        let serialization = vec![0xa0];
        insert_delegation(&db, hash(&serialization), serialization).await;
        let transaction = db.begin().await.unwrap();
        let error = backfill(&transaction, None).await.unwrap_err();
        assert!(error.to_string().contains("delegation decoding failed"));
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
}
