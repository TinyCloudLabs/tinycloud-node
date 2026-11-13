//! PostgreSQL-only opaque restore leases. Raw prefixes and identities are absent.
use crate::{
    models::space_purge_prefix_repair as repair,
    space_purge_ledger::{LedgerKeys, LedgerRecord},
};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveValue::Set, ConnectionTrait, DatabaseBackend, DbErr, EntityTrait, FromQueryResult,
    Statement,
};
use time::OffsetDateTime;
#[derive(Clone, FromQueryResult)]
pub struct ClaimedPrefixRepair {
    pub repair_id: String,
    pub object_key: String,
    pub store_kind: String,
    pub prefix_hmac: String,
    pub lease_token: String,
}
fn postgres(conn: &impl ConnectionTrait) -> Result<(), DbErr> {
    if conn.get_database_backend() != DatabaseBackend::Postgres {
        return Err(DbErr::Custom(
            "prefix restore repair requires PostgreSQL".into(),
        ));
    }
    Ok(())
}
/// Call in the transaction retaining the authenticated source record.
pub async fn enqueue(
    conn: &impl ConnectionTrait,
    keys: &LedgerKeys,
    record: &LedgerRecord,
) -> Result<(), DbErr> {
    let path = record
        .object_key()
        .map_err(|_| DbErr::Custom("invalid repair evidence".into()))?;
    let body = record
        .to_bytes()
        .map_err(|_| DbErr::Custom("invalid repair evidence".into()))?;
    keys.verify(&path, &body)
        .map_err(|_| DbErr::Custom("unverifiable repair evidence".into()))?;
    if record.kind != "space" || record.version != 2 {
        return Err(DbErr::Custom(
            "missing authenticated prefix inventory".into(),
        ));
    }
    let now = OffsetDateTime::now_utc();
    for prefix in &record.prefixes {
        repair::Entity::insert(repair::ActiveModel {
            repair_id: Set(uuid::Uuid::new_v4().to_string()),
            object_key: Set(path.clone()),
            store_kind: Set(prefix.store_kind.clone()),
            prefix_hmac: Set(prefix.prefix_hmac.clone()),
            phase: Set("pending".into()),
            updated_at: Set(now),
            next_attempt_at: Set(now),
            attempt_count: Set(0),
            lease_token: Set(None),
            lease_until: Set(None),
        })
        .on_conflict(OnConflict::new().do_nothing().to_owned())
        .do_nothing()
        .exec(conn)
        .await?;
    }
    Ok(())
}
pub async fn claim(
    conn: &impl ConnectionTrait,
    token: &str,
    path: &str,
    kind: &str,
    digest: &str,
) -> Result<Option<ClaimedPrefixRepair>, DbErr> {
    postgres(conn)?;
    uuid::Uuid::parse_str(token).map_err(|_| DbErr::Custom("invalid repair lease".into()))?;
    ClaimedPrefixRepair::find_by_statement(Statement::from_sql_and_values(DatabaseBackend::Postgres,
        "UPDATE space_purge_prefix_repair SET lease_token=$1,lease_until=clock_timestamp()+INTERVAL '60 seconds',updated_at=clock_timestamp(),attempt_count=attempt_count+1
         WHERE repair_id=(SELECT repair_id FROM space_purge_prefix_repair WHERE object_key=$2 AND store_kind=$3 AND prefix_hmac=$4
         AND phase='pending' AND next_attempt_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp()) FOR UPDATE SKIP LOCKED LIMIT 1)
         RETURNING repair_id,object_key,store_kind,prefix_hmac,lease_token",[token.into(),path.into(),kind.into(),digest.into()])).one(conn).await
}
pub async fn renew(
    conn: &impl ConnectionTrait,
    claim: &ClaimedPrefixRepair,
) -> Result<bool, DbErr> {
    postgres(conn)?;
    Ok(conn.execute(Statement::from_sql_and_values(DatabaseBackend::Postgres,
        "UPDATE space_purge_prefix_repair SET lease_until=clock_timestamp()+INTERVAL '60 seconds',updated_at=clock_timestamp()
         WHERE repair_id=$1 AND lease_token=$2 AND phase='pending' AND lease_until>clock_timestamp()",[claim.repair_id.clone().into(),claim.lease_token.clone().into()])).await?.rows_affected()==1)
}
/// Only after transport's verified-empty result; stale leases cannot advance.
pub async fn complete(
    conn: &impl ConnectionTrait,
    claim: &ClaimedPrefixRepair,
) -> Result<bool, DbErr> {
    postgres(conn)?;
    Ok(conn.execute(Statement::from_sql_and_values(DatabaseBackend::Postgres,
        "UPDATE space_purge_prefix_repair SET phase='complete',lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp()
         WHERE repair_id=$1 AND lease_token=$2 AND phase='pending' AND lease_until>clock_timestamp()",[claim.repair_id.clone().into(),claim.lease_token.clone().into()])).await?.rows_affected()==1)
}
pub async fn release(
    conn: &impl ConnectionTrait,
    claim: &ClaimedPrefixRepair,
) -> Result<bool, DbErr> {
    postgres(conn)?;
    Ok(conn.execute(Statement::from_sql_and_values(DatabaseBackend::Postgres,
        "UPDATE space_purge_prefix_repair SET lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp()
         WHERE repair_id=$1 AND lease_token=$2 AND phase='pending' AND lease_until>clock_timestamp()",[claim.repair_id.clone().into(),claim.lease_token.clone().into()])).await?.rows_affected()==1)
}
