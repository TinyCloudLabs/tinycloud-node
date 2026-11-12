//! Durable PostgreSQL purge leases and forward-only progress.
use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, FromQueryResult, Statement};
use time::OffsetDateTime;

#[derive(Debug, Clone, FromQueryResult)]
pub struct ClaimedPurge {
    pub purge_id: String,
    pub space: String,
    pub phase: String,
    pub fence_generation: i64,
    pub accepted_at: OffsetDateTime,
    pub lease_token: String,
}

fn postgres(conn: &impl ConnectionTrait) -> Result<(), DbErr> {
    if conn.get_database_backend() != DatabaseBackend::Postgres {
        return Err(DbErr::Custom(
            "space purge worker requires PostgreSQL".into(),
        ));
    }
    Ok(())
}

/// Claim one due job without waiting on another worker's row lock.
/// The caller supplies a fresh UUID for every acquisition, including retries.
pub async fn claim(
    conn: &impl ConnectionTrait,
    lease_token: &str,
) -> Result<Option<ClaimedPurge>, DbErr> {
    postgres(conn)?;
    uuid::Uuid::parse_str(lease_token)
        .map_err(|_| DbErr::Custom("invalid purge lease token".into()))?;
    ClaimedPurge::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        "UPDATE space_purge_job SET lease_token=$1, lease_until=clock_timestamp()+INTERVAL '60 seconds',
            updated_at=clock_timestamp(), attempt_count=attempt_count+1
         WHERE purge_id=(SELECT purge_id FROM space_purge_job
            WHERE phase<>'complete' AND next_attempt_at<=clock_timestamp()
            AND (lease_until IS NULL OR lease_until<=clock_timestamp())
            ORDER BY next_attempt_at, purge_id FOR UPDATE SKIP LOCKED LIMIT 1)
         RETURNING purge_id, space, phase, fence_generation, accepted_at, lease_token",
        [lease_token.into()],
    )).one(conn).await
}

/// Renew before a bounded I/O batch. Expired holders cannot renew or advance.
pub async fn renew(conn: &impl ConnectionTrait, job: &ClaimedPurge) -> Result<bool, DbErr> {
    postgres(conn)?;
    Ok(conn.execute(Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        "UPDATE space_purge_job SET lease_until=clock_timestamp()+INTERVAL '60 seconds', updated_at=clock_timestamp()
         WHERE purge_id=$1 AND lease_token=$2 AND fence_generation=$3 AND phase=$4
         AND lease_until>clock_timestamp()",
        [job.purge_id.clone().into(), job.lease_token.clone().into(), job.fence_generation.into(), job.phase.clone().into()],
    )).await?.rows_affected()==1)
}

/// Advance after a phase's effects have been acknowledged. Database cleanup
/// passes its existing transaction here so deletion and progress commit together.
/// Terminal completion belongs to the ledger/tombstone transaction.
pub async fn advance(conn: &impl ConnectionTrait, job: &ClaimedPurge) -> Result<bool, DbErr> {
    postgres(conn)?;
    let next = match job.phase.as_str() {
        "drain" => "database",
        "database" => "access",
        "access" => "objects",
        _ => return Err(DbErr::Custom("invalid purge phase transition".into())),
    };
    Ok(conn.execute(Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        "UPDATE space_purge_job SET phase=$5, updated_at=clock_timestamp(),
            next_attempt_at=clock_timestamp(), lease_token=NULL, lease_until=NULL, last_error_code=NULL
         WHERE purge_id=$1 AND lease_token=$2 AND fence_generation=$3 AND phase=$4
         AND lease_until>clock_timestamp()",
        [job.purge_id.clone().into(), job.lease_token.clone().into(), job.fence_generation.into(), job.phase.clone().into(), next.into()],
    )).await?.rows_affected()==1)
}

/// Release a failed attempt for retry. Only fixed error codes are persisted;
/// object keys, raw identities and provider error messages do not belong here.
pub async fn retry(
    conn: &impl ConnectionTrait,
    job: &ClaimedPurge,
    error_code: &str,
) -> Result<bool, DbErr> {
    postgres(conn)?;
    if error_code.is_empty()
        || error_code.len() > 64
        || !error_code
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c == b'_')
    {
        return Err(DbErr::Custom("invalid purge error code".into()));
    }
    Ok(conn
        .execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "UPDATE space_purge_job SET next_attempt_at=clock_timestamp()+INTERVAL '60 seconds',
            updated_at=clock_timestamp(), last_error_code=$5, lease_token=NULL, lease_until=NULL
         WHERE purge_id=$1 AND lease_token=$2 AND fence_generation=$3 AND phase=$4
         AND lease_until>clock_timestamp()",
            [
                job.purge_id.clone().into(),
                job.lease_token.clone().into(),
                job.fence_generation.into(),
                job.phase.clone().into(),
                error_code.into(),
            ],
        ))
        .await?
        .rows_affected()
        == 1)
}
