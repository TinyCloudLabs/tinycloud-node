//! Immutable authenticated database copy used to repair either durable side.
use crate::{
    models::space_purge_ledger_copy as copy,
    space_purge_ledger::{LedgerKeys, LedgerRecord},
};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use time::OffsetDateTime;

pub async fn retain<C: ConnectionTrait>(
    conn: &C,
    keys: &LedgerKeys,
    path: &str,
    body: &[u8],
    now: OffsetDateTime,
) -> Result<LedgerRecord, DbErr> {
    let record = keys
        .verify(path, body)
        .map_err(|_| DbErr::Custom("unverifiable purge evidence".into()))?;
    let bytes = record
        .to_bytes()
        .map_err(|_| DbErr::Custom("invalid purge evidence".into()))?;
    copy::Entity::insert(copy::ActiveModel {
        object_key: Set(path.into()),
        body: Set(bytes.clone()),
        recorded_at: Set(now),
    })
    .on_conflict(
        OnConflict::column(copy::Column::ObjectKey)
            .do_nothing()
            .to_owned(),
    )
    .do_nothing()
    .exec(conn)
    .await?;
    let existing = copy::Entity::find_by_id(path)
        .one(conn)
        .await?
        .ok_or_else(|| DbErr::Custom("missing purge evidence".into()))?;
    let existing = keys
        .verify(path, &existing.body)
        .map_err(|_| DbErr::Custom("unverifiable stored purge evidence".into()))?;
    if existing
        .to_bytes()
        .map_err(|_| DbErr::Custom("invalid stored purge evidence".into()))?
        != bytes
    {
        return Err(DbErr::Custom(
            "conflicting authenticated purge evidence".into(),
        ));
    }
    Ok(record)
}
