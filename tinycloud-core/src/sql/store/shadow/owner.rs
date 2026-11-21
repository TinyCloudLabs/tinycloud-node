//! Owner marker: one host per `sql/v1/` namespace. At first enable the
//! uploader allocates a random 128-bit store ID, persists it in the control
//! database's `sql_store_owner` table and writes the object
//! `sql/v1/_owner/v1` with that ID as the body via `put_if_absent`. At
//! every subsequent boot the pair is re-checked:
//!
//! - both present and equal: ok.
//! - both present and different: refuse to start (the object was written by
//!   another control database; another node holds this namespace).
//! - row absent, marker present (control DB wiped but bucket retained):
//!   refuse to start.
//! - row present, marker absent: a fresh bucket was given to an existing
//!   control DB; re-write the marker to restore the pair.
//! - both absent: first enable; write both.
//!
//! None of the error paths log the body: the store ID is treated as
//! opaque. The marker is written before the uploader starts its first
//! cycle; callers sequence that.
//!
//! A later change that lists orphans or deletes by prefix must exclude
//! `sql/v1/_probe/` and `sql/v1/_owner/`, so the marker is not counted as
//! an unregistered orphan.
//!
//! TC-1491.

use rand::RngCore;
use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::models::sql_store_owner as owner;

/// The fixed object key for the owner marker.
pub const OWNER_OBJECT_KEY: &str = "sql/v1/_owner/v1";

#[derive(Debug, thiserror::Error)]
pub enum OwnerMarkerError {
    #[error("sql_store owner marker mismatch")]
    Mismatch,
    #[error("sql_store owner row is missing but marker is present")]
    RowMissingMarkerPresent,
    #[error("sql_store owner store ID in the control database is not canonical")]
    Malformed,
    #[error("sql_store owner marker control-DB error: {0}")]
    Database(#[from] sea_orm::DbErr),
    #[error("sql_store owner marker system error: {0}")]
    System(String),
}

/// The 128-bit store ID in its canonical form: 32 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreId(String);

impl StoreId {
    /// Freshly minted from the system RNG.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Accept only 32 lowercase hex characters; any other input is malformed.
    pub fn parse(text: &str) -> Result<Self, OwnerMarkerError> {
        if text.len() == 32 && text.bytes().all(is_lower_hex) {
            Ok(Self(text.to_owned()))
        } else {
            Err(OwnerMarkerError::Malformed)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_body(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// Read the owner row, if any. The sole row is asserted; a second row is
/// treated as malformed state (the operator must repair the table).
pub async fn load_owner_row<C: ConnectionTrait>(
    conn: &C,
) -> Result<Option<StoreId>, OwnerMarkerError> {
    let rows = owner::Entity::find().all(conn).await?;
    match rows.len() {
        0 => Ok(None),
        1 => Ok(Some(StoreId::parse(&rows[0].store_id)?)),
        _ => Err(OwnerMarkerError::Malformed),
    }
}

/// Insert the owner row if absent; return the (possibly newly stored) store
/// ID. The invariant is exactly one row across the lifetime of the
/// control database: a load runs first and short-circuits when a row is
/// present, so a fresh candidate is never inserted on a second boot. On a
/// concurrent first-enable race, the second writer's INSERT is guarded by a
/// `WHERE NOT EXISTS (SELECT 1 FROM sql_store_owner)` clause that is
/// evaluated by the engine at insert time; the second row is never written
/// because the clause is false by then. One of the two store IDs wins; the
/// other is lost (that candidate was never visible outside this function).
/// Portable across SQLite, PostgreSQL and MySQL.
pub async fn insert_or_load_owner_row(
    conn: &DatabaseConnection,
    desired: &StoreId,
) -> Result<StoreId, OwnerMarkerError> {
    if let Some(existing) = load_owner_row(conn).await? {
        return Ok(existing);
    }
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| OwnerMarkerError::System(e.to_string()))?;
    // Singleton guard: INSERT ... SELECT ... WHERE NOT EXISTS (...) is
    // evaluated by the engine at insert time, so a concurrent writer that
    // races past the `load_owner_row` short-circuit above will see the
    // guard as false and write zero rows (sea-orm's exec_without_returning
    // does not care). Portable across SQLite, PostgreSQL and MySQL.
    let backend = conn.get_database_backend();
    let stmt = sea_orm::Statement::from_sql_and_values(
        backend,
        "INSERT INTO sql_store_owner (store_id, created_at) \
         SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM sql_store_owner)",
        [desired.as_str().into(), now.into()],
    );
    conn.execute(stmt).await?;
    load_owner_row(conn)
        .await?
        .ok_or_else(|| OwnerMarkerError::System("owner row inserted but not readable".into()))
}

/// What the boot check decides. `Write` means the marker object is missing and
/// the uploader must `put_if_absent` it before the first cycle; `Ok` means the
/// marker matches and nothing needs to be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootOutcome {
    Ok(StoreId),
    Write(StoreId),
}

/// Pure comparison used by the boot path. Kept here so it can be unit-tested
/// without a database and without an object store.
pub fn compare(
    row: Option<&StoreId>,
    marker_body: Option<&[u8]>,
) -> Result<BootOutcome, OwnerMarkerError> {
    match (row, marker_body) {
        (Some(id), Some(body)) => {
            let other = StoreId::parse(std::str::from_utf8(body).map_err(|_| {
                OwnerMarkerError::System("owner marker body is not valid UTF-8".into())
            })?)?;
            if *id == other {
                Ok(BootOutcome::Ok(id.clone()))
            } else {
                Err(OwnerMarkerError::Mismatch)
            }
        }
        (Some(id), None) => Ok(BootOutcome::Write(id.clone())),
        (None, Some(_)) => Err(OwnerMarkerError::RowMissingMarkerPresent),
        (None, None) => {
            // First enable: caller freshly mints and inserts.
            Err(OwnerMarkerError::System("owner marker row absent".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_id_is_thirty_two_lowercase_hex_characters() {
        let id = StoreId::random();
        assert_eq!(id.as_str().len(), 32);
        assert!(id.as_str().bytes().all(is_lower_hex));
    }

    #[test]
    fn parse_rejects_uppercase_hex_and_wrong_length() {
        assert!(StoreId::parse("ABCDEF0123456789abcdef0123456789").is_err());
        assert!(StoreId::parse("abcd").is_err());
        assert!(StoreId::parse("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
        assert!(StoreId::parse("00000000000000000000000000000000").is_ok());
    }

    #[test]
    fn compare_matches_when_row_equals_marker_body() {
        let id = StoreId::parse("deadbeefcafebabe00000000000000ff").unwrap();
        assert_eq!(
            compare(Some(&id), Some(id.as_str().as_bytes())).unwrap(),
            BootOutcome::Ok(id.clone())
        );
    }

    #[test]
    fn compare_mismatch_when_row_differs_from_marker() {
        let a = StoreId::parse("11111111111111111111111111111111").unwrap();
        let b = StoreId::parse("22222222222222222222222222222222").unwrap();
        assert!(matches!(
            compare(Some(&a), Some(b.as_str().as_bytes())),
            Err(OwnerMarkerError::Mismatch)
        ));
    }

    #[test]
    fn compare_row_present_marker_absent_asks_to_write() {
        let id = StoreId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(
            compare(Some(&id), None).unwrap(),
            BootOutcome::Write(id.clone())
        );
    }

    #[test]
    fn compare_row_absent_marker_present_refuses() {
        let id = StoreId::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        assert!(matches!(
            compare(None, Some(id.as_str().as_bytes())),
            Err(OwnerMarkerError::RowMissingMarkerPresent)
        ));
    }

    #[test]
    fn mismatch_error_message_does_not_contain_the_body() {
        let err = OwnerMarkerError::Mismatch.to_string();
        assert_eq!(err, "sql_store owner marker mismatch");
        assert!(!err.contains('0'));
    }

    #[test]
    fn body_is_the_hex_ascii_of_the_store_id() {
        let id = StoreId::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(id.as_body(), b"0123456789abcdef0123456789abcdef".to_vec());
    }
}
