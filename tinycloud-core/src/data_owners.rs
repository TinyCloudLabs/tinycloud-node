//! TC-1482: the distinct wallet addresses that own data on this node, for the
//! read-only `GET /admin/stats` route.
//!
//! # What counts
//!
//! An owner counts when at least one of their spaces other than the automatic
//! `account` registry space holds data:
//!
//! - **KV**: at least one `current_kv` row with `deleted = false`; or
//! - **SQL/DuckDB**: at least one `database_artifact` row. Artifact rows are
//!   never deleted (there is no delete path), so "has created a database in
//!   that space" is the strongest statement the table supports; a dropped
//!   database still leaves its row.
//!
//! `database_legacy_artifact` rows are fence markers for pre-identity physical
//! names, not data, and are not read.
//!
//! The owner is parsed from the space id
//! (`tinycloud:pkh:eip155:<chain>:0x<address>:<name>`), lowercased, and
//! de-duplicated across spaces and chains. Spaces whose owner is not an
//! `eip155` address (a `did:key` owner, for example) are skipped.
//!
//! # Cost
//!
//! One statement, no per-space work in Rust. The KV half drives from the
//! `space` table and asks, for each space, whether `current_kv` has a live row.
//! `current_kv` is keyed `(space, key)`, so that is one index probe per space
//! that stops at the first live row; it never scans a space's keys and never
//! scans the table. The artifact half is one scan of `database_artifact`
//! restricted to the `space` column, which the table's primary key
//! `(service, space, name)` covers, so no payload is read. Compare
//! `GET /admin/usage`, which issues one `store_size` call per space.

use sea_orm::{ConnectionTrait, DbErr, Statement};
use std::collections::BTreeSet;
use std::str::FromStr;
use tinycloud_auth::resource::SpaceId;

/// The name of the registry space OpenKey writes at sign-in. It never counts
/// on its own.
pub const ACCOUNT_SPACE: &str = "account";

/// Most owners one call returns: the consumer's own limit (OpenKey refuses a
/// longer list). More is an error, never a partial list.
pub const MAX_OWNERS: usize = 200_000;

/// Most space ids one call reads, which bounds memory (about 110 bytes each).
/// More is an error, never a partial list. Every owner has an `account` space,
/// so this is deliberately above [`MAX_OWNERS`].
pub const MAX_SPACES_SCANNED: usize = 400_000;

/// Why no list was produced.
#[derive(Debug)]
pub enum DataOwnersError {
    /// The statement failed.
    Db(DbErr),
    /// More than [`MAX_SPACES_SCANNED`] spaces or [`MAX_OWNERS`] owners.
    TooLarge,
}

impl From<DbErr> for DataOwnersError {
    fn from(error: DbErr) -> Self {
        Self::Db(error)
    }
}

/// Space ids with live data: live KV in a `space` row, or any artifact. The
/// outer `LIMIT` is the memory bound plus one, so a result past it is
/// detected instead of silently cut. `UNION` removes the spaces both halves
/// return. Written for SQLite, PostgreSQL and MySQL; the only parameter is
/// the numeric bound, which is a constant of this crate.
fn query(limit: usize) -> String {
    format!(
        "SELECT u.id FROM (\
           SELECT s.id AS id FROM space s \
           WHERE EXISTS (SELECT 1 FROM current_kv k WHERE k.space = s.id AND NOT k.deleted) \
           UNION \
           SELECT a.space AS id FROM database_artifact a\
         ) u LIMIT {limit}"
    )
}

/// Run the single statement and reduce its rows to owners: sorted, lowercase,
/// each exactly `0x` and 40 hex digits.
pub async fn collect<C: ConnectionTrait>(conn: &C) -> Result<Vec<String>, DataOwnersError> {
    collect_bounded(conn, MAX_SPACES_SCANNED, MAX_OWNERS).await
}

async fn collect_bounded<C: ConnectionTrait>(
    conn: &C,
    max_spaces: usize,
    max_owners: usize,
) -> Result<Vec<String>, DataOwnersError> {
    let rows = conn
        .query_all(Statement::from_string(
            conn.get_database_backend(),
            query(max_spaces + 1),
        ))
        .await?;
    if rows.len() > max_spaces {
        return Err(DataOwnersError::TooLarge);
    }
    let mut owners = BTreeSet::new();
    for row in &rows {
        let id: String = row.try_get_by_index(0)?;
        if let Some(owner) = data_owner(&id) {
            owners.insert(owner);
        }
    }
    if owners.len() > max_owners {
        return Err(DataOwnersError::TooLarge);
    }
    Ok(owners.into_iter().collect())
}

/// The lowercase owner address of a space id, or `None` for the `account`
/// space, an unparsable id, and an owner that is not an `eip155` address.
fn data_owner(space_id: &str) -> Option<String> {
    let space = SpaceId::from_str(space_id).ok()?;
    if space.name().as_str() == ACCOUNT_SPACE {
        return None;
    }
    // `did:pkh:eip155:<chain>:<address>`
    let mut parts = space.did().as_str().split(':');
    let (Some("did"), Some("pkh"), Some("eip155"), Some(chain), Some(address), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    let hex = address.strip_prefix("0x")?;
    if chain.is_empty()
        || !chain.bytes().all(|b| b.is_ascii_digit())
        || hex.len() != 40
        || !hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some(address.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectOptions, Database, DatabaseConnection, DbBackend};
    use sea_orm_migration::MigratorTrait;

    const ALICE: &str = "0x0abcdefabcdefabcdefabcdefabcdefabcdefabc";
    const BOB: &str = "0x1111111111111111111111111111111111111111";
    const CAROL: &str = "0x2222222222222222222222222222222222222222";
    const DAVE: &str = "0x3333333333333333333333333333333333333333";
    const EVE: &str = "0x4444444444444444444444444444444444444444";

    fn id(chain: u64, address: &str, name: &str) -> String {
        format!("tinycloud:pkh:eip155:{chain}:{address}:{name}")
    }

    async fn sqlite() -> DatabaseConnection {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        crate::migrations::Migrator::up(&conn, None).await.unwrap();
        conn
    }

    async fn exec(conn: &DatabaseConnection, sql: &str, values: Vec<sea_orm::Value>) {
        conn.execute(Statement::from_sql_and_values(
            conn.get_database_backend(),
            sql,
            values,
        ))
        .await
        .unwrap();
    }

    fn placeholders(conn: &DatabaseConnection, n: usize) -> String {
        (1..=n)
            .map(|i| match conn.get_database_backend() {
                DbBackend::Postgres => format!("${i}"),
                _ => "?".to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    async fn add_space(conn: &DatabaseConnection, space: &str) {
        let sql = format!("INSERT INTO space (id) VALUES ({})", placeholders(conn, 1));
        exec(conn, &sql, vec![space.into()]).await;
    }

    async fn add_kv(conn: &DatabaseConnection, space: &str, key: &str, deleted: bool) {
        let sql = format!(
            "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, \
             metadata, deleted) VALUES ({})",
            placeholders(conn, 9)
        );
        let blob = |tag: &str| sea_orm::Value::Bytes(Some(Box::new(tag.as_bytes().to_vec())));
        exec(
            conn,
            &sql,
            vec![
                space.into(),
                key.into(),
                blob("invocation"),
                1i64.into(),
                blob("epoch"),
                1i64.into(),
                blob("value"),
                sea_orm::Value::Json(Some(Box::new(serde_json::json!({})))),
                deleted.into(),
            ],
        )
        .await;
    }

    async fn add_artifact(conn: &DatabaseConnection, space: &str, service: &str) {
        let sql = format!(
            "INSERT INTO database_artifact (service, space, name, revision, content_hash, \
             payload, size_bytes, backend, storage_mode, created_at, updated_at, \
             checkpoint_size_bytes, checkpoint_content_hash, delta_size_bytes) \
             VALUES ({})",
            placeholders(conn, 14)
        );
        exec(
            conn,
            &sql,
            vec![
                service.into(),
                space.into(),
                "main".into(),
                1i64.into(),
                "hash".into(),
                sea_orm::Value::Bytes(Some(Box::new(vec![0u8; 8]))),
                8i64.into(),
                "sqlite".into(),
                "checkpoint".into(),
                "now".into(),
                "now".into(),
                8i64.into(),
                "hash".into(),
                0i64.into(),
            ],
        )
        .await;
    }

    async fn owners(conn: &DatabaseConnection) -> Vec<String> {
        collect(conn).await.unwrap()
    }

    /// The behaviour contract, run against whichever backend `conn` is.
    async fn assert_owner_rules(conn: &DatabaseConnection) {
        assert!(owners(conn).await.is_empty(), "an empty node has no owners");

        // Only the automatic registry space: not counted, whatever it holds.
        let alice_account = id(1, ALICE, "account");
        add_space(conn, &alice_account).await;
        add_kv(conn, &alice_account, "bootstrap/complete", false).await;
        add_artifact(conn, &alice_account, "sql").await;
        assert!(owners(conn).await.is_empty());

        // A space with no data at all is not counted either.
        let empty = id(1, BOB, "default");
        add_space(conn, &empty).await;
        assert!(owners(conn).await.is_empty());

        // Registry + one data space: counted once.
        let alice_data = id(1, ALICE, "default");
        add_space(conn, &alice_data).await;
        add_kv(conn, &alice_data, "notes/a", false).await;
        add_kv(conn, &alice_data, "notes/b", false).await;
        assert_eq!(owners(conn).await, vec![ALICE]);

        // Same owner on another chain and another space: still once.
        let alice_chain = id(137, ALICE, "photos");
        add_space(conn, &alice_chain).await;
        add_kv(conn, &alice_chain, "p/1", false).await;
        let alice_more = id(1, ALICE, "work");
        add_space(conn, &alice_more).await;
        add_kv(conn, &alice_more, "w/1", false).await;
        assert_eq!(owners(conn).await, vec![ALICE]);

        // Mixed-case spelling of the same address dedupes with the lowercase one.
        let alice_upper = id(1, "0x0ABCDEFabcdefABCDEFabcdefABCDEFabcdefABC", "mixed");
        add_space(conn, &alice_upper).await;
        add_kv(conn, &alice_upper, "m/1", false).await;
        assert_eq!(owners(conn).await, vec![ALICE]);

        // Deleted-only data: not counted. A live row beside tombstones: counted.
        let carol = id(1, CAROL, "default");
        add_space(conn, &carol).await;
        add_kv(conn, &carol, "gone/1", true).await;
        add_kv(conn, &carol, "gone/2", true).await;
        assert_eq!(owners(conn).await, vec![ALICE]);
        let dave = id(1, DAVE, "default");
        add_space(conn, &dave).await;
        add_kv(conn, &dave, "a", true).await;
        add_kv(conn, &dave, "b", false).await;
        assert_eq!(owners(conn).await, vec![ALICE, DAVE]);

        // Artifact-only owner (SQL or DuckDB, no KV, no `space` row needed).
        let eve = id(1, EVE, "analytics");
        add_artifact(conn, &eve, "sql").await;
        add_artifact(conn, &eve, "duckdb").await;
        assert_eq!(owners(conn).await, vec![ALICE, DAVE, EVE]);

        // Spaces holding live data whose owner is not a 40-digit hex eip155
        // address never reach the list.
        for malformed in [
            id(1, "0xabc", "default"),
            id(1, "0x00000000000000000000000000000000000000001", "default"),
            id(1, "0xgggggggggggggggggggggggggggggggggggggggg", "default"),
            id(1, "0000000000000000000000000000000000000001", "default"),
            "tinycloud:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK:default".to_owned(),
            "tinycloud:pkh:solana:1:0x0000000000000000000000000000000000000001:default".to_owned(),
            "not-a-space-id".to_owned(),
        ] {
            add_space(conn, &malformed).await;
            add_kv(conn, &malformed, "k", false).await;
        }
        add_artifact(conn, "also-not-a-space-id", "sql").await;
        assert_eq!(owners(conn).await, vec![ALICE, DAVE, EVE]);

        // Every entry is exactly `0x` + 40 lowercase hex digits, sorted.
        let result = owners(conn).await;
        assert!(result.iter().all(|owner| {
            owner.len() == 42
                && owner.starts_with("0x")
                && owner[2..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }));
        let mut sorted = result.clone();
        sorted.sort();
        assert_eq!(result, sorted);
    }

    #[tokio::test]
    async fn sqlite_owner_rules() {
        assert_owner_rules(&sqlite().await).await;
    }

    #[tokio::test]
    async fn postgres_owner_rules() {
        let Some(schema) =
            crate::test_support::PostgresTestSchema::new("postgres_owner_rules").await
        else {
            return;
        };
        assert_owner_rules(&schema.conn).await;
    }

    /// Past either bound the result is an error, never a shorter list.
    async fn assert_bounds_fail_instead_of_truncating(conn: &DatabaseConnection) {
        for n in 0..5u64 {
            let space = id(1, &format!("0x{n:040x}"), "default");
            add_space(conn, &space).await;
            add_kv(conn, &space, "k", false).await;
        }
        // Exactly at both bounds is fine.
        assert_eq!(collect_bounded(conn, 5, 5).await.unwrap().len(), 5);
        assert_eq!(collect_bounded(conn, 50, 50).await.unwrap().len(), 5);
        // One more space than may be read.
        assert!(matches!(
            collect_bounded(conn, 4, 50).await,
            Err(DataOwnersError::TooLarge)
        ));
        // One more owner than may be returned.
        assert!(matches!(
            collect_bounded(conn, 50, 4).await,
            Err(DataOwnersError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn sqlite_bounds_fail_instead_of_truncating() {
        assert_bounds_fail_instead_of_truncating(&sqlite().await).await;
    }

    #[tokio::test]
    async fn postgres_bounds_fail_instead_of_truncating() {
        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_bounds_fail_instead_of_truncating",
        )
        .await
        else {
            return;
        };
        assert_bounds_fail_instead_of_truncating(&schema.conn).await;
    }

    #[test]
    fn owner_parsing() {
        let lower = "0x0abcdefabcdefabcdefabcdefabcdefabcdefabc";
        assert_eq!(
            data_owner(&format!("tinycloud:pkh:eip155:1:{lower}:default")),
            Some(lower.to_string())
        );
        assert_eq!(
            data_owner("tinycloud:pkh:eip155:10:0x0ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABC:x"),
            Some(lower.to_string())
        );
        // The registry space, exactly named, is the only exclusion; a longer or
        // differently cased name is data.
        assert_eq!(
            data_owner(&format!("tinycloud:pkh:eip155:1:{lower}:account")),
            None
        );
        assert!(data_owner(&format!("tinycloud:pkh:eip155:1:{lower}:account2")).is_some());
        assert!(data_owner(&format!("tinycloud:pkh:eip155:1:{lower}:Account")).is_some());
        // Not a 40-digit eip155 address owner.
        assert_eq!(
            data_owner("tinycloud:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK:default"),
            None
        );
        assert_eq!(data_owner("tinycloud:pkh:eip155:1:0xabc:default"), None);
        assert_eq!(
            data_owner("tinycloud:pkh:eip155:1:0x0abcdefabcdefabcdefabcdefabcdefabcdefabc0:d"),
            None
        );
        assert_eq!(
            data_owner("tinycloud:pkh:eip155:1:0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz:d"),
            None
        );
        assert_eq!(
            data_owner("tinycloud:pkh:eip155::0x0abcdefabcdefabcdefabcdefabcdefabcdefabc:d"),
            None
        );
        assert_eq!(data_owner("garbage"), None);
    }
}
