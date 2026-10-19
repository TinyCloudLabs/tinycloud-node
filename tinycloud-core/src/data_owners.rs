//! TC-1482: the distinct wallet addresses that own data on this node, for the
//! read-only `GET /admin/stats` route.
//!
//! # What counts
//!
//! An owner counts when at least one of their spaces holds data that sign-in
//! and vault unlock do not create by themselves. Sign-in creates,
//! automatically, in every bootstrapped account: KV in `account` and SQL
//! tables in `account` and `secrets` (OpenKey's `tinycloud-bootstrap`).
//! `vault.unlock()` writes three KV rows in `public` whose keys start with
//! `.well-known/vault-` (`vault-pubkey`, `vault-version`, `vault-space`), and
//! an app may unlock automatically. So:
//!
//! - **`account`**: never counts, neither its KV nor its database artifacts.
//! - **`secrets`**: its **KV** counts (a stored secret is real data); its
//!   **database artifacts do not** (the sign-in bootstrap's table).
//! - **`public`**: its KV counts, except rows whose key starts with the exact,
//!   case-sensitive prefix `.well-known/vault-` (vault metadata). Any other
//!   `public` row, and the same prefix in any other space, still counts.
//! - **every other space**: KV and database artifacts both count.
//!
//! The name is the exact last segment of the space id; see [`name_test`].
//! App first-use data (a database an app creates, such as a `conversations`
//! table) counts: it means a person used an app that stores on TinyCloud.
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

/// The registry space OpenKey writes at sign-in. It never counts on its own:
/// neither its KV nor its database artifacts.
pub const ACCOUNT_SPACE: &str = "account";

/// The secrets space. OpenKey's sign-in bootstrap creates a SQL table in it,
/// so its database artifacts never count. Its KV rows (stored secrets) do.
pub const SECRETS_SPACE: &str = "secrets";

/// The `public` space, where `vault.unlock()` writes its metadata.
pub const PUBLIC_SPACE: &str = "public";

/// Keys in the `public` space that start with this exact prefix are vault
/// metadata (`.well-known/vault-pubkey`, `.well-known/vault-version`,
/// `.well-known/vault-space`), not data. ASCII only, so its byte length is its
/// character length in SQL `SUBSTR`.
pub const VAULT_METADATA_PREFIX: &str = ".well-known/vault-";

/// Most owners one call returns: the consumer's own limit (OpenKey refuses a
/// longer list). More is an error, never a partial list.
pub const MAX_OWNERS: usize = 200_000;

/// Most distinct spaces one call reads, which bounds memory (about 110 bytes
/// each). Spaces that do not count (the automatic `account` space, the
/// `secrets` space's database artifacts, and a `public` space holding only
/// vault metadata) are excluded in SQL and are not part of this number. More
/// is an error, never a partial list.
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

/// `SUBSTR` of the last `name.len() + 1` characters of the space id in
/// `column`, compared with `op` (`=` or `<>`) to `':<name>'`. A space id is
/// `tinycloud:pkh:eip155:<chain>:0x<address>:<name>` and the id parser splits
/// at the LAST `:`, so a name never contains one and "ends in `:<name>`" is
/// "the name is exactly `<name>`": `xsecrets` and an owner part that happens to
/// contain the word cannot match. `SUBSTR` with `=` is used rather than
/// `LIKE`, which is ASCII-case-insensitive on SQLite (so it would drop an
/// `Account` space that the node treats as ordinary data). `:public` is 7
/// characters, so its substring starts at `LENGTH - 6`.
fn name_test(column: &str, name: &str, op: &str) -> String {
    let suffix = format!(":{name}");
    format!(
        "SUBSTR({column}, LENGTH({column}) - {}) {op} '{suffix}'",
        suffix.len() - 1
    )
}

/// The `WHERE` condition that is true when the space id in `column` does NOT
/// end in `:<name>`.
fn not_named(column: &str, name: &str) -> String {
    name_test(column, name, "<>")
}

/// The condition that is true when the space id in `column` ends in `:<name>`.
fn named(column: &str, name: &str) -> String {
    name_test(column, name, "=")
}

/// Space ids with counted data, each at most once (`UNION`):
///
/// - KV half: a `space` row, not named `account`, with a live `current_kv` row
///   that is not vault metadata (in a space named `public`, a key starting
///   with [`VAULT_METADATA_PREFIX`]);
/// - artifact half: a `database_artifact` space not named `account` or `secrets`.
///
/// The exclusions are in SQL, before the outer `LIMIT`, so the bound counts
/// DISTINCT SPACES THAT COUNT, not sign-in bookkeeping rows. The outer `LIMIT`
/// is the memory bound plus one, so a result past it is detected instead of
/// silently cut. Written for SQLite, PostgreSQL and MySQL; the only parameter
/// is the numeric bound, and the names and prefix are constants of this crate
/// (no `_`, `%` or quote in them, so inlining them is exact).
fn query(limit: usize) -> String {
    let kv_not_account = not_named("s.id", ACCOUNT_SPACE);
    let kv_in_public = named("s.id", PUBLIC_SPACE);
    let prefix = VAULT_METADATA_PREFIX;
    let prefix_len = prefix.len();
    let artifact_not_account = not_named("a.space", ACCOUNT_SPACE);
    let artifact_not_secrets = not_named("a.space", SECRETS_SPACE);
    format!(
        "SELECT u.id FROM (\
           SELECT s.id AS id FROM space s \
           WHERE {kv_not_account} \
             AND EXISTS (SELECT 1 FROM current_kv k WHERE k.space = s.id AND NOT k.deleted \
               AND NOT ({kv_in_public} AND SUBSTR(k.key, 1, {prefix_len}) = '{prefix}')) \
           UNION \
           SELECT a.space AS id FROM database_artifact a \
           WHERE {artifact_not_account} AND {artifact_not_secrets}\
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

/// The lowercase owner address of a space id, or `None` for an unparsable id
/// and an owner that is not an `eip155` address. The automatic `account` and
/// `secrets` spaces are excluded by [`query`], before the row bound.
fn data_owner(space_id: &str) -> Option<String> {
    let space = SpaceId::from_str(space_id).ok()?;
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

    /// `account` and `secrets` are matched by their exact name segment, so a
    /// name that merely contains or ends with those words still counts, and
    /// the exclusions drop exactly what the contract says.
    async fn assert_exclusions_are_exact(conn: &DatabaseConnection) {
        let owner = |n: u64| format!("0x{n:040x}");

        // Owner 1: only KV in `secrets` (a stored secret): counted.
        let secret_kv = id(1, &owner(1), "secrets");
        add_space(conn, &secret_kv).await;
        add_kv(conn, &secret_kv, "vault/api-key", false).await;
        // Owner 2: tombstoned KV in `secrets` only: not counted.
        let secret_gone = id(1, &owner(2), "secrets");
        add_space(conn, &secret_gone).await;
        add_kv(conn, &secret_gone, "vault/old", true).await;
        // Owner 3: only an artifact in `secrets` (the sign-in table): not counted.
        add_artifact(conn, &id(1, &owner(3), "secrets"), "sql").await;
        // Owner 4: artifacts in `account` (SQL and DuckDB) and KV in `account`: not counted.
        let account = id(1, &owner(4), "account");
        add_space(conn, &account).await;
        add_kv(conn, &account, "bootstrap/complete", false).await;
        add_artifact(conn, &account, "sql").await;
        add_artifact(conn, &account, "duckdb").await;
        // Owner 5: the whole sign-in footprint at once: not counted.
        add_artifact(conn, &id(1, &owner(5), "secrets"), "sql").await;
        add_artifact(conn, &id(1, &owner(5), "account"), "sql").await;
        let account5 = id(1, &owner(5), "account");
        add_space(conn, &account5).await;
        add_kv(conn, &account5, "bootstrap/complete", false).await;
        assert_eq!(owners(conn).await, vec![owner(1)]);

        // Any other space counts, by KV or by artifact, whatever it is
        // named next to the excluded words.
        let mut expected = vec![owner(1)];
        for (n, name) in [
            "xsecrets",
            "secrets2",
            "my-secrets",
            "secrets-old",
            "Secrets",
            "SECRETS",
            "xaccount",
            "account2",
            "my-account",
            "Account",
            "ACCOUNT",
            "default",
            "applications",
            "public",
        ]
        .into_iter()
        .enumerate()
        {
            let who = owner(100 + n as u64);
            add_artifact(conn, &id(1, &who, name), "sql").await;
            expected.push(who);
            let who_kv = owner(200 + n as u64);
            let space = id(1, &who_kv, name);
            add_space(conn, &space).await;
            add_kv(conn, &space, "k", false).await;
            expected.push(who_kv);
            assert_eq!(
                owners(conn).await.len(),
                expected.len(),
                "a space named {name:?} must count"
            );
        }
        expected.sort();
        assert_eq!(owners(conn).await, expected);

        // An artifact in `secrets` beside a live KV secret: counted by the KV.
        // An owner with `secrets` artifact and a real artifact elsewhere: counted.
        let both = id(1, &owner(6), "secrets");
        add_artifact(conn, &both, "sql").await;
        add_space(conn, &both).await;
        add_kv(conn, &both, "vault/token", false).await;
        add_artifact(conn, &id(1, &owner(7), "secrets"), "sql").await;
        add_artifact(conn, &id(1, &owner(7), "notes"), "sql").await;
        let result = owners(conn).await;
        assert!(result.contains(&owner(6)) && result.contains(&owner(7)));
        assert_eq!(result.len(), expected.len() + 2);
    }

    #[tokio::test]
    async fn sqlite_exclusions_are_exact() {
        assert_exclusions_are_exact(&sqlite().await).await;
    }

    #[tokio::test]
    async fn postgres_exclusions_are_exact() {
        let Some(schema) =
            crate::test_support::PostgresTestSchema::new("postgres_exclusions_are_exact").await
        else {
            return;
        };
        assert_exclusions_are_exact(&schema.conn).await;
    }

    /// The space bound counts distinct spaces that count, not sign-in rows:
    /// any number of sign-in-only accounts leaves it untouched.
    async fn assert_bound_counts_distinct_counted_spaces(conn: &DatabaseConnection) {
        for n in 0..20u64 {
            let who = format!("0x{n:040x}");
            let account = id(1, &who, "account");
            add_space(conn, &account).await;
            add_kv(conn, &account, "bootstrap/complete", false).await;
            add_artifact(conn, &account, "sql").await;
            add_artifact(conn, &id(1, &who, "secrets"), "sql").await;
        }
        // 20 signed-in accounts, no counted space: fits even a bound of 1.
        assert!(collect_bounded(conn, 1, 1).await.unwrap().is_empty());

        // One owner whose KV and artifact are in the SAME space is one space.
        let real = id(1, &format!("0x{:040x}", 99), "default");
        add_space(conn, &real).await;
        add_kv(conn, &real, "k", false).await;
        add_artifact(conn, &real, "sql").await;
        assert_eq!(collect_bounded(conn, 1, 1).await.unwrap().len(), 1);

        // A second counted space of the same owner is a second space: over a
        // bound of 1 it is an error, never a shorter list.
        let second = id(1, &format!("0x{:040x}", 99), "photos");
        add_artifact(conn, &second, "sql").await;
        assert!(matches!(
            collect_bounded(conn, 1, 5).await,
            Err(DataOwnersError::TooLarge)
        ));
        assert_eq!(collect_bounded(conn, 2, 1).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn sqlite_bound_counts_distinct_counted_spaces() {
        assert_bound_counts_distinct_counted_spaces(&sqlite().await).await;
    }

    #[tokio::test]
    async fn postgres_bound_counts_distinct_counted_spaces() {
        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_bound_counts_distinct_counted_spaces",
        )
        .await
        else {
            return;
        };
        assert_bound_counts_distinct_counted_spaces(&schema.conn).await;
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

    // ---- Sign-in replay -------------------------------------------------
    //
    // What a fresh account gets from OpenKey's sign-in bootstrap
    // (openkey `apps/api/src/services/tinycloud-bootstrap.ts`, run against
    // openkey 82edce3 / js-sdk ba66248; the SQL text is js-sdk
    // `packages/bootstrap/src/index.ts` `ACCOUNT_INDEX_SCHEMA` and
    // `SECRET_RECORDS_SCHEMA`), and from the SDK's default private-key / CLI
    // sign-in (`TinyCloudNode.runAccountBootstrap`, which adds the
    // `system/bootstrap/complete` marker). SQL goes through the real
    // `SqlService` and `SeaOrmDatabaseArtifactRepository`, so the
    // `database_artifact` rows are the ones the node writes, not hand-made.
    // KV rows are inserted directly: the KV write path needs signed
    // delegations, and `data_owners` reads only `space` and `current_kv`.
    //
    // If the bootstrap gains a space or table, update this replay; a
    // sign-in-only account listed as an owner is the symptom this test pins.

    const ACCOUNT_INDEX_SCHEMA: [&str; 10] = [
        "CREATE TABLE IF NOT EXISTS applications (app_id TEXT PRIMARY KEY, name TEXT, \
         description TEXT, updated_at TEXT, manifest_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS application_state (app_id TEXT PRIMARY KEY, \
         manifest_hash TEXT NOT NULL, indexed_at TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS spaces (space_id TEXT PRIMARY KEY, name TEXT NOT NULL, \
         owner_did TEXT NOT NULL, type TEXT NOT NULL, permissions_json TEXT NOT NULL, \
         status TEXT NOT NULL, registered_at TEXT, updated_at TEXT NOT NULL, expires_at TEXT)",
        "CREATE TABLE IF NOT EXISTS delegations (cid TEXT PRIMARY KEY, direction TEXT NOT NULL, \
         space_id TEXT NOT NULL, space_name TEXT, counterparty_did TEXT NOT NULL, \
         delegate_did TEXT NOT NULL, delegator_did TEXT, path TEXT NOT NULL, \
         actions_json TEXT NOT NULL, expiry TEXT NOT NULL, status TEXT NOT NULL, \
         created_at TEXT, updated_at TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sync_state (source TEXT PRIMARY KEY, \
         synced_at TEXT NOT NULL, count INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_delegations_direction ON delegations(direction)",
        "CREATE INDEX IF NOT EXISTS idx_delegations_space ON delegations(space_id)",
        "CREATE INDEX IF NOT EXISTS idx_delegations_counterparty ON delegations(counterparty_did)",
        "CREATE INDEX IF NOT EXISTS idx_spaces_owner ON spaces(owner_did)",
        "CREATE INDEX IF NOT EXISTS idx_spaces_type ON spaces(type)",
    ];
    const SECRET_RECORDS_SCHEMA: &str =
        "CREATE TABLE IF NOT EXISTS secret_records (scope TEXT NOT NULL, name TEXT NOT NULL, \
         provider_id TEXT, custom_note TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, \
         last_tested TEXT, test_status TEXT, test_message TEXT, PRIMARY KEY(scope, name))";
    const BOOTSTRAP_SPACES: [&str; 5] = ["default", "applications", "account", "secrets", "public"];

    fn space_id(owner: &str, name: &str) -> SpaceId {
        id(1, owner, name).parse().unwrap()
    }

    async fn sql_execute(
        service: &crate::sql::SqlService,
        owner: &str,
        space: &str,
        database: &str,
        ability: &str,
        request: crate::sql::SqlRequest,
    ) {
        service
            .execute(
                &space_id(owner, space),
                database,
                request,
                None,
                ability.to_string(),
            )
            .await
            .unwrap_or_else(|error| panic!("{space}/{database}: {error:?}"));
    }

    /// The writes of one sign-in, in the bootstrap's order.
    async fn replay_sign_in(
        conn: &DatabaseConnection,
        service: &crate::sql::SqlService,
        owner: &str,
    ) {
        use crate::sql::{types::SqlStatement, SqlRequest, SqlValue};

        // 1-2. Host the five spaces and activate their sessions: `space` rows,
        // no KV and no SQL.
        for name in BOOTSTRAP_SPACES {
            add_space(conn, &id(1, owner, name)).await;
        }
        // 3. The registry tables, in the `account` database of `account`
        // (`tinycloud.sql/schema`; the carrier statement is the last one).
        sql_execute(
            service,
            owner,
            "account",
            "account",
            "tinycloud.sql/schema",
            SqlRequest::Execute {
                sql: ACCOUNT_INDEX_SCHEMA[9].to_string(),
                params: vec![],
                schema: Some(ACCOUNT_INDEX_SCHEMA.iter().map(|s| s.to_string()).collect()),
            },
        )
        .await;
        // 4a. KV in `account`: one `spaces/<id>` entry per space, the secrets
        // application manifest, and the SDK's `system/bootstrap/complete` marker.
        for name in BOOTSTRAP_SPACES {
            let key = format!("spaces/{}", id(1, owner, name));
            add_kv(conn, &id(1, owner, "account"), &key, false).await;
        }
        add_kv(
            conn,
            &id(1, owner, "account"),
            "applications/xyz.tinycloud.secrets",
            false,
        )
        .await;
        add_kv(
            conn,
            &id(1, owner, "account"),
            "system/bootstrap/complete",
            false,
        )
        .await;
        // 4b. The same five spaces as rows of the `spaces` table.
        sql_execute(
            service,
            owner,
            "account",
            "account",
            "tinycloud.sql/write",
            SqlRequest::Batch {
                statements: BOOTSTRAP_SPACES
                    .iter()
                    .map(|name| SqlStatement {
                        sql: "INSERT OR REPLACE INTO spaces (space_id, name, owner_did, type, \
                              permissions_json, status, registered_at, updated_at, expires_at) \
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                            .to_string(),
                        params: vec![
                            SqlValue::Text(id(1, owner, name)),
                            SqlValue::Text(name.to_string()),
                            SqlValue::Text(format!("did:pkh:eip155:1:{owner}")),
                            SqlValue::Text("owned".into()),
                            SqlValue::Text("[\"*\"]".into()),
                            SqlValue::Text("active".into()),
                            SqlValue::Text("now".into()),
                            SqlValue::Text("now".into()),
                            SqlValue::Null,
                        ],
                    })
                    .collect(),
            },
        )
        .await;
        // 5. The secrets-records table, in database `default` of `secrets`.
        sql_execute(
            service,
            owner,
            "secrets",
            "default",
            "tinycloud.sql/schema",
            SqlRequest::Execute {
                sql: SECRET_RECORDS_SCHEMA.to_string(),
                params: vec![],
                schema: Some(vec![SECRET_RECORDS_SCHEMA.to_string()]),
            },
        )
        .await;
    }

    async fn count(conn: &DatabaseConnection, table: &str, space: &str) -> i64 {
        let sql = format!(
            "SELECT COUNT(*) AS n FROM {table} WHERE space = {}",
            placeholders(conn, 1)
        );
        conn.query_one(Statement::from_sql_and_values(
            conn.get_database_backend(),
            &sql,
            vec![space.into()],
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap()
    }

    /// Owners that only signed in are not listed; owners that also stored
    /// anything outside what sign-in writes are.
    async fn assert_sign_in_only_owners_are_not_listed(conn: &DatabaseConnection) {
        use crate::{database_artifacts::SeaOrmDatabaseArtifactRepository, sql::SqlService};

        let cache = tempfile::TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            0,
            std::sync::Arc::new(SeaOrmDatabaseArtifactRepository::new(conn.clone())),
        );
        let signed_in = |n: u64| format!("0x{:040x}", 0xa000 + n);
        let (only, only_sdk, secret_kv, other_kv, other_sql) = (
            signed_in(1),
            signed_in(2),
            signed_in(3),
            signed_in(4),
            signed_in(5),
        );
        // Owners that also unlock the vault (`vault.unlock()` writes three KV
        // rows in `public`), then differ in what else they hold.
        let (unlock_only, unlock_notes, unlock_deleted, unlock_other_space) =
            (signed_in(6), signed_in(7), signed_in(8), signed_in(9));
        let (unlock_wk_other, unlock_wk_nodash, unlock_case) =
            (signed_in(10), signed_in(11), signed_in(12));
        let unlockers = [
            &unlock_only,
            &unlock_notes,
            &unlock_deleted,
            &unlock_other_space,
            &unlock_wk_other,
            &unlock_wk_nodash,
            &unlock_case,
        ];
        for owner in [&only, &only_sdk, &secret_kv, &other_kv, &other_sql]
            .into_iter()
            .chain(unlockers)
        {
            replay_sign_in(conn, &service, owner).await;
        }

        // The replay really wrote what a sign-in writes: the account and the
        // secrets database (artifact rows) and the account's KV. Without the
        // exclusions every one of these owners would be listed.
        for owner in [&only, &secret_kv] {
            assert_eq!(
                count(conn, "database_artifact", &id(1, owner, "account")).await,
                1
            );
            assert_eq!(
                count(conn, "database_artifact", &id(1, owner, "secrets")).await,
                1
            );
            assert_eq!(count(conn, "current_kv", &id(1, owner, "account")).await, 7);
        }
        let raw: BTreeSet<String> = conn
            .query_all(Statement::from_string(
                conn.get_database_backend(),
                "SELECT space FROM database_artifact UNION SELECT space FROM current_kv"
                    .to_string(),
            ))
            .await
            .unwrap()
            .iter()
            .map(|row| row.try_get_by_index::<String>(0).unwrap())
            .collect();
        assert!(raw.contains(&id(1, &only, "secrets")) && raw.contains(&id(1, &only, "account")));
        assert!(
            owners(conn).await.is_empty(),
            "an owner who only signed in must not be listed: {:?}",
            owners(conn).await
        );

        // Sign-in + vault unlock only: the three `.well-known/vault-*` rows
        // in `public` are present (live) but are not data.
        for owner in unlockers {
            let public = id(1, owner, "public");
            for key in [
                ".well-known/vault-pubkey",
                ".well-known/vault-version",
                ".well-known/vault-space",
            ] {
                add_kv(conn, &public, key, false).await;
            }
            assert_eq!(count(conn, "current_kv", &public).await, 3);
        }
        assert!(
            owners(conn).await.is_empty(),
            "sign-in plus vault unlock must not be listed: {:?}",
            owners(conn).await
        );

        // A stored secret: KV in `secrets`.
        let secrets = id(1, &secret_kv, "secrets");
        add_kv(conn, &secrets, "vault/openai", false).await;
        assert_eq!(owners(conn).await, vec![secret_kv.clone()]);

        // Data in another space: KV in `default`, a SQL table in `default`.
        add_kv(conn, &id(1, &other_kv, "default"), "notes/a", false).await;
        sql_execute(
            &service,
            &other_sql,
            "default",
            "main",
            "tinycloud.sql/write",
            crate::sql::SqlRequest::Execute {
                sql: "CREATE TABLE notes (id INTEGER)".to_string(),
                params: vec![],
                schema: None,
            },
        )
        .await;
        let mut expected = vec![secret_kv, other_kv, other_sql];
        expected.sort();
        assert_eq!(owners(conn).await, expected);

        // Each of these makes an unlocked owner count. Checked one at a time,
        // so a wider filter fails on the first row it wrongly hides.
        let public = |owner: &String| id(1, owner, "public");
        let cases: [(&String, String, &str); 5] = [
            // any other `public` KV
            (&unlock_notes, public(&unlock_notes), "notes/x"),
            // the prefix, but in another space
            (
                &unlock_other_space,
                id(1, &unlock_other_space, "default"),
                ".well-known/vault-pubkey",
            ),
            // another `.well-known/` key
            (
                &unlock_wk_other,
                public(&unlock_wk_other),
                ".well-known/other",
            ),
            // `vault` without the dash
            (
                &unlock_wk_nodash,
                public(&unlock_wk_nodash),
                ".well-known/vault",
            ),
            // the prefix is case-sensitive
            (&unlock_case, public(&unlock_case), ".Well-Known/vault-x"),
        ];
        for (owner, space, key) in cases {
            let before = owners(conn).await;
            assert!(!before.contains(owner), "{key} not yet written");
            add_kv(conn, &space, key, false).await;
            let after = owners(conn).await;
            assert!(after.contains(owner), "{key} in {space} must count");
            assert_eq!(after.len(), before.len() + 1);
        }

        // A deleted `public` row that is not metadata does not count.
        add_kv(conn, &public(&unlock_deleted), "notes/gone", true).await;
        assert!(!owners(conn).await.contains(&unlock_deleted));

        assert!(!owners(conn).await.contains(&only));
        assert!(!owners(conn).await.contains(&only_sdk));
        assert!(!owners(conn).await.contains(&unlock_only));
    }

    #[tokio::test]
    async fn sqlite_sign_in_only_owners_are_not_listed() {
        assert_sign_in_only_owners_are_not_listed(&sqlite().await).await;
    }

    #[tokio::test]
    async fn postgres_sign_in_only_owners_are_not_listed() {
        let Some(schema) = crate::test_support::PostgresTestSchema::new(
            "postgres_sign_in_only_owners_are_not_listed",
        )
        .await
        else {
            return;
        };
        assert_sign_in_only_owners_are_not_listed(&schema.conn).await;
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
        // The `account` / `secrets` exclusions are in the SQL, not here (see
        // `assert_exclusions_are_exact`).
        assert!(data_owner(&format!("tinycloud:pkh:eip155:1:{lower}:account")).is_some());
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
