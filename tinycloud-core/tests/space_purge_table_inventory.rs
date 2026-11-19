use std::collections::{BTreeMap, BTreeSet};
use tinycloud_core::{
    migrations::Migrator,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement},
    sea_orm_migration::MigratorTrait,
    space_purge_database::{PURGED_BY_OWNER, PURGED_BY_SPACE, RETAINED},
};

/// Columns whose values name a space (or a resource under one) or a principal
/// that can own a space. HMAC digests are opaque and deliberately excluded.
const NAMING_COLUMNS: &str =
    "c.column_name IN ('space','space_id','owner','owner_did','network_id',
        'did','resource','delegator','delegatee','invoker','revoker','requester','grantor')
     OR c.column_name LIKE '%\\_space' OR c.column_name LIKE '%\\_space\\_id'
     OR c.column_name LIKE '%\\_did'
     OR (c.table_name,c.column_name) IN (('space','id'),('actor','id'))";

#[tokio::test]
async fn postgres_every_space_or_owner_table_is_classified() {
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!("purge_tables_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let discovered: BTreeSet<String> = db
        .query_all(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT DISTINCT c.table_name::text AS name FROM information_schema.columns c
                 JOIN information_schema.tables t
                   ON t.table_schema=c.table_schema AND t.table_name=c.table_name
                 WHERE c.table_schema=current_schema() AND t.table_type='BASE TABLE'
                 AND ({NAMING_COLUMNS})"
            ),
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.try_get("", "name").unwrap())
        .collect();
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();

    let mut lists: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (table, _) in PURGED_BY_SPACE {
        lists.entry(table).or_default().push("PURGED_BY_SPACE");
    }
    for table in PURGED_BY_OWNER {
        lists.entry(table).or_default().push("PURGED_BY_OWNER");
    }
    for (table, reason) in RETAINED {
        assert!(!reason.is_empty(), "{table} is retained without a reason");
        lists.entry(table).or_default().push("RETAINED");
    }
    let unclassified: Vec<_> = discovered
        .iter()
        .filter(|table| !lists.contains_key(table.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "tables naming a space or owner without a purge classification in \
         space_purge_database.rs: {unclassified:?}"
    );
    let ambiguous: Vec<_> = lists
        .iter()
        .filter(|(_, in_lists)| in_lists.len() > 1)
        .collect();
    assert!(
        ambiguous.is_empty(),
        "tables classified more than once: {ambiguous:?}"
    );
    let stale: Vec<_> = lists
        .keys()
        .filter(|table| !discovered.contains(**table))
        .collect();
    assert!(
        stale.is_empty(),
        "classified tables with no space or owner column: {stale:?}"
    );
}
