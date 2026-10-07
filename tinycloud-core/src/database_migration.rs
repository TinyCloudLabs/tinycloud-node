//! Explicit migration from pre-N2 physical names to full-path identities.
//! The durable artifact and its checkpoint/WAL columns are never rewritten.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter, QuerySelect, TransactionTrait,
};
use sea_orm_migration::SchemaManager;
use serde::Serialize;

use crate::{
    database_identity::{legacy_duckdb_name, legacy_sql_name, logical_name},
    models::{abilities, database_alias, database_artifact, database_legacy_artifact},
    relationships::invoked_abilities,
    types::Resource,
};

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error(transparent)]
    Database(#[from] DbErr),
    #[error("invalid service, space, path or physical name")]
    InvalidIdentity,
    #[error("legacy artifact is not quarantined or does not exist")]
    MissingLegacyArtifact,
    #[error("digest artifact or another alias already occupies this logical identity")]
    Collision,
    #[error("physical artifact is already assigned to another identity")]
    AlreadyAssigned,
    #[error("quarantined legacy artifact is unreachable without an explicit alias")]
    Quarantined,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("checkpoint failed: {0}")]
    Checkpoint(String),
}

#[derive(Clone, Debug, Serialize)]
pub struct InventoryItem {
    pub service: String,
    pub space: String,
    pub physical_name: String,
    pub durable: bool,
    pub cached: bool,
    pub paths: Vec<Option<String>>,
    pub classification: &'static str,
    pub collision: bool,
}

fn legacy_name(service: &str, path: Option<&str>) -> String {
    if service == "duckdb" {
        legacy_duckdb_name(path)
    } else {
        legacy_sql_name(path)
    }
}

async fn artifact_exists<C: sea_orm::ConnectionTrait>(
    conn: &C,
    service: &str,
    space: &str,
    name: &str,
) -> Result<bool, DbErr> {
    Ok(database_artifact::Entity::find_by_id((
        service.to_owned(),
        space.to_owned(),
        name.to_owned(),
    ))
    .select_only()
    .column(database_artifact::Column::Name)
    .into_tuple::<String>()
    .one(conn)
    .await?
    .is_some())
}

/// Scan durable rows and local cache files, then attribute each old artifact
/// using both stored grants and recorded invocations. A cache-only file is
/// reported, but cannot be aliased until its durable artifact is recovered.
pub async fn inventory(
    conn: &DatabaseConnection,
    datadir: &Path,
) -> Result<Vec<InventoryItem>, MigrationError> {
    let aliases_exist = SchemaManager::new(conn).has_table("database_alias").await?;
    let rows: Vec<(String, String, String)> = database_artifact::Entity::find()
        .select_only()
        .column(database_artifact::Column::Service)
        .column(database_artifact::Column::Space)
        .column(database_artifact::Column::Name)
        .into_tuple()
        .all(conn)
        .await?;
    let mut artifacts: BTreeMap<(String, String, String), (bool, bool)> = BTreeMap::new();
    for (service, space, name) in rows {
        if service == "sql" || service == "duckdb" {
            artifacts.entry((service, space, name)).or_default().0 = true;
        }
    }
    for (service, extension) in [("sql", ".db"), ("duckdb", ".duckdb")] {
        let root = datadir.join(service);
        if !root.exists() {
            continue;
        }
        for space_entry in std::fs::read_dir(root)? {
            let space_entry = space_entry?;
            if !space_entry.file_type()?.is_dir() {
                continue;
            }
            let space = space_entry.file_name().to_string_lossy().into_owned();
            for entry in std::fs::read_dir(space_entry.path())? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let filename = entry.file_name().to_string_lossy().into_owned();
                let name = filename.strip_suffix(extension).or_else(|| {
                    if service == "sql" {
                        filename
                            .strip_suffix(".db-wal")
                            .or_else(|| filename.strip_suffix(".db-shm"))
                    } else {
                        filename.strip_suffix(".duckdb.wal")
                    }
                });
                if let Some(name) = name {
                    artifacts
                        .entry((service.to_owned(), space.clone(), name.to_owned()))
                        .or_default()
                        .1 = true;
                }
            }
        }
    }
    let mut history: BTreeMap<(String, String, String), BTreeSet<Option<String>>> = BTreeMap::new();
    let grants: Vec<Resource> = abilities::Entity::find()
        .select_only()
        .column(abilities::Column::Resource)
        .into_tuple()
        .all(conn)
        .await?;
    let invocations: Vec<Resource> = invoked_abilities::Entity::find()
        .select_only()
        .column(invoked_abilities::Column::Resource)
        .into_tuple()
        .all(conn)
        .await?;
    for resource in grants.into_iter().chain(invocations) {
        let Some(id) = resource.tinycloud_resource() else {
            continue;
        };
        let service = id.service().as_str();
        if service != "sql" && service != "duckdb" {
            continue;
        }
        let path = id.path().map(|p| p.as_str().to_owned());
        let name = legacy_name(service, path.as_deref());
        history
            .entry((service.to_owned(), id.space().to_string(), name))
            .or_default()
            .insert(path);
    }
    let mut result = Vec::new();
    for ((service, space, physical_name), (durable, cached)) in artifacts {
        let paths: Vec<_> = history
            .remove(&(service.clone(), space.clone(), physical_name.clone()))
            .unwrap_or_default()
            .into_iter()
            .collect();
        let classification = match paths.len() {
            0 => "unattributed",
            1 => "unique",
            _ => "ambiguous",
        };
        let collision = if paths.len() == 1 {
            let digest = logical_name(paths[0].as_deref());
            let existing = if aliases_exist {
                database_alias::Entity::find_by_id((service.clone(), space.clone(), digest.clone()))
                    .one(conn)
                    .await?
            } else {
                None
            };
            artifact_exists(conn, &service, &space, &digest).await?
                || existing.is_some_and(|alias| {
                    alias.physical_name != physical_name || alias.path != paths[0]
                })
        } else {
            false
        };
        result.push(InventoryItem {
            service,
            space,
            physical_name,
            durable,
            cached,
            paths,
            classification,
            collision,
        });
    }
    Ok(result)
}

/// Resolve only through an explicit alias, or to an unreserved N2 digest.
pub async fn resolve(
    conn: &DatabaseConnection,
    service: &str,
    space: &str,
    path: Option<&str>,
) -> Result<String, MigrationError> {
    let digest = logical_name(path);
    if let Some(alias) =
        database_alias::Entity::find_by_id((service.to_owned(), space.to_owned(), digest.clone()))
            .one(conn)
            .await?
    {
        if artifact_exists(conn, service, space, &digest).await? {
            return Err(MigrationError::Collision);
        }
        if database_legacy_artifact::Entity::find_by_id((
            service.to_owned(),
            space.to_owned(),
            alias.physical_name.clone(),
        ))
        .one(conn)
        .await?
        .is_none()
            || !artifact_exists(conn, service, space, &alias.physical_name).await?
        {
            return Err(MigrationError::MissingLegacyArtifact);
        }
        return Ok(alias.physical_name);
    }
    // A short legacy spelling is reserved even though its N2 digest differs.
    // This makes attempted access to both mapped and unresolved old names an
    // explicit rejection, rather than allowing an apparently empty database.
    if let Some(short_name) = path.filter(|p| !p.contains('/')) {
        if database_legacy_artifact::Entity::find_by_id((
            service.to_owned(),
            space.to_owned(),
            short_name.to_owned(),
        ))
        .one(conn)
        .await?
        .is_some()
        {
            return Err(MigrationError::Quarantined);
        }
    }
    if path.is_none()
        && database_legacy_artifact::Entity::find_by_id((
            service.to_owned(),
            space.to_owned(),
            "default".to_owned(),
        ))
        .one(conn)
        .await?
        .is_some()
    {
        return Err(MigrationError::Quarantined);
    }
    if database_legacy_artifact::Entity::find_by_id((
        service.to_owned(),
        space.to_owned(),
        digest.clone(),
    ))
    .one(conn)
    .await?
    .is_some()
    {
        return Err(MigrationError::Quarantined);
    }
    Ok(digest)
}

fn validate(
    service: &str,
    space: &str,
    path: Option<&str>,
    physical: &str,
) -> Result<(), MigrationError> {
    if !matches!(service, "sql" | "duckdb")
        || legacy_name(service, path) != physical
        || physical.contains('/')
        || physical.contains('\\')
        || physical.contains('\0')
        || physical.contains("..")
        || space.parse::<tinycloud_auth::resource::SpaceId>().is_err()
    {
        return Err(MigrationError::InvalidIdentity);
    }
    let uri = match path {
        Some(path) => format!("{space}/{service}/{path}"),
        None => format!("{space}/{service}"),
    };
    let id: tinycloud_auth::resource::ResourceId =
        uri.parse().map_err(|_| MigrationError::InvalidIdentity)?;
    if id.path().map(|p| p.as_str()) != path || id.query().is_some() || id.fragment().is_some() {
        return Err(MigrationError::InvalidIdentity);
    }
    Ok(())
}

/// Mark every old artifact quarantined and insert unique aliases atomically.
/// Any collision refuses the whole transaction. Re-running is idempotent.
pub async fn apply_inventory(
    conn: &DatabaseConnection,
    items: &[InventoryItem],
) -> Result<(), MigrationError> {
    let tx = conn.begin().await?;
    for item in items {
        if database_legacy_artifact::Entity::find_by_id((
            item.service.clone(),
            item.space.clone(),
            item.physical_name.clone(),
        ))
        .one(&tx)
        .await?
        .is_none()
        {
            database_legacy_artifact::ActiveModel {
                service: Set(item.service.clone()),
                space: Set(item.space.clone()),
                physical_name: Set(item.physical_name.clone()),
            }
            .insert(&tx)
            .await?;
        }
    }
    for item in items {
        if item.classification == "unique" && item.durable {
            set_alias_in(
                &tx,
                &item.service,
                &item.space,
                item.paths[0].as_deref(),
                &item.physical_name,
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn set_alias_in<C: sea_orm::ConnectionTrait>(
    conn: &C,
    service: &str,
    space: &str,
    path: Option<&str>,
    physical: &str,
) -> Result<(), MigrationError> {
    validate(service, space, path, physical)?;
    let digest = logical_name(path);
    if database_legacy_artifact::Entity::find_by_id((
        service.to_owned(),
        space.to_owned(),
        physical.to_owned(),
    ))
    .one(conn)
    .await?
    .is_none()
        || !artifact_exists(conn, service, space, physical).await?
    {
        return Err(MigrationError::MissingLegacyArtifact);
    }
    if artifact_exists(conn, service, space, &digest).await? {
        return Err(MigrationError::Collision);
    }
    if let Some(existing) =
        database_alias::Entity::find_by_id((service.to_owned(), space.to_owned(), digest.clone()))
            .one(conn)
            .await?
    {
        return if existing.physical_name == physical && existing.path.as_deref() == path {
            Ok(())
        } else {
            Err(MigrationError::Collision)
        };
    }
    if database_alias::Entity::find()
        .filter(database_alias::Column::Service.eq(service))
        .filter(database_alias::Column::Space.eq(space))
        .filter(database_alias::Column::PhysicalName.eq(physical))
        .one(conn)
        .await?
        .is_some()
    {
        return Err(MigrationError::AlreadyAssigned);
    }
    database_alias::ActiveModel {
        service: Set(service.to_owned()),
        space: Set(space.to_owned()),
        logical_name: Set(digest),
        path: Set(path.map(str::to_owned)),
        physical_name: Set(physical.to_owned()),
    }
    .insert(conn)
    .await?;
    Ok(())
}

/// Assign an ambiguous or unattributed artifact only after operator approval.
pub async fn set_alias(
    conn: &DatabaseConnection,
    service: &str,
    space: &str,
    path: Option<&str>,
    physical: &str,
) -> Result<(), MigrationError> {
    let tx = conn.begin().await?;
    set_alias_in(&tx, service, space, path, physical).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn clear_alias(
    conn: &DatabaseConnection,
    service: &str,
    space: &str,
    path: Option<&str>,
) -> Result<(), MigrationError> {
    validate(service, space, path, &legacy_name(service, path))?;
    database_alias::Entity::delete_by_id((
        service.to_owned(),
        space.to_owned(),
        logical_name(path),
    ))
    .exec(conn)
    .await?;
    Ok(())
}

pub async fn aliases(
    conn: &DatabaseConnection,
) -> Result<Vec<database_alias::Model>, MigrationError> {
    Ok(database_alias::Entity::find().all(conn).await?)
}

/// Return the durable quarantine registry for an operator report.
pub async fn quarantined(
    conn: &DatabaseConnection,
) -> Result<Vec<database_legacy_artifact::Model>, MigrationError> {
    Ok(database_legacy_artifact::Entity::find().all(conn).await?)
}

/// Checkpoint every local cache with the node stopped. Artifact rows and
/// their durable checkpoint/delta columns are untouched. Built without the
/// `duckdb` feature, this refuses a directory containing DuckDB files.
pub fn checkpoint_cache(datadir: &Path) -> Result<(usize, usize), MigrationError> {
    let mut sqlite_count = 0;
    #[cfg(feature = "duckdb")]
    let mut duckdb_count = 0;
    #[cfg(not(feature = "duckdb"))]
    let duckdb_count = 0;
    for (service, suffix) in [("duckdb", ".duckdb"), ("sql", ".db")] {
        let root = datadir.join(service);
        if !root.exists() {
            continue;
        }
        for space_entry in std::fs::read_dir(root)? {
            let space_entry = space_entry?;
            if !space_entry.file_type()?.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(space_entry.path())? {
                let entry = entry?;
                if !entry.file_type()?.is_file()
                    || !entry.file_name().to_string_lossy().ends_with(suffix)
                {
                    continue;
                }
                if service == "sql" {
                    let db = rusqlite::Connection::open_with_flags(
                        entry.path(),
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
                    )
                    .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
                    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                        .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
                    sqlite_count += 1;
                } else {
                    #[cfg(feature = "duckdb")]
                    {
                        let db = duckdb::Connection::open(entry.path())
                            .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
                        db.execute_batch("CHECKPOINT;")
                            .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
                        duckdb_count += 1;
                    }
                    #[cfg(not(feature = "duckdb"))]
                    return Err(MigrationError::Checkpoint(
                        "rebuild the CLI with --features duckdb".into(),
                    ));
                }
            }
        }
    }
    Ok((sqlite_count, duckdb_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_scans_space_caches_without_renaming_files() {
        let root = tempfile::tempdir().unwrap();
        let sql_dir = root.path().join("sql").join("space");
        std::fs::create_dir_all(&sql_dir).unwrap();
        let sql_path = sql_dir.join("threads.db");
        let db = rusqlite::Connection::open(&sql_path).unwrap();
        db.execute_batch(
            "PRAGMA journal_mode=WAL; CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('row');",
        )
        .unwrap();
        drop(db);
        #[cfg(feature = "duckdb")]
        {
            let duck_dir = root.path().join("duckdb").join("space");
            std::fs::create_dir_all(&duck_dir).unwrap();
            let duck = duckdb::Connection::open(duck_dir.join("default.duckdb")).unwrap();
            duck.execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('row');")
                .unwrap();
        }
        let counts = checkpoint_cache(root.path()).unwrap();
        assert_eq!(counts.0, 1);
        #[cfg(feature = "duckdb")]
        assert_eq!(counts.1, 1);
        #[cfg(not(feature = "duckdb"))]
        assert_eq!(counts.1, 0);
        assert!(sql_path.exists());
    }
}
