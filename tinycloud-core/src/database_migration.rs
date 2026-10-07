//! Explicit migration from pre-N2 physical names to full-path identities.
//! The durable artifact and its checkpoint/WAL columns are never rewritten.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr,
    EntityTrait, QueryFilter, QuerySelect, TransactionTrait,
};
use sea_orm_migration::SchemaManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    database_identity::{legacy_duckdb_name, legacy_sql_name, logical_name},
    models::{
        abilities, database_alias, database_artifact, database_identity_fence,
        database_legacy_artifact,
    },
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
    #[error("SQL/DuckDB identity fence is not enabled in metadata")]
    FenceRequired,
    #[error("inventory cannot alias this legacy name: {0}")]
    InvalidInventory(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("checkpoint failed: {0}")]
    Checkpoint(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableFingerprint {
    pub name: String,
    pub schema_hash: String,
    pub row_count: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactFingerprint {
    pub schema_hash: String,
    pub tables: Vec<TableFingerprint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InventoryItem {
    pub service: String,
    pub space: String,
    pub physical_name: String,
    pub durable: bool,
    pub cached: bool,
    pub paths: Vec<Option<String>>,
    pub classification: String,
    pub collision: bool,
    pub fingerprint: Option<ArtifactFingerprint>,
}

fn hash_schema(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn quote_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn fingerprint_sqlite(path: &Path) -> Result<ArtifactFingerprint, MigrationError> {
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
    let mut statement = db.prepare("SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
    let schemas: Vec<(String, String)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| MigrationError::Checkpoint(e.to_string()))?
        .collect::<Result<_, _>>()
        .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
    let mut tables = Vec::new();
    for (name, schema) in schemas {
        let sql = format!("SELECT COUNT(*) FROM {}", quote_identifier(&name));
        let row_count = db
            .query_row(&sql, [], |row| row.get(0))
            .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
        tables.push(TableFingerprint {
            name,
            schema_hash: hash_schema(&schema),
            row_count,
        });
    }
    let schema_hash = hash_schema(
        &serde_json::to_string(
            &tables
                .iter()
                .map(|t| (&t.name, &t.schema_hash))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| MigrationError::Checkpoint(e.to_string()))?,
    );
    Ok(ArtifactFingerprint {
        schema_hash,
        tables,
    })
}

#[cfg(feature = "duckdb")]
fn fingerprint_duckdb(path: &Path) -> Result<ArtifactFingerprint, MigrationError> {
    let db =
        duckdb::Connection::open(path).map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
    let mut statement = db.prepare("SELECT table_schema, table_name FROM information_schema.tables WHERE table_type='BASE TABLE' AND table_schema NOT IN ('information_schema', 'pg_catalog') ORDER BY table_schema, table_name")
        .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
    let names: Vec<(String, String)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| MigrationError::Checkpoint(e.to_string()))?
        .collect::<Result<_, _>>()
        .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
    let mut tables = Vec::new();
    for (schema, name) in names {
        let columns: Vec<(String, String, String)> = db.prepare("SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_schema=?1 AND table_name=?2 ORDER BY ordinal_position")
            .map_err(|e| MigrationError::Checkpoint(e.to_string()))?
            .query_map(duckdb::params![schema, name], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| MigrationError::Checkpoint(e.to_string()))?
            .collect::<Result<_, _>>().map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
        let sql = format!(
            "SELECT COUNT(*) FROM {}.{}",
            quote_identifier(&schema),
            quote_identifier(&name)
        );
        let row_count = db
            .query_row(&sql, [], |row| row.get(0))
            .map_err(|e| MigrationError::Checkpoint(e.to_string()))?;
        tables.push(TableFingerprint {
            name: format!("{schema}.{name}"),
            schema_hash: hash_schema(&format!("{columns:?}")),
            row_count,
        });
    }
    let schema_hash = hash_schema(
        &serde_json::to_string(
            &tables
                .iter()
                .map(|t| (&t.name, &t.schema_hash))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| MigrationError::Checkpoint(e.to_string()))?,
    );
    Ok(ArtifactFingerprint {
        schema_hash,
        tables,
    })
}

async fn fingerprint<C: ConnectionTrait>(
    conn: &C,
    datadir: &Path,
    service: &str,
    space: &str,
    name: &str,
) -> Result<Option<ArtifactFingerprint>, MigrationError> {
    let row = database_artifact::Entity::find_by_id((
        service.to_owned(),
        space.to_owned(),
        name.to_owned(),
    ))
    .one(conn)
    .await?;
    let temp = tempfile::tempdir()?;
    let suffix = if service == "sql" { ".db" } else { ".duckdb" };
    let path = temp.path().join(format!("artifact{suffix}"));
    if let Some(row) = row {
        std::fs::write(&path, row.payload)?;
        if let Some(delta) = row.delta_payload {
            let wal = if service == "sql" {
                format!("{}-wal", path.display())
            } else {
                format!("{}.wal", path.display())
            };
            std::fs::write(wal, delta)?;
        }
    } else {
        let cache = datadir
            .join(service)
            .join(space)
            .join(format!("{name}{suffix}"));
        if !cache.exists() {
            return Ok(None);
        }
        std::fs::copy(&cache, &path)?;
        let wal_suffix = if service == "sql" { "-wal" } else { ".wal" };
        let source_wal = format!("{}{wal_suffix}", cache.display());
        if Path::new(&source_wal).exists() {
            std::fs::copy(source_wal, format!("{}{wal_suffix}", path.display()))?;
        }
    }
    if service == "sql" {
        fingerprint_sqlite(&path).map(Some)
    } else {
        #[cfg(feature = "duckdb")]
        {
            fingerprint_duckdb(&path).map(Some)
        }
        #[cfg(not(feature = "duckdb"))]
        {
            Err(MigrationError::Checkpoint(
                "rebuild the CLI with --features duckdb".into(),
            ))
        }
    }
}

/// Only N2's exact on-disk spellings are excluded. A malformed prefix is
/// still inventoried and fenced, rather than silently treated as migrated.
pub fn is_digest_name(name: &str) -> bool {
    name == "v2n"
        || (name.len() == 67
            && name.starts_with("v2d")
            && name[3..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}

pub async fn set_fence(conn: &DatabaseConnection, enabled: bool) -> Result<(), MigrationError> {
    if !enabled && has_unmigrated_artifacts(conn).await? {
        return Err(MigrationError::FenceRequired);
    }
    let tx = conn.begin().await?;
    database_identity_fence::Entity::delete_by_id(1)
        .exec(&tx)
        .await?;
    database_identity_fence::ActiveModel {
        id: Set(1),
        enabled: Set(enabled),
    }
    .insert(&tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn metadata_fenced<C: ConnectionTrait>(conn: &C) -> Result<bool, MigrationError> {
    Ok(database_identity_fence::Entity::find_by_id(1)
        .one(conn)
        .await?
        .is_some_and(|row| row.enabled))
}

pub async fn require_fence<C: ConnectionTrait>(conn: &C) -> Result<(), MigrationError> {
    if metadata_fenced(conn).await? {
        Ok(())
    } else {
        Err(MigrationError::FenceRequired)
    }
}

pub async fn has_unmigrated_artifacts<C: ConnectionTrait>(
    conn: &C,
) -> Result<bool, MigrationError> {
    let registered: BTreeSet<(String, String, String)> = database_legacy_artifact::Entity::find()
        .select_only()
        .column(database_legacy_artifact::Column::Service)
        .column(database_legacy_artifact::Column::Space)
        .column(database_legacy_artifact::Column::PhysicalName)
        .into_tuple::<(String, String, String)>()
        .all(conn)
        .await?
        .into_iter()
        .collect();
    let rows: Vec<(String, String, String)> = database_artifact::Entity::find()
        .filter(database_artifact::Column::Service.is_in(["sql", "duckdb"]))
        .select_only()
        .column(database_artifact::Column::Service)
        .column(database_artifact::Column::Space)
        .column(database_artifact::Column::Name)
        .into_tuple()
        .all(conn)
        .await?;
    Ok(rows
        .into_iter()
        .any(|row| !is_digest_name(&row.2) && !registered.contains(&row)))
}

/// Caches only the expensive legacy-artifact inventory. The durable metadata
/// fence is read on every check, so turning it on takes effect even while an
/// earlier "unfenced" inventory result is cached.
#[derive(Debug)]
pub struct EffectiveFenceCache {
    legacy: tokio::sync::Mutex<Option<(Instant, bool)>>,
    ttl: Duration,
}

impl Default for EffectiveFenceCache {
    fn default() -> Self {
        Self {
            legacy: tokio::sync::Mutex::new(None),
            ttl: Duration::from_secs(1),
        }
    }
}

impl EffectiveFenceCache {
    /// Check the durable fence on every call and refresh the legacy scan after its TTL.
    pub async fn check(
        &self,
        conn: &DatabaseConnection,
        configured: bool,
    ) -> Result<bool, MigrationError> {
        if configured || metadata_fenced(conn).await? {
            return Ok(true);
        }
        let mut cached = self.legacy.lock().await;
        if let Some((checked_at, fenced)) = *cached {
            if checked_at.elapsed() < self.ttl {
                return Ok(fenced);
            }
        }
        let scan_started = Instant::now();
        let fenced = has_unmigrated_artifacts(conn).await?;
        *cached = Some((scan_started, fenced));
        Ok(fenced)
    }
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
    inventory_in(conn, datadir, aliases_exist).await
}

async fn inventory_in<C: ConnectionTrait>(
    conn: &C,
    datadir: &Path,
    aliases_exist: bool,
) -> Result<Vec<InventoryItem>, MigrationError> {
    let rows: Vec<(String, String, String)> = database_artifact::Entity::find()
        .filter(database_artifact::Column::Service.is_in(["sql", "duckdb"]))
        .select_only()
        .column(database_artifact::Column::Service)
        .column(database_artifact::Column::Space)
        .column(database_artifact::Column::Name)
        .into_tuple()
        .all(conn)
        .await?;
    let mut artifacts: BTreeMap<(String, String, String), (bool, bool)> = BTreeMap::new();
    for (service, space, name) in rows {
        if !is_digest_name(&name) {
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
                if let Some(name) = name.filter(|name| !is_digest_name(name)) {
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
        .filter(
            abilities::Column::Resource
                .contains("/sql")
                .or(abilities::Column::Resource.contains("/duckdb")),
        )
        .select_only()
        .column(abilities::Column::Resource)
        .into_tuple()
        .all(conn)
        .await?;
    let invocations: Vec<Resource> = invoked_abilities::Entity::find()
        .filter(
            invoked_abilities::Column::Resource
                .contains("/sql")
                .or(invoked_abilities::Column::Resource.contains("/duckdb")),
        )
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
            let physical_alias = if aliases_exist {
                database_alias::Entity::find()
                    .filter(database_alias::Column::Service.eq(&service))
                    .filter(database_alias::Column::Space.eq(&space))
                    .filter(database_alias::Column::PhysicalName.eq(&physical_name))
                    .one(conn)
                    .await?
            } else {
                None
            };
            artifact_exists(conn, &service, &space, &digest).await?
                || existing.is_some_and(|alias| {
                    alias.physical_name != physical_name || alias.path != paths[0]
                })
                || physical_alias
                    .is_some_and(|alias| alias.logical_name != digest || alias.path != paths[0])
        } else {
            false
        };
        result.push(InventoryItem {
            fingerprint: fingerprint(conn, datadir, &service, &space, &physical_name).await?,
            service,
            space,
            physical_name,
            durable,
            cached,
            paths,
            classification: classification.to_owned(),
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
    let old_name = legacy_name(service, path);
    if database_legacy_artifact::Entity::find_by_id((
        service.to_owned(),
        space.to_owned(),
        old_name.clone(),
    ))
    .one(conn)
    .await?
    .is_some()
        && database_alias::Entity::find()
            .filter(database_alias::Column::Service.eq(service))
            .filter(database_alias::Column::Space.eq(space))
            .filter(database_alias::Column::PhysicalName.eq(&old_name))
            .one(conn)
            .await?
            .is_none()
    {
        return Err(MigrationError::Quarantined);
    }
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
    apply_inventory_in(&tx, items).await?;
    tx.commit().await?;
    Ok(())
}

pub fn validate_inventory(items: &[InventoryItem]) -> Result<(), MigrationError> {
    for item in items {
        if item.collision {
            return Err(MigrationError::Collision);
        }
        // Even an unresolved artifact must be called out during dry-run if
        // no future authorized mapping could pass set_alias_in.
        if item.physical_name.contains('/')
            || item.physical_name.contains('\\')
            || item.physical_name.contains('\0')
            || item.physical_name.contains("..")
        {
            return Err(MigrationError::InvalidInventory(format!(
                "{}/{}/{}",
                item.service, item.space, item.physical_name
            )));
        }
        if item.classification == "unique" && item.durable {
            validate(
                &item.service,
                &item.space,
                item.paths[0].as_deref(),
                &item.physical_name,
            )
            .map_err(|_| {
                MigrationError::InvalidInventory(format!(
                    "{}/{}/{}",
                    item.service, item.space, item.physical_name
                ))
            })?;
        }
    }
    Ok(())
}

pub async fn apply(
    conn: &DatabaseConnection,
    datadir: &Path,
) -> Result<Vec<InventoryItem>, MigrationError> {
    let tx = conn.begin().await?;
    require_fence(&tx).await?;
    let items = inventory_in(&tx, datadir, true).await?;
    validate_inventory(&items)?;
    apply_inventory_in(&tx, &items).await?;
    tx.commit().await?;
    Ok(items)
}

async fn apply_inventory_in<C: ConnectionTrait>(
    conn: &C,
    items: &[InventoryItem],
) -> Result<(), MigrationError> {
    validate_inventory(items)?;
    for item in items {
        if database_legacy_artifact::Entity::find_by_id((
            item.service.clone(),
            item.space.clone(),
            item.physical_name.clone(),
        ))
        .one(conn)
        .await?
        .is_none()
        {
            database_legacy_artifact::ActiveModel {
                service: Set(item.service.clone()),
                space: Set(item.space.clone()),
                physical_name: Set(item.physical_name.clone()),
            }
            .insert(conn)
            .await?;
        }
    }
    for item in items {
        if item.classification == "unique" && item.durable {
            set_alias_in(
                conn,
                &item.service,
                &item.space,
                item.paths[0].as_deref(),
                &item.physical_name,
            )
            .await?;
        }
    }
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
    require_fence(&tx).await?;
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
    let tx = conn.begin().await?;
    require_fence(&tx).await?;
    database_alias::Entity::delete_by_id((
        service.to_owned(),
        space.to_owned(),
        logical_name(path),
    ))
    .exec(&tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn aliases(
    conn: &DatabaseConnection,
) -> Result<Vec<database_alias::Model>, MigrationError> {
    if !SchemaManager::new(conn).has_table("database_alias").await? {
        return Ok(Vec::new());
    }
    Ok(database_alias::Entity::find().all(conn).await?)
}

/// Return the durable quarantine registry for an operator report.
pub async fn quarantined(
    conn: &DatabaseConnection,
) -> Result<Vec<database_legacy_artifact::Model>, MigrationError> {
    if !SchemaManager::new(conn)
        .has_table("database_legacy_artifact")
        .await?
    {
        return Ok(Vec::new());
    }
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

    #[tokio::test]
    async fn effective_fence_caches_legacy_scan_but_observes_metadata_fence_live() {
        use sea_orm::Database;
        use sea_orm_migration::MigratorTrait;

        let dir = tempfile::tempdir().unwrap();
        let conn = Database::connect(format!(
            "sqlite:{}?mode=rwc",
            dir.path().join("caps.db").display()
        ))
        .await
        .unwrap();
        crate::migrations::Migrator::up(&conn, None).await.unwrap();
        let cache = EffectiveFenceCache {
            legacy: tokio::sync::Mutex::new(None),
            ttl: Duration::from_secs(60),
        };
        assert!(!cache.check(&conn, false).await.unwrap());
        database_artifact::ActiveModel {
            service: Set("sql".into()),
            space: Set("test-space".into()),
            name: Set("threads".into()),
            revision: Set(1),
            content_hash: Set("fixture".into()),
            payload: Set(vec![]),
            size_bytes: Set(0),
            backend: Set("sqlite".into()),
            storage_mode: Set("database-blob".into()),
            created_at: Set("2026-01-01T00:00:00Z".into()),
            updated_at: Set("2026-01-01T00:00:00Z".into()),
            checkpoint_size_bytes: Set(0),
            checkpoint_content_hash: Set("fixture".into()),
            delta_payload: Set(None),
            delta_content_hash: Set(None),
            delta_size_bytes: Set(0),
        }
        .insert(&conn)
        .await
        .unwrap();
        assert!(!cache.check(&conn, false).await.unwrap(), "scan is cached");
        cache.legacy.lock().await.as_mut().unwrap().0 = Instant::now() - Duration::from_secs(61);
        assert!(
            cache.check(&conn, false).await.unwrap(),
            "unmigrated artifact fences"
        );
        database_legacy_artifact::ActiveModel {
            service: Set("sql".into()),
            space: Set("test-space".into()),
            physical_name: Set("threads".into()),
        }
        .insert(&conn)
        .await
        .unwrap();
        cache.legacy.lock().await.as_mut().unwrap().0 = Instant::now() - Duration::from_secs(61);
        assert!(
            !cache.check(&conn, false).await.unwrap(),
            "migration clears auto fence"
        );
        set_fence(&conn, true).await.unwrap();
        assert!(
            cache.check(&conn, false).await.unwrap(),
            "metadata fence bypasses cached false"
        );
        set_fence(&conn, false).await.unwrap();
        assert!(!cache.check(&conn, false).await.unwrap());
        assert!(
            cache.check(&conn, true).await.unwrap(),
            "configured fence is immediate"
        );
    }

    #[test]
    fn only_exact_n2_names_are_excluded_and_invalid_legacy_names_fail_preview() {
        let digest = logical_name(Some("web/threads"));
        assert!(is_digest_name(&digest));
        assert!(is_digest_name("v2n"));
        assert!(!is_digest_name("v2dnot-a-digest"));
        assert!(!is_digest_name("v2dABC"));
        let jwk = tinycloud_auth::ssi::jwk::JWK::generate_ed25519().unwrap();
        let did = tinycloud_auth::resolver::DID_METHODS
            .generate(&jwk, "key")
            .unwrap();
        let space = tinycloud_auth::resource::SpaceId::new(did, "preview".parse().unwrap());
        let item = InventoryItem {
            service: "sql".into(),
            space: space.to_string(),
            physical_name: "notes..v2".into(),
            durable: true,
            cached: false,
            paths: vec![Some("web/notes..v2".into())],
            classification: "unique".into(),
            collision: false,
            fingerprint: None,
        };
        assert!(matches!(
            validate_inventory(std::slice::from_ref(&item)),
            Err(MigrationError::InvalidInventory(_))
        ));
        let mut unattributed = item;
        unattributed.classification = "unattributed".into();
        unattributed.paths.clear();
        assert!(matches!(
            validate_inventory(&[unattributed]),
            Err(MigrationError::InvalidInventory(_))
        ));
    }

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
