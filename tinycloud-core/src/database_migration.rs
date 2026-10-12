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

/// Fields read from production artifact rows. This deliberately excludes both
/// bytea payload columns, even when the row is very large.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactMetadata {
    pub revision: i64,
    pub size_bytes: i64,
    pub checkpoint_content_hash: String,
    pub checkpoint_size_bytes: i64,
    pub delta_content_hash: Option<String>,
    pub delta_size_bytes: i64,
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
    pub metadata: Option<ArtifactMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_fingerprint: Option<ArtifactFingerprint>,
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

fn artifact_metadata_query(
    service: &str,
    space: &str,
    name: &str,
) -> sea_orm::Select<database_artifact::Entity> {
    database_artifact::Entity::find_by_id((service.to_owned(), space.to_owned(), name.to_owned()))
        .select_only()
        .column(database_artifact::Column::Revision)
        .column(database_artifact::Column::SizeBytes)
        .column(database_artifact::Column::CheckpointContentHash)
        .column(database_artifact::Column::CheckpointSizeBytes)
        .column(database_artifact::Column::DeltaContentHash)
        .column(database_artifact::Column::DeltaSizeBytes)
}

fn artifact_identity_query() -> sea_orm::Select<database_artifact::Entity> {
    database_artifact::Entity::find()
        .filter(database_artifact::Column::Service.is_in(["sql", "duckdb"]))
        .select_only()
        .column(database_artifact::Column::Service)
        .column(database_artifact::Column::Space)
        .column(database_artifact::Column::Name)
}

fn artifact_name_query(
    service: &str,
    space: &str,
    name: &str,
) -> sea_orm::Select<database_artifact::Entity> {
    database_artifact::Entity::find_by_id((service.to_owned(), space.to_owned(), name.to_owned()))
        .select_only()
        .column(database_artifact::Column::Name)
}

async fn fingerprint<C: ConnectionTrait>(
    conn: &C,
    service: &str,
    space: &str,
    name: &str,
) -> Result<Option<ArtifactMetadata>, MigrationError> {
    let row: Option<(i64, i64, String, i64, Option<String>, i64)> =
        artifact_metadata_query(service, space, name)
            .into_tuple()
            .one(conn)
            .await?;
    Ok(row.map(
        |(
            revision,
            size_bytes,
            checkpoint_content_hash,
            checkpoint_size_bytes,
            delta_content_hash,
            delta_size_bytes,
        )| ArtifactMetadata {
            revision,
            size_bytes,
            checkpoint_content_hash,
            checkpoint_size_bytes,
            delta_content_hash,
            delta_size_bytes,
        },
    ))
}

/// Reads artifact bytes only for an explicitly designated local snapshot.
/// Production-facing inventory, apply, report, and verify never call this.
async fn offline_fingerprint<C: ConnectionTrait>(
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

/// Full schema and row-count inspection is limited to an operator-designated
/// local snapshot. The caller must enforce that boundary before invoking it.
pub async fn offline_inventory(
    conn: &DatabaseConnection,
    datadir: &Path,
) -> Result<Vec<InventoryItem>, MigrationError> {
    let mut items = inventory(conn, datadir).await?;
    for item in &mut items {
        item.offline_fingerprint = offline_fingerprint(
            conn,
            datadir,
            &item.service,
            &item.space,
            &item.physical_name,
        )
        .await?;
    }
    Ok(items)
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
    let rows: Vec<(String, String, String)> =
        artifact_identity_query().into_tuple().all(conn).await?;
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
    Ok(artifact_name_query(service, space, name)
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
    let rows: Vec<(String, String, String)> =
        artifact_identity_query().into_tuple().all(conn).await?;
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
            metadata: fingerprint(conn, &service, &space, &physical_name).await?,
            offline_fingerprint: None,
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

/// One point lookup that `resolve` depends on. Each tag names exactly one of
/// the lookups `resolve_sequential` issues, with the same `WHERE` predicate, so
/// the database's own comparison rules decide every match as before. Rust only
/// checks which tags came back; it never compares names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolveLookup {
    /// `database_alias` by (service, space, logical_name = digest).
    Alias,
    /// `database_artifact` by (service, space, name = digest).
    DigestArtifact,
    /// `database_legacy_artifact` by the alias's physical name.
    AliasLegacy,
    /// `database_artifact` by the alias's physical name.
    AliasArtifact,
    /// `database_legacy_artifact` by the pre-N2 name of `path`.
    OldLegacy,
    /// Any `database_alias` whose physical name is the pre-N2 name of `path`.
    OldAlias,
    /// `database_legacy_artifact` by a short (slash-free) `path`.
    ShortLegacy,
    /// `database_legacy_artifact` by `default`, for a pathless database.
    DefaultLegacy,
    /// `database_legacy_artifact` by the digest itself.
    DigestLegacy,
}

impl ResolveLookup {
    const ALL: [Self; 9] = [
        Self::Alias,
        Self::DigestArtifact,
        Self::AliasLegacy,
        Self::AliasArtifact,
        Self::OldLegacy,
        Self::OldAlias,
        Self::ShortLegacy,
        Self::DefaultLegacy,
        Self::DigestLegacy,
    ];

    fn tag(self) -> &'static str {
        match self {
            Self::Alias => "alias",
            Self::DigestArtifact => "digest_artifact",
            Self::AliasLegacy => "alias_legacy",
            Self::AliasArtifact => "alias_artifact",
            Self::OldLegacy => "old_legacy",
            Self::OldAlias => "old_alias",
            Self::ShortLegacy => "short_legacy",
            Self::DefaultLegacy => "default_legacy",
            Self::DigestLegacy => "digest_legacy",
        }
    }
}

/// Every lookup `resolve` may need, as one `UNION ALL` statement: one branch
/// per lookup, each tagged and each with the predicate its own query used to
/// have. The two alias-dependent lookups read the alias's physical name with
/// the same primary-key lookup, as a subquery. Artifact branches select only
/// `name`, never a payload column.
fn resolve_query(
    service: &str,
    space: &str,
    path: Option<&str>,
) -> sea_orm::sea_query::SelectStatement {
    use database_alias::{Column as AliasColumn, Entity as AliasTable};
    use database_artifact::{Column as ArtifactColumn, Entity as ArtifactTable};
    use database_legacy_artifact::{Column as LegacyColumn, Entity as LegacyTable};
    use sea_orm::sea_query::{
        Alias, Expr, IntoIden, Query, SelectStatement, SimpleExpr, UnionType,
    };

    /// `SELECT '<tag>' AS lookup, <value> AS name FROM <table>
    ///  WHERE service = $service AND space = $space AND <name>`
    fn branch<T: IntoIden + Copy + 'static, C: IntoIden + Copy + 'static>(
        lookup: ResolveLookup,
        table: T,
        [service_column, space_column, value_column]: [C; 3],
        (service, space): (&str, &str),
        name: SimpleExpr,
    ) -> SelectStatement {
        Query::select()
            .expr_as(Expr::val(lookup.tag()), Alias::new("lookup"))
            .expr_as(Expr::col((table, value_column)), Alias::new("name"))
            .from(table)
            .and_where(Expr::col((table, service_column)).eq(service))
            .and_where(Expr::col((table, space_column)).eq(space))
            .and_where(name)
            .to_owned()
    }

    let key = (service, space);
    let digest = logical_name(path);
    let old_name = legacy_name(service, path);
    let alias = [
        AliasColumn::Service,
        AliasColumn::Space,
        AliasColumn::PhysicalName,
    ];
    let artifact = [
        ArtifactColumn::Service,
        ArtifactColumn::Space,
        ArtifactColumn::Name,
    ];
    let legacy = [
        LegacyColumn::Service,
        LegacyColumn::Space,
        LegacyColumn::PhysicalName,
    ];
    let alias_logical = Expr::col((AliasTable, AliasColumn::LogicalName)).eq(digest.as_str());
    let alias_physical = || Expr::col((AliasTable, AliasColumn::PhysicalName));
    let artifact_name = || Expr::col((ArtifactTable, ArtifactColumn::Name));
    let legacy_name = || Expr::col((LegacyTable, LegacyColumn::PhysicalName));
    // The alias's physical name, by the alias primary key (at most one row).
    let alias_target = Query::select()
        .column((AliasTable, AliasColumn::PhysicalName))
        .from(AliasTable)
        .and_where(Expr::col((AliasTable, AliasColumn::Service)).eq(service))
        .and_where(Expr::col((AliasTable, AliasColumn::Space)).eq(space))
        .and_where(alias_logical.clone())
        .to_owned();

    let mut query = branch(ResolveLookup::Alias, AliasTable, alias, key, alias_logical);
    let mut branches = vec![
        branch(
            ResolveLookup::DigestArtifact,
            ArtifactTable,
            artifact,
            key,
            artifact_name().eq(digest.as_str()),
        ),
        branch(
            ResolveLookup::AliasLegacy,
            LegacyTable,
            legacy,
            key,
            legacy_name().in_subquery(alias_target.clone()),
        ),
        branch(
            ResolveLookup::AliasArtifact,
            ArtifactTable,
            artifact,
            key,
            artifact_name().in_subquery(alias_target),
        ),
        branch(
            ResolveLookup::OldLegacy,
            LegacyTable,
            legacy,
            key,
            legacy_name().eq(old_name.as_str()),
        ),
        branch(
            ResolveLookup::OldAlias,
            AliasTable,
            alias,
            key,
            alias_physical().eq(old_name.as_str()),
        ),
    ];
    if let Some(short_name) = path.filter(|p| !p.contains('/')) {
        branches.push(branch(
            ResolveLookup::ShortLegacy,
            LegacyTable,
            legacy,
            key,
            legacy_name().eq(short_name),
        ));
    }
    if path.is_none() {
        branches.push(branch(
            ResolveLookup::DefaultLegacy,
            LegacyTable,
            legacy,
            key,
            legacy_name().eq("default"),
        ));
    }
    branches.push(branch(
        ResolveLookup::DigestLegacy,
        LegacyTable,
        legacy,
        key,
        legacy_name().eq(digest.as_str()),
    ));
    for next in branches {
        query.union(UnionType::All, next);
    }
    query
}

/// Resolve only through an explicit alias, or to an unreserved N2 digest.
///
/// On PostgreSQL and SQLite all lookups run as one statement
/// (`resolve_query`); the decision below is `resolve_sequential`'s, in the
/// same precedence. MySQL keeps `resolve_sequential`: the single statement
/// compares the alias's physical name column to column and unions `name`
/// columns of three tables, and MySQL tables created at different times may
/// carry different collations.
pub async fn resolve(
    conn: &DatabaseConnection,
    service: &str,
    space: &str,
    path: Option<&str>,
) -> Result<String, MigrationError> {
    if conn.get_database_backend() == sea_orm::DatabaseBackend::MySql {
        return resolve_sequential(conn, service, space, path).await;
    }
    let digest = logical_name(path);
    let rows = conn
        .query_all(
            conn.get_database_backend()
                .build(&resolve_query(service, space, path)),
        )
        .await?;
    let mut alias_physical_name = None;
    let mut found = BTreeSet::new();
    for row in rows {
        let tag: String = row.try_get("", "lookup")?;
        let Some(lookup) = ResolveLookup::ALL.into_iter().find(|l| l.tag() == tag) else {
            return Err(DbErr::Custom(format!("unexpected resolve lookup tag {tag}")).into());
        };
        if lookup == ResolveLookup::Alias {
            alias_physical_name = Some(row.try_get::<String>("", "name")?);
        }
        found.insert(lookup.tag());
    }
    let found = |lookup: ResolveLookup| found.contains(lookup.tag());

    if let Some(physical_name) = alias_physical_name {
        if found(ResolveLookup::DigestArtifact) {
            return Err(MigrationError::Collision);
        }
        if !found(ResolveLookup::AliasLegacy) || !found(ResolveLookup::AliasArtifact) {
            return Err(MigrationError::MissingLegacyArtifact);
        }
        return Ok(physical_name);
    }
    // A short legacy spelling is reserved even though its N2 digest differs.
    // This makes attempted access to both mapped and unresolved old names an
    // explicit rejection, rather than allowing an apparently empty database.
    if found(ResolveLookup::OldLegacy) && !found(ResolveLookup::OldAlias) {
        return Err(MigrationError::Quarantined);
    }
    if path.is_some_and(|p| !p.contains('/')) && found(ResolveLookup::ShortLegacy) {
        return Err(MigrationError::Quarantined);
    }
    if path.is_none() && found(ResolveLookup::DefaultLegacy) {
        return Err(MigrationError::Quarantined);
    }
    if found(ResolveLookup::DigestLegacy) {
        return Err(MigrationError::Quarantined);
    }
    Ok(digest)
}

/// `resolve` as one statement per lookup, as shipped in 1.20.x. MySQL still
/// uses it, and the single-statement `resolve` is tested against it.
async fn resolve_sequential(
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

    use sea_orm::QueryTrait;

    #[test]
    fn production_inventory_queries_never_select_artifact_payloads() {
        for backend in [
            sea_orm::DatabaseBackend::Postgres,
            sea_orm::DatabaseBackend::Sqlite,
        ] {
            for sql in [
                artifact_identity_query().build(backend).to_string(),
                artifact_name_query("sql", "space", "threads")
                    .build(backend)
                    .to_string(),
                artifact_metadata_query("sql", "space", "threads")
                    .build(backend)
                    .to_string(),
            ] {
                assert!(!sql.contains("\"payload\""), "{sql}");
                assert!(!sql.contains("\"delta_payload\""), "{sql}");
            }
            let sql = artifact_metadata_query("sql", "space", "threads")
                .build(backend)
                .to_string();
            for field in [
                "revision",
                "size_bytes",
                "checkpoint_content_hash",
                "checkpoint_size_bytes",
                "delta_content_hash",
                "delta_size_bytes",
            ] {
                assert!(sql.contains(field), "{sql}");
            }
        }
    }

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
            metadata: None,
            offline_fingerprint: None,
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

    /// `resolve`'s outcome as a comparable value. Every fixture below is
    /// expected to resolve or to fail with one of these three errors.
    fn resolve_outcome(result: Result<String, MigrationError>) -> String {
        match result {
            Ok(name) => format!("ok:{name}"),
            Err(MigrationError::Collision) => "collision".into(),
            Err(MigrationError::MissingLegacyArtifact) => "missing-legacy-artifact".into(),
            Err(MigrationError::Quarantined) => "quarantined".into(),
            Err(other) => panic!("unexpected resolve error: {other:?}"),
        }
    }

    /// Every branch of `resolve`, checked against the statement-per-lookup
    /// oracle and against the outcome each branch is meant to produce. Each
    /// case gets its own space, and unrelated rows in other spaces and
    /// services must not change any outcome.
    async fn assert_resolve_matches_sequential(conn: &DatabaseConnection) {
        let artifact = |service: &str, space: &str, name: &str| database_artifact::ActiveModel {
            service: Set(service.into()),
            space: Set(space.into()),
            name: Set(name.into()),
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
        };
        let legacy =
            |service: &str, space: &str, name: &str| database_legacy_artifact::ActiveModel {
                service: Set(service.into()),
                space: Set(space.into()),
                physical_name: Set(name.into()),
            };
        let alias = |service: &str, space: &str, path: Option<&str>, physical: &str| {
            database_alias::ActiveModel {
                service: Set(service.into()),
                space: Set(space.into()),
                logical_name: Set(logical_name(path)),
                path: Set(path.map(str::to_owned)),
                physical_name: Set(physical.into()),
            }
        };

        enum Row<'a> {
            Artifact(&'a str),
            Legacy(&'a str),
            Alias(Option<&'a str>, &'a str),
        }
        use Row::{Alias, Artifact, Legacy};
        let threads = logical_name(Some("app/threads"));
        let digest_of = |path: Option<&str>| format!("ok:{}", logical_name(path));
        // (case, path, rows in the case's own space, expected outcome)
        let cases: Vec<(&str, Option<&str>, Vec<Row>, String)> = vec![
            (
                "miss",
                Some("app/threads"),
                vec![],
                digest_of(Some("app/threads")),
            ),
            (
                "miss-short",
                Some("threads"),
                vec![],
                digest_of(Some("threads")),
            ),
            ("miss-pathless", None, vec![], "ok:v2n".into()),
            (
                "alias-hit",
                Some("app/threads"),
                vec![
                    Alias(Some("app/threads"), "threads"),
                    Legacy("threads"),
                    Artifact("threads"),
                ],
                "ok:threads".into(),
            ),
            (
                "alias-hit-pathless",
                None,
                vec![
                    Alias(None, "default"),
                    Legacy("default"),
                    Artifact("default"),
                ],
                "ok:default".into(),
            ),
            (
                "alias-collides-with-digest-artifact",
                Some("app/threads"),
                vec![
                    Alias(Some("app/threads"), "threads"),
                    Legacy("threads"),
                    Artifact("threads"),
                    Artifact(&threads),
                ],
                "collision".into(),
            ),
            (
                "alias-without-legacy-row",
                Some("app/threads"),
                vec![Alias(Some("app/threads"), "threads"), Artifact("threads")],
                "missing-legacy-artifact".into(),
            ),
            (
                "alias-without-artifact",
                Some("app/threads"),
                vec![Alias(Some("app/threads"), "threads"), Legacy("threads")],
                "missing-legacy-artifact".into(),
            ),
            (
                // Only the alias for this path counts: another alias's legacy
                // row and artifact do not satisfy it.
                "alias-checks-only-its-own-physical-name",
                Some("app/threads"),
                vec![
                    Alias(Some("app/threads"), "threads"),
                    Alias(Some("other/notes"), "notes"),
                    Legacy("notes"),
                    Artifact("notes"),
                ],
                "missing-legacy-artifact".into(),
            ),
            (
                "alias-collision-is-checked-before-missing-legacy",
                Some("app/threads"),
                vec![Alias(Some("app/threads"), "threads"), Artifact(&threads)],
                "collision".into(),
            ),
            (
                "alias-hit-wins-over-reserved-names",
                Some("app/threads"),
                vec![
                    Alias(Some("app/threads"), "threads"),
                    Legacy("threads"),
                    Artifact("threads"),
                    Legacy(&threads),
                ],
                "ok:threads".into(),
            ),
            (
                "legacy-old-name",
                Some("app/threads"),
                vec![Legacy("threads")],
                "quarantined".into(),
            ),
            (
                "legacy-old-name-aliased-by-another-path",
                Some("app/threads"),
                vec![Legacy("threads"), Alias(Some("other/threads"), "threads")],
                digest_of(Some("app/threads")),
            ),
            (
                "legacy-short-name",
                Some("notes"),
                vec![Legacy("notes")],
                "quarantined".into(),
            ),
            (
                // The old-name check passes (an alias maps "notes"), so only
                // the short-name check can reject it.
                "legacy-short-name-behind-an-aliased-old-name",
                Some("notes"),
                vec![Legacy("notes"), Alias(Some("other/notes"), "notes")],
                "quarantined".into(),
            ),
            (
                "legacy-default",
                None,
                vec![Legacy("default")],
                "quarantined".into(),
            ),
            (
                // Likewise: only the pathless "default" check can reject it.
                "legacy-default-behind-an-aliased-old-name",
                None,
                vec![Legacy("default"), Alias(Some("other/db"), "default")],
                "quarantined".into(),
            ),
            (
                "legacy-default-does-not-reserve-a-path",
                Some("app/threads"),
                vec![Legacy("default")],
                digest_of(Some("app/threads")),
            ),
            (
                "legacy-digest-name",
                Some("app/threads"),
                vec![Legacy(&threads)],
                "quarantined".into(),
            ),
            (
                "case-variant-is-another-name",
                Some("app/threads"),
                vec![Legacy("Threads"), Alias(Some("app/Threads"), "Threads")],
                digest_of(Some("app/threads")),
            ),
        ];

        let mut checked = 0;
        for service in ["sql", "duckdb"] {
            // Rows for every case's names, but in other spaces and the other
            // service: none of them may change an outcome.
            let noise_service = if service == "sql" { "duckdb" } else { "sql" };
            for (index, (_, _, rows, _)) in cases.iter().enumerate() {
                for (noise_service, noise_space) in [
                    (noise_service, format!("{service}-case-{index}")),
                    (service, format!("{service}-noise-{index}")),
                ] {
                    for row in rows {
                        match row {
                            Artifact(name) => artifact(noise_service, &noise_space, name)
                                .insert(conn)
                                .await
                                .map(|_| ()),
                            Legacy(name) => legacy(noise_service, &noise_space, name)
                                .insert(conn)
                                .await
                                .map(|_| ()),
                            Alias(path, physical) => {
                                alias(noise_service, &noise_space, *path, physical)
                                    .insert(conn)
                                    .await
                                    .map(|_| ())
                            }
                        }
                        .unwrap();
                    }
                }
            }
            for (index, (case, path, rows, expected)) in cases.iter().enumerate() {
                let space = format!("{service}-case-{index}");
                // Before the case's own rows exist, both see a plain miss.
                for before in [
                    resolve(conn, service, &space, *path).await,
                    resolve_sequential(conn, service, &space, *path).await,
                ] {
                    assert_eq!(
                        resolve_outcome(before),
                        digest_of(*path),
                        "{service}/{case} before its rows exist"
                    );
                }
                for row in rows {
                    match row {
                        Artifact(name) => artifact(service, &space, name)
                            .insert(conn)
                            .await
                            .map(|_| ()),
                        Legacy(name) => {
                            legacy(service, &space, name).insert(conn).await.map(|_| ())
                        }
                        Alias(path, physical) => alias(service, &space, *path, physical)
                            .insert(conn)
                            .await
                            .map(|_| ()),
                    }
                    .unwrap();
                }
                let single = resolve_outcome(resolve(conn, service, &space, *path).await);
                let sequential =
                    resolve_outcome(resolve_sequential(conn, service, &space, *path).await);
                assert_eq!(single, sequential, "{service}/{case}: single vs sequential");
                assert_eq!(&single, expected, "{service}/{case}");
                checked += 1;
            }
        }
        assert_eq!(checked, 2 * cases.len());

        // DuckDB maps an unsafe name to "default", so its short-name check is
        // the only one that sees the name itself.
        let space = "duckdb-unsafe-short-name";
        legacy("duckdb", space, "a..b").insert(conn).await.unwrap();
        assert_eq!(legacy_name("duckdb", Some("a..b")), "default");
        for result in [
            resolve(conn, "duckdb", space, Some("a..b")).await,
            resolve_sequential(conn, "duckdb", space, Some("a..b")).await,
        ] {
            assert_eq!(resolve_outcome(result), "quarantined");
        }
    }

    #[test]
    fn resolve_query_never_selects_artifact_payloads() {
        use sea_orm::DatabaseBackend;

        for backend in [
            DatabaseBackend::Postgres,
            DatabaseBackend::Sqlite,
            DatabaseBackend::MySql,
        ] {
            for path in [Some("app/threads"), Some("threads"), None] {
                let sql = backend
                    .build(&resolve_query("sql", "space", path))
                    .to_string();
                assert!(!sql.contains("payload"), "{sql}");
                // Alias, digest artifact, the alias's legacy row and artifact, the
                // old name, any alias of the old name, the digest as a legacy
                // name; plus the short name or "default" when they apply.
                let branches = if path == Some("app/threads") { 7 } else { 8 };
                assert_eq!(sql.matches("UNION ALL").count(), branches - 1, "{sql}");
            }
        }
    }

    #[tokio::test]
    async fn single_statement_resolve_matches_sequential_resolve() {
        use sea_orm::Database;
        use sea_orm_migration::MigratorTrait;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let dir = tempfile::tempdir().unwrap();
        let mut conn = Database::connect(format!(
            "sqlite:{}?mode=rwc",
            dir.path().join("caps.db").display()
        ))
        .await
        .unwrap();
        crate::migrations::Migrator::up(&conn, None).await.unwrap();
        assert_resolve_matches_sequential(&conn).await;

        // One statement per resolve, whichever branch decides it: a miss, an
        // alias hit, the short-name check and the pathless "default" check.
        let statements = Arc::new(AtomicUsize::new(0));
        let counter = statements.clone();
        conn.set_metric_callback(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let miss = format!("ok:{}", logical_name(Some("app/threads")));
        for (space, path, expected) in [
            ("sql-case-0", Some("app/threads"), miss.as_str()),
            ("sql-case-3", Some("app/threads"), "ok:threads"),
            ("sql-case-14", Some("notes"), "quarantined"),
            ("sql-case-16", None, "quarantined"),
        ] {
            let before = statements.load(Ordering::SeqCst);
            let outcome = resolve_outcome(resolve(&conn, "sql", space, path).await);
            assert_eq!(statements.load(Ordering::SeqCst) - before, 1, "{space}");
            assert_eq!(outcome, expected, "{space}");
        }
    }

    #[tokio::test]
    async fn postgres_single_statement_resolve_matches_sequential_resolve() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_single_statement_resolve_matches_sequential_resolve",
        )
        .await
        else {
            return;
        };
        assert_resolve_matches_sequential(&fixture.conn).await;
    }
}
