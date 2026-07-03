use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use tinycloud_auth::resource::SpaceId;
use tokio::sync::RwLock;

use crate::database_artifacts::{
    DatabaseArtifact, DatabaseArtifactError, DatabaseArtifactRepository,
};

/// Process-local mirror of durable SQL artifact sizes, keyed by space then
/// (service, db-name). Read on the hot path by `SpaceDatabase::store_size`;
/// updated on every artifact save by `SizeTrackingArtifactRepository`.
/// Single-instance assumption (same as `SpaceSizes`): the SQLite deploy is a
/// single writer, the Postgres compose runs one node container.
#[derive(Debug, Clone, Default)]
#[allow(clippy::type_complexity)]
pub struct SqlSizes(Arc<RwLock<HashMap<String, HashMap<(String, String), u64>>>>);

impl SqlSizes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Boot seed: one SELECT of (service, space, name, size_bytes) — NOT payload.
    /// INSTANCE method (not a constructor) so the handle is wired into the
    /// decorator + SpaceDatabase BEFORE migrations run, then populated AFTER
    /// `TinyCloud::new` (which runs `Migrator::up`, db.rs:142) has created the
    /// `database_artifact` table. A constructor that SELECTs before migrations
    /// would hit a nonexistent table and fail boot on a fresh datadir.
    pub async fn seed_from(
        &self,
        conn: &sea_orm::DatabaseConnection,
    ) -> Result<(), sea_orm::DbErr> {
        use crate::models::database_artifact::{Column, Entity};
        use sea_orm::{EntityTrait, QuerySelect};
        let rows: Vec<(String, String, String, i64)> = Entity::find()
            .select_only()
            .column(Column::Service)
            .column(Column::Space)
            .column(Column::Name)
            .column(Column::SizeBytes)
            .into_tuple()
            .all(conn)
            .await?;
        let mut fresh: HashMap<String, HashMap<(String, String), u64>> = HashMap::new();
        for (service, space, name, size) in rows {
            fresh
                .entry(space)
                .or_default()
                .insert((service, name), size.max(0) as u64);
        }
        *self.0.write().await = fresh; // overwrite the map wholesale with DB truth
        Ok(())
    }

    /// Overwrite (not accumulate) the size for one (service, space, db-name).
    pub async fn update(&self, service: &str, space: &str, name: &str, size_bytes: u64) {
        self.0
            .write()
            .await
            .entry(space.to_string())
            .or_default()
            .insert((service.to_string(), name.to_string()), size_bytes);
    }

    /// Sum of all SQL/DuckDB artifact bytes for a space (0 if none).
    pub async fn space_total(&self, space: &SpaceId) -> u64 {
        self.0
            .read()
            .await
            .get(&space.to_string())
            .map(|inner| inner.values().sum())
            .unwrap_or(0)
    }
}

/// Decorator over a [`DatabaseArtifactRepository`] that records the size of
/// every saved artifact into a shared [`SqlSizes`] map (overwrite-on-save,
/// mirroring the repository's one-row-per-(service, space, db-name) truth).
///
/// Metering correctness depends on a single instance wrapping the ONE
/// repository that all SQL/DuckDB services share: saves that bypass this
/// decorator are invisible to `store_size` until the next `seed_from`.
pub struct SizeTrackingArtifactRepository {
    inner: Arc<dyn DatabaseArtifactRepository>,
    sizes: SqlSizes,
}

impl SizeTrackingArtifactRepository {
    /// Wrap `inner`, recording sizes into `sizes` on every successful save.
    pub fn new(inner: Arc<dyn DatabaseArtifactRepository>, sizes: SqlSizes) -> Self {
        Self { inner, sizes }
    }
}

#[async_trait]
impl DatabaseArtifactRepository for SizeTrackingArtifactRepository {
    async fn load(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError> {
        self.inner.load(service, space, name).await
    }

    async fn save(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
        let artifact = self.inner.save(service, space, name, payload).await?;
        self.sizes
            .update(service, space, name, artifact.size_bytes.max(0) as u64)
            .await;
        Ok(artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database_artifacts::SeaOrmDatabaseArtifactRepository,
        migrations::Migrator,
        sea_orm::{ConnectOptions, Database},
        sea_orm_migration::MigratorTrait,
    };
    use tinycloud_auth::{
        resolver::DID_METHODS,
        ssi::{dids::DIDBuf, jwk::JWK},
    };

    fn test_space_id(name: &str) -> SpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, name.parse().unwrap())
    }

    async fn migrated_repo() -> (
        SeaOrmDatabaseArtifactRepository,
        sea_orm::DatabaseConnection,
    ) {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        (SeaOrmDatabaseArtifactRepository::new(conn.clone()), conn)
    }

    #[tokio::test]
    async fn sql_sizes_update_overwrites_not_accumulates() {
        let space = test_space_id("overwrite");
        let key = space.to_string();
        let sizes = SqlSizes::new();
        sizes.update("sql", &key, "a", 100).await;
        sizes.update("sql", &key, "a", 250).await;
        assert_eq!(sizes.space_total(&space).await, 250);
    }

    #[tokio::test]
    async fn sql_sizes_space_total_sums_services() {
        let space = test_space_id("sums");
        let other = test_space_id("other");
        let key = space.to_string();
        let sizes = SqlSizes::new();
        sizes.update("sql", &key, "threads", 100).await;
        sizes.update("duckdb", &key, "analytics", 40).await;
        assert_eq!(sizes.space_total(&space).await, 140);
        assert_eq!(sizes.space_total(&other).await, 0);
    }

    #[tokio::test]
    async fn size_tracking_repo_records_on_save() {
        let (raw, _conn) = migrated_repo().await;
        let sizes = SqlSizes::new();
        let repo = SizeTrackingArtifactRepository::new(Arc::new(raw), sizes.clone());
        let space = test_space_id("records");
        let key = space.to_string();
        const N: usize = 4096;
        repo.save("sql", &key, "main", vec![0u8; N]).await.unwrap();
        assert_eq!(sizes.space_total(&space).await, N as u64);
    }

    #[tokio::test]
    async fn sql_sizes_seed_from_reads_existing_rows() {
        let (raw, conn) = migrated_repo().await;
        let space = test_space_id("seed");
        let key = space.to_string();
        let first = 128usize;
        let second = 256usize;
        raw.save("sql", &key, "one", vec![0u8; first])
            .await
            .unwrap();
        raw.save("sql", &key, "two", vec![0u8; second])
            .await
            .unwrap();

        let sizes = SqlSizes::new();
        sizes.seed_from(&conn).await.unwrap();
        assert_eq!(sizes.space_total(&space).await, (first + second) as u64);

        // Wholesale-overwrite semantics: a larger revision of one db, re-seed.
        let third = 1024usize;
        raw.save("sql", &key, "one", vec![0u8; third])
            .await
            .unwrap();
        sizes.seed_from(&conn).await.unwrap();
        assert_eq!(sizes.space_total(&space).await, (third + second) as u64);
    }
}
