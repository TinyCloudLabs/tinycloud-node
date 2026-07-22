use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{hash::hash, models::database_artifact};

#[derive(Debug, Clone)]
pub struct DatabaseArtifact {
    pub payload: Vec<u8>,
    pub content_hash: String,
    pub revision: i64,
    pub size_bytes: i64,
    pub updated_at: String,
    pub backend: String,
    pub storage_mode: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DatabaseArtifactError {
    #[error("database artifact storage error: {0}")]
    Db(#[from] DbErr),
    #[error("database artifact payload too large: {0} bytes")]
    PayloadTooLarge(u64),
    #[error("database artifact backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait DatabaseArtifactRepository: Send + Sync {
    async fn load(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError>;

    async fn save(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError>;
}

#[derive(Clone)]
pub struct SeaOrmDatabaseArtifactRepository {
    conn: DatabaseConnection,
}

impl SeaOrmDatabaseArtifactRepository {
    pub fn new(conn: DatabaseConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl DatabaseArtifactRepository for SeaOrmDatabaseArtifactRepository {
    async fn load(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError> {
        load_artifact(&self.conn, service, space, name).await
    }

    async fn save(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
        save_artifact(&self.conn, service, space, name, payload).await
    }
}

/// Transaction-aware artifact load: identical semantics to
/// [`DatabaseArtifactRepository::load`], generic over any [`ConnectionTrait`]
/// (a plain `DatabaseConnection` OR a `DatabaseTransaction`). Extracted as a
/// free function (compute-service-implementation-plan.md P1: "the transaction
/// seam is a core primitive, not a service-module change") so the compute
/// deploy path can read/write artifacts inside the SAME SeaORM transaction
/// that persists `D_fn`, instead of going through the trait object that owns
/// its own standalone `DatabaseConnection`.
pub async fn load_artifact<C: ConnectionTrait>(
    conn: &C,
    service: &str,
    space: &str,
    name: &str,
) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError> {
    database_artifact::Entity::find_by_id((
        service.to_string(),
        space.to_string(),
        name.to_string(),
    ))
    .one(conn)
    .await
    .map(|row| {
        row.map(|model| DatabaseArtifact {
            payload: model.payload,
            content_hash: model.content_hash,
            revision: model.revision,
            size_bytes: model.size_bytes,
            updated_at: model.updated_at,
            backend: model.backend,
            storage_mode: model.storage_mode,
        })
    })
    .map_err(DatabaseArtifactError::Db)
}

/// Transaction-aware artifact save: identical semantics to
/// [`DatabaseArtifactRepository::save`] (content-addressed identity,
/// `(service, space, name)`-keyed revision bump, payload REPLACES the prior
/// row), generic over any [`ConnectionTrait`]. See [`load_artifact`] for why
/// this is a free function rather than a trait method.
pub async fn save_artifact<C: ConnectionTrait>(
    conn: &C,
    service: &str,
    space: &str,
    name: &str,
    payload: Vec<u8>,
) -> Result<DatabaseArtifact, DatabaseArtifactError> {
    let size_bytes = i64::try_from(payload.len())
        .map_err(|_| DatabaseArtifactError::PayloadTooLarge(payload.len() as u64))?;
    let content_hash = hash(&payload).to_cid(0x55).to_string();
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current timestamps should format as RFC3339");

    let existing = database_artifact::Entity::find_by_id((
        service.to_string(),
        space.to_string(),
        name.to_string(),
    ))
    .one(conn)
    .await?;

    let revision = existing
        .as_ref()
        .map(|model| model.revision + 1)
        .unwrap_or(1);
    let created_at = existing
        .as_ref()
        .map(|model| model.created_at.clone())
        .unwrap_or_else(|| now.clone());

    let active = database_artifact::ActiveModel {
        service: Set(service.to_string()),
        space: Set(space.to_string()),
        name: Set(name.to_string()),
        revision: Set(revision),
        content_hash: Set(content_hash.clone()),
        payload: Set(payload.clone()),
        size_bytes: Set(size_bytes),
        backend: Set("storage.database".to_string()),
        storage_mode: Set("database-blob".to_string()),
        created_at: Set(created_at),
        updated_at: Set(now.clone()),
    };

    let model = if existing.is_some() {
        active.update(conn).await?
    } else {
        active.insert(conn).await?
    };

    Ok(DatabaseArtifact {
        payload,
        content_hash,
        revision: model.revision,
        size_bytes: model.size_bytes,
        updated_at: model.updated_at,
        backend: model.backend,
        storage_mode: model.storage_mode,
    })
}
