//! Shared fixtures for the store-master tests (TC-1491 P4.2a).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use tinycloud_auth::resource::SpaceId;
use tinycloud_auth::{
    resolver::DID_METHODS,
    ssi::{dids::DIDBuf, jwk::JWK},
};

use super::{init_working_copy, ControlModeGate};
use crate::database_artifacts::SeaOrmDatabaseArtifactRepository;
use crate::migrations::Migrator;
use crate::sql::durability::DurabilityPolicy;
use crate::sql::service::SqlService;
use crate::sql::store::key::DbRef;
use crate::sql::store::mode::{transition_row, Expected, StoreMode};
use crate::sql::store::shadow::{LocalNotice, Notice, ShadowSink};
use crate::sql::types::{SqlError, SqlExecutionResult, SqlRequest, SqlResponse, SqlValue};

pub(crate) const DB: &str = "main";

pub(crate) fn space_id(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap()).unwrap()
}

/// A recording sink for the commit notices.
#[derive(Default)]
pub(crate) struct ProbeSink {
    notices: Mutex<Vec<LocalNotice>>,
}

impl ProbeSink {
    pub(crate) fn notices(&self) -> Vec<LocalNotice> {
        self.notices.lock().unwrap().clone()
    }
}

impl ShadowSink for ProbeSink {
    fn notify(&self, _notice: Notice) {}
    fn notify_local(&self, notice: LocalNotice) {
        self.notices.lock().unwrap().push(notice);
    }
}

/// A temp base directory, a control database and one space.
pub(crate) struct Rig {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) space: SpaceId,
    pub(crate) control: DatabaseConnection,
    pub(crate) repo: Arc<SeaOrmDatabaseArtifactRepository>,
}

impl Rig {
    pub(crate) async fn new(name: &str) -> Self {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        let control = Database::connect(options).await.unwrap();
        Migrator::up(&control, None).await.unwrap();
        Self {
            dir: tempfile::tempdir().unwrap(),
            space: space_id(name),
            repo: Arc::new(SeaOrmDatabaseArtifactRepository::new(control.clone())),
            control,
        }
    }

    pub(crate) fn base(&self) -> String {
        self.dir.path().to_string_lossy().into_owned()
    }

    pub(crate) fn main_path(&self) -> PathBuf {
        self.dir
            .path()
            .join(self.space.to_string())
            .join(format!("{DB}.db"))
    }

    pub(crate) fn wal_path(&self) -> PathBuf {
        PathBuf::from(format!("{}-wal", self.main_path().display()))
    }

    /// A local database `items (v TEXT NOT NULL)` carrying the counter at
    /// `start_seq`, as the cutover would leave it.
    pub(crate) fn create_working_copy(&self, start_seq: u64) {
        let path = self.main_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "journal_mode", "wal").unwrap();
            conn.execute_batch("CREATE TABLE items (v TEXT NOT NULL)")
                .unwrap();
        }
        init_working_copy(&path, start_seq).unwrap();
    }

    /// The mode row, through the real transitions, ending in `store_master`.
    pub(crate) async fn make_store_master(&self) {
        let space = self.space.to_string();
        let db = DbRef {
            space: &space,
            db_id: DB,
        };
        let mut epoch = transition_row(&self.control, &db, None, StoreMode::Shadow, None)
            .await
            .unwrap();
        epoch = transition_row(
            &self.control,
            &db,
            Some(Expected {
                mode: StoreMode::Shadow,
                epoch,
            }),
            StoreMode::CuttingOver,
            None,
        )
        .await
        .unwrap();
        transition_row(
            &self.control,
            &db,
            Some(Expected {
                mode: StoreMode::CuttingOver,
                epoch,
            }),
            StoreMode::StoreMaster,
            Some("node-a"),
        )
        .await
        .unwrap();
    }

    pub(crate) fn gate(&self) -> Arc<ControlModeGate> {
        Arc::new(ControlModeGate::new(self.control.clone()))
    }

    /// A service that serves the rig's store-master database from its local
    /// file.
    pub(crate) fn service(
        &self,
        sink: Arc<dyn ShadowSink>,
        policy: DurabilityPolicy,
    ) -> SqlService {
        SqlService::new(self.base(), 0, self.repo.clone())
            .with_durability(policy)
            .with_shadow(sink)
            .with_store_master_gate(self.gate())
    }
}

pub(crate) async fn run(
    service: &SqlService,
    space: &SpaceId,
    sql: &str,
) -> Result<SqlExecutionResult, SqlError> {
    service
        .execute(
            space,
            DB,
            SqlRequest::Execute {
                sql: sql.to_owned(),
                params: vec![],
                schema: None,
            },
            None,
            "tinycloud.sql/admin".into(),
        )
        .await
}

pub(crate) async fn insert(
    service: &SqlService,
    space: &SpaceId,
    value: &str,
) -> Result<SqlExecutionResult, SqlError> {
    run(
        service,
        space,
        &format!("INSERT INTO items (v) VALUES ('{value}')"),
    )
    .await
}

pub(crate) async fn query(
    service: &SqlService,
    space: &SpaceId,
    sql: &str,
) -> Result<Vec<Vec<SqlValue>>, SqlError> {
    let result = service
        .execute(
            space,
            DB,
            SqlRequest::Query {
                sql: sql.to_owned(),
                params: vec![],
                max_rows: None,
                max_bytes: None,
            },
            None,
            "tinycloud.sql/admin".into(),
        )
        .await?;
    match result.response {
        SqlResponse::Query(q) => Ok(q.rows),
        other => panic!("not a query response: {other:?}"),
    }
}

pub(crate) async fn count(service: &SqlService, space: &SpaceId) -> i64 {
    match &query(service, space, "SELECT count(*) FROM items")
        .await
        .unwrap()[0][0]
    {
        SqlValue::Integer(n) => *n,
        other => panic!("not an integer: {other:?}"),
    }
}
