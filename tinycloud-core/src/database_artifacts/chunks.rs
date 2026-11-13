//! Opt-in checkpoint persistence with bounded statements and immutable parts.
use super::*;
use rand::RngCore;
use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
use tinycloud_auth::resource::SpaceId;
use tokio::io::AsyncReadExt;

pub const CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct ChunkLimits {
    pub artifact_bytes: u64,
    pub account_bytes: u64,
}

fn statement(sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}

const REAP_CANDIDATE: &str = "SELECT service,space,name,part_id FROM artifact_part p WHERE state<>'published' AND lease_until<=statement_timestamp() AND NOT EXISTS(SELECT 1 FROM database_artifact d WHERE d.service=p.service AND d.space=p.space AND d.name=p.name AND (d.checkpoint_part_id=p.part_id OR d.delta_part_id=p.part_id)) ORDER BY lease_until LIMIT 1";
const OWNER_REAP_CANDIDATE: &str = "SELECT service,space,name,part_id FROM artifact_part p WHERE owner=$1 AND state<>'published' AND lease_until<=statement_timestamp() AND NOT EXISTS(SELECT 1 FROM database_artifact d WHERE d.service=p.service AND d.space=p.space AND d.name=p.name AND (d.checkpoint_part_id=p.part_id OR d.delta_part_id=p.part_id)) ORDER BY lease_until LIMIT 1";

impl SeaOrmDatabaseArtifactRepository {
    pub(super) async fn ensure_legacy_write(
        &self,
        service: &str,
        _space: &str,
        _name: &str,
    ) -> Result<(), DatabaseArtifactError> {
        if self.conn.get_database_backend() != DbBackend::Postgres {
            return Ok(());
        }
        if self.chunk_limits.is_some() && service == "sql" {
            return Err(DatabaseArtifactError::IncrementalPersistenceUnsupported);
        }
        Ok(())
    }

    pub async fn configure_chunked_storage(&self) -> Result<(), DatabaseArtifactError> {
        if let Some(limits) = self.chunk_limits {
            self.conn
                .execute(statement(
                    "SELECT artifact_enable($1,$2)",
                    vec![
                        (limits.account_bytes.min(i64::MAX as u64) as i64).into(),
                        (limits.artifact_bytes.min(i64::MAX as u64) as i64).into(),
                    ],
                ))
                .await?;
        }
        Ok(())
    }

    pub async fn chunk_storage_active(&self) -> Result<bool, DatabaseArtifactError> {
        if self.conn.get_database_backend() != DbBackend::Postgres {
            return Ok(false);
        }
        Ok(self
            .conn
            .query_one(statement(
                "SELECT account_limit>0 AS active FROM artifact_storage_settings WHERE id=1",
                vec![],
            ))
            .await?
            .is_some_and(|row| row.try_get::<bool>("", "active").unwrap_or(false)))
    }

    /// Each call frees at most one payload chunk per statement. Selection is
    /// advisory; the database rechecks pointers and takes the owner/part locks.
    pub async fn reap_unused_parts(&self, max_steps: usize) -> Result<(), DatabaseArtifactError> {
        self.reap_parts(None, max_steps).await
    }

    async fn reap_owner_best_effort(&self, owner: &str) {
        // A request never pays another owner's cleanup bill. The background
        // collector completes larger passes independently of request success.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            self.reap_parts(Some(owner), 16),
        )
        .await;
    }

    async fn reap_parts(
        &self,
        owner: Option<&str>,
        max_steps: usize,
    ) -> Result<(), DatabaseArtifactError> {
        for _ in 0..max_steps {
            let candidate = match owner {
                Some(owner) => statement(OWNER_REAP_CANDIDATE, vec![owner.into()]),
                None => statement(REAP_CANDIDATE, vec![]),
            };
            let Some(row) = self.conn.query_one(candidate).await? else {
                break;
            };
            let values = vec![
                row.try_get::<String>("", "service")?.into(),
                row.try_get::<String>("", "space")?.into(),
                row.try_get::<String>("", "name")?.into(),
                row.try_get::<String>("", "part_id")?.into(),
            ];
            let row = self
                .conn
                .query_one(statement(
                    "SELECT artifact_reap_one($1,$2,$3,$4) AS progress",
                    values,
                ))
                .await?
                .ok_or(DatabaseArtifactError::ArtifactChanged)?;
            // Another collector can finish the selected part first. A fresh
            // candidate query must still reach the rest of this bounded pass.
            let _progress = row.try_get::<bool>("", "progress")?;
        }
        Ok(())
    }

    pub(super) async fn write_chunk_snapshot(
        &self,
        service: &str,
        space: &str,
        name: &str,
        snapshot: tempfile::NamedTempFile,
        expected: ArtifactExpectation,
    ) -> Result<ArtifactMeta, DatabaseArtifactError> {
        if self.conn.get_database_backend() != DbBackend::Postgres {
            return Err(DatabaseArtifactError::IncrementalPersistenceUnsupported);
        }
        let limits = match self.chunk_limits {
            Some(limits) => limits,
            None => {
                let row=self.conn.query_one(statement("SELECT account_limit,artifact_limit FROM artifact_storage_settings WHERE id=1",vec![]))
                    .await?.ok_or(DatabaseArtifactError::IncrementalPersistenceUnsupported)?;
                ChunkLimits {
                    artifact_bytes: row.try_get::<i64>("", "artifact_limit")?.max(0) as u64,
                    account_bytes: row.try_get::<i64>("", "account_limit")?.max(0) as u64,
                }
            }
        };
        let size = snapshot.as_file().metadata().map_err(io_error)?.len();
        if limits.artifact_bytes == 0
            || limits.account_bytes == 0
            || size > limits.artifact_bytes
            || size > i64::MAX as u64
        {
            return Err(DatabaseArtifactError::StorageLimit);
        }
        self.check_write(size.min(CHUNK_BYTES as u64) as usize)?;
        let space_id: SpaceId = space
            .parse()
            .map_err(|_| DatabaseArtifactError::Backend("invalid artifact space".into()))?;
        let owner = space_id.did().to_string();
        self.configure_chunked_storage().await?;
        self.reap_owner_best_effort(&owner).await;
        let current = self.load_meta(service, space, name).await?;
        expected.check(
            current
                .as_ref()
                .map(|m| (m.revision, m.checkpoint_content_hash.as_str())),
        )?;
        let mut random = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let part_id = hex::encode(random);
        let count = i32::try_from(size.div_ceil(CHUNK_BYTES as u64))
            .map_err(|_| DatabaseArtifactError::StorageLimit)?;
        self.conn
            .execute(statement(
                "INSERT INTO artifact_account(owner) VALUES($1) ON CONFLICT DO NOTHING",
                vec![owner.clone().into()],
            ))
            .await?;
        let mut cleanup = UploadCleanup {
            repo: self.clone(),
            service: service.into(),
            space: space.into(),
            name: name.into(),
            part_id: part_id.clone(),
            armed: true,
        };
        let reserved = self
            .conn
            .query_one(statement(
                "SELECT artifact_reserve($1,$2,$3,$4,$5,$6,$7,$8,$9) AS admitted",
                vec![
                    service.into(),
                    space.into(),
                    name.into(),
                    part_id.clone().into(),
                    owner.clone().into(),
                    (size as i64).into(),
                    count.into(),
                    current.as_ref().map(|m| m.revision).into(),
                    current
                        .as_ref()
                        .map(|m| m.checkpoint_content_hash.clone())
                        .into(),
                ],
            ))
            .await?
            .ok_or(DatabaseArtifactError::ArtifactChanged)?;
        if !reserved.try_get::<bool>("", "admitted")? {
            cleanup.armed = false;
            return Err(DatabaseArtifactError::StorageLimit);
        }

        let mut file = tokio::fs::File::open(snapshot.path())
            .await
            .map_err(io_error)?;
        let mut buffer = vec![0u8; CHUNK_BYTES];
        let mut hasher = Blake3Hasher::new();
        let mut total = 0u64;
        let mut ordinal = 0i32;
        loop {
            let mut used = 0;
            while used < buffer.len() {
                let n = file.read(&mut buffer[used..]).await.map_err(io_error)?;
                if n == 0 {
                    break;
                }
                used += n;
            }
            if used == 0 {
                break;
            }
            total += used as u64;
            if total > size {
                return Err(DatabaseArtifactError::StorageLimit);
            }
            hasher.update(&buffer[..used]);
            self.conn.execute(statement(
                "WITH lease AS (UPDATE artifact_part SET lease_until=clock_timestamp()+interval '120 seconds' WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND state='uploading' RETURNING part_id) INSERT INTO artifact_chunk(service,space,name,part_id,ordinal,payload) SELECT $1,$2,$3,$4,$5,$6 FROM lease",
                vec![service.into(),space.into(),name.into(),part_id.clone().into(),ordinal.into(),buffer[..used].to_vec().into()],
            )).await?;
            ordinal += 1;
        }
        if total != size || ordinal != count {
            return Err(DatabaseArtifactError::SizeMismatch {
                part: "checkpoint",
                expected: size,
                actual: total,
            });
        }
        let cid = hasher.finalize().to_cid(0x55).to_string();
        let sealed = self
            .conn
            .execute(statement(
                r#"
UPDATE artifact_part p SET state='sealed',content_hash=$5
WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND state='uploading'
 AND (SELECT count(*) FROM artifact_chunk c WHERE
 (c.service,c.space,c.name,c.part_id)=(p.service,p.space,p.name,p.part_id))=p.chunk_count
 AND (SELECT COALESCE(sum(octet_length(payload)),0) FROM artifact_chunk c WHERE
 (c.service,c.space,c.name,c.part_id)=(p.service,p.space,p.name,p.part_id))=p.size_bytes
"#,
                vec![
                    service.into(),
                    space.into(),
                    name.into(),
                    part_id.clone().into(),
                    cid.clone().into(),
                ],
            ))
            .await?;
        if sealed.rows_affected() != 1 {
            return Err(DatabaseArtifactError::ArtifactChanged);
        }
        let revision = current.as_ref().map_or(1, |m| m.revision + 1);
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("timestamp");
        let mut values: Vec<Value> = vec![
            service.into(),
            space.into(),
            name.into(),
            part_id.clone().into(),
            revision.into(),
            cid.clone().into(),
            (size as i64).into(),
            now.clone().into(),
        ];
        #[cfg(test)]
        if let Some(barrier) = &self.chunk_publish_barrier {
            barrier.wait().await;
        }
        // One metadata-only statement is the acknowledgement boundary. Parts
        // are already durable and sealed; no transaction spans the transfer.
        let sql = if let Some(previous) = current {
            values.extend([
                previous.revision.into(),
                previous.checkpoint_content_hash.into(),
            ]);
            r#"WITH owner_lock AS MATERIALIZED (SELECT owner FROM artifact_account
 WHERE owner=(SELECT owner FROM artifact_part WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4) FOR UPDATE),
 ready AS (SELECT p.part_id FROM artifact_part p CROSS JOIN owner_lock
 WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND state='sealed' FOR UPDATE OF p)
UPDATE database_artifact SET checkpoint_part_id=$4,delta_part_id=NULL,
 revision=$5,content_hash=$6,checkpoint_content_hash=$6,size_bytes=$7,
 checkpoint_size_bytes=$7,payload=''::bytea,delta_payload=NULL,
 delta_content_hash=NULL,delta_size_bytes=0,storage_mode='checkpoint-parts-v1',
 layout_generation=layout_generation+1,updated_at=$8
WHERE service=$1 AND space=$2 AND name=$3 AND revision=$9 AND checkpoint_content_hash=$10
 AND EXISTS(SELECT 1 FROM ready)"#
        } else {
            r#"WITH owner_lock AS MATERIALIZED (SELECT owner FROM artifact_account
 WHERE owner=(SELECT owner FROM artifact_part WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4) FOR UPDATE),
 ready AS (SELECT p.part_id FROM artifact_part p CROSS JOIN owner_lock
 WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND state='sealed' FOR UPDATE OF p)
INSERT INTO database_artifact(service,space,name,checkpoint_part_id,revision,content_hash,
 checkpoint_content_hash,size_bytes,checkpoint_size_bytes,payload,backend,storage_mode,
 created_at,updated_at,delta_size_bytes,layout_generation)
SELECT $1,$2,$3,$4,$5,$6,$6,$7,$7,''::bytea,'storage.database','checkpoint-parts-v1',$8,$8,0,1
FROM ready ON CONFLICT DO NOTHING"#
        };
        if self
            .conn
            .execute(statement(sql, values))
            .await?
            .rows_affected()
            != 1
        {
            return Err(DatabaseArtifactError::StaleLineage);
        }
        cleanup.armed = false;
        // Reclamation is outside the publish statement. If this pass cannot
        // finish, the periodic collector keeps the bytes charged until freed.
        #[cfg(test)]
        let reclaim = !self.chunk_reclaim_paused;
        #[cfg(not(test))]
        let reclaim = true;
        if reclaim {
            self.reap_owner_best_effort(&owner).await;
        }
        Ok(ArtifactMeta {
            revision,
            size_bytes: size as i64,
            content_hash: cid.clone(),
            checkpoint_content_hash: cid,
            checkpoint_size_bytes: size as i64,
            delta_content_hash: None,
            delta_size_bytes: 0,
            updated_at: now,
            storage_mode: "checkpoint-parts-v1".into(),
            backend: "storage.database".into(),
        })
    }

    pub(super) async fn read_chunk_layout(
        &self,
        service: &str,
        space: &str,
        name: &str,
        meta: &ArtifactMeta,
        sink: &mut dyn ArtifactSink,
    ) -> Result<bool, DatabaseArtifactError> {
        if self.conn.get_database_backend() != DbBackend::Postgres
            || meta.storage_mode != "checkpoint-parts-v1"
        {
            return Ok(false);
        }
        // Parts stream in bounded statements, so the single-row read cap does
        // not apply. A sink that keeps the whole artifact in memory still
        // holds it all at once, like a single-row read (TC-2961).
        let _large = if sink.buffers_in_memory() {
            let total = u64::try_from(
                meta.checkpoint_size_bytes
                    .saturating_add(meta.delta_size_bytes),
            )
            .unwrap_or(0);
            self.large_transfer_permit(total).await
        } else {
            None
        };
        let row=self.conn.query_one(statement(
            "SELECT checkpoint_part_id,delta_part_id,revision,checkpoint_content_hash,layout_generation FROM database_artifact WHERE service=$1 AND space=$2 AND name=$3",
            vec![service.into(),space.into(),name.into()],
        )).await?.ok_or(DatabaseArtifactError::ArtifactChanged)?;
        let generation: i64 = row.try_get("", "layout_generation")?;
        let part: Option<String> = row.try_get("", "checkpoint_part_id")?;
        let Some(part) = part else { return Ok(false) };
        if row.try_get::<i64>("", "revision")? != meta.revision
            || row.try_get::<String>("", "checkpoint_content_hash")? != meta.checkpoint_content_hash
        {
            return Err(DatabaseArtifactError::ArtifactChanged);
        }
        if row
            .try_get::<Option<String>>("", "delta_part_id")?
            .is_some()
            || meta.has_delta()
        {
            return Err(DatabaseArtifactError::IncrementalPersistenceUnsupported);
        }
        let manifest=self.conn.query_one(statement(
            "SELECT size_bytes,chunk_count,content_hash FROM artifact_part WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND state='published'",
            vec![service.into(),space.into(),name.into(),part.clone().into()],
        )).await?.ok_or(DatabaseArtifactError::ArtifactChanged)?;
        let size = manifest.try_get::<i64>("", "size_bytes")?;
        let count = manifest.try_get::<i32>("", "chunk_count")?;
        let cid = manifest.try_get::<String>("", "content_hash")?;
        if size != meta.checkpoint_size_bytes
            || cid != meta.checkpoint_content_hash
            || size < 0
            || count as u64 != (size as u64).div_ceil(CHUNK_BYTES as u64)
        {
            return Err(DatabaseArtifactError::ArtifactChanged);
        }
        sink.begin_part(ArtifactPart::Checkpoint).await?;
        sink.size_hint(ArtifactPart::Checkpoint, size as u64);
        let mut hasher = Blake3Hasher::new();
        let mut total = 0u64;
        for ordinal in 0..count {
            let row=self.conn.query_one(statement(
                "SELECT payload FROM artifact_chunk WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND ordinal=$5",
                vec![service.into(),space.into(),name.into(),part.clone().into(),ordinal.into()],
            )).await?.ok_or(DatabaseArtifactError::ArtifactChanged)?;
            let bytes: Vec<u8> = row.try_get("", "payload")?;
            let expected = (size as u64 - total).min(CHUNK_BYTES as u64);
            if bytes.len() as u64 != expected {
                return Err(DatabaseArtifactError::SizeMismatch {
                    part: "checkpoint",
                    expected,
                    actual: bytes.len() as u64,
                });
            }
            hasher.update(&bytes);
            sink.write(&bytes).await?;
            total += bytes.len() as u64;
        }
        if hasher.finalize().to_cid(0x55).to_string() != cid || cid != meta.content_hash {
            tracing::warn!(
                event = "artifact_part_hash_mismatch",
                "Artifact part integrity check failed"
            );
            return Err(DatabaseArtifactError::HashMismatch { part: "checkpoint" });
        }
        let unchanged=self.conn.query_one(statement(
            "SELECT 1 AS present FROM database_artifact WHERE service=$1 AND space=$2 AND name=$3 AND revision=$4 AND checkpoint_content_hash=$5 AND checkpoint_part_id=$6 AND layout_generation=$7",
            vec![service.into(),space.into(),name.into(),meta.revision.into(),cid.into(),part.into(),generation.into()],
        )).await?.is_some();
        if !unchanged {
            return Err(DatabaseArtifactError::ArtifactChanged);
        };
        sink.finish_part().await?;
        Ok(true)
    }
}

struct UploadCleanup {
    repo: SeaOrmDatabaseArtifactRepository,
    service: String,
    space: String,
    name: String,
    part_id: String,
    armed: bool,
}
impl Drop for UploadCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let repo = self.repo.clone();
        let values: Vec<Value> = vec![
            self.service.clone().into(),
            self.space.clone().into(),
            self.name.clone().into(),
            self.part_id.clone().into(),
        ];
        runtime.spawn(async move {
            // Publication may have committed despite a lost response: the
            // database checks references before permitting any deletion.
            for _ in 0..2048 {
                let Ok(Some(row)) = repo
                    .conn
                    .query_one(statement(
                        "SELECT artifact_reap_one($1,$2,$3,$4,true) AS progress",
                        values.clone(),
                    ))
                    .await
                else {
                    break;
                };
                if row.try_get::<bool>("", "progress").ok() != Some(true) {
                    break;
                }
            }
        });
    }
}

fn io_error(error: std::io::Error) -> DatabaseArtifactError {
    DatabaseArtifactError::Sink(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn snapshot(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    #[tokio::test]
    async fn postgres_chunked_checkpoint_owner_reservations_and_integrity() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_owner_reservations_and_integrity",
        )
        .await
        else {
            return;
        };
        let first = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:one";
        let second = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:two";
        let legacy = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone());
        legacy
            .save(
                "sql",
                first,
                "legacy",
                vec![1; 128],
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let repo = legacy.clone().with_chunk_limits(Some(ChunkLimits {
            artifact_bytes: CHUNK_BYTES as u64,
            account_bytes: (CHUNK_BYTES + 128) as u64,
        }));
        let payload = vec![7; CHUNK_BYTES];
        let (a, b) = tokio::join!(
            repo.save_snapshot(
                "sql",
                first,
                "main",
                snapshot(&payload),
                ArtifactExpectation::Absent
            ),
            repo.save_snapshot(
                "sql",
                second,
                "main",
                snapshot(&payload),
                ArtifactExpectation::Absent
            ),
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        let (space, meta) = match (a, b) {
            (Ok(meta), Err(DatabaseArtifactError::StorageLimit)) => (first, meta),
            (Err(DatabaseArtifactError::StorageLimit), Ok(meta)) => (second, meta),
            other => panic!("unexpected {other:?}"),
        };
        let reserved = fixture
            .conn
            .query_one(statement(
                "SELECT reserved_bytes FROM artifact_account",
                vec![],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "reserved_bytes")
            .unwrap();
        assert_eq!(reserved, CHUNK_BYTES as i64);
        let mut sink = MemorySink::default();
        read_artifact(&repo, "sql", space, "main", &mut sink)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sink.checkpoint, payload);
        assert!(matches!(
            legacy
                .save("sql", space, "main", vec![1], ArtifactExpectation::Any)
                .await,
            Err(DatabaseArtifactError::StaleLineage)
        ));
        let immutable = fixture
            .conn
            .execute_unprepared("UPDATE artifact_chunk SET payload=decode('00','hex')")
            .await;
        assert!(immutable.is_err(), "sealed bytes must be immutable");
        // Simulate storage corruption under the fixture's administrative role.
        fixture.conn.execute_unprepared("ALTER TABLE artifact_chunk DISABLE TRIGGER artifact_chunk_guard; UPDATE artifact_chunk SET payload=set_byte(payload,0,8); ALTER TABLE artifact_chunk ENABLE TRIGGER artifact_chunk_guard;").await.unwrap();
        let error = repo
            .read_chunks("sql", space, "main", &meta, &mut MemorySink::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, DatabaseArtifactError::HashMismatch { .. }),
            "{error:?}"
        );
    }
    #[tokio::test]
    async fn postgres_chunked_checkpoint_publish_cas_race_and_reclamation() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_publish_cas_race_and_reclamation",
        )
        .await
        else {
            return;
        };
        let space = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:race";
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 1024,
                account_bytes: 8192,
            }),
        );
        let legacy = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone());
        let base = legacy
            .save(
                "sql",
                space,
                "main",
                vec![0; 128],
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let expected = ArtifactExpectation::Derived {
            revision: base.revision,
            checkpoint_content_hash: base.checkpoint_content_hash,
        };
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut racing = repo.clone();
        racing.chunk_publish_barrier = Some(barrier.clone());
        let upload = tokio::spawn(async move {
            racing
                .save_snapshot("sql", space, "main", snapshot(&[1; 128]), expected)
                .await
        });
        let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if fixture
                .conn
                .query_one(statement(
                    "SELECT 1 AS ready FROM artifact_part WHERE state='sealed'",
                    vec![],
                ))
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
            assert!(tokio::time::Instant::now() < bound);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let second = repo
            .save_snapshot(
                "sql",
                space,
                "main",
                snapshot(&[2; 128]),
                ArtifactExpectation::Any,
            )
            .await;
        assert!(
            matches!(second, Err(DatabaseArtifactError::StorageLimit)),
            "second replacement must refuse: {second:?}"
        );
        // Administrative failure injection changes the base after reservation,
        // modelling a late stale publication independently of the credit fence.
        fixture.conn.execute_unprepared("ALTER TABLE database_artifact DISABLE TRIGGER artifact_metadata_guard; UPDATE database_artifact SET revision=revision+1; ALTER TABLE database_artifact ENABLE TRIGGER artifact_metadata_guard;").await.unwrap();
        barrier.wait().await;
        let outcome = upload.await.unwrap();
        assert!(
            matches!(outcome, Err(DatabaseArtifactError::StaleLineage)),
            "stale publication was admitted: {outcome:?}"
        );
        for _ in 0..100 {
            repo.reap_unused_parts(64).await.unwrap();
            let n = fixture
                .conn
                .query_one(statement(
                    "SELECT count(*)::bigint AS n FROM artifact_part",
                    vec![],
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<i64>("", "n")
                .unwrap();
            if n == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Replacements must not accumulate quota charges or deleted bytes.
        for byte in 3..15 {
            repo.save_snapshot(
                "sql",
                space,
                "main",
                snapshot(&[byte; 128]),
                ArtifactExpectation::Any,
            )
            .await
            .unwrap();
        }
        let reserved = fixture
            .conn
            .query_one(statement(
                "SELECT reserved_bytes FROM artifact_account",
                vec![],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "reserved_bytes")
            .unwrap();
        assert_eq!(reserved, 128);
        fixture
            .conn
            .execute_unprepared("DELETE FROM database_artifact")
            .await
            .unwrap();
        repo.reap_unused_parts(64).await.unwrap();
        let state=fixture.conn.query_one(statement("SELECT reserved_bytes,(SELECT count(*)::bigint FROM artifact_chunk) AS chunks FROM artifact_account",vec![])).await.unwrap().unwrap();
        assert_eq!(state.try_get::<i64>("", "reserved_bytes").unwrap(), 0);
        assert_eq!(state.try_get::<i64>("", "chunks").unwrap(), 0);
        // A process crash after reservation/first chunk: the next pass fences
        // the expired upload, deletes it and releases its charge.
        fixture.conn.execute_unprepared(&format!("UPDATE artifact_account SET reserved_bytes=512; INSERT INTO artifact_part(service,space,name,part_id,owner,size_bytes,chunk_count,lease_until) SELECT 'sql','{space}','crashed','0123456789abcdef',owner,512,1,clock_timestamp()-interval '1 second' FROM artifact_account; INSERT INTO artifact_chunk SELECT service,space,name,part_id,0,decode(repeat('00',512),'hex') FROM artifact_part;")).await.unwrap();
        repo.reap_unused_parts(64).await.unwrap();
        assert_eq!(
            fixture
                .conn
                .query_one(statement(
                    "SELECT reserved_bytes FROM artifact_account",
                    vec![]
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<i64>("", "reserved_bytes")
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn postgres_chunked_checkpoint_exact_owner_and_legacy_duckdb_quota() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_exact_owner_and_legacy_duckdb_quota",
        )
        .await
        else {
            return;
        };
        let parent = "tinycloud:web:example.com:notes";
        let child = "tinycloud:web:example.com:alice:notes";
        let legacy = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone());
        for space in [parent, child] {
            legacy
                .save(
                    "duckdb",
                    space,
                    "main",
                    vec![1; 600],
                    ArtifactExpectation::Absent,
                )
                .await
                .unwrap();
        }
        let repo = legacy.clone().with_chunk_limits(Some(ChunkLimits {
            artifact_bytes: 1024,
            account_bytes: 1000,
        }));
        repo.configure_chunked_storage().await.unwrap();
        let owners = fixture
            .conn
            .query_all(statement(
                "SELECT owner,legacy_bytes FROM artifact_account ORDER BY owner",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(owners.len(), 2);
        assert_eq!(
            owners[0].try_get::<String>("", "owner").unwrap(),
            "did:web:example.com"
        );
        assert_eq!(
            owners[1].try_get::<String>("", "owner").unwrap(),
            "did:web:example.com:alice"
        );
        assert!(owners
            .iter()
            .all(|row| row.try_get::<i64>("", "legacy_bytes").unwrap() == 600));
        legacy
            .save(
                "duckdb",
                parent,
                "second",
                vec![2; 400],
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let refused = legacy
            .save(
                "duckdb",
                parent,
                "third",
                vec![3; 1],
                ArtifactExpectation::Absent,
            )
            .await;
        assert!(
            matches!(refused, Err(DatabaseArtifactError::StorageLimit)),
            "{refused:?}"
        );
        legacy
            .save(
                "duckdb",
                child,
                "second",
                vec![4; 400],
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn postgres_chunked_checkpoint_cancelled_upload_releases_reservation() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_cancelled_upload_releases_reservation",
        )
        .await
        else {
            return;
        };
        let space = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:cancel";
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 1024,
                account_bytes: 1024,
            }),
        );
        let mut blocked = repo.clone();
        blocked.chunk_publish_barrier = Some(std::sync::Arc::new(tokio::sync::Barrier::new(2)));
        let upload = tokio::spawn(async move {
            blocked
                .save_snapshot(
                    "sql",
                    space,
                    "cancelled",
                    snapshot(&[9; 512]),
                    ArtifactExpectation::Absent,
                )
                .await
        });
        let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let staged = fixture
                .conn
                .query_one(statement(
                    "SELECT 1 AS ready FROM artifact_part WHERE state='sealed'",
                    vec![],
                ))
                .await
                .unwrap()
                .is_some();
            if staged {
                break;
            }
            assert!(
                tokio::time::Instant::now() < bound,
                "upload did not reach publication barrier"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        upload.abort();
        assert!(upload.await.unwrap_err().is_cancelled());
        let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let charge = fixture
                .conn
                .query_one(statement(
                    "SELECT reserved_bytes FROM artifact_account",
                    vec![],
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<i64>("", "reserved_bytes")
                .unwrap();
            if charge == 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < bound,
                "cancelled reservation was not released"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(repo
            .load_meta("sql", space, "cancelled")
            .await
            .unwrap()
            .is_none());
        repo.save_snapshot(
            "sql",
            space,
            "retry",
            snapshot(&[10; 1024]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn postgres_chunked_checkpoint_at_quota_replacement_credit() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_at_quota_replacement_credit",
        )
        .await
        else {
            return;
        };
        let space = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:credit";
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 1024,
                account_bytes: 512,
            }),
        );
        repo.save_snapshot(
            "sql",
            space,
            "main",
            snapshot(&[1; 512]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let grow = repo
            .save_snapshot(
                "sql",
                space,
                "main",
                snapshot(&[2; 513]),
                ArtifactExpectation::Any,
            )
            .await;
        assert!(
            matches!(grow, Err(DatabaseArtifactError::StorageLimit)),
            "{grow:?}"
        );
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut blocked = repo.clone();
        blocked.chunk_publish_barrier = Some(barrier.clone());
        let shrink = tokio::spawn(async move {
            blocked
                .save_snapshot(
                    "sql",
                    space,
                    "main",
                    snapshot(&[3; 256]),
                    ArtifactExpectation::Any,
                )
                .await
        });
        let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if fixture
                .conn
                .query_one(statement(
                    "SELECT 1 AS ready FROM artifact_part WHERE replacing AND state='sealed'",
                    vec![],
                ))
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
            assert!(tokio::time::Instant::now() < bound);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let second = repo
            .save_snapshot(
                "sql",
                space,
                "main",
                snapshot(&[4; 128]),
                ArtifactExpectation::Any,
            )
            .await;
        assert!(matches!(second, Err(DatabaseArtifactError::StorageLimit)));
        // Pending shrinkage cannot fund another database, then be aborted.
        let other = repo
            .save_snapshot(
                "sql",
                space,
                "other",
                snapshot(&[5; 1]),
                ArtifactExpectation::Absent,
            )
            .await;
        assert!(matches!(other, Err(DatabaseArtifactError::StorageLimit)));
        barrier.wait().await;
        assert_eq!(shrink.await.unwrap().unwrap().size_bytes, 256);
        repo.save_snapshot(
            "sql",
            space,
            "other",
            snapshot(&[6; 256]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let row = fixture
            .conn
            .query_one(statement(
                "SELECT reserved_bytes,credit_bytes FROM artifact_account",
                vec![],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "reserved_bytes").unwrap(), 512);
        assert_eq!(row.try_get::<i64>("", "credit_bytes").unwrap(), 0);
    }
    async fn ledger(fixture: &crate::test_support::PostgresTestSchema) -> (i64, i64) {
        let row = fixture
            .conn
            .query_one(statement(
                "SELECT reserved_bytes,credit_bytes FROM artifact_account",
                vec![],
            ))
            .await
            .unwrap()
            .unwrap();
        (
            row.try_get("", "reserved_bytes").unwrap(),
            row.try_get("", "credit_bytes").unwrap(),
        )
    }

    async fn await_replacement(fixture: &crate::test_support::PostgresTestSchema) {
        let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if fixture
                .conn
                .query_one(statement(
                    "SELECT 1 AS ready FROM artifact_part WHERE replacing AND state='sealed'",
                    vec![],
                ))
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
            assert!(tokio::time::Instant::now() < bound);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn postgres_chunked_checkpoint_shrink_abort_and_staging_crash() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_shrink_abort_and_staging_crash",
        )
        .await
        else {
            return;
        };
        let space =
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:abort-credit";
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 1024,
                account_bytes: 512,
            }),
        );
        let base = repo
            .save_snapshot(
                "sql",
                space,
                "main",
                snapshot(&[1; 512]),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        for _ in 0..3 {
            let mut blocked = repo.clone();
            blocked.chunk_publish_barrier = Some(std::sync::Arc::new(tokio::sync::Barrier::new(2)));
            let upload = tokio::spawn(async move {
                blocked
                    .save_snapshot(
                        "sql",
                        space,
                        "main",
                        snapshot(&[2; 256]),
                        ArtifactExpectation::Any,
                    )
                    .await
            });
            await_replacement(&fixture).await;
            assert_eq!(ledger(&fixture).await, (768, 256));
            upload.abort();
            assert!(upload.await.unwrap_err().is_cancelled());
            let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
            while ledger(&fixture).await != (512, 0) {
                assert!(tokio::time::Instant::now() < bound);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        // An owner process disappears after a partial chunk upload; there is
        // no Rust drop guard in the crashed process to do this cleanup.
        let owner = space.parse::<SpaceId>().unwrap().did().to_string();
        let admitted = fixture
            .conn
            .query_one(statement(
                "SELECT artifact_reserve('sql',$1,'main','crashed-credit',$2,256,1,$3,$4) AS ok",
                vec![
                    space.into(),
                    owner.into(),
                    base.revision.into(),
                    base.checkpoint_content_hash.into(),
                ],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<bool>("", "ok")
            .unwrap();
        assert!(admitted);
        fixture.conn.execute(statement("INSERT INTO artifact_chunk SELECT service,space,name,part_id,0,$1 FROM artifact_part WHERE part_id='crashed-credit'",vec![vec![3u8;128].into()])).await.unwrap();
        repo.reap_unused_parts(64).await.unwrap();
        assert_eq!(
            ledger(&fixture).await,
            (768, 256),
            "unexpired upload stays charged"
        );
        fixture.conn.execute_unprepared("UPDATE artifact_part SET lease_until=clock_timestamp()-interval '1 second' WHERE part_id='crashed-credit'").await.unwrap();
        repo.reap_unused_parts(64).await.unwrap();
        assert_eq!(ledger(&fixture).await, (512, 0));
        assert!(fixture
            .conn
            .query_one(statement(
                "SELECT 1 FROM artifact_chunk WHERE part_id='crashed-credit'",
                vec![]
            ))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn postgres_chunked_checkpoint_delete_during_staging_fences_publish() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_delete_during_staging_fences_publish",
        )
        .await
        else {
            return;
        };
        let space =
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:delete-credit";
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 1024,
                account_bytes: 512,
            }),
        );
        repo.save_snapshot(
            "sql",
            space,
            "main",
            snapshot(&[1; 512]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut blocked = repo.clone();
        blocked.chunk_publish_barrier = Some(barrier.clone());
        let upload = tokio::spawn(async move {
            blocked
                .save_snapshot(
                    "sql",
                    space,
                    "main",
                    snapshot(&[2; 256]),
                    ArtifactExpectation::Any,
                )
                .await
        });
        await_replacement(&fixture).await;
        fixture
            .conn
            .execute_unprepared("DELETE FROM database_artifact")
            .await
            .unwrap();
        assert_eq!(
            ledger(&fixture).await,
            (768, 0),
            "all physical parts stay charged after deletion"
        );
        barrier.wait().await;
        assert!(matches!(
            upload.await.unwrap(),
            Err(DatabaseArtifactError::StaleLineage)
        ));
        repo.reap_unused_parts(64).await.unwrap();
        assert_eq!(ledger(&fixture).await, (0, 0));
        assert!(repo
            .load_meta("sql", space, "main")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn postgres_chunked_checkpoint_publish_credit_waits_for_physical_deletion() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_publish_credit_waits_for_physical_deletion",
        )
        .await
        else {
            return;
        };
        let space =
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:physical-credit";
        let old = CHUNK_BYTES + 64;
        let new = 256 * 1024;
        let mut repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone())
            .with_chunk_limits(Some(ChunkLimits {
                artifact_bytes: 2 * CHUNK_BYTES as u64,
                account_bytes: old as u64,
            }));
        repo.chunk_reclaim_paused = true;
        repo.save_snapshot(
            "sql",
            space,
            "main",
            snapshot(&vec![1; old]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let old_part = fixture
            .conn
            .query_one(statement(
                "SELECT checkpoint_part_id FROM database_artifact",
                vec![],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<String>("", "checkpoint_part_id")
            .unwrap();
        repo.save_snapshot(
            "sql",
            space,
            "main",
            snapshot(&vec![2; new]),
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        assert_eq!(ledger(&fixture).await, ((old + new) as i64, new as i64));
        let args = vec![
            "sql".into(),
            space.into(),
            "main".into(),
            old_part.clone().into(),
        ];
        fixture
            .conn
            .query_one(statement(
                "SELECT artifact_reap_one($1,$2,$3,$4)",
                args.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(
            ledger(&fixture).await,
            ((old + new) as i64, new as i64),
            "partial deletion must not free quota"
        );
        fixture
            .conn
            .query_one(statement("SELECT artifact_reap_one($1,$2,$3,$4)", args))
            .await
            .unwrap();
        assert_eq!(ledger(&fixture).await, (new as i64, 0));
        assert!(fixture
            .conn
            .query_one(statement(
                "SELECT 1 FROM artifact_chunk WHERE part_id=$1",
                vec![old_part.into()]
            ))
            .await
            .unwrap()
            .is_none());
        repo.save_snapshot(
            "sql",
            space,
            "other",
            snapshot(&vec![3; old - new]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn postgres_chunked_checkpoint_over_cap_owner_can_shrink() {
        for initially_chunked in [false, true] {
            let Some(fixture) = crate::test_support::PostgresTestSchema::new(
                "postgres_chunked_checkpoint_over_cap_owner_can_shrink",
            )
            .await
            else {
                return;
            };
            let space =
                "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:over-cap";
            let legacy = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone());
            if initially_chunked {
                let initial = legacy.clone().with_chunk_limits(Some(ChunkLimits {
                    artifact_bytes: 1024,
                    account_bytes: 1024,
                }));
                initial
                    .save_snapshot(
                        "sql",
                        space,
                        "main",
                        snapshot(&[1; 512]),
                        ArtifactExpectation::Absent,
                    )
                    .await
                    .unwrap();
            } else {
                legacy
                    .save(
                        "sql",
                        space,
                        "main",
                        vec![1; 512],
                        ArtifactExpectation::Absent,
                    )
                    .await
                    .unwrap();
            }
            let capped = legacy.with_chunk_limits(Some(ChunkLimits {
                artifact_bytes: 1024,
                account_bytes: 128,
            }));
            capped.configure_chunked_storage().await.unwrap();
            capped
                .save_snapshot(
                    "sql",
                    space,
                    "main",
                    snapshot(&[2; 512]),
                    ArtifactExpectation::Any,
                )
                .await
                .unwrap();
            capped
                .save_snapshot(
                    "sql",
                    space,
                    "main",
                    snapshot(&[3; 400]),
                    ArtifactExpectation::Any,
                )
                .await
                .unwrap();
            let growth = capped
                .save_snapshot(
                    "sql",
                    space,
                    "main",
                    snapshot(&[4; 401]),
                    ArtifactExpectation::Any,
                )
                .await;
            assert!(matches!(growth, Err(DatabaseArtifactError::StorageLimit)));
            capped
                .save_snapshot(
                    "sql",
                    space,
                    "main",
                    snapshot(&[5; 128]),
                    ArtifactExpectation::Any,
                )
                .await
                .unwrap();
            capped.reap_unused_parts(64).await.unwrap();
            assert_eq!(ledger(&fixture).await, (128, 0));
        }
    }

    #[tokio::test]
    async fn postgres_chunked_checkpoint_multi_chunk_abort_keeps_charge_until_gone() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_multi_chunk_abort_keeps_charge_until_gone",
        )
        .await
        else {
            return;
        };
        let space =
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:abort-chunks";
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 4 * CHUNK_BYTES as u64,
                account_bytes: 4 * CHUNK_BYTES as u64,
            }),
        );
        let base = repo
            .save_snapshot(
                "sql",
                space,
                "main",
                snapshot(&vec![1; CHUNK_BYTES]),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let owner = space.parse::<SpaceId>().unwrap().did().to_string();
        let stage_size = 2 * CHUNK_BYTES + 64;
        let admitted = fixture
            .conn
            .query_one(statement(
                "SELECT artifact_reserve('sql',$1,'main','multi-abort',$2,$3,3,$4,$5) AS ok",
                vec![
                    space.into(),
                    owner.into(),
                    (stage_size as i64).into(),
                    base.revision.into(),
                    base.checkpoint_content_hash.into(),
                ],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<bool>("", "ok")
            .unwrap();
        assert!(admitted);
        for (ordinal, size) in [CHUNK_BYTES, CHUNK_BYTES, 64].into_iter().enumerate() {
            fixture.conn.execute(statement("INSERT INTO artifact_chunk SELECT service,space,name,part_id,$1,$2 FROM artifact_part WHERE part_id='multi-abort'",vec![(ordinal as i32).into(),vec![2u8;size].into()])).await.unwrap();
        }
        for remaining in [2, 1] {
            fixture
                .conn
                .query_one(statement(
                    "SELECT artifact_reap_one('sql',$1,'main','multi-abort',true)",
                    vec![space.into()],
                ))
                .await
                .unwrap();
            assert_eq!(
                ledger(&fixture).await,
                ((CHUNK_BYTES + stage_size) as i64, CHUNK_BYTES as i64)
            );
            let n = fixture
                .conn
                .query_one(statement(
                    "SELECT count(*)::bigint AS n FROM artifact_chunk WHERE part_id='multi-abort'",
                    vec![],
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<i64>("", "n")
                .unwrap();
            assert_eq!(n, remaining);
        }
        fixture
            .conn
            .query_one(statement(
                "SELECT artifact_reap_one('sql',$1,'main','multi-abort',true)",
                vec![space.into()],
            ))
            .await
            .unwrap();
        assert_eq!(ledger(&fixture).await, (CHUNK_BYTES as i64, 0));
        assert!(fixture
            .conn
            .query_one(statement(
                "SELECT 1 FROM artifact_chunk WHERE part_id='multi-abort'",
                vec![]
            ))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn postgres_chunked_checkpoint_concurrent_legacy_quota_is_atomic() {
        use sea_orm::TransactionTrait;
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_concurrent_legacy_quota_is_atomic",
        )
        .await
        else {
            return;
        };
        let first = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:legacy-one";
        let second = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:legacy-two";
        let legacy = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone());
        for i in 0..8 {
            legacy
                .save(
                    if i % 2 == 0 { "sql" } else { "duckdb" },
                    if i % 2 == 0 { first } else { second },
                    &format!("db-{i}"),
                    vec![],
                    ArtifactExpectation::Absent,
                )
                .await
                .unwrap();
        }
        legacy
            .clone()
            .with_chunk_limits(Some(ChunkLimits {
                artifact_bytes: 1024,
                account_bytes: 512,
            }))
            .configure_chunked_storage()
            .await
            .unwrap();
        let blocker = fixture.connect(1).await;
        let held = blocker.begin().await.unwrap();
        held.query_one(statement(
            "SELECT owner FROM artifact_account FOR UPDATE",
            vec![],
        ))
        .await
        .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
        let tasks = (0..8)
            .map(|i| {
                let repo = legacy.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    repo.save(
                        if i % 2 == 0 { "sql" } else { "duckdb" },
                        if i % 2 == 0 { first } else { second },
                        &format!("db-{i}"),
                        vec![7; 256],
                        ArtifactExpectation::Any,
                    )
                    .await
                })
            })
            .collect::<Vec<_>>();
        let observer = fixture.connect(1).await;
        let bound = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let n=observer.query_one(statement("SELECT count(DISTINCT l.pid)::bigint AS n FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.relation='artifact_account'::regclass AND l.mode='RowExclusiveLock' AND l.granted AND a.wait_event_type='Lock'",vec![])).await.unwrap().unwrap().try_get::<i64>("","n").unwrap();
            if n >= 4 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < bound,
                "legacy writers did not overlap at owner lock: {n}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        held.rollback().await.unwrap();
        let mut admitted = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(_) => admitted += 1,
                Err(DatabaseArtifactError::StorageLimit) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(
            admitted, 2,
            "concurrent legacy quota check admitted too many writes"
        );
        let state=fixture.conn.query_one(statement("SELECT legacy_bytes,(SELECT sum(size_bytes)::bigint FROM database_artifact) AS live FROM artifact_account",vec![])).await.unwrap().unwrap();
        assert_eq!(state.try_get::<i64>("", "legacy_bytes").unwrap(), 512);
        assert_eq!(state.try_get::<i64>("", "live").unwrap(), 512);
    }

    #[tokio::test]
    async fn postgres_chunked_checkpoint_reclaim_is_owner_scoped_and_best_effort() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_reclaim_is_owner_scoped_and_best_effort",
        )
        .await
        else {
            return;
        };
        let space =
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:isolated-reap";
        let owner = space.parse::<SpaceId>().unwrap().did().to_string();
        let other = "did:pkh:eip155:1:0x0000000000000000000000000000000000000002";
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 1024,
                account_bytes: 4096,
            }),
        );
        repo.configure_chunked_storage().await.unwrap();
        fixture
            .conn
            .execute(statement(
                "INSERT INTO artifact_account(owner) VALUES($1)",
                vec![other.into()],
            ))
            .await
            .unwrap();
        fixture.conn.execute(statement("INSERT INTO artifact_part(service,space,name,part_id,owner,size_bytes,chunk_count,state,lease_until) SELECT 'sql','synthetic-published','db-'||n,'part-'||n,$1,0,0,'published',clock_timestamp()-interval '1 year' FROM generate_series(1,100000) AS n",vec![other.into()])).await.unwrap();
        fixture.conn.execute(statement("INSERT INTO artifact_part(service,space,name,part_id,owner,size_bytes,chunk_count,state,lease_until) SELECT 'sql','synthetic-deleting','db-'||n,'garbage-'||n,$1,0,0,'deleting',clock_timestamp()-interval '1 day' FROM generate_series(1,4096) AS n",vec![other.into()])).await.unwrap();
        fixture
            .conn
            .execute_unprepared("ANALYZE artifact_part")
            .await
            .unwrap();
        let plan = fixture
            .conn
            .query_all(statement(
                &format!("EXPLAIN (ANALYZE,TIMING OFF) {OWNER_REAP_CANDIDATE}"),
                vec![owner.clone().into()],
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String>("", "QUERY PLAN").unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(plan.contains("artifact_part_reap_owner"), "{plan}");
        assert!(!plan.contains("Seq Scan on artifact_part"), "{plan}");
        repo.save_snapshot(
            "sql",
            space,
            "main",
            snapshot(&[1; 64]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let n = fixture
            .conn
            .query_one(statement(
                "SELECT count(*)::bigint AS n FROM artifact_part WHERE owner=$1",
                vec![other.into()],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap();
        assert_eq!(n, 104096, "writer reclaimed another owner's parts");
        // Real database failure injection: a failing collector must not fail
        // a write with sufficient quota, even for its own owner's garbage.
        fixture.conn.execute(statement("INSERT INTO artifact_part(service,space,name,part_id,owner,size_bytes,chunk_count,state,lease_until) VALUES('sql',$1,'broken','bad-reap',$2,0,0,'deleting',clock_timestamp())",vec![space.into(),owner.into()])).await.unwrap();
        fixture.conn.execute_unprepared("CREATE OR REPLACE FUNCTION artifact_reap_one(p_service text,p_space text,p_name text,p_id text,abort_upload boolean DEFAULT false) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic collector failure'; END $$").await.unwrap();
        repo.save_snapshot(
            "sql",
            space,
            "second",
            snapshot(&[2; 64]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn postgres_chunked_checkpoint_honours_single_statement_cap() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_checkpoint_honours_single_statement_cap",
        )
        .await
        else {
            return;
        };
        let space =
            "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:statement-cap";
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 4 * CHUNK_BYTES as u64,
                account_bytes: 8 * CHUNK_BYTES as u64,
            }),
        );
        let refused = repo
            .clone()
            .with_max_write_bytes(4096)
            .save_snapshot(
                "sql",
                space,
                "refused",
                snapshot(&vec![1; 4097]),
                ArtifactExpectation::Absent,
            )
            .await;
        assert!(
            matches!(
                refused,
                Err(DatabaseArtifactError::WriteLimitExceeded {
                    bytes: 4097,
                    limit: 4096
                })
            ),
            "{refused:?}"
        );
        // The complete artifact may exceed the statement cap: each bounded
        // chunk must obey it, as well as the separate artifact/account limits.
        let saved = repo
            .with_max_write_bytes(CHUNK_BYTES as u64)
            .save_snapshot(
                "sql",
                space,
                "streamed",
                snapshot(&vec![2; CHUNK_BYTES + 1]),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        assert_eq!(saved.size_bytes, CHUNK_BYTES as i64 + 1);
    }

    /// Counts the bytes a read delivers without holding them.
    #[derive(Default)]
    struct CountingSink {
        bytes: u64,
    }

    #[async_trait]
    impl ArtifactSink for CountingSink {
        fn buffers_in_memory(&self) -> bool {
            false
        }
        async fn reset(&mut self) -> Result<(), DatabaseArtifactError> {
            self.bytes = 0;
            Ok(())
        }
        async fn begin_part(&mut self, _part: ArtifactPart) -> Result<(), DatabaseArtifactError> {
            Ok(())
        }
        async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError> {
            self.bytes += bytes.len() as u64;
            Ok(())
        }
        async fn finish_part(&mut self) -> Result<(), DatabaseArtifactError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn postgres_chunked_read_is_not_held_to_the_single_row_read_cap() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_read_is_not_held_to_the_single_row_read_cap",
        )
        .await
        else {
            return;
        };
        let space = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:read-cap";
        let over = DEFAULT_MAX_ARTIFACT_READ_BYTES as usize + 1;
        // Seed a single-row artifact over the default read cap with the write
        // cap off, as an older node could have stored it.
        SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone())
            .with_max_write_bytes(0)
            .save(
                "sql",
                space,
                "legacy",
                vec![3; over],
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 2 * over as u64,
                account_bytes: 4 * over as u64,
            }),
        );
        repo.save_snapshot(
            "sql",
            space,
            "parts",
            snapshot(&vec![4; over]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();

        let mut parts = CountingSink::default();
        read_artifact(&repo, "sql", space, "parts", &mut parts)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parts.bytes, over as u64);

        let legacy =
            read_artifact(&repo, "sql", space, "legacy", &mut CountingSink::default()).await;
        assert!(
            matches!(legacy, Err(DatabaseArtifactError::ReadLimitExceeded { .. })),
            "{legacy:?}"
        );
    }

    #[tokio::test]
    async fn postgres_chunked_in_memory_read_waits_for_a_large_transfer_slot() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_in_memory_read_waits_for_a_large_transfer_slot",
        )
        .await
        else {
            return;
        };
        let space = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:permit";
        let size = BASE_TIMEOUT_PAYLOAD_BYTES + 1;
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
            Some(ChunkLimits {
                artifact_bytes: 2 * size as u64,
                account_bytes: 4 * size as u64,
            }),
        );
        repo.save_snapshot(
            "sql",
            space,
            "main",
            snapshot(&vec![5; size]),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        let held: Vec<_> = (0..MAX_CONCURRENT_LARGE_TRANSFERS)
            .map(|_| repo.large_transfers.try_acquire().unwrap())
            .collect();

        // A streaming sink holds no more than a statement's bytes: no slot.
        let mut streamed = CountingSink::default();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            read_artifact(&repo, "sql", space, "main", &mut streamed),
        )
        .await
        .expect("a streaming read waited for a transfer slot")
        .unwrap()
        .unwrap();
        assert_eq!(streamed.bytes, size as u64);

        // A sink holding the whole artifact waits until a slot frees.
        let waiting = {
            let repo = repo.clone();
            tokio::spawn(async move {
                let mut sink = MemorySink::default();
                read_artifact(&repo, "sql", space, "main", &mut sink)
                    .await
                    .map(|_| sink.checkpoint.len())
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !waiting.is_finished(),
            "an in-memory read took no transfer slot"
        );
        drop(held);
        assert_eq!(waiting.await.unwrap().unwrap(), size);
    }

    /// A row that reads as parts but turns out legacy falls back without
    /// holding a parts slot, and the legacy read keeps its own cap and slot.
    #[tokio::test]
    async fn postgres_chunked_fallback_to_legacy_holds_no_parts_slot() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_fallback_to_legacy_holds_no_parts_slot",
        )
        .await
        else {
            return;
        };
        let space = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:fallback";
        let size = BASE_TIMEOUT_PAYLOAD_BYTES + 1;
        let repo = SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone());
        repo.save(
            "sql",
            space,
            "fb",
            vec![7; size],
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        // The metadata says parts while the row holds a single payload: the
        // state a read sees when a parts row is replaced by a legacy one
        // between its metadata and row reads.
        fixture
            .conn
            .execute_unprepared(
                "UPDATE database_artifact SET storage_mode = 'checkpoint-parts-v1' \
                 WHERE name = 'fb'",
            )
            .await
            .unwrap();

        // One slot free: an in-memory fallback completes, which it could not
        // if the parts slot were still held when the legacy read takes its own.
        let held: Vec<_> = (0..MAX_CONCURRENT_LARGE_TRANSFERS - 1)
            .map(|_| repo.large_transfers.try_acquire().unwrap())
            .collect();
        let mut sink = MemorySink::default();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read_artifact(&repo, "sql", space, "fb", &mut sink),
        )
        .await
        .expect("the fallback held the parts slot into the legacy read")
        .unwrap()
        .unwrap();
        assert_eq!(sink.checkpoint.len(), size);
        assert_eq!(repo.large_transfers.available_permits(), 1);
        drop(held);

        // No slot free: even a streaming fallback waits for the legacy slot.
        let held: Vec<_> = (0..MAX_CONCURRENT_LARGE_TRANSFERS)
            .map(|_| repo.large_transfers.try_acquire().unwrap())
            .collect();
        let waiting = {
            let repo = repo.clone();
            tokio::spawn(async move {
                let mut sink = CountingSink::default();
                read_artifact(&repo, "sql", space, "fb", &mut sink)
                    .await
                    .map(|_| sink.bytes)
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!waiting.is_finished(), "the legacy fallback took no slot");
        drop(held);
        let read = tokio::time::timeout(std::time::Duration::from_secs(30), waiting)
            .await
            .expect("the fallback did not finish once a slot freed");
        assert_eq!(read.unwrap().unwrap(), size as u64);

        // The single-row read cap still applies to the fallback.
        let capped = repo.clone().with_max_read_bytes(size as u64 - 1);
        let refused =
            read_artifact(&capped, "sql", space, "fb", &mut CountingSink::default()).await;
        assert!(
            matches!(
                refused,
                Err(DatabaseArtifactError::ReadLimitExceeded { .. })
            ),
            "{refused:?}"
        );
        assert_eq!(
            repo.large_transfers.available_permits(),
            MAX_CONCURRENT_LARGE_TRANSFERS
        );
    }
}
