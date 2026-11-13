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

impl SeaOrmDatabaseArtifactRepository {
    pub(super) async fn ensure_legacy_write(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<(), DatabaseArtifactError> {
        if self.conn.get_database_backend() != DbBackend::Postgres {
            return Ok(());
        }
        if (self.chunk_limits.is_some() && service == "sql") || self.conn.query_one(statement(
            "SELECT 1 AS present FROM database_artifact WHERE service=$1 AND space=$2 AND name=$3 AND checkpoint_part_id IS NOT NULL",
            vec![service.into(), space.into(), name.into()],
        )).await?.is_some() {
            return Err(DatabaseArtifactError::IncrementalPersistenceUnsupported);
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
        let limits = self
            .chunk_limits
            .ok_or(DatabaseArtifactError::IncrementalPersistenceUnsupported)?;
        if self.conn.get_database_backend() != DbBackend::Postgres {
            return Err(DatabaseArtifactError::IncrementalPersistenceUnsupported);
        }
        let size = snapshot.as_file().metadata().map_err(io_error)?.len();
        if limits.artifact_bytes == 0
            || limits.account_bytes == 0
            || size > limits.artifact_bytes
            || size > i64::MAX as u64
        {
            return Err(DatabaseArtifactError::StorageLimit);
        }
        let space_id: SpaceId = space
            .parse()
            .map_err(|_| DatabaseArtifactError::Backend("invalid artifact space".into()))?;
        let owner = space_id.did().to_string();
        let owner_prefix = format!("tinycloud:{}:", space_id.suffix());
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
        // The owner-row update serialises parallel reservations. Legacy live
        // artifacts are included until their pointer publication replaces them.
        // A failed/cancelled upload remains reserved, never silently reusable.
        let reserved = self
            .conn
            .execute(statement(
                r#"
WITH reservation AS (
 UPDATE artifact_account SET reserved_bytes=reserved_bytes+$2
 WHERE owner=$1 AND reserved_bytes <= $3-$2-
   (SELECT COALESCE(sum(size_bytes),0) FROM database_artifact
    WHERE checkpoint_part_id IS NULL AND left(space,length($4))=$4)
 RETURNING owner
)
INSERT INTO artifact_part(service,space,name,part_id,owner,size_bytes,chunk_count)
SELECT $5,$6,$7,$8,owner,$2,$9 FROM reservation
"#,
                vec![
                    owner.into(),
                    (size as i64).into(),
                    (limits.account_bytes.min(i64::MAX as u64) as i64).into(),
                    owner_prefix.into(),
                    service.into(),
                    space.into(),
                    name.into(),
                    part_id.clone().into(),
                    count.into(),
                ],
            ))
            .await?;
        if reserved.rows_affected() != 1 {
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
                "INSERT INTO artifact_chunk(service,space,name,part_id,ordinal,payload) VALUES($1,$2,$3,$4,$5,$6)",
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
UPDATE artifact_part p SET sealed=true,content_hash=$5
WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND NOT sealed
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
            part_id.into(),
            revision.into(),
            cid.clone().into(),
            (size as i64).into(),
            now.clone().into(),
        ];
        // One metadata-only statement is the acknowledgement boundary. Parts
        // are already durable and sealed; no transaction spans the transfer.
        let sql = if let Some(previous) = current {
            values.extend([
                previous.revision.into(),
                previous.checkpoint_content_hash.into(),
            ]);
            r#"WITH ready AS (SELECT part_id FROM artifact_part
 WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND sealed FOR UPDATE)
UPDATE database_artifact SET checkpoint_part_id=$4,delta_part_id=NULL,
 revision=$5,content_hash=$6,checkpoint_content_hash=$6,size_bytes=$7,
 checkpoint_size_bytes=$7,payload=''::bytea,delta_payload=NULL,
 delta_content_hash=NULL,delta_size_bytes=0,storage_mode='database-blob',updated_at=$8
WHERE service=$1 AND space=$2 AND name=$3 AND revision=$9 AND checkpoint_content_hash=$10
 AND EXISTS(SELECT 1 FROM ready)"#
        } else {
            r#"WITH ready AS (SELECT part_id FROM artifact_part
 WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND sealed FOR UPDATE)
INSERT INTO database_artifact(service,space,name,checkpoint_part_id,revision,content_hash,
 checkpoint_content_hash,size_bytes,checkpoint_size_bytes,payload,backend,storage_mode,
 created_at,updated_at,delta_size_bytes)
SELECT $1,$2,$3,$4,$5,$6,$6,$7,$7,''::bytea,'storage.database','database-blob',$8,$8,0
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
        Ok(ArtifactMeta {
            revision,
            size_bytes: size as i64,
            content_hash: cid.clone(),
            checkpoint_content_hash: cid,
            checkpoint_size_bytes: size as i64,
            delta_content_hash: None,
            delta_size_bytes: 0,
            updated_at: now,
            storage_mode: "database-blob".into(),
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
        if self.conn.get_database_backend() != DbBackend::Postgres {
            return Ok(false);
        }
        let row=self.conn.query_one(statement(
            "SELECT checkpoint_part_id,delta_part_id,revision,checkpoint_content_hash FROM database_artifact WHERE service=$1 AND space=$2 AND name=$3",
            vec![service.into(),space.into(),name.into()],
        )).await?.ok_or(DatabaseArtifactError::ArtifactChanged)?;
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
            "SELECT size_bytes,chunk_count,content_hash FROM artifact_part WHERE service=$1 AND space=$2 AND name=$3 AND part_id=$4 AND sealed",
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
            "SELECT 1 AS present FROM database_artifact WHERE service=$1 AND space=$2 AND name=$3 AND revision=$4 AND checkpoint_content_hash=$5 AND checkpoint_part_id=$6",
            vec![service.into(),space.into(),name.into(),meta.revision.into(),cid.into(),part.into()],
        )).await?.is_some();
        if !unchanged {
            return Err(DatabaseArtifactError::ArtifactChanged);
        };
        sink.finish_part().await?;
        Ok(true)
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
            Err(DatabaseArtifactError::IncrementalPersistenceUnsupported)
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
}
