//! TC-1491 slice 1b: the SQL object stores (`storage::sql_object`).
//!
//! One conformance set runs against the in-memory store, the filesystem store
//! and the S3 store. The S3 store runs against an in-process S3 API (no
//! network, every test of this file) and, in the `#[ignore]` tests, against
//! the at-rest harness MinIO with the same `TC887_S3_*` environment as
//! `tests/s3_block_store.rs`:
//!
//! ```sh
//! (set -a; . "$RUN_DIR/harness.env"; set +a;
//!  cargo test -p tinycloud-node --test sql_object_store -- --ignored)
//! ```
//!
//! Every call to the real S3 API is wrapped in a 30 s timeout so a regression
//! fails instead of hanging.

use std::{collections::BTreeMap, future::Future, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
    Router,
};
use parking_lot::Mutex;
use percent_encoding::percent_decode_str;
use tinycloud::storage::{
    s3::{S3BlockConfig, S3BlockStore},
    sql_object::{FsSqlObjectStore, S3SqlObjectStore, WriteMode},
};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    sql::store::{
        object::sha256, DbRef, Lineage, MemorySqlObjectStore, ObjectKey, ObjectMeta, PutOutcome,
        SqlObjectStore, SqlStoreError,
    },
    storage::{ByteRangeSpec, StorageConfig, StoreSize},
};

// ---------------------------------------------------------------------------
// Keys and bodies
// ---------------------------------------------------------------------------

fn body(len: usize) -> Vec<u8> {
    let salt = rand::random::<u8>() as usize;
    (0..len).map(|i| ((i * 13 + salt) % 251) as u8).collect()
}

/// A key of a fresh, random database and lineage: unique per call and per run.
fn key_for(bytes: &[u8]) -> ObjectKey {
    key_in(&format!("tinycloud:sqltest:{}", tag()), "v2n", bytes)
}

fn key_in(space: &str, db_id: &str, bytes: &[u8]) -> ObjectKey {
    ObjectKey::snapshot(
        &DbRef { space, db_id },
        &Lineage::random(),
        1,
        &sha256(bytes),
    )
    .unwrap()
}

fn tag() -> String {
    hex::encode(rand::random::<[u8; 6]>())
}

async fn whole<S: SqlObjectStore>(store: &S, key: &ObjectKey) -> Option<Vec<u8>> {
    store
        .get_range(key, ByteRangeSpec::From { start: 0 })
        .await
        .unwrap()
        .map(|r| r.data)
}

async fn part<S: SqlObjectStore>(
    store: &S,
    key: &ObjectKey,
    range: ByteRangeSpec,
) -> Option<(u64, u64, Vec<u8>)> {
    store
        .get_range(key, range)
        .await
        .unwrap()
        .map(|r| (r.start, r.total_size, r.data))
}

// ---------------------------------------------------------------------------
// The conformance set
// ---------------------------------------------------------------------------

/// Writes bytes under a key behind the store's back.
#[async_trait]
trait Planter: Send + Sync {
    async fn plant(&self, key: &ObjectKey, bytes: Vec<u8>);
}

async fn conformance<S: SqlObjectStore + 'static>(store: Arc<S>, planter: Option<&dyn Planter>) {
    let s = &*store;

    // Create, then the same bytes again: refused as present, bytes unchanged.
    let b = body(300);
    let k = key_for(&b);
    assert_eq!(s.head(&k).await.unwrap(), None);
    assert!(s
        .get_range(&k, ByteRangeSpec::From { start: 0 })
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        s.put_if_absent(&k, b.clone()).await.unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        s.put_if_absent(&k, b.clone()).await.unwrap(),
        PutOutcome::AlreadyPresent
    );
    assert_eq!(whole(s, &k).await.unwrap(), b);
    assert_eq!(
        s.head(&k).await.unwrap(),
        Some(ObjectMeta {
            bytes: 300,
            sha256: sha256(&b)
        })
    );

    // A body that does not hash to the key is refused and stores nothing.
    let mut wrong = b.clone();
    wrong[0] ^= 1;
    assert!(matches!(
        s.put_if_absent(&k, wrong.clone()).await,
        Err(SqlStoreError::BodyMismatch)
    ));
    assert_eq!(whole(s, &k).await.unwrap(), b);
    let k_unmade = key_for(&wrong);
    assert!(matches!(
        s.put_if_absent(&k_unmade, b.clone()).await,
        Err(SqlStoreError::BodyMismatch)
    ));
    assert_eq!(s.head(&k_unmade).await.unwrap(), None);

    // Ranges, pinned to what the in-memory store answers.
    use ByteRangeSpec::*;
    let at = |start: usize, end: usize| (start as u64, 300, b[start..=end].to_vec());
    assert_eq!(
        part(s, &k, Inclusive { start: 10, end: 19 }).await,
        Some(at(10, 19))
    );
    assert_eq!(
        part(s, &k, Inclusive { start: 0, end: 299 }).await,
        Some(at(0, 299))
    );
    assert_eq!(
        part(
            s,
            &k,
            Inclusive {
                start: 0,
                end: 10_000
            }
        )
        .await,
        Some(at(0, 299))
    );
    assert_eq!(
        part(
            s,
            &k,
            Inclusive {
                start: 299,
                end: 299
            }
        )
        .await,
        Some(at(299, 299))
    );
    assert_eq!(
        part(
            s,
            &k,
            Inclusive {
                start: 290,
                end: 10_000
            }
        )
        .await,
        Some(at(290, 299))
    );
    assert_eq!(part(s, &k, From { start: 299 }).await, Some(at(299, 299)));
    assert_eq!(part(s, &k, From { start: 0 }).await, Some(at(0, 299)));
    assert_eq!(part(s, &k, Suffix { length: 1 }).await, Some(at(299, 299)));
    assert_eq!(part(s, &k, Suffix { length: 5 }).await, Some(at(295, 299)));
    assert_eq!(part(s, &k, Suffix { length: 300 }).await, Some(at(0, 299)));
    assert_eq!(
        part(s, &k, Suffix { length: 10_000 }).await,
        Some(at(0, 299))
    );
    // Nothing is selected: start beyond the end, an inverted range, a
    // zero-length suffix.
    assert_eq!(part(s, &k, From { start: 300 }).await, None);
    assert_eq!(
        part(
            s,
            &k,
            Inclusive {
                start: 300,
                end: 310
            }
        )
        .await,
        None
    );
    assert_eq!(part(s, &k, Inclusive { start: 5, end: 4 }).await, None);
    assert_eq!(part(s, &k, Suffix { length: 0 }).await, None);

    // The empty object: it exists, and no range of it selects anything.
    let empty = key_for(b"");
    assert_eq!(
        s.put_if_absent(&empty, Vec::new()).await.unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        s.put_if_absent(&empty, Vec::new()).await.unwrap(),
        PutOutcome::AlreadyPresent
    );
    assert_eq!(
        s.head(&empty).await.unwrap(),
        Some(ObjectMeta {
            bytes: 0,
            sha256: sha256(b"")
        })
    );
    assert_eq!(part(s, &empty, From { start: 0 }).await, None);
    assert_eq!(part(s, &empty, Suffix { length: 1 }).await, None);
    assert_eq!(part(s, &empty, Inclusive { start: 0, end: 0 }).await, None);

    // Stored bytes that differ from the key's content are never replaced.
    if let Some(planter) = planter {
        for (len, planted_len) in [(64usize, 64usize), (64, 7)] {
            let wanted = body(len);
            let other = body(planted_len);
            assert_ne!(wanted, other);
            let key = key_for(&wanted);
            planter.plant(&key, other.clone()).await;
            for _ in 0..2 {
                assert!(matches!(
                    s.put_if_absent(&key, wanted.clone()).await,
                    Err(SqlStoreError::Conflict)
                ));
                assert_eq!(whole(s, &key).await.unwrap(), other);
            }
        }
    }

    concurrent_creators(store, 40).await;
}

/// 8 creators of one key, `rounds` times over fresh keys: exactly one wins.
async fn concurrent_creators<S: SqlObjectStore + 'static>(store: Arc<S>, rounds: usize) {
    for _ in 0..rounds {
        let b = body(1024);
        let k = key_for(&b);
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (store, k, b) = (store.clone(), k.clone(), b.clone());
                tokio::spawn(async move { store.put_if_absent(&k, b).await })
            })
            .collect();
        let mut created = 0;
        let mut present = 0;
        for task in tasks {
            match task.await.unwrap().unwrap() {
                PutOutcome::Created => created += 1,
                PutOutcome::AlreadyPresent => present += 1,
            }
        }
        assert_eq!((created, present), (1, 7));
        assert_eq!(whole(&*store, &k).await.unwrap(), b);
    }
}

// ---------------------------------------------------------------------------
// In-memory
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_conformance() {
    conformance(Arc::new(MemorySqlObjectStore::default()), None).await;
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

/// `{tempdir}/sql-store` next to `{tempdir}/blocks`, on a real disk.
fn fs_dirs() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("sqlobj-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let root = dir.path().join("sql-store");
    let blocks = dir.path().join("blocks");
    (dir, root, blocks)
}

fn fs_store() -> (tempfile::TempDir, Arc<FsSqlObjectStore>) {
    let (dir, root, blocks) = fs_dirs();
    let store = Arc::new(FsSqlObjectStore::open(root, &blocks).unwrap());
    (dir, store)
}

struct FsPlanter(Arc<FsSqlObjectStore>);

#[async_trait]
impl Planter for FsPlanter {
    async fn plant(&self, key: &ObjectKey, bytes: Vec<u8>) {
        let path = self.0.path_for(key).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fs_conformance() {
    let (_dir, store) = fs_store();
    let planter = FsPlanter(store.clone());
    conformance(store, Some(&planter)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fs_leftover_temp_files_never_block_a_create() {
    let (_dir, store) = fs_store();
    let b = body(2048);
    let k = key_for(&b);
    let path = store.path_for(&k).unwrap();
    let parent = path.parent().unwrap();
    // A crash between the temp write and the link leaves the full body (or a
    // part of it) under a temp name.
    std::fs::create_dir_all(parent).unwrap();
    std::fs::write(parent.join(".tmp-0123456789abcdef0123456789abcdef"), &b).unwrap();
    std::fs::write(
        parent.join(".tmp-ffffffffffffffffffffffffffffffff"),
        &b[..100],
    )
    .unwrap();
    let leftovers = names_in(parent);
    assert_eq!(leftovers.len(), 2);

    assert_eq!(
        store.put_if_absent(&k, b.clone()).await.unwrap(),
        PutOutcome::Created
    );
    assert_eq!(std::fs::read(&path).unwrap(), b);
    // The stray files are untouched; the create left none of its own.
    let mut expected = leftovers.clone();
    expected.push(path.file_name().unwrap().to_str().unwrap().to_owned());
    expected.sort();
    assert_eq!(names_in(parent), expected);

    // Every outcome removes its temp file.
    assert_eq!(
        store.put_if_absent(&k, b.clone()).await.unwrap(),
        PutOutcome::AlreadyPresent
    );
    assert_eq!(names_in(parent), expected);
    let planted = body(2048);
    let conflicted = key_for(&b);
    let conflicted_path = store.path_for(&conflicted).unwrap();
    std::fs::create_dir_all(conflicted_path.parent().unwrap()).unwrap();
    std::fs::write(&conflicted_path, &planted).unwrap();
    assert!(matches!(
        store.put_if_absent(&conflicted, b.clone()).await,
        Err(SqlStoreError::Conflict)
    ));
    assert_eq!(names_in(conflicted_path.parent().unwrap()).len(), 1);
    assert_eq!(std::fs::read(&conflicted_path).unwrap(), planted);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fs_keys_never_resolve_outside_the_root() {
    let (dir, store) = fs_store();
    for (space, db) in [
        ("tinycloud:../../escape", "v2n"),
        ("tinycloud:x", ".."),
        ("tinycloud:x", "a/b"),
        ("/etc", "/passwd"),
        ("tinycloud:x", "a\\b"),
        ("..", "."),
    ] {
        let b = body(32);
        let k = key_in(space, db, &b);
        let path = store.path_for(&k).unwrap();
        assert!(path.starts_with(store.root()), "{path:?}");
        assert_eq!(
            store.put_if_absent(&k, b.clone()).await.unwrap(),
            PutOutcome::Created
        );
        assert_eq!(std::fs::read(&path).unwrap(), b);
    }
    // Nothing was created beside the root.
    assert_eq!(names_in(dir.path()), vec!["sql-store".to_owned()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fs_large_objects_are_hashed_in_chunks_and_ranged() {
    let (_dir, store) = fs_store();
    let b: Vec<u8> = (0..(3 << 20) + 17).map(|i| (i % 253) as u8).collect();
    let k = key_for(&b);
    assert_eq!(
        store.put_if_absent(&k, b.clone()).await.unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        store.put_if_absent(&k, b.clone()).await.unwrap(),
        PutOutcome::AlreadyPresent
    );
    assert_eq!(
        store.head(&k).await.unwrap(),
        Some(ObjectMeta {
            bytes: b.len() as u64,
            sha256: sha256(&b)
        })
    );
    let start = (1 << 20) - 5;
    let got = part(
        &*store,
        &k,
        ByteRangeSpec::Inclusive {
            start: start as u64,
            end: (start + 10) as u64,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        got,
        (start as u64, b.len() as u64, b[start..=start + 10].to_vec())
    );
}

#[test]
fn fs_open_refuses_a_root_that_overlaps_the_block_store() {
    let (dir, _root, blocks) = fs_dirs();
    for root in [
        blocks.clone(),
        blocks.join("sql-store"),
        dir.path().to_path_buf(),
    ] {
        assert!(matches!(
            FsSqlObjectStore::open(root.clone(), &blocks),
            Err(SqlStoreError::Invalid(_))
        ));
    }
    assert!(!blocks.join("sql-store").exists());
    assert!(matches!(
        FsSqlObjectStore::open("relative/sql-store".into(), &blocks),
        Err(SqlStoreError::Invalid(_))
    ));
}

// ---------------------------------------------------------------------------
// S3: an in-process S3 API
// ---------------------------------------------------------------------------

const MOCK_BUCKET: &str = "tc1491";

/// How the in-process API answers a PUT with `If-None-Match: *`.
#[derive(Clone, Copy)]
enum Conditional {
    /// Refuses to replace an existing object (412), as S3 does.
    Honour,
    /// Replaces the object, as a provider ignoring the header does.
    Ignore,
    /// Answers with this status and error code.
    Reject(u16, &'static str),
}

/// key -> (body, x-amz-meta-sha256)
type Objects = BTreeMap<String, (Vec<u8>, Option<String>)>;

#[derive(Clone)]
struct MockS3 {
    objects: Arc<Mutex<Objects>>,
    conditional: Arc<Mutex<Conditional>>,
    requests: Arc<Mutex<Vec<String>>>,
}

fn reply(status: u16, headers: Vec<(&str, String)>, body: Vec<u8>) -> Response {
    let mut builder = Response::builder().status(StatusCode::from_u16(status).unwrap());
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(Body::from(body)).unwrap()
}

fn error_reply(status: u16, code: &str) -> Response {
    reply(
        status,
        vec![("content-type", "application/xml".into())],
        format!("<Error><Code>{code}</Code><Message>{code}</Message></Error>").into_bytes(),
    )
}

fn parse_range(value: &str) -> Option<ByteRangeSpec> {
    let (first, last) = value.strip_prefix("bytes=")?.split_once('-')?;
    Some(match (first, last) {
        ("", n) => ByteRangeSpec::Suffix {
            length: n.parse().ok()?,
        },
        (a, "") => ByteRangeSpec::From {
            start: a.parse().ok()?,
        },
        (a, b) => ByteRangeSpec::Inclusive {
            start: a.parse().ok()?,
            end: b.parse().ok()?,
        },
    })
}

async fn mock_api(
    State(s3): State<MockS3>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = percent_decode_str(uri.path())
        .decode_utf8_lossy()
        .into_owned();
    let rest = path.trim_start_matches('/');
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    if bucket != MOCK_BUCKET {
        return error_reply(404, "NoSuchBucket");
    }
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let mut objects = s3.objects.lock();
    match (&method, key.is_empty()) {
        (&Method::GET, true) => {
            let prefix = uri
                .query()
                .unwrap_or("")
                .split('&')
                .find_map(|pair| pair.strip_prefix("prefix="))
                .map(|p| percent_decode_str(p).decode_utf8_lossy().into_owned())
                .unwrap_or_default();
            s3.requests.lock().push(format!("LIST {prefix}"));
            let contents: String = objects
                .iter()
                .filter(|(key, _)| key.starts_with(&prefix))
                .map(|(key, (data, _))| {
                    format!(
                        "<Contents><Key>{key}</Key><Size>{}</Size></Contents>",
                        data.len()
                    )
                })
                .collect();
            reply(
                200,
                vec![("content-type", "application/xml".into())],
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult>\
                     <Name>{MOCK_BUCKET}</Name><IsTruncated>false</IsTruncated>{contents}\
                     </ListBucketResult>"
                )
                .into_bytes(),
            )
        }
        (&Method::PUT, false) => {
            let conditional = header("if-none-match").as_deref() == Some("*");
            s3.requests
                .lock()
                .push(format!("PUT {key} conditional={conditional}"));
            if conditional {
                match *s3.conditional.lock() {
                    Conditional::Reject(status, code) => return error_reply(status, code),
                    Conditional::Honour if objects.contains_key(key) => {
                        return error_reply(412, "PreconditionFailed")
                    }
                    _ => {}
                }
            }
            objects.insert(key.to_owned(), (body.to_vec(), header("x-amz-meta-sha256")));
            reply(200, vec![("etag", "\"mock\"".into())], Vec::new())
        }
        (&Method::HEAD, false) => {
            s3.requests.lock().push(format!("HEAD {key}"));
            match objects.get(key) {
                Some((data, sha)) => {
                    let mut headers = vec![("content-length", data.len().to_string())];
                    if let Some(sha) = sha {
                        headers.push(("x-amz-meta-sha256", sha.clone()));
                    }
                    reply(200, headers, Vec::new())
                }
                None => reply(404, Vec::new(), Vec::new()),
            }
        }
        (&Method::GET, false) => {
            s3.requests.lock().push(format!("GET {key}"));
            let Some((data, _)) = objects.get(key) else {
                return error_reply(404, "NoSuchKey");
            };
            let total = data.len() as u64;
            let Some(spec) = header("range").as_deref().and_then(parse_range) else {
                return reply(
                    200,
                    vec![("content-length", total.to_string())],
                    data.clone(),
                );
            };
            match spec.resolve(total) {
                None => error_reply(416, "InvalidRange"),
                Some(r) => {
                    let slice = data[r.start() as usize..=r.end() as usize].to_vec();
                    reply(
                        206,
                        vec![
                            ("content-length", slice.len().to_string()),
                            (
                                "content-range",
                                format!("bytes {}-{}/{total}", r.start(), r.end()),
                            ),
                        ],
                        slice,
                    )
                }
            }
        }
        _ => error_reply(501, "NotImplemented"),
    }
}

async fn start_mock(conditional: Conditional) -> Result<(MockS3, S3BlockConfig)> {
    // The S3 client reads credentials from the AWS_* environment.
    std::env::set_var("AWS_ACCESS_KEY_ID", "tc1491");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "tc1491");
    std::env::set_var("AWS_REGION", "us-east-1");
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    let s3 = MockS3 {
        objects: Arc::default(),
        conditional: Arc::new(Mutex::new(conditional)),
        requests: Arc::default(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let app = Router::new().fallback(mock_api).with_state(s3.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let config = serde_json::from_value(serde_json::json!({
        "bucket": MOCK_BUCKET,
        "endpoint": endpoint,
    }))?;
    Ok((s3, config))
}

// ---------------------------------------------------------------------------
// S3: tests shared by the in-process API and the harness MinIO
// ---------------------------------------------------------------------------

async fn limited<T>(what: &str, work: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), work)
        .await
        .unwrap_or_else(|_| panic!("{what} timed out after 30 s"))
}

/// Every call bounded by 30 s.
struct Timed<S>(S);

#[async_trait]
impl<S: SqlObjectStore> SqlObjectStore for Timed<S> {
    async fn put_if_absent(
        &self,
        key: &ObjectKey,
        body: Vec<u8>,
    ) -> Result<PutOutcome, SqlStoreError> {
        limited("put_if_absent", self.0.put_if_absent(key, body)).await
    }
    async fn get_range(
        &self,
        key: &ObjectKey,
        range: ByteRangeSpec,
    ) -> Result<Option<tinycloud_core::sql::store::ObjectRange>, SqlStoreError> {
        limited("get_range", self.0.get_range(key, range)).await
    }
    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError> {
        limited("head", self.0.head(key)).await
    }
}

/// Puts an object straight to S3, as an object written by something else.
struct S3Planter {
    store: Arc<S3SqlObjectStore>,
    with_metadata: bool,
}

impl S3Planter {
    async fn put_raw(&self, key: &ObjectKey, bytes: Vec<u8>) {
        let request = self
            .store
            .client()
            .put_object()
            .bucket(self.store.bucket())
            .key(key.as_str());
        let request = if self.with_metadata {
            request.metadata("sha256", hex::encode(sha256(&bytes)))
        } else {
            request
        };
        limited(
            "planting an object",
            request
                .body(aws_sdk_s3::primitives::ByteStream::from(bytes))
                .send(),
        )
        .await
        .unwrap();
    }
}

#[async_trait]
impl Planter for S3Planter {
    async fn plant(&self, key: &ObjectKey, bytes: Vec<u8>) {
        self.put_raw(key, bytes).await
    }
}

async fn s3_conformance(config: &S3BlockConfig, mode: WriteMode) {
    let store = Arc::new(S3SqlObjectStore::open_with_mode(config, mode).await);
    let planter = S3Planter {
        store: store.clone(),
        with_metadata: true,
    };
    struct Shared(Arc<S3SqlObjectStore>);
    #[async_trait]
    impl SqlObjectStore for Shared {
        async fn put_if_absent(
            &self,
            key: &ObjectKey,
            body: Vec<u8>,
        ) -> Result<PutOutcome, SqlStoreError> {
            self.0.put_if_absent(key, body).await
        }
        async fn get_range(
            &self,
            key: &ObjectKey,
            range: ByteRangeSpec,
        ) -> Result<Option<tinycloud_core::sql::store::ObjectRange>, SqlStoreError> {
            self.0.get_range(key, range).await
        }
        async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError> {
            self.0.head(key).await
        }
    }
    conformance(Arc::new(Timed(Shared(store))), Some(&planter)).await;
}

/// An object without the `sha256` metadata is never taken for a match.
async fn s3_object_without_hash_metadata_is_an_error(config: &S3BlockConfig, mode: WriteMode) {
    let store = Arc::new(Timed(S3SqlObjectStore::open_with_mode(config, mode).await));
    let raw = Arc::new(S3SqlObjectStore::open_with_mode(config, mode).await);
    let planter = S3Planter {
        store: raw,
        with_metadata: false,
    };
    let b = body(64);
    let k = key_for(&b);
    planter.plant(&k, b.clone()).await;
    assert!(matches!(
        store.head(&k).await,
        Err(SqlStoreError::Backend(_))
    ));
    assert!(matches!(
        store.put_if_absent(&k, b.clone()).await,
        Err(SqlStoreError::Backend(_))
    ));
    assert_eq!(whole(&*store, &k).await.unwrap(), b);
}

/// The KV boot scan lists `tinycloud:`-prefixed keys only: the sizes it
/// computes are the same with and without `sql/v1/` objects in the bucket.
async fn kv_scan_ignores_sql_objects(config: &S3BlockConfig) {
    let store = Arc::new(S3SqlObjectStore::open_with_mode(config, WriteMode::Conditional).await);
    let t = tag();
    let space = format!("tinycloud:key:scan:{t}");
    let sql_only = format!("tinycloud:key:sqlonly:{t}");
    let space_id: SpaceId = space.parse().unwrap();
    let sql_only_id: SpaceId = sql_only.parse().unwrap();
    let put_raw = |key: String, len: usize| {
        let store = store.clone();
        async move {
            limited(
                "raw put",
                store
                    .client()
                    .put_object()
                    .bucket(store.bucket())
                    .key(key)
                    .body(aws_sdk_s3::primitives::ByteStream::from(vec![7u8; len]))
                    .send(),
            )
            .await
            .unwrap();
        }
    };
    let open = || async {
        limited("block store open", async {
            StorageConfig::<S3BlockStore>::open(config).await.unwrap()
        })
        .await
    };
    let sizes = |store: S3BlockStore| {
        let (a, b) = (space_id.clone(), sql_only_id.clone());
        async move {
            (
                store.total_size(&a).await.unwrap(),
                store.total_size(&b).await.unwrap(),
            )
        }
    };

    // KV-style objects: `{space}/{hash}`.
    put_raw(format!("{space}/aaaa"), 5).await;
    put_raw(format!("{space}/bbbb"), 7).await;
    let before = sizes(open().await).await;
    assert_eq!(before, (Some(12), None));

    // SQL objects, through the store and as raw keys shaped like the
    // namespace: none of them belongs to a space.
    for len in [10, 4096, 1 << 20] {
        let b = body(len);
        let k = key_in(&space, "v2n", &b);
        assert!(k.as_str().starts_with("sql/v1/"));
        limited("sql put", store.put_if_absent(&k, b))
            .await
            .unwrap();
    }
    put_raw(format!("sql/v1/{space}/db/lineage/snap/x"), 1000).await;
    put_raw(format!("sql/v1/{sql_only}/db/x"), 2000).await;
    put_raw(format!("sql/v1/{sql_only}/x"), 3000).await;
    let after = sizes(open().await).await;
    assert_eq!(after, before);
}

// ---------------------------------------------------------------------------
// S3: in-process API
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mock_s3_conditional_conformance() -> Result<()> {
    let (_s3, config) = start_mock(Conditional::Honour).await?;
    s3_conformance(&config, WriteMode::Conditional).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mock_s3_check_then_write_conformance_with_a_provider_that_ignores_the_header() -> Result<()>
{
    let (_s3, config) = start_mock(Conditional::Ignore).await?;
    s3_conformance(&config, WriteMode::CheckThenWrite).await;
    Ok(())
}

#[tokio::test]
async fn mock_s3_object_without_hash_metadata_is_an_error() -> Result<()> {
    for mode in [WriteMode::Conditional, WriteMode::CheckThenWrite] {
        let (_s3, config) = start_mock(Conditional::Honour).await?;
        s3_object_without_hash_metadata_is_an_error(&config, mode).await;
    }
    Ok(())
}

#[tokio::test]
async fn mock_s3_kv_scan_ignores_sql_objects() -> Result<()> {
    let (s3, config) = start_mock(Conditional::Honour).await?;
    kv_scan_ignores_sql_objects(&config).await;
    // The scan asks for the KV key prefix only.
    let lists: Vec<String> = s3
        .requests
        .lock()
        .iter()
        .filter(|r| r.starts_with("LIST"))
        .cloned()
        .collect();
    assert!(
        !lists.is_empty() && lists.iter().all(|r| r == "LIST tinycloud:"),
        "{lists:?}"
    );
    Ok(())
}

#[tokio::test]
async fn mock_s3_body_mismatch_sends_no_request() -> Result<()> {
    for mode in [WriteMode::Conditional, WriteMode::CheckThenWrite] {
        let (s3, config) = start_mock(Conditional::Honour).await?;
        let store = S3SqlObjectStore::open_with_mode(&config, mode).await;
        let k = key_for(b"abc");
        assert!(matches!(
            store.put_if_absent(&k, b"abd".to_vec()).await,
            Err(SqlStoreError::BodyMismatch)
        ));
        assert!(s3.requests.lock().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn mock_s3_conditional_create_is_one_request_and_a_412_is_checked() -> Result<()> {
    let (s3, config) = start_mock(Conditional::Honour).await?;
    let store = S3SqlObjectStore::open_with_mode(&config, WriteMode::Conditional).await;
    let b = body(40);
    let k = key_for(&b);
    assert_eq!(
        store.put_if_absent(&k, b.clone()).await?,
        PutOutcome::Created
    );
    assert_eq!(s3.requests.lock().len(), 1);
    assert!(s3.requests.lock()[0].ends_with("conditional=true"));
    s3.requests.lock().clear();
    assert_eq!(
        store.put_if_absent(&k, b).await?,
        PutOutcome::AlreadyPresent
    );
    // The refused PUT, then the check of the stored object.
    let log = s3.requests.lock().clone();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log[0].starts_with("PUT ") && log[1].starts_with("HEAD "));
    Ok(())
}

#[tokio::test]
async fn mock_s3_check_then_write_never_sends_an_unconditional_put_for_an_existing_object(
) -> Result<()> {
    let (s3, config) = start_mock(Conditional::Ignore).await?;
    let store = S3SqlObjectStore::open_with_mode(&config, WriteMode::CheckThenWrite).await;
    let b = body(40);
    let k = key_for(&b);
    assert_eq!(
        store.put_if_absent(&k, b.clone()).await?,
        PutOutcome::Created
    );
    s3.requests.lock().clear();
    assert_eq!(
        store.put_if_absent(&k, b).await?,
        PutOutcome::AlreadyPresent
    );
    let log = s3.requests.lock().clone();
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(log[0].starts_with("HEAD "));
    Ok(())
}

async fn probe_against(
    conditional: Conditional,
) -> Result<(MockS3, Result<WriteMode, SqlStoreError>)> {
    let (s3, config) = start_mock(conditional).await?;
    let store = S3SqlObjectStore::open_with_mode(&config, WriteMode::Conditional).await;
    let mode = S3SqlObjectStore::probe(store.client(), store.bucket()).await;
    Ok((s3, mode))
}

#[tokio::test]
async fn mock_s3_probe_selects_the_mode_the_provider_supports() -> Result<()> {
    // Honoured: the second request is refused.
    let (s3, mode) = probe_against(Conditional::Honour).await?;
    assert_eq!(mode?, WriteMode::Conditional);
    assert_eq!(
        *s3.requests.lock(),
        vec![
            "PUT sql/v1/_probe/v1 conditional=true",
            "PUT sql/v1/_probe/v1 conditional=true"
        ]
    );
    assert!(s3.objects.lock().contains_key("sql/v1/_probe/v1"));

    // Ignored: the second request succeeds.
    let (s3, mode) = probe_against(Conditional::Ignore).await?;
    assert_eq!(mode?, WriteMode::CheckThenWrite);
    assert_eq!(s3.requests.lock().len(), 2);

    // The provider rejects the header.
    for (status, code) in [(501, "NotImplemented"), (400, "InvalidArgument")] {
        let (_s3, mode) = probe_against(Conditional::Reject(status, code)).await?;
        assert_eq!(mode?, WriteMode::CheckThenWrite, "{status}");
    }

    // Any other failure is an error, not a silent fallback.
    for (status, code) in [(500, "InternalError"), (403, "AccessDenied")] {
        let (_s3, mode) = probe_against(Conditional::Reject(status, code)).await?;
        assert!(matches!(mode, Err(SqlStoreError::Backend(_))), "{status}");
    }
    Ok(())
}

#[tokio::test]
async fn mock_s3_probe_object_from_an_earlier_start_is_not_overwritten() -> Result<()> {
    let (s3, config) = start_mock(Conditional::Honour).await?;
    let store = S3SqlObjectStore::open_with_mode(&config, WriteMode::Conditional).await;
    for _ in 0..2 {
        let mode = S3SqlObjectStore::probe(store.client(), store.bucket()).await?;
        assert_eq!(mode, WriteMode::Conditional);
    }
    // First start: created, then refused. Second start: refused at once.
    assert_eq!(s3.requests.lock().len(), 3);
    assert_eq!(s3.objects.lock().len(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// S3: the at-rest harness MinIO
// ---------------------------------------------------------------------------

fn env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} (load the harness env)"))
}

fn minio_config() -> Result<S3BlockConfig> {
    // The S3 client reads credentials from the AWS_* environment.
    std::env::set_var("AWS_ACCESS_KEY_ID", env("TC887_S3_ACCESS_KEY_ID")?);
    std::env::set_var("AWS_SECRET_ACCESS_KEY", env("TC887_S3_SECRET_ACCESS_KEY")?);
    std::env::set_var("AWS_REGION", env("TC887_S3_REGION")?);
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    Ok(serde_json::from_value(serde_json::json!({
        "bucket": env("TC887_S3_BUCKET")?,
        "endpoint": env("TC887_S3_ENDPOINT")?,
    }))?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn minio_probe_selects_conditional_writes() -> Result<()> {
    let config = minio_config()?;
    let store = S3SqlObjectStore::open_with_mode(&config, WriteMode::Conditional).await;
    for _ in 0..2 {
        let mode = limited(
            "probe",
            S3SqlObjectStore::probe(store.client(), store.bucket()),
        )
        .await?;
        println!("sql object store probe selected {}", mode.as_str());
        assert_eq!(mode, WriteMode::Conditional);
    }
    // `open` runs the probe and keeps its answer.
    let opened = limited("open", S3SqlObjectStore::open(&config)).await?;
    assert_eq!(opened.mode(), WriteMode::Conditional);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn minio_conditional_conformance() -> Result<()> {
    s3_conformance(&minio_config()?, WriteMode::Conditional).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn minio_check_then_write_conformance() -> Result<()> {
    s3_conformance(&minio_config()?, WriteMode::CheckThenWrite).await;
    Ok(())
}

/// The provider itself: concurrent conditional PUTs of one key, with no
/// store in between. Exactly one is created; the others are refused with 412
/// (or 409 while another write of the key is in flight), and none hangs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn minio_concurrent_conditional_puts_create_one_object() -> Result<()> {
    let config = minio_config()?;
    let store = Arc::new(S3SqlObjectStore::open_with_mode(&config, WriteMode::Conditional).await);
    for round in 0..10 {
        let b = body(1024);
        let key = key_for(&b);
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (store, key, b) = (store.clone(), key.as_str().to_owned(), b.clone());
                tokio::spawn(async move {
                    let started = std::time::Instant::now();
                    let result = limited(
                        "conditional put",
                        store
                            .client()
                            .put_object()
                            .bucket(store.bucket())
                            .key(key)
                            .if_none_match("*")
                            .body(aws_sdk_s3::primitives::ByteStream::from(b))
                            .send(),
                    )
                    .await;
                    let outcome = match result {
                        Ok(_) => "created".to_owned(),
                        Err(e) => {
                            format!("status {:?}", e.raw_response().map(|r| r.status().as_u16()))
                        }
                    };
                    (outcome, started.elapsed())
                })
            })
            .collect();
        let mut outcomes = Vec::new();
        for task in tasks {
            outcomes.push(task.await?);
        }
        let created = outcomes.iter().filter(|(o, _)| o == "created").count();
        let refused = outcomes
            .iter()
            .filter(|(o, _)| o == "status Some(412)" || o == "status Some(409)")
            .count();
        assert!(created == 1 && refused == 7, "round {round}: {outcomes:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn minio_object_without_hash_metadata_is_an_error() -> Result<()> {
    let config = minio_config()?;
    for mode in [WriteMode::Conditional, WriteMode::CheckThenWrite] {
        s3_object_without_hash_metadata_is_an_error(&config, mode).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn minio_kv_scan_ignores_sql_objects() -> Result<()> {
    kv_scan_ignores_sql_objects(&minio_config()?).await;
    Ok(())
}
