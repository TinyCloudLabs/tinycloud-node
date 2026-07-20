use rand::RngCore;
use rocket::{
    data::{Data, ToByteUnit},
    http::{ContentType, Header, Status},
    request::{FromRequest, Outcome, Request},
    response::{self, Responder, Response},
    State,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::Cursor,
    str::FromStr,
    time::{Duration, Instant},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::{
    cacaos::siwe::{encode_eip55, Message},
    resource::{Path as TinyPath, ResourceId, Service, SpaceId},
    siwe_recap::{Ability as RecapAbility, Capability as RecapCapability},
};
use tinycloud_core::{
    hash::{hash, Hash},
    sea_orm::{
        ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, QueryResult, Statement,
        TransactionTrait,
    },
};

use crate::config::TcBenchConfig;
use crate::routes::public::RawKeyPath;

const MAX_BLOCK_BYTES: u64 = 8 * 1024 * 1024;
const CONTRACT_BLAKE3: &str =
    "1e205ad6e946aa0531e1b0eace481d37f6e8eab41f306ae9930728fa2200e562d2e2";
const GOLDEN_VECTORS_BLAKE3: &str =
    "1e2096624e1af33369aad3a0d2b0b57d157062f44cbe3bfdce3298c3cb762171bce4";
const BLOCK_FIXTURES_BLAKE3: &str =
    "1e205f04e79a84c3456b69170bdf1d2542ab6f7c4d0774f6ba7892283e7eee5c78ea";

const BLOCK_GET_ACTIONS: &[&str] = &["tinycloud.kv/get", "tinycloud.kv/put"];

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactHashes {
    pub contract_blake3: &'static str,
    pub golden_vectors_blake3: &'static str,
    pub block_fixtures_blake3: &'static str,
    pub worker_bundle_sha256: String,
    pub wasm_bundle_sha256: String,
}

impl Default for ArtifactHashes {
    fn default() -> Self {
        Self {
            contract_blake3: CONTRACT_BLAKE3,
            golden_vectors_blake3: GOLDEN_VECTORS_BLAKE3,
            block_fixtures_blake3: BLOCK_FIXTURES_BLAKE3,
            worker_bundle_sha256: String::new(),
            wasm_bundle_sha256: String::new(),
        }
    }
}

impl ArtifactHashes {
    fn from_config(config: &TcBenchConfig) -> Result<Self, DbErr> {
        Ok(Self {
            contract_blake3: CONTRACT_BLAKE3,
            golden_vectors_blake3: GOLDEN_VECTORS_BLAKE3,
            block_fixtures_blake3: BLOCK_FIXTURES_BLAKE3,
            worker_bundle_sha256: required_sha256_config(
                "tc_bench.worker_bundle_sha256",
                config.worker_bundle_sha256.as_deref(),
            )?,
            wasm_bundle_sha256: required_sha256_config(
                "tc_bench.wasm_bundle_sha256",
                config.wasm_bundle_sha256.as_deref(),
            )?,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SqliteHealth {
    pub journal_mode: String,
    pub synchronous: String,
    pub pool_size: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchHealth {
    pub ok: bool,
    pub suite: &'static str,
    pub target: &'static str,
    pub region: String,
    pub connection_mode: &'static str,
    pub artifact_hashes: ArtifactHashes,
    pub sqlite: SqliteHealth,
}

#[derive(Clone, Debug)]
pub struct BenchState {
    db: DatabaseConnection,
    region: String,
    sqlite: SqliteHealth,
    artifact_hashes: ArtifactHashes,
}

#[derive(Debug, Clone)]
pub struct BenchSessionToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BenchSessionToken {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(raw) = request
            .headers()
            .get_one("Authorization")
            .or_else(|| request.headers().get_one("X-Bench-Session"))
        else {
            return Outcome::Forward(Status::Unauthorized);
        };
        let token = raw
            .strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("bearer "))
            .unwrap_or(raw)
            .to_string();
        Outcome::Success(BenchSessionToken(token))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredCapability {
    pub service: String,
    pub space: String,
    pub path: String,
    pub action: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthVerifyRequest {
    pub siwe: String,
    pub signature: String,
    #[serde(rename = "requiredCapability")]
    pub required_capability: RequiredCapability,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthVerifySession {
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthVerifyResponse {
    pub ok: bool,
    pub principal_did: String,
    pub address: String,
    pub recap_depth: usize,
    pub session: AuthVerifySession,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KvPutRequest {
    pub value: Value,
    pub content_type: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KvResponse {
    pub ok: bool,
    pub space: String,
    pub path: String,
    pub content_type: String,
    pub content_hash: String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KvPutResponse {
    pub ok: bool,
    pub space: String,
    pub path: String,
    pub content_hash: String,
    pub etag: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockResponse {
    pub ok: bool,
    pub multihash: String,
    pub size_bytes: usize,
    pub etag: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
struct BenchError {
    status: Status,
    code: &'static str,
    message: String,
}

impl BenchError {
    fn new(status: Status, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn bad_json(message: impl Into<String>) -> Self {
        Self::new(Status::BadRequest, "BAD_JSON", message)
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(Status::BadRequest, "BAD_REQUEST", message)
    }

    fn auth_missing(message: impl Into<String>) -> Self {
        Self::new(Status::Unauthorized, "AUTH_MISSING", message)
    }

    fn auth_invalid_signature(message: impl Into<String>) -> Self {
        Self::new(Status::Unauthorized, "AUTH_INVALID_SIGNATURE", message)
    }

    fn auth_expired(message: impl Into<String>) -> Self {
        Self::new(Status::Unauthorized, "AUTH_EXPIRED", message)
    }

    fn nonce_replay(message: impl Into<String>) -> Self {
        Self::new(Status::Conflict, "NONCE_REPLAY", message)
    }

    fn ability_denied(message: impl Into<String>) -> Self {
        Self::new(Status::Forbidden, "ABILITY_DENIED", message)
    }

    fn kv_not_found(message: impl Into<String>) -> Self {
        Self::new(Status::NotFound, "KV_NOT_FOUND", message)
    }

    fn block_not_found(message: impl Into<String>) -> Self {
        Self::new(Status::NotFound, "BLOCK_NOT_FOUND", message)
    }

    fn block_too_large(message: impl Into<String>) -> Self {
        Self::new(Status::PayloadTooLarge, "BLOCK_TOO_LARGE", message)
    }

    fn digest_mismatch(message: impl Into<String>) -> Self {
        Self::new(Status::UnprocessableEntity, "DIGEST_MISMATCH", message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(Status::InternalServerError, "INTERNAL", message)
    }
}

#[derive(Debug, Clone)]
struct BenchTimings {
    stages: Vec<(&'static str, Duration)>,
}

#[derive(Debug)]
pub struct BenchResponder(Response<'static>);

impl BenchResponder {
    fn new(response: Response<'static>) -> Self {
        Self(response)
    }
}

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for BenchResponder {
    fn respond_to(self, request: &'r Request<'_>) -> response::Result<'static> {
        let _ = request;
        Ok(self.0)
    }
}

impl BenchTimings {
    fn new() -> Self {
        Self { stages: Vec::new() }
    }

    fn record(&mut self, stage: &'static str, duration: Duration) {
        self.stages.push((stage, duration));
    }

    fn header_value(&self) -> String {
        self.stages
            .iter()
            .map(|(stage, duration)| format!("{stage};dur={:.3}", duration.as_secs_f64() * 1000.0))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl BenchState {
    pub async fn new(
        config: &TcBenchConfig,
        db: DatabaseConnection,
        sqlite_pool_size: u32,
    ) -> Result<Self, DbErr> {
        let sqlite = SqliteHealth {
            journal_mode: "WAL".to_string(),
            synchronous: "default".to_string(),
            pool_size: sqlite_pool_size,
        };
        let state = Self {
            db,
            region: config.region.clone(),
            sqlite,
            artifact_hashes: ArtifactHashes::from_config(config)?,
        };
        state.ensure_schema().await?;
        Ok(state)
    }

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    fn region(&self) -> String {
        self.region.clone()
    }

    fn health(&self) -> BenchHealth {
        BenchHealth {
            ok: true,
            suite: "tc-bench-v1",
            target: "rust-node-phala-cvm",
            region: self.region(),
            connection_mode: "direct",
            artifact_hashes: self.artifact_hashes.clone(),
            sqlite: self.sqlite.clone(),
        }
    }

    async fn ensure_schema(&self) -> Result<(), DbErr> {
        if self.db.get_database_backend() != DatabaseBackend::Sqlite {
            return Ok(());
        }

        for sql in [
            r#"
            CREATE TABLE IF NOT EXISTS tc_bench_sessions (
                token TEXT PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE,
                principal_did TEXT NOT NULL,
                address TEXT NOT NULL,
                recap_depth INTEGER NOT NULL,
                service TEXT NOT NULL,
                space TEXT NOT NULL,
                path TEXT NOT NULL,
                action TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            "#,
            r#"
            CREATE TABLE IF NOT EXISTS tc_bench_kv (
                space TEXT NOT NULL,
                path TEXT NOT NULL,
                value_json TEXT NOT NULL,
                content_type TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                etag TEXT NOT NULL,
                PRIMARY KEY(space, path)
            )
            "#,
            r#"
            CREATE TABLE IF NOT EXISTS tc_bench_blocks (
                multihash TEXT PRIMARY KEY,
                bytes BLOB NOT NULL,
                size_bytes INTEGER NOT NULL,
                etag TEXT NOT NULL
            )
            "#,
        ] {
            self.db
                .execute(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    sql.to_string(),
                ))
                .await?;
        }

        Ok(())
    }
}

fn response_with_headers(
    status: Status,
    content_type: ContentType,
    body: Vec<u8>,
    timings: &BenchTimings,
) -> BenchResponder {
    let request_id = random_token();
    let mut response = Response::build();
    response.status(status);
    response.header(content_type);
    response.header(Header::new("Cache-Control", "no-store"));
    response.header(Header::new("Server-Timing", timings.header_value()));
    response.header(Header::new("X-TC-Request-ID", request_id.clone()));
    response.header(Header::new("X-TC-Executed", request_id));
    response.sized_body(body.len(), Cursor::new(body));
    BenchResponder::new(response.finalize())
}

fn json_response<T: Serialize>(
    status: Status,
    value: &T,
    timings: &mut BenchTimings,
) -> BenchResponder {
    let serialize_start = Instant::now();
    let body = match serde_json::to_vec(value) {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                BenchError::internal("failed to serialize response"),
                timings,
            )
        }
    };
    timings.record("serialize", serialize_start.elapsed());
    response_with_headers(status, ContentType::JSON, body, timings)
}

fn error_response(error: BenchError, timings: &BenchTimings) -> BenchResponder {
    let mut timings = timings.clone();
    let serialize_start = Instant::now();
    let body = serde_json::to_vec(&ErrorEnvelope {
        error: ErrorBody {
            code: error.code,
            message: error.message,
        },
    })
    .unwrap_or_else(|_| {
        br#"{"error":{"code":"INTERNAL","message":"failed to serialize error response"}}"#.to_vec()
    });
    timings.record("serialize", serialize_start.elapsed());
    response_with_headers(error.status, ContentType::JSON, body, &timings)
}

fn parse_json_body<T: for<'de> Deserialize<'de>>(body: &str) -> Result<T, BenchError> {
    serde_json::from_str(body).map_err(|e| BenchError::bad_json(e.to_string()))
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(canonicalize_json)
                .collect::<Vec<_>>(),
        ),
        Value::Object(values) => {
            let mut map = BTreeMap::new();
            for (k, v) in values {
                map.insert(k, canonicalize_json(v));
            }
            Value::Object(map.into_iter().collect())
        }
        other => other,
    }
}

fn hex_to_hash(hex_str: &str) -> Result<Hash, BenchError> {
    let decoded = hex::decode(hex_str).map_err(|e| BenchError::bad_request(e.to_string()))?;
    Hash::try_from(decoded).map_err(|e| BenchError::bad_request(e.to_string()))
}

fn blake3_content_hash(bytes: &[u8]) -> String {
    format!("blake3-{}", hex::encode(hash(bytes).as_ref()))
}

fn eip55_address(bytes: &[u8]) -> Result<String, BenchError> {
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|_| BenchError::auth_invalid_signature("expected 20-byte EVM address"))?;
    Ok(format!("0x{}", encode_eip55(&address)))
}

fn principal_did(chain_id: u64, address: &str) -> String {
    format!("did:pkh:eip155:{chain_id}:{address}")
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn required_resource(required: &RequiredCapability) -> Result<ResourceId, BenchError> {
    let space = SpaceId::from_str(&required.space)
        .map_err(|_| BenchError::bad_request("invalid requiredCapability.space"))?;
    let service = Service::from_str(&required.service)
        .map_err(|_| BenchError::bad_request("invalid requiredCapability.service"))?;
    let path = TinyPath::from_str(&required.path)
        .map_err(|_| BenchError::bad_request("invalid requiredCapability.path"))?;
    Ok(space.to_resource(service, Some(path), None, None))
}

fn normalize_bench_service(service: &str) -> String {
    if service.starts_with("tinycloud.") {
        service.to_string()
    } else {
        format!("tinycloud.{service}")
    }
}

fn path_contains(granted_path: &str, requested_path: &str) -> bool {
    if granted_path.is_empty() || granted_path == "/" {
        return true;
    }
    if granted_path == requested_path {
        return true;
    }
    if granted_path.ends_with('/') {
        return requested_path.starts_with(granted_path);
    }
    if requested_path.ends_with('/') {
        return granted_path.starts_with(requested_path);
    }
    if requested_path.ends_with(&format!("/{granted_path}")) {
        return true;
    }
    requested_path.ends_with(&format!("/{granted_path}"))
}

fn recap_matches_required_capability(
    recap: &RecapCapability<()>,
    required: &RequiredCapability,
    _required_resource: &ResourceId,
    required_action: &RecapAbility,
) -> bool {
    recap.abilities().iter().any(|(resource_uri, actions)| {
        let Ok(granted_resource) = ResourceId::from_str(resource_uri.as_str()) else {
            return false;
        };
        normalize_bench_service(granted_resource.service().as_str())
            == normalize_bench_service(&required.service)
            && granted_resource.space().to_string() == required.space
            && path_contains(
                granted_resource
                    .path()
                    .map(|path| path.as_str())
                    .unwrap_or(""),
                &required.path,
            )
            && actions.keys().any(|ability| ability == required_action)
    })
}

fn session_expired(expires_at: &str) -> Result<bool, BenchError> {
    let expires_at = OffsetDateTime::parse(expires_at, &Rfc3339)
        .map_err(|e| BenchError::internal(e.to_string()))?;
    Ok(OffsetDateTime::now_utc() >= expires_at)
}

async fn load_session<C>(db: &C, token: &str) -> Result<Option<BenchSessionRow>, DbErr>
where
    C: ConnectionTrait + ?Sized,
{
    let statement = Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT token, nonce, principal_did, address, recap_depth, service, space, path, action, expires_at FROM tc_bench_sessions WHERE token = ?".to_string(),
        vec![token.into()],
    );
    let row = db.query_one(statement).await?;
    match row {
        None => Ok(None),
        Some(row) => Ok(Some(BenchSessionRow::try_from(row)?)),
    }
}

async fn load_kv<C>(db: &C, space: &SpaceId, path: &str) -> Result<Option<BenchKvRow>, DbErr>
where
    C: ConnectionTrait + ?Sized,
{
    let statement = Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT space, path, value_json, content_type, content_hash FROM tc_bench_kv WHERE space = ? AND path = ?".to_string(),
        vec![space.to_string().into(), path.to_string().into()],
    );
    let row = db.query_one(statement).await?;
    match row {
        None => Ok(None),
        Some(row) => Ok(Some(BenchKvRow::try_from(row)?)),
    }
}

async fn load_block<C>(db: &C, multihash: &str) -> Result<Option<BenchBlockRow>, DbErr>
where
    C: ConnectionTrait + ?Sized,
{
    let statement = Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT bytes FROM tc_bench_blocks WHERE multihash = ?".to_string(),
        vec![multihash.to_string().into()],
    );
    let row = db.query_one(statement).await?;
    match row {
        None => Ok(None),
        Some(row) => Ok(Some(BenchBlockRow::try_from(row)?)),
    }
}

fn parse_signature(signature: &str) -> Result<[u8; 65], BenchError> {
    let signature = signature.strip_prefix("0x").unwrap_or(signature);
    let bytes =
        hex::decode(signature).map_err(|e| BenchError::auth_invalid_signature(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| BenchError::auth_invalid_signature("signature must be 65 bytes"))
}

fn verify_block_session(session: &BenchSessionRow) -> Result<(), BenchError> {
    if session.service != "tinycloud.kv"
        || !BLOCK_GET_ACTIONS
            .iter()
            .any(|action| *action == session.action)
    {
        return Err(BenchError::ability_denied(
            "session does not authorize block access",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct BenchSessionRow {
    token: String,
    nonce: String,
    principal_did: String,
    address: String,
    recap_depth: usize,
    service: String,
    space: String,
    path: String,
    action: String,
    expires_at: String,
}

impl TryFrom<QueryResult> for BenchSessionRow {
    type Error = DbErr;

    fn try_from(row: QueryResult) -> Result<Self, Self::Error> {
        Ok(Self {
            token: row.try_get("", "token")?,
            nonce: row.try_get("", "nonce")?,
            principal_did: row.try_get("", "principal_did")?,
            address: row.try_get("", "address")?,
            recap_depth: row.try_get::<i64>("", "recap_depth")? as usize,
            service: row.try_get("", "service")?,
            space: row.try_get("", "space")?,
            path: row.try_get("", "path")?,
            action: row.try_get("", "action")?,
            expires_at: row.try_get("", "expires_at")?,
        })
    }
}

#[derive(Debug)]
struct BenchKvRow {
    space: String,
    path: String,
    value_json: String,
    content_type: String,
    content_hash: String,
}

impl TryFrom<QueryResult> for BenchKvRow {
    type Error = DbErr;

    fn try_from(row: QueryResult) -> Result<Self, Self::Error> {
        Ok(Self {
            space: row.try_get("", "space")?,
            path: row.try_get("", "path")?,
            value_json: row.try_get("", "value_json")?,
            content_type: row.try_get("", "content_type")?,
            content_hash: row.try_get("", "content_hash")?,
        })
    }
}

#[derive(Debug)]
struct BenchBlockRow {
    bytes: Vec<u8>,
}

impl TryFrom<QueryResult> for BenchBlockRow {
    type Error = DbErr;

    fn try_from(row: QueryResult) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: row.try_get("", "bytes")?,
        })
    }
}

async fn store_session(state: &BenchState, session: &BenchSessionRow) -> Result<bool, DbErr> {
    let tx = state.db().begin().await?;
    let result = tx.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT OR IGNORE INTO tc_bench_sessions (token, nonce, principal_did, address, recap_depth, service, space, path, action, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)".to_string(),
        vec![
            session.token.clone().into(),
            session.nonce.clone().into(),
            session.principal_did.clone().into(),
            session.address.clone().into(),
            (session.recap_depth as i64).into(),
            session.service.clone().into(),
            session.space.clone().into(),
            session.path.clone().into(),
            session.action.clone().into(),
            session.expires_at.clone().into(),
        ],
    ))
    .await?;
    if result.rows_affected() == 0 {
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

async fn upsert_kv(
    state: &BenchState,
    space: &SpaceId,
    path: &str,
    value_json: &str,
    content_type: &str,
    content_hash: &str,
    etag: &str,
) -> Result<bool, DbErr> {
    let tx = state.db().begin().await?;
    let existed = load_kv(&tx, space, path).await?.is_some();
    tx.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT OR REPLACE INTO tc_bench_kv (space, path, value_json, content_type, content_hash, etag) VALUES (?, ?, ?, ?, ?, ?)".to_string(),
        vec![
            space.to_string().into(),
            path.to_string().into(),
            value_json.to_string().into(),
            content_type.to_string().into(),
            content_hash.to_string().into(),
            etag.to_string().into(),
        ],
    ))
    .await?;
    tx.commit().await?;
    Ok(!existed)
}

async fn upsert_block(
    state: &BenchState,
    multihash: &str,
    bytes: &[u8],
    size_bytes: usize,
    etag: &str,
) -> Result<bool, DbErr> {
    let tx = state.db().begin().await?;
    let existed = load_block(&tx, multihash).await?.is_some();
    tx.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT OR REPLACE INTO tc_bench_blocks (multihash, bytes, size_bytes, etag) VALUES (?, ?, ?, ?)".to_string(),
        vec![
            multihash.to_string().into(),
            bytes.to_vec().into(),
            (size_bytes as i64).into(),
            etag.to_string().into(),
        ],
    ))
    .await?;
    tx.commit().await?;
    Ok(!existed)
}

fn json_error(error: BenchError, timings: &BenchTimings) -> BenchResponder {
    error_response(error, timings)
}

fn build_json_body<T: Serialize>(
    status: Status,
    value: &T,
    timings: &mut BenchTimings,
) -> BenchResponder {
    json_response(status, value, timings)
}

fn response_json_error(error: BenchError, timings: &BenchTimings) -> BenchResponder {
    json_error(error, timings)
}

fn required_sha256_config(name: &str, value: Option<&str>) -> Result<String, DbErr> {
    let value =
        value.ok_or_else(|| DbErr::Custom(format!("missing required config field {name}")))?;
    if value.len() != 64
        || !value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(DbErr::Custom(format!(
            "config field {name} must be a 64-character hexadecimal string"
        )));
    }
    Ok(value.to_string())
}

#[post("/auth/verify", data = "<body>")]
pub async fn auth_verify(body: String, state: &State<BenchState>) -> BenchResponder {
    let mut timings = BenchTimings::new();
    let parse_start = Instant::now();
    let request: AuthVerifyRequest = match parse_json_body(&body) {
        Ok(request) => request,
        Err(err) => return response_json_error(err, &timings),
    };
    timings.record("parse", parse_start.elapsed());

    let auth_start = Instant::now();
    let message = match Message::from_str(&request.siwe) {
        Ok(message) => message,
        Err(e) => return response_json_error(BenchError::bad_request(e.to_string()), &timings),
    };

    if !message.valid_now() {
        return response_json_error(
            BenchError::auth_expired("SIWE message is expired"),
            &timings,
        );
    }

    let signature = match parse_signature(&request.signature) {
        Ok(signature) => signature,
        Err(err) => return response_json_error(err, &timings),
    };

    let _recovered = match message.verify_eip191(&signature) {
        Ok(recovered) => recovered,
        Err(e) => {
            return response_json_error(BenchError::auth_invalid_signature(e.to_string()), &timings)
        }
    };

    let message_address = match eip55_address(&message.address) {
        Ok(address) => address,
        Err(err) => return response_json_error(err, &timings),
    };

    timings.record("auth", auth_start.elapsed());

    let delegation_start = Instant::now();
    let recap = match RecapCapability::<()>::extract_and_verify(&message) {
        Ok(Some(recap)) => recap,
        Ok(None) => {
            return response_json_error(
                BenchError::auth_missing("missing ReCap resource"),
                &timings,
            )
        }
        Err(e) => {
            let message = match e {
                tinycloud_auth::siwe_recap::VerificationError::IncorrectStatement(_) => {
                    "SIWE statement does not match the embedded ReCap"
                }
                tinycloud_auth::siwe_recap::VerificationError::Decoding(_) => {
                    "invalid embedded ReCap"
                }
            };
            return response_json_error(BenchError::ability_denied(message), &timings);
        }
    };

    let required_resource = match required_resource(&request.required_capability) {
        Ok(resource) => resource,
        Err(err) => return response_json_error(err, &timings),
    };
    let required_action = match RecapAbility::try_from(request.required_capability.action.clone()) {
        Ok(action) => action,
        Err(e) => return response_json_error(BenchError::bad_request(e.to_string()), &timings),
    };

    if !recap_matches_required_capability(
        &recap,
        &request.required_capability,
        &required_resource,
        &required_action,
    ) {
        return response_json_error(
            BenchError::ability_denied("required capability not covered by the recap"),
            &timings,
        );
    }

    let expires_at = match message.expiration_time {
        Some(timestamp) => timestamp.to_string(),
        None => {
            return response_json_error(
                BenchError::bad_request("SIWE message missing expiration time"),
                &timings,
            )
        }
    };
    let session = BenchSessionRow {
        token: random_token(),
        nonce: message.nonce.clone(),
        principal_did: principal_did(message.chain_id, &message_address),
        address: message_address,
        recap_depth: recap.proof().len(),
        service: request.required_capability.service.clone(),
        space: request.required_capability.space.clone(),
        path: request.required_capability.path.clone(),
        action: request.required_capability.action.clone(),
        expires_at,
    };

    let store_result = store_session(state, &session).await;
    timings.record("delegation", delegation_start.elapsed());
    match store_result {
        Ok(true) => {}
        Ok(false) => {
            return response_json_error(BenchError::nonce_replay("nonce already used"), &timings)
        }
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    }

    let response = AuthVerifyResponse {
        ok: true,
        principal_did: session.principal_did.clone(),
        address: session.address.clone(),
        recap_depth: session.recap_depth,
        session: AuthVerifySession {
            token: session.token.clone(),
            expires_at: session.expires_at.clone(),
        },
    };
    build_json_body(Status::Ok, &response, &mut timings)
}

#[put("/kv/<space>/<path..>", data = "<body>")]
pub async fn kv_put(
    space: &str,
    path: RawKeyPath,
    body: String,
    token: Option<BenchSessionToken>,
    state: &State<BenchState>,
) -> BenchResponder {
    let mut timings = BenchTimings::new();
    let path = path.0;
    let parse_start = Instant::now();
    let request: KvPutRequest = match parse_json_body(&body) {
        Ok(request) => request,
        Err(err) => return response_json_error(err, &timings),
    };
    timings.record("parse", parse_start.elapsed());

    let auth_start = Instant::now();
    let token = match token {
        Some(token) => token.0,
        None => {
            return response_json_error(
                BenchError::auth_missing("missing benchmark session token"),
                &timings,
            )
        }
    };
    let session = match load_session(state.inner().db(), &token).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return response_json_error(
                BenchError::auth_missing("unknown benchmark session token"),
                &timings,
            )
        }
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    };
    if session_expired(&session.expires_at).unwrap_or(true) {
        return response_json_error(
            BenchError::auth_expired("benchmark session expired"),
            &timings,
        );
    }
    timings.record("auth", auth_start.elapsed());

    let delegation_start = Instant::now();
    let space_id = match SpaceId::from_str(space) {
        Ok(space) => space,
        Err(_) => {
            return response_json_error(BenchError::bad_request("invalid space ID"), &timings)
        }
    };
    if session.service != "tinycloud.kv"
        || session.space != space_id.to_string()
        || session.path != path
        || session.action != "tinycloud.kv/put"
    {
        return response_json_error(
            BenchError::ability_denied("session does not authorize the requested KV write"),
            &timings,
        );
    }

    if request.content_type != "application/json" {
        return response_json_error(
            BenchError::bad_request("contentType must be application/json"),
            &timings,
        );
    }

    let canonical = canonicalize_json(request.value);
    if !canonical.is_object() {
        return response_json_error(
            BenchError::bad_request("value must be a JSON object"),
            &timings,
        );
    }
    let canonical_bytes = match serde_json::to_vec(&canonical) {
        Ok(bytes) => bytes,
        Err(e) => return response_json_error(BenchError::internal(e.to_string()), &timings),
    };
    let actual_hash = blake3_content_hash(&canonical_bytes);
    if actual_hash != request.content_hash {
        return response_json_error(
            BenchError::digest_mismatch("declared contentHash did not match the JSON body"),
            &timings,
        );
    }
    timings.record("delegation", delegation_start.elapsed());

    let sqlite_start = Instant::now();
    let etag = format!("\"{}\"", actual_hash);
    let existed = match upsert_kv(
        state,
        &space_id,
        &path,
        &serde_json::to_string(&canonical).unwrap_or_else(|_| "{}".to_string()),
        &request.content_type,
        &request.content_hash,
        &etag,
    )
    .await
    {
        Ok(created) => !created,
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    };
    timings.record("sqlite", sqlite_start.elapsed());

    let response = KvPutResponse {
        ok: true,
        space: space_id.to_string(),
        path,
        content_hash: request.content_hash,
        etag,
    };
    build_json_body(
        if existed { Status::Ok } else { Status::Created },
        &response,
        &mut timings,
    )
}

#[get("/kv/<space>/<path..>")]
pub async fn kv_get(
    space: &str,
    path: RawKeyPath,
    token: Option<BenchSessionToken>,
    state: &State<BenchState>,
) -> BenchResponder {
    let mut timings = BenchTimings::new();
    let path = path.0;
    let parse_start = Instant::now();
    let space_id = match SpaceId::from_str(space) {
        Ok(space) => space,
        Err(_) => {
            return response_json_error(BenchError::bad_request("invalid space ID"), &timings)
        }
    };
    timings.record("parse", parse_start.elapsed());

    let auth_start = Instant::now();
    let token = match token {
        Some(token) => token.0,
        None => {
            return response_json_error(
                BenchError::auth_missing("missing benchmark session token"),
                &timings,
            )
        }
    };
    let session = match load_session(state.inner().db(), &token).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return response_json_error(
                BenchError::auth_missing("unknown benchmark session token"),
                &timings,
            )
        }
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    };
    if session_expired(&session.expires_at).unwrap_or(true) {
        return response_json_error(
            BenchError::auth_expired("benchmark session expired"),
            &timings,
        );
    }
    timings.record("auth", auth_start.elapsed());

    let delegation_start = Instant::now();
    if session.service != "tinycloud.kv"
        || session.space != space_id.to_string()
        || session.path != path
        || session.action != "tinycloud.kv/get"
    {
        return response_json_error(
            BenchError::ability_denied("session does not authorize the requested KV read"),
            &timings,
        );
    }
    timings.record("delegation", delegation_start.elapsed());

    let sqlite_start = Instant::now();
    let row = match load_kv(state.inner().db(), &space_id, &path).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return response_json_error(BenchError::kv_not_found("key not found"), &timings)
        }
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    };
    timings.record("sqlite", sqlite_start.elapsed());

    let value: Value = match serde_json::from_str(&row.value_json) {
        Ok(value) => value,
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    };
    let response = KvResponse {
        ok: true,
        space: row.space,
        path: row.path,
        content_type: row.content_type,
        content_hash: row.content_hash,
        value,
    };
    build_json_body(Status::Ok, &response, &mut timings)
}

#[put("/block/<multihash>", data = "<data>")]
pub async fn block_put(
    multihash: &str,
    data: Data<'_>,
    token: Option<BenchSessionToken>,
    state: &State<BenchState>,
) -> BenchResponder {
    let mut timings = BenchTimings::new();
    let parse_start = Instant::now();
    let claimed = match hex_to_hash(multihash) {
        Ok(hash) => hash,
        Err(err) => return response_json_error(err, &timings),
    };
    timings.record("parse", parse_start.elapsed());

    let auth_start = Instant::now();
    let token = match token {
        Some(token) => token.0,
        None => {
            return response_json_error(
                BenchError::auth_missing("missing benchmark session token"),
                &timings,
            )
        }
    };
    let session = match load_session(state.inner().db(), &token).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return response_json_error(
                BenchError::auth_missing("unknown benchmark session token"),
                &timings,
            )
        }
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    };
    if session_expired(&session.expires_at).unwrap_or(true) {
        return response_json_error(
            BenchError::auth_expired("benchmark session expired"),
            &timings,
        );
    }
    timings.record("auth", auth_start.elapsed());

    let delegation_start = Instant::now();
    if let Err(err) = verify_block_session(&session) {
        return response_json_error(err, &timings);
    }
    timings.record("delegation", delegation_start.elapsed());

    let block_io_start = Instant::now();
    let capped = match data.open(MAX_BLOCK_BYTES.bytes()).into_bytes().await {
        Ok(capped) => capped,
        Err(err) => {
            return response_json_error(BenchError::internal(err.to_string()), &timings);
        }
    };
    if !capped.is_complete() {
        return response_json_error(
            BenchError::block_too_large("block body exceeded the configured maximum"),
            &timings,
        );
    }
    let bytes = capped.into_inner();
    let actual = hash(&bytes);
    if actual != claimed {
        return response_json_error(
            BenchError::digest_mismatch("declared multihash did not match the block body"),
            &timings,
        );
    }

    let etag = format!("\"{}\"", blake3_content_hash(&bytes));
    let upsert_result = upsert_block(state, multihash, &bytes, bytes.len(), &etag).await;
    timings.record("block_io", block_io_start.elapsed());
    let existed = match upsert_result {
        Ok(created) => !created,
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    };

    let response = BlockResponse {
        ok: true,
        multihash: multihash.to_string(),
        size_bytes: bytes.len(),
        etag,
    };
    build_json_body(
        if existed { Status::Ok } else { Status::Created },
        &response,
        &mut timings,
    )
}

#[get("/block/<multihash>")]
pub async fn block_get(
    multihash: &str,
    token: Option<BenchSessionToken>,
    state: &State<BenchState>,
) -> BenchResponder {
    let mut timings = BenchTimings::new();
    let parse_start = Instant::now();
    if hex_to_hash(multihash).is_err() {
        return response_json_error(BenchError::bad_request("invalid multihash"), &timings);
    }
    timings.record("parse", parse_start.elapsed());

    let auth_start = Instant::now();
    let token = match token {
        Some(token) => token.0,
        None => {
            return response_json_error(
                BenchError::auth_missing("missing benchmark session token"),
                &timings,
            )
        }
    };
    let session = match load_session(state.inner().db(), &token).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return response_json_error(
                BenchError::auth_missing("unknown benchmark session token"),
                &timings,
            )
        }
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    };
    if session_expired(&session.expires_at).unwrap_or(true) {
        return response_json_error(
            BenchError::auth_expired("benchmark session expired"),
            &timings,
        );
    }
    timings.record("auth", auth_start.elapsed());

    let delegation_start = Instant::now();
    if let Err(err) = verify_block_session(&session) {
        return response_json_error(err, &timings);
    }
    timings.record("delegation", delegation_start.elapsed());

    let block_io_start = Instant::now();
    let row_result = load_block(state.inner().db(), multihash).await;
    timings.record("block_io", block_io_start.elapsed());
    let row = match row_result {
        Ok(Some(row)) => row,
        Ok(None) => {
            return response_json_error(BenchError::block_not_found("block not found"), &timings)
        }
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    };

    let serialize_start = Instant::now();
    timings.record("serialize", serialize_start.elapsed());
    response_with_headers(
        Status::Ok,
        ContentType::new("application", "octet-stream"),
        row.bytes,
        &timings,
    )
}

#[get("/health")]
pub async fn health(state: &State<BenchState>) -> BenchResponder {
    let mut timings = BenchTimings::new();
    let serialize_start = Instant::now();
    let body = state.health();
    let body = match serde_json::to_vec(&body) {
        Ok(body) => body,
        Err(err) => {
            return response_json_error(BenchError::internal(err.to_string()), &timings);
        }
    };
    timings.record("serialize", serialize_start.elapsed());
    response_with_headers(Status::Ok, ContentType::JSON, body, &timings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use k256::ecdsa::SigningKey;
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::Client;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use sha3::{Digest, Keccak256};
    use tempfile::TempDir;
    use time::{Duration as TimeDuration, OffsetDateTime};
    use tinycloud_auth::{
        cacaos::siwe::{Message, Version},
        resolver::DID_METHODS,
        resource::SpaceId,
        siwe_recap::{Ability as RecapAbility, Capability as RecapCapability},
        ssi::{dids::DIDBuf, jwk::JWK},
    };
    use tinycloud_core::sea_orm::{ConnectOptions, Database};

    fn test_space_id(name: &str) -> SpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, name.parse().unwrap())
    }

    fn bench_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11u8; 32].into()).unwrap()
    }

    fn ethereum_address(signing_key: &SigningKey) -> [u8; 20] {
        let public_key = signing_key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&public_key.as_bytes()[1..]);
        digest[12..].try_into().unwrap()
    }

    fn signed_siwe_payload(
        signing_key: &SigningKey,
        required_capability: &RequiredCapability,
        nonce: &str,
    ) -> Result<(String, String)> {
        let address = ethereum_address(signing_key);
        let resource =
            required_resource(required_capability).map_err(|err| anyhow::anyhow!(err.message))?;
        let mut recap = RecapCapability::<Value>::new();
        recap.with_action(
            resource.as_uri().clone(),
            RecapAbility::try_from(required_capability.action.clone())?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
        let message = recap.build_message(Message {
            scheme: Some("https".parse().unwrap()),
            domain: "bench.local".parse().unwrap(),
            address,
            statement: None,
            uri: "https://bench.local/tc-bench".parse().unwrap(),
            version: Version::V1,
            chain_id: 1,
            nonce: nonce.to_string(),
            issued_at: (OffsetDateTime::now_utc() - TimeDuration::minutes(1)).into(),
            expiration_time: Some((OffsetDateTime::now_utc() + TimeDuration::hours(1)).into()),
            not_before: None,
            request_id: None,
            resources: vec![],
        })?;
        let (signature, recovery_id) =
            signing_key.sign_prehash_recoverable(&message.eip191_hash()?)?;
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        signature_bytes[64] = u8::from(recovery_id) + 27;
        Ok((
            message.to_string(),
            format!("0x{}", hex::encode(signature_bytes)),
        ))
    }

    fn auth_verify_body(
        required_capability: RequiredCapability,
        signing_key: &SigningKey,
        nonce: &str,
    ) -> Result<String> {
        let (siwe, signature) = signed_siwe_payload(signing_key, &required_capability, nonce)?;
        Ok(serde_json::to_string(&AuthVerifyRequest {
            siwe,
            signature,
            required_capability,
        })?)
    }

    fn tc_bench_fixture_path(relative: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../../repositories/tc-bench")
            .join(relative)
    }

    fn load_frozen_golden_vectors() -> Result<FrozenGoldenVectors> {
        let path = tc_bench_fixture_path("fixtures/golden-vectors.json").canonicalize()?;
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    fn load_frozen_runtime_artifacts() -> Result<Value> {
        let path = tc_bench_fixture_path("artifacts/runtime-artifacts.json").canonicalize()?;
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    fn auth_verify_request_body(vector: &FrozenVector) -> Result<String> {
        Ok(serde_json::to_string(&AuthVerifyRequest {
            siwe: vector.siwe.clone(),
            signature: vector.signature.clone(),
            required_capability: vector.operation.clone(),
        })?)
    }

    fn block_put_capability(vector: &FrozenVector) -> RequiredCapability {
        RequiredCapability {
            service: vector.operation.service.clone(),
            space: vector.operation.space.clone(),
            path: vector.operation.path.clone(),
            action: "tinycloud.kv/put".to_string(),
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FrozenGoldenVectors {
        valid: Vec<FrozenVector>,
        invalid: Vec<FrozenVector>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FrozenVector {
        case: String,
        endpoint: String,
        #[serde(default)]
        proof_cids: Vec<String>,
        #[serde(default)]
        replay_of: Option<Box<FrozenVector>>,
        #[serde(default)]
        digest: Option<FrozenDigest>,
        #[serde(default)]
        block: Option<FrozenBlock>,
        siwe: String,
        signature: String,
        operation: RequiredCapability,
        expected: FrozenExpected,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FrozenExpected {
        status: u16,
        code: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FrozenDigest {
        claimed: String,
        actual: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FrozenBlock {
        fixture: String,
        size_bytes: usize,
        path: String,
        content_type: String,
        claimed_multihash: String,
        actual_multihash: String,
    }

    async fn bench_client() -> Result<(TempDir, Client)> {
        let tempdir = TempDir::new()?;
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        let bench_config = TcBenchConfig {
            region: "test-region".to_string(),
            worker_bundle_sha256: Some("a".repeat(64)),
            wasm_bundle_sha256: Some("b".repeat(64)),
        };
        let state = BenchState::new(&bench_config, db, 1).await?;
        let rocket = rocket::build()
            .mount(
                "/",
                routes![auth_verify, kv_put, kv_get, block_put, block_get, health],
            )
            .manage(state);
        let client = Client::tracked(rocket).await?;
        Ok((tempdir, client))
    }

    async fn issue_session(
        client: &Client,
        required_capability: RequiredCapability,
        signing_key: &SigningKey,
        nonce: &str,
    ) -> Result<String> {
        let body = auth_verify_body(required_capability, signing_key, nonce)?;
        let response = client
            .post("/auth/verify")
            .header(ContentType::JSON)
            .body(body)
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(
            status,
            Status::Ok,
            "unexpected auth/verify response: {body}"
        );
        let json: Value = serde_json::from_str(&body)?;
        Ok(json["session"]["token"]
            .as_str()
            .expect("session token present")
            .to_string())
    }

    fn bearer(token: &str) -> Header<'static> {
        Header::new("Authorization", format!("Bearer {token}"))
    }

    #[tokio::test]
    async fn tc_bench_frozen_vectors_match_contract() -> Result<()> {
        let frozen = load_frozen_golden_vectors()?;

        for vector in &frozen.valid {
            assert_eq!(
                vector.endpoint.as_str(),
                "POST /auth/verify",
                "unexpected valid endpoint"
            );
            let (_tempdir, client) = bench_client().await?;
            let response = client
                .post("/auth/verify")
                .header(ContentType::JSON)
                .body(auth_verify_request_body(vector)?)
                .dispatch()
                .await;
            let status = response.status();
            let body = response.into_string().await.unwrap_or_default();
            assert_eq!(
                status,
                Status::Ok,
                "unexpected response for valid case {}: {body}",
                vector.case
            );
            let json: Value = serde_json::from_str(&body)?;
            assert_eq!(json["ok"], true);
            assert_eq!(
                json["recapDepth"].as_u64(),
                Some(vector.proof_cids.len() as u64)
            );
            assert_eq!(
                json["session"]["token"].as_str().unwrap_or_default().len(),
                64
            );
        }

        for vector in &frozen.invalid {
            let (_tempdir, client) = bench_client().await?;
            match vector.endpoint.as_str() {
                "POST /auth/verify" => {
                    if let Some(replay_of) = &vector.replay_of {
                        let replay_first = client
                            .post("/auth/verify")
                            .header(ContentType::JSON)
                            .body(auth_verify_request_body(replay_of)?)
                            .dispatch()
                            .await;
                        assert_eq!(
                            replay_first.status(),
                            Status::Ok,
                            "replay seed request failed for {}",
                            vector.case
                        );
                    }

                    let response = client
                        .post("/auth/verify")
                        .header(ContentType::JSON)
                        .body(auth_verify_request_body(vector)?)
                        .dispatch()
                        .await;
                    let status = response.status();
                    let body = response.into_string().await.unwrap_or_default();
                    assert_eq!(
                        status,
                        Status::from_code(vector.expected.status)
                            .unwrap_or(Status::InternalServerError),
                        "unexpected response for invalid case {}: {body}",
                        vector.case
                    );
                    let json: Value = serde_json::from_str(&body)?;
                    assert_eq!(json["error"]["code"], vector.expected.code);
                }
                "PUT /block/:multihash" => {
                    let block = vector
                        .block
                        .as_ref()
                        .expect("digest mismatch block fixture");
                    assert_eq!(block.fixture.as_str(), "64KiB");
                    assert_eq!(block.content_type.as_str(), "application/octet-stream");
                    let body = std::fs::read(tc_bench_fixture_path(&block.path).canonicalize()?)?;
                    let actual = hex::encode(Vec::<u8>::from(hash(&body)));
                    assert_eq!(
                        actual, block.actual_multihash,
                        "frozen block fixture hash mismatch"
                    );
                    assert_eq!(
                        body.len(),
                        block.size_bytes,
                        "frozen block fixture size mismatch"
                    );
                    assert_eq!(
                        vector.digest.as_ref().map(|digest| digest.claimed.as_str()),
                        Some(block.claimed_multihash.as_str())
                    );
                    assert_eq!(
                        vector.digest.as_ref().map(|digest| digest.actual.as_str()),
                        Some(block.actual_multihash.as_str())
                    );

                    let session_token = issue_session(
                        &client,
                        block_put_capability(vector),
                        &bench_signing_key(),
                        "urn:uuid:00000000-0000-4000-8000-000000000030",
                    )
                    .await?;
                    let response = client
                        .put(format!("/block/{}", block.claimed_multihash))
                        .header(bearer(&session_token))
                        .header(ContentType::new("application", "octet-stream"))
                        .body(body)
                        .dispatch()
                        .await;
                    let status = response.status();
                    let body = response.into_string().await.unwrap_or_default();
                    assert_eq!(
                        status,
                        Status::from_code(vector.expected.status)
                            .unwrap_or(Status::InternalServerError),
                        "unexpected response for invalid case {}: {body}",
                        vector.case
                    );
                    let json: Value = serde_json::from_str(&body)?;
                    assert_eq!(json["error"]["code"], vector.expected.code);
                }
                other => panic!("unexpected frozen endpoint: {other}"),
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn tc_bench_health_emits_trace_headers_and_frozen_contract_hash() -> Result<()> {
        let (_tempdir, client) = bench_client().await?;
        let frozen_runtime_artifacts = load_frozen_runtime_artifacts()?;
        let response = client.get("/health").dispatch().await;
        let status = response.status();
        let request_id = response
            .headers()
            .get_one("X-TC-Request-ID")
            .unwrap_or_default()
            .to_string();
        let executed_id = response
            .headers()
            .get_one("X-TC-Executed")
            .unwrap_or_default()
            .to_string();
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(status, Status::Ok, "unexpected health response: {body}");

        assert!(!request_id.is_empty(), "missing X-TC-Request-ID");
        assert_eq!(request_id, executed_id, "trace headers must match");

        let json: Value = serde_json::from_str(&body)?;
        assert_eq!(
            json["artifactHashes"]["contractBlake3"],
            frozen_runtime_artifacts["contractBlake3"]
        );
        assert_eq!(
            json["artifactHashes"]["goldenVectorsBlake3"],
            frozen_runtime_artifacts["goldenVectorsBlake3"]
        );
        assert_eq!(
            json["artifactHashes"]["blockFixturesBlake3"],
            frozen_runtime_artifacts["blockFixturesBlake3"]
        );

        Ok(())
    }

    #[tokio::test]
    async fn tc_bench_golden_vector_happy_path_round_trips() -> Result<()> {
        let (_tempdir, client) = bench_client().await?;
        let signing_key = bench_signing_key();
        let space = test_space_id("bench");
        let kv_path = "app/transcript/1";
        let kv_value = json!({
            "message": "hello tc-bench",
            "sequence": 1,
        });
        let kv_content = serde_json::to_vec(&canonicalize_json(kv_value.clone()))?;
        let kv_hash = blake3_content_hash(&kv_content);
        let kv_put_capability = RequiredCapability {
            service: "tinycloud.kv".to_string(),
            space: space.to_string(),
            path: kv_path.to_string(),
            action: "tinycloud.kv/put".to_string(),
        };
        let kv_put_token = issue_session(
            &client,
            kv_put_capability,
            &signing_key,
            "urn:uuid:00000000-0000-4000-8000-000000000001",
        )
        .await?;
        let kv_put_response = client
            .put(format!("/kv/{}/{}", space, kv_path))
            .header(bearer(&kv_put_token))
            .header(ContentType::JSON)
            .body(serde_json::to_string(&KvPutRequest {
                value: kv_value.clone(),
                content_type: "application/json".to_string(),
                content_hash: kv_hash.clone(),
            })?)
            .dispatch()
            .await;
        let kv_put_status = kv_put_response.status();
        let kv_put_body = kv_put_response.into_string().await.unwrap_or_default();
        assert_eq!(
            kv_put_status,
            Status::Created,
            "unexpected kv/put response: {kv_put_body}"
        );

        let kv_get_capability = RequiredCapability {
            service: "tinycloud.kv".to_string(),
            space: space.to_string(),
            path: kv_path.to_string(),
            action: "tinycloud.kv/get".to_string(),
        };
        let kv_get_token = issue_session(
            &client,
            kv_get_capability,
            &signing_key,
            "urn:uuid:00000000-0000-4000-8000-000000000002",
        )
        .await?;
        let kv_get_response = client
            .get(format!("/kv/{}/{}", space, kv_path))
            .header(bearer(&kv_get_token))
            .dispatch()
            .await;
        let kv_get_status = kv_get_response.status();
        let kv_get_body = kv_get_response.into_string().await.unwrap_or_default();
        assert_eq!(
            kv_get_status,
            Status::Ok,
            "unexpected kv/get response: {kv_get_body}"
        );
        let kv_get_json: Value = serde_json::from_str(&kv_get_body)?;
        assert_eq!(kv_get_json["value"], kv_value);

        let block_bytes = b"bench block payload".to_vec();
        let block_hash = hex::encode(Vec::<u8>::from(hash(&block_bytes)));
        let block_capability = RequiredCapability {
            service: "tinycloud.kv".to_string(),
            space: space.to_string(),
            path: "blocks/vector.bin".to_string(),
            action: "tinycloud.kv/put".to_string(),
        };
        let block_token = issue_session(
            &client,
            block_capability,
            &signing_key,
            "urn:uuid:00000000-0000-4000-8000-000000000003",
        )
        .await?;
        let block_put_response = client
            .put(format!("/block/{block_hash}"))
            .header(bearer(&block_token))
            .body(block_bytes.clone())
            .dispatch()
            .await;
        let block_put_status = block_put_response.status();
        let block_put_body = block_put_response.into_string().await.unwrap_or_default();
        assert_eq!(
            block_put_status,
            Status::Created,
            "unexpected block/put response: {block_put_body}"
        );

        let block_get_response = client
            .get(format!("/block/{block_hash}"))
            .header(bearer(&block_token))
            .dispatch()
            .await;
        let block_get_status = block_get_response.status();
        let block_get_body = block_get_response.into_bytes().await.unwrap_or_default();
        assert_eq!(block_get_status, Status::Ok);
        assert_eq!(block_get_body, block_bytes);

        Ok(())
    }

    #[tokio::test]
    async fn tc_bench_replayed_nonce_is_rejected() -> Result<()> {
        let (_tempdir, client) = bench_client().await?;
        let signing_key = bench_signing_key();
        let space = test_space_id("bench-replay");
        let capability = RequiredCapability {
            service: "tinycloud.kv".to_string(),
            space: space.to_string(),
            path: "app/transcript/2".to_string(),
            action: "tinycloud.kv/put".to_string(),
        };
        let body = auth_verify_body(
            capability,
            &signing_key,
            "urn:uuid:00000000-0000-4000-8000-000000000010",
        )?;

        let first = client
            .post("/auth/verify")
            .header(ContentType::JSON)
            .body(body.clone())
            .dispatch()
            .await;
        assert_eq!(first.status(), Status::Ok);

        let replay = client
            .post("/auth/verify")
            .header(ContentType::JSON)
            .body(body)
            .dispatch()
            .await;
        let status = replay.status();
        let body = replay.into_string().await.unwrap_or_default();
        assert_eq!(
            status,
            Status::Conflict,
            "unexpected replay response: {body}"
        );
        let json: Value = serde_json::from_str(&body)?;
        assert_eq!(json["error"]["code"], "NONCE_REPLAY");

        Ok(())
    }

    #[tokio::test]
    async fn tc_bench_digest_mismatch_rejections_are_reported() -> Result<()> {
        let (_tempdir, client) = bench_client().await?;
        let signing_key = bench_signing_key();
        let space = test_space_id("bench-digest");
        let kv_path = "app/transcript/3";
        let kv_capability = RequiredCapability {
            service: "tinycloud.kv".to_string(),
            space: space.to_string(),
            path: kv_path.to_string(),
            action: "tinycloud.kv/put".to_string(),
        };
        let kv_token = issue_session(
            &client,
            kv_capability,
            &signing_key,
            "urn:uuid:00000000-0000-4000-8000-000000000020",
        )
        .await?;
        let kv_body = serde_json::to_string(&KvPutRequest {
            value: json!({"message": "digest mismatch"}),
            content_type: "application/json".to_string(),
            content_hash: "blake3-0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        })?;
        let kv_response = client
            .put(format!("/kv/{}/{}", space, kv_path))
            .header(bearer(&kv_token))
            .header(ContentType::JSON)
            .body(kv_body)
            .dispatch()
            .await;
        let kv_status = kv_response.status();
        let kv_body = kv_response.into_string().await.unwrap_or_default();
        assert_eq!(
            kv_status,
            Status::UnprocessableEntity,
            "unexpected kv mismatch response: {kv_body}"
        );
        let kv_json: Value = serde_json::from_str(&kv_body)?;
        assert_eq!(kv_json["error"]["code"], "DIGEST_MISMATCH");

        let block_bytes = b"block mismatch body".to_vec();
        let block_hash = hex::encode(Vec::<u8>::from(hash(b"block mismatch expected")));
        let block_capability = RequiredCapability {
            service: "tinycloud.kv".to_string(),
            space: space.to_string(),
            path: "blocks/vector.bin".to_string(),
            action: "tinycloud.kv/put".to_string(),
        };
        let block_token = issue_session(
            &client,
            block_capability,
            &signing_key,
            "urn:uuid:00000000-0000-4000-8000-000000000021",
        )
        .await?;
        let block_response = client
            .put(format!("/block/{block_hash}"))
            .header(bearer(&block_token))
            .body(block_bytes)
            .dispatch()
            .await;
        let block_status = block_response.status();
        let block_body = block_response.into_string().await.unwrap_or_default();
        assert_eq!(
            block_status,
            Status::UnprocessableEntity,
            "unexpected block mismatch response: {block_body}"
        );
        let block_json: Value = serde_json::from_str(&block_body)?;
        assert_eq!(block_json["error"]["code"], "DIGEST_MISMATCH");

        Ok(())
    }
}
