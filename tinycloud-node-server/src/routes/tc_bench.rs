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

use crate::routes::public::RawKeyPath;

const MAX_BLOCK_BYTES: u64 = 8 * 1024 * 1024;
const CONTRACT_BLAKE3: &str =
    "1e208a8e069e914faf6463582745dc75d2b06c349564aa158b21d9d6a501e4aa7105";
const GOLDEN_VECTORS_BLAKE3: &str =
    "1e20e75cc06a1a2cf0c75940af750742d6252d093ff004e6842c4ac56a5f42816ed9";
const BLOCK_FIXTURES_BLAKE3: &str =
    "1e20fd380eb6142753252ea5bd71cc90300dfcc13794c4044eca16e458ca5566a403";

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
    fn from_env() -> Result<Self, DbErr> {
        Ok(Self {
            contract_blake3: CONTRACT_BLAKE3,
            golden_vectors_blake3: GOLDEN_VECTORS_BLAKE3,
            block_fixtures_blake3: BLOCK_FIXTURES_BLAKE3,
            worker_bundle_sha256: required_sha256_env("TC_BENCH_WORKER_BUNDLE_SHA256")?,
            wasm_bundle_sha256: required_sha256_env("TC_BENCH_WASM_BUNDLE_SHA256")?,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredCapability {
    pub service: String,
    pub space: String,
    pub path: String,
    pub action: String,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
        region: String,
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
            region,
            sqlite,
            artifact_hashes: ArtifactHashes::from_env()?,
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
    let mut response = Response::build();
    response.status(status);
    response.header(content_type);
    response.header(Header::new("Cache-Control", "no-store"));
    response.header(Header::new("Server-Timing", timings.header_value()));
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

async fn nonce_replayed<C>(db: &C, nonce: &str) -> Result<bool, DbErr>
where
    C: ConnectionTrait + ?Sized,
{
    let statement = Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT 1 FROM tc_bench_sessions WHERE nonce = ? LIMIT 1".to_string(),
        vec![nonce.to_string().into()],
    );
    Ok(db.query_one(statement).await?.is_some())
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

async fn store_session(state: &BenchState, session: &BenchSessionRow) -> Result<(), DbErr> {
    let tx = state.db().begin().await?;
    tx.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO tc_bench_sessions (token, nonce, principal_did, address, recap_depth, service, space, path, action, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)".to_string(),
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
    tx.commit().await?;
    Ok(())
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

fn required_sha256_env(name: &str) -> Result<String, DbErr> {
    let value = std::env::var(name)
        .map_err(|_| DbErr::Custom(format!("missing required environment variable {name}")))?;
    if value.len() != 64
        || !value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(DbErr::Custom(format!(
            "environment variable {name} must be a 64-character hexadecimal string"
        )));
    }
    Ok(value)
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

    let recovered = match message.verify_eip191(&signature) {
        Ok(recovered) => recovered,
        Err(e) => {
            return response_json_error(BenchError::auth_invalid_signature(e.to_string()), &timings)
        }
    };

    let recovered: [u8; 20] = match recovered.try_into() {
        Ok(address) => address,
        Err(_) => {
            return response_json_error(
                BenchError::auth_invalid_signature("recovered signer must be a 20-byte address"),
                &timings,
            )
        }
    };
    if recovered != message.address {
        return response_json_error(
            BenchError::auth_invalid_signature("recovered signer did not match the SIWE address"),
            &timings,
        );
    }
    let recovered_address = match eip55_address(&recovered) {
        Ok(address) => address,
        Err(err) => return response_json_error(err, &timings),
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

    if recap
        .can_do(&required_resource.as_uri(), &required_action)
        .is_none()
    {
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
        principal_did: principal_did(message.chain_id, &recovered_address),
        address: message_address,
        recap_depth: recap.proof().len(),
        service: request.required_capability.service.clone(),
        space: request.required_capability.space.clone(),
        path: request.required_capability.path.clone(),
        action: request.required_capability.action.clone(),
        expires_at,
    };

    match nonce_replayed(state.inner().db(), &session.nonce).await {
        Ok(true) => {
            return response_json_error(BenchError::nonce_replay("nonce already used"), &timings)
        }
        Ok(false) => {}
        Err(err) => return response_json_error(BenchError::internal(err.to_string()), &timings),
    }
    let store_result = store_session(state, &session).await;
    timings.record("delegation", delegation_start.elapsed());
    if let Err(err) = store_result {
        return response_json_error(BenchError::internal(err.to_string()), &timings);
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
