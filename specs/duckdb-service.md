# Spec: DuckDB Service for TinyCloud-Node

**Date:** 2026-03-06
**Status:** Draft
**Service identifier:** `duckdb`
**Primary consumer:** CRM applications

---

## 1. Overview

Add a DuckDB service (`tinycloud.duckdb/*`) to tinycloud-node, running alongside the existing SQLite-based SQL service (`tinycloud.sql/*`). DuckDB serves as an embedded analytical database with columnar storage, per-space isolation, and the same UCAN capability model used by all TinyCloud services.

The client application will use this as its **sole database** (full replacement of local `workspace.duckdb` files), sending all queries over the network via UCAN invocations.

---

## 2. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| SQL engine | DuckDB via `duckdb-rs` crate (in-process) | Columnar, analytical, embedded — no separate server |
| Security model | Parser validation + DuckDB settings | No authorizer hook in DuckDB; `enable_external_access=false`, `allow_unsigned_extensions=false` |
| KV bridge | Explicit ingest/export actions | Not virtual filesystem. Client-driven data movement between KV and DuckDB |
| Wire format | JSON default, Arrow IPC via Accept header | `Accept: application/vnd.apache.arrow.stream` triggers Arrow response |
| Schema management | Dumb SQL pipe | Service executes SQL. Client application manages its own schema via DDL |
| DDL policy | `tinycloud.duckdb/write` allows DDL | CREATE TABLE/VIEW, ALTER, DROP all allowed with write ability |
| Instance lifecycle | Actor model, configurable idle timeout (default 5 min) | Same pattern as SQL service. Connection dies after timeout, re-opens on next query |
| Storage | Hybrid: in-memory → file promotion at threshold | Same as SQL service. Default threshold configurable |
| Batch transactions | Optional via `transactional` field | `{ transactional: true }` wraps batch in BEGIN/COMMIT with ROLLBACK on failure |
| Migration | Both .duckdb file import AND SQL replay | Import for fast binary restore, SQL replay for portable/incremental |
| Export | DuckDB file only | Mirror of SQL service export behavior |

---

## 3. Abilities

```
tinycloud.duckdb/read       — SELECT only. No modifications.
tinycloud.duckdb/write      — INSERT, UPDATE, DELETE + DDL (CREATE, ALTER, DROP)
tinycloud.duckdb/admin      — All above + settings, pragmas, configuration
tinycloud.duckdb/ingest     — Load data from KV storage into a DuckDB table
tinycloud.duckdb/export     — Write DuckDB query results to KV storage
tinycloud.duckdb/import     — Upload a raw .duckdb file as the space's database
tinycloud.duckdb/describe   — Introspection: returns structured schema info
tinycloud.duckdb/*          — Wildcard: all abilities
```

### Caveats (same structure as SQL service)

```json
{
  "duckdbCaveats": {
    "tables": ["people", "companies"],
    "columns": ["id", "name", "email"],
    "statements": [
      { "name": "getUserById", "sql": "SELECT * FROM people WHERE id = ?" }
    ],
    "readOnly": true
  }
}
```

Caveats are passed in UCAN invocation facts under key `"duckdbCaveats"`.

---

## 4. Request / Response Types

### 4.1 Actions

#### Query

```json
{
  "action": "query",
  "sql": "SELECT * FROM people WHERE status = ?",
  "params": ["active"]
}
```

Response (JSON):
```json
{
  "columns": ["id", "name", "email", "status"],
  "rows": [
    [1, "Alice", "alice@example.com", "active"]
  ],
  "rowCount": 1
}
```

Response (Arrow): Raw Arrow IPC stream bytes. Triggered by `Accept: application/vnd.apache.arrow.stream`.

#### Execute

```json
{
  "action": "execute",
  "sql": "INSERT INTO people (name, email) VALUES (?, ?)",
  "params": ["Bob", "bob@example.com"],
  "schema": [
    "CREATE TABLE IF NOT EXISTS people (id INTEGER PRIMARY KEY, name TEXT, email TEXT)"
  ]
}
```

Response:
```json
{
  "changes": 1,
  "lastInsertRowId": 42
}
```

`schema` is optional — runs DDL statements before the main statement (for bootstrapping tables on first write).

#### Batch

```json
{
  "action": "batch",
  "statements": [
    { "sql": "INSERT INTO people (name) VALUES (?)", "params": ["Alice"] },
    { "sql": "INSERT INTO people (name) VALUES (?)", "params": ["Bob"] }
  ],
  "transactional": true
}
```

When `transactional: true`, all statements are wrapped in `BEGIN`/`COMMIT`. On failure, `ROLLBACK`. Default: `false` (each statement runs independently, stops on first error).

Response:
```json
{
  "results": [
    { "changes": 1, "lastInsertRowId": 1 },
    { "changes": 1, "lastInsertRowId": 2 }
  ]
}
```

#### ExecuteStatement

```json
{
  "action": "execute_statement",
  "name": "getUserById",
  "params": [42]
}
```

Looks up prepared statement from caveats by name. Returns QueryResponse or ExecuteResponse depending on statement type.

#### Describe

```json
{
  "action": "describe"
}
```

Response:
```json
{
  "tables": [
    {
      "name": "people",
      "columns": [
        { "name": "id", "type": "INTEGER", "nullable": false },
        { "name": "name", "type": "VARCHAR", "nullable": true },
        { "name": "email", "type": "VARCHAR", "nullable": true }
      ],
      "rowCount": 1500
    }
  ],
  "views": [
    { "name": "v_people", "sql": "SELECT ..." }
  ]
}
```

Uses `information_schema.tables`, `information_schema.columns`, and `duckdb_tables()` internally. Requires `tinycloud.duckdb/describe` ability.

#### Ingest (KV → DuckDB)

```json
{
  "action": "ingest",
  "source": "data/events.parquet",
  "format": "parquet",
  "table": "events",
  "mode": "replace"
}
```

- `source`: KV path within the space's storage
- `format`: `"parquet"`, `"csv"`, `"json"`
- `table`: Target DuckDB table name
- `mode`: `"replace"` (DROP + CREATE) or `"append"` (INSERT INTO)

The service reads the file from KV block storage, writes it to a temp location, and uses DuckDB's native `read_parquet()` / `read_csv()` / `read_json()` to load it.

Requires `tinycloud.duckdb/ingest` ability. Table must pass caveats allowlist.

#### Export (DuckDB → KV)

```json
{
  "action": "export_to_kv",
  "sql": "SELECT * FROM events WHERE date > '2026-01-01'",
  "destination": "exports/recent_events.parquet",
  "format": "parquet"
}
```

Runs the query, writes results to a temp file using DuckDB's `COPY ... TO`, then persists to KV storage at the given path.

Requires `tinycloud.duckdb/export` ability.

#### Export (raw .duckdb file)

```json
{
  "action": "export"
}
```

Returns the raw `.duckdb` file as binary. Content-Type: `application/x-duckdb`.

#### Import (.duckdb file)

The `.duckdb` file is sent as the request body (binary). The service replaces the space's database with the uploaded file.

Requires `tinycloud.duckdb/import` ability.

### 4.2 Value Types

DuckDB has richer types than SQLite. The `DuckDbValue` enum:

```rust
pub enum DuckDbValue {
    Null,
    Boolean(bool),
    Integer(i64),
    BigInt(i128),
    Float(f32),
    Double(f64),
    Text(String),
    Blob(Vec<u8>),
    Date(String),       // ISO 8601 date
    Timestamp(String),  // ISO 8601 timestamp
    List(Vec<DuckDbValue>),
    Struct(HashMap<String, DuckDbValue>),
}
```

Serialized to JSON following DuckDB's native JSON output conventions. `List` and `Struct` are key differentiators from the SQLite service.

---

## 5. Architecture

### 5.1 Module Structure

```
tinycloud-core/src/duckdb/
├── mod.rs              — Module exports
├── types.rs            — DuckDbRequest, DuckDbResponse, DuckDbValue, DuckDbError
├── service.rs          — DuckDbService (manages database actors per space)
├── database.rs         — DatabaseHandle, spawn_actor, message handling
├── parser.rs           — SQL validation using sqlparser with DuckDB/Generic dialect
├── caveats.rs          — DuckDbCaveats (table/column allowlists, prepared statements)
├── storage.rs          — StorageMode (InMemory/File), open_connection, promote_to_file
└── describe.rs         — Schema introspection logic
```

Mirrors the `sql/` module structure. Does NOT share code with the SQL service — independent implementation using `duckdb-rs` instead of `rusqlite`.

### 5.2 Service Layer

```rust
pub struct DuckDbService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    base_path: String,
    memory_threshold: u64,
    idle_timeout_secs: u64,
    max_memory_per_connection: String,  // e.g. "128MB"
    kv_storage: Arc<BlockStores>,       // For ingest/export actions
}
```

Registered as Rocket managed state alongside `SqlService`:

```rust
let duckdb_service = DuckDbService::new(
    config.storage.duckdb.path.clone(),
    config.storage.duckdb.memory_threshold.as_u64(),
    config.storage.duckdb.idle_timeout_secs,
    config.storage.duckdb.max_memory_per_connection.clone(),
    block_stores.clone(),
);

rocket::custom(config)
    .manage(tinycloud)
    .manage(staging)
    .manage(sql_service)
    .manage(duckdb_service)  // new
```

### 5.3 Actor Model

Same pattern as SQL service:

```
Client request
  → Route handler (src/routes/mod.rs)
    → DuckDbService.execute(space, db_name, request, caveats, ability)
      → DatabaseHandle.send(message)  [mpsc channel]
        → Actor (tokio::task::spawn_blocking)
          → duckdb::Connection
            → Execute query
          ← Result
        ← oneshot response
      ← DuckDbResponse
    ← InvocationOutcome::DuckDbResult | DuckDbExport | DuckDbArrow
  ← HTTP Response
```

Each `(space_id, db_name)` pair gets one actor. Actor holds a `duckdb::Connection`. Actor shuts down after configurable idle timeout (default 5 min).

### 5.4 Connection Settings

On every new connection:

```rust
conn.execute_batch("
    SET enable_external_access = false;
    SET allow_unsigned_extensions = false;
    SET max_memory = '{max_memory_per_connection}';
")?;
```

These settings disable filesystem access and extension loading, confining DuckDB to its own database file.

### 5.5 Dispatch Integration

In `src/routes/mod.rs`, add DuckDB capability extraction alongside SQL:

```rust
// Existing: extract SQL capabilities
let sql_caps = ...;

// New: extract DuckDB capabilities
let duckdb_caps: Vec<_> = capabilities.iter().filter_map(|c| {
    match (&c.resource, c.ability.as_ref().as_ref()) {
        (Resource::TinyCloud(r), ability)
            if r.service().as_str() == "duckdb"
                && ability.starts_with("tinycloud.duckdb/") =>
        {
            Some((r.clone(), ability.to_string()))
        }
        _ => None,
    }
}).collect();

if !duckdb_caps.is_empty() {
    return handle_duckdb_invoke(i, data, tinycloud, duckdb_service, &duckdb_caps).await;
}
```

### 5.6 Arrow Response

When the request includes `Accept: application/vnd.apache.arrow.stream`:

```rust
InvocationOutcome::DuckDbArrow(bytes) => {
    Response::build()
        .header(ContentType::new("application", "vnd.apache.arrow.stream"))
        .sized_body(bytes.len(), std::io::Cursor::new(bytes))
        .ok()
}
```

The actor uses `duckdb::Arrow` result type and serializes via `arrow::ipc::writer::StreamWriter`.

---

## 6. Configuration

Add to `src/config.rs`:

```rust
pub struct DuckDbStorageConfig {
    #[serde(default = "default_duckdb_path")]
    pub path: String,                          // default: "./tinycloud/duckdb"

    pub limit: Option<ByteUnit>,               // Storage quota per space (future)

    #[serde(default = "default_duckdb_memory_threshold")]
    pub memory_threshold: ByteUnit,            // default: 10 MiB (promote to file)

    #[serde(default = "default_duckdb_idle_timeout")]
    pub idle_timeout_secs: u64,                // default: 300 (5 minutes)

    #[serde(default = "default_duckdb_max_memory")]
    pub max_memory_per_connection: String,      // default: "128MB"
}
```

Add to `Storage` struct:

```rust
pub struct Storage {
    pub blocks: BlockConfig,
    pub staging: BlockStage,
    pub database: String,
    pub limit: Option<ByteUnit>,
    pub sql: SqlStorageConfig,
    pub duckdb: DuckDbStorageConfig,  // new
}
```

Example `tinycloud.toml`:

```toml
[storage.duckdb]
path = "./tinycloud/duckdb"
memory_threshold = "10 MiB"
idle_timeout_secs = 300
max_memory_per_connection = "128MB"
```

---

## 7. Version / Features

Update the `/version` endpoint:

```rust
features: vec!["kv", "delegation", "sharing", "sql", "duckdb"],
```

---

## 8. Dependencies

Add to `tinycloud-core/Cargo.toml`:

```toml
duckdb = { version = "1.1", features = ["bundled"] }
arrow = { version = "53", features = ["ipc"] }
```

`sqlparser` is already a dependency (used by SQL service). Reuse with `GenericDialect` or `DuckDbDialect` for DuckDB SQL validation.

`dashmap` is already a dependency.

---

## 9. Parser Differences from SQL Service

The SQL service parser uses `SQLiteDialect`. DuckDB parser should use `GenericDialect` (sqlparser doesn't have a DuckDB dialect as of v0.44) or a future `DuckDbDialect` if available.

Key validation differences:

| Check | SQLite service | DuckDB service |
|-------|---------------|----------------|
| ATTACH/DETACH | Block | Block |
| DDL | Requires admin or write | Requires write (less restrictive) |
| External access functions | N/A | Block `read_parquet('http://...')`, `httpfs`, etc. (redundant with `enable_external_access=false` but defense in depth) |
| COPY TO/FROM | N/A | Block in parser (use explicit export/ingest actions instead) |
| SET statements | Pragma whitelist | Block all SET except via admin ability |
| Extensions | N/A | Block INSTALL/LOAD extension statements |

---

## 10. Error Types

```rust
pub enum DuckDbError {
    DuckDb(String),              // Database engine error
    PermissionDenied(String),    // Ability/caveat violation
    DatabaseNotFound,            // No database at path
    ResponseTooLarge(u64),       // Exceeds 10MB JSON limit
    QuotaExceeded,               // Storage quota hit
    InvalidStatement(String),    // Unknown prepared statement name
    SchemaError(String),         // DDL execution failed
    ReadOnlyViolation,           // Write attempted with read ability
    ParseError(String),          // SQL parsing failed
    IngestError(String),         // KV → DuckDB load failed
    ExportError(String),         // DuckDB → KV write failed
    ImportError(String),         // .duckdb file upload failed
    Internal(String),            // System error
}
```

HTTP status mapping:
- `DuckDb`, `InvalidStatement`, `SchemaError`, `ParseError` → 400
- `PermissionDenied`, `ReadOnlyViolation` → 403
- `DatabaseNotFound` → 404
- `ResponseTooLarge` → 413
- `QuotaExceeded` → 429
- `IngestError`, `ExportError`, `ImportError` → 500
- `Internal` → 500

---

## 11. Storage Layout

```
{base_path}/
  {space_id}/
    {db_name}.duckdb         # Database file (after promotion from memory)
```

Default `db_name` is `"default"` (extracted from invocation path, same as SQL service).

Example: `./tinycloud/duckdb/tinycloud:pkh:eip155:1:0xabc123:myspace/default.duckdb`

---

## 12. Implementation Plan

### Phase 1: Core service (MVP)
1. Add `duckdb` and `arrow` dependencies to `Cargo.toml`
2. Create `tinycloud-core/src/duckdb/` module with all files
3. Implement `types.rs` — request/response/error enums
4. Implement `storage.rs` — connection open, hybrid storage, promote_to_file
5. Implement `parser.rs` — SQL validation with GenericDialect, DuckDB-specific blocks
6. Implement `caveats.rs` — mirror SQL service caveats
7. Implement `database.rs` — actor model with DuckDB connection
8. Implement `service.rs` — DuckDbService with execute/export
9. Implement `describe.rs` — schema introspection

### Phase 2: Server integration
10. Add `DuckDbStorageConfig` to `src/config.rs`
11. Add `InvocationOutcome::DuckDbResult`, `DuckDbExport`, `DuckDbArrow` variants
12. Add `handle_duckdb_invoke()` to `src/routes/mod.rs`
13. Wire DuckDB capability extraction into `invoke()` route
14. Register `DuckDbService` as Rocket managed state in `src/lib.rs`
15. Update `/version` features to include `"duckdb"`

### Phase 3: KV bridge
16. Implement ingest action (KV → DuckDB via temp file + read_parquet/csv/json)
17. Implement export_to_kv action (query → temp file → KV storage)

### Phase 4: Arrow support
18. Add Arrow IPC serialization in actor response path
19. Add Accept header detection in route handler
20. Add `DuckDbArrow` response encoding

### Phase 5: Import
21. Implement .duckdb file import (binary upload → replace database file)
22. Handle actor shutdown/restart on import (replace file while actor is alive)

---

## 13. Application Migration Path

1. **Export** existing local `workspace.duckdb` via the application CLI or UI
2. **Import** the file to tinycloud via `tinycloud.duckdb/import` action
3. **Update** the application's `duckdbQuery*` / `duckdbExec*` functions to call tinycloud-node's `/invoke` endpoint with DuckDB UCAN invocations instead of shelling out to the `duckdb` CLI binary
4. **Remove** local DuckDB CLI dependency from the application

Alternatively, replay schema + data via SQL batch:
1. Export schema: `EXPORT DATABASE '/tmp/export'` locally
2. Read the generated SQL files
3. Send as batch execute to tinycloud DuckDB service

---

## 14. Resolved Questions

- **Concurrent writers**: The actor model serializes all access. Multiple tabs/devices queue through one actor — acceptable for CRM workloads.
- **Database size limits**: Skip for now. Not enforced in the SQL service either.
- **WASM bindings**: Yes — both SQL and DuckDB services get WASM bindings. See Section 15.

---

## 15. SDK: WASM Bindings & TypeScript Services

Both the SQL service and DuckDB service need SDK support across three layers: WASM bindings (Rust), TypeScript service classes, and retry/error handling.

### 15.1 WASM Bindings (tinycloud-sdk-wasm)

Add convenience functions for constructing invocation headers for SQL and DuckDB operations. These don't execute queries — they prepare the UCAN invocation that the TypeScript SDK sends via HTTP.

#### SQL WASM Bindings

```rust
// tinycloud-sdk-wasm/src/sql.rs

#[wasm_bindgen]
pub fn sql_invoke(
    session_jwk: &str,
    delegation_header: &str,
    space: &str,
    db_name: &str,
    ability: &str,          // "tinycloud.sql/read", "tinycloud.sql/write", etc.
    caveats_json: Option<String>,  // Serialized SqlCaveats
) -> Result<String, JsValue> {
    // Returns serialized InvocationHeaders (authorization header value)
    // Same pattern as existing invoke() but with sql service + caveats in facts
}
```

#### DuckDB WASM Bindings

```rust
// tinycloud-sdk-wasm/src/duckdb.rs

#[wasm_bindgen]
pub fn duckdb_invoke(
    session_jwk: &str,
    delegation_header: &str,
    space: &str,
    db_name: &str,
    ability: &str,          // "tinycloud.duckdb/read", "tinycloud.duckdb/write", etc.
    caveats_json: Option<String>,  // Serialized DuckDbCaveats
) -> Result<String, JsValue> {
    // Returns serialized InvocationHeaders
}
```

### 15.2 TypeScript Service Classes (sdk-services)

Follow the existing `KVService` / `BaseService` pattern.

#### ISQLService Interface

```typescript
// packages/sdk-services/src/sql/ISQLService.ts

export interface ISQLService extends IService {
  query(sql: string, params?: SqlValue[], options?: SQLOptions): Promise<Result<QueryResponse>>;
  execute(sql: string, params?: SqlValue[], options?: SQLExecuteOptions): Promise<Result<ExecuteResponse>>;
  batch(statements: BatchStatement[], options?: SQLBatchOptions): Promise<Result<BatchResponse>>;
  executeStatement(name: string, params?: SqlValue[], options?: SQLOptions): Promise<Result<QueryResponse | ExecuteResponse>>;
  export(options?: SQLOptions): Promise<Result<Blob>>;
  describe(options?: SQLOptions): Promise<Result<SchemaInfo>>;
}

export interface SQLExecuteOptions extends SQLOptions {
  schema?: string[];  // DDL to run before the statement
}

export interface SQLBatchOptions extends SQLOptions {
  transactional?: boolean;
}

export interface SQLOptions {
  signal?: AbortSignal;
  dbName?: string;  // default: "default"
}
```

#### IDuckDbService Interface

```typescript
// packages/sdk-services/src/duckdb/IDuckDbService.ts

export interface IDuckDbService extends IService {
  query(sql: string, params?: DuckDbValue[], options?: DuckDbQueryOptions): Promise<Result<QueryResponse>>;
  execute(sql: string, params?: DuckDbValue[], options?: DuckDbExecuteOptions): Promise<Result<ExecuteResponse>>;
  batch(statements: BatchStatement[], options?: DuckDbBatchOptions): Promise<Result<BatchResponse>>;
  executeStatement(name: string, params?: DuckDbValue[], options?: DuckDbOptions): Promise<Result<QueryResponse | ExecuteResponse>>;
  describe(options?: DuckDbOptions): Promise<Result<SchemaInfo>>;
  ingest(source: string, format: IngestFormat, table: string, mode: IngestMode, options?: DuckDbOptions): Promise<Result<IngestResponse>>;
  exportToKv(sql: string, destination: string, format: ExportFormat, options?: DuckDbOptions): Promise<Result<ExportResponse>>;
  export(options?: DuckDbOptions): Promise<Result<Blob>>;
  import(file: Blob | ArrayBuffer, options?: DuckDbOptions): Promise<Result<void>>;
}

export interface DuckDbQueryOptions extends DuckDbOptions {
  format?: "json" | "arrow";  // default: "json"
}

export interface DuckDbExecuteOptions extends DuckDbOptions {
  schema?: string[];
}

export interface DuckDbBatchOptions extends DuckDbOptions {
  transactional?: boolean;  // default: false
}

export interface DuckDbOptions {
  signal?: AbortSignal;
  dbName?: string;
}

export type IngestFormat = "parquet" | "csv" | "json";
export type IngestMode = "replace" | "append";
export type ExportFormat = "parquet" | "csv" | "json";
```

### 15.3 Error Handling & Retry

The web-sdk already defines `RetryPolicy` and error codes but doesn't wire them into service calls. Both SQL and DuckDB services should implement retry with the existing infrastructure.

#### Error Codes (additions to sdk-services/src/types.ts)

```typescript
export const ErrorCodes = {
  // ... existing codes ...

  // SQL-specific
  SQL_PARSE_ERROR: "SQL_PARSE_ERROR",
  SQL_WRITE_FAILED: "SQL_WRITE_FAILED",
  SQL_READ_ONLY_VIOLATION: "SQL_READ_ONLY_VIOLATION",
  SQL_RESPONSE_TOO_LARGE: "SQL_RESPONSE_TOO_LARGE",
  SQL_SCHEMA_ERROR: "SQL_SCHEMA_ERROR",

  // DuckDB-specific
  DUCKDB_PARSE_ERROR: "DUCKDB_PARSE_ERROR",
  DUCKDB_WRITE_FAILED: "DUCKDB_WRITE_FAILED",
  DUCKDB_READ_ONLY_VIOLATION: "DUCKDB_READ_ONLY_VIOLATION",
  DUCKDB_RESPONSE_TOO_LARGE: "DUCKDB_RESPONSE_TOO_LARGE",
  DUCKDB_SCHEMA_ERROR: "DUCKDB_SCHEMA_ERROR",
  DUCKDB_INGEST_FAILED: "DUCKDB_INGEST_FAILED",
  DUCKDB_EXPORT_FAILED: "DUCKDB_EXPORT_FAILED",
  DUCKDB_IMPORT_FAILED: "DUCKDB_IMPORT_FAILED",

  // Shared
  SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
  WRITE_UNAVAILABLE: "WRITE_UNAVAILABLE",
};
```

#### Retry Logic (new utility in sdk-services)

```typescript
// packages/sdk-services/src/retry.ts

export async function withRetry<T>(
  operation: (attempt: number) => Promise<Result<T>>,
  policy: RetryPolicy,
  emit?: (event: string, data: unknown) => void,
): Promise<Result<T>> {
  let lastResult: Result<T>;

  for (let attempt = 1; attempt <= policy.maxAttempts; attempt++) {
    lastResult = await operation(attempt);

    if (lastResult.ok) return lastResult;

    const isRetryable = policy.retryableErrors.includes(lastResult.error.code);
    const isLastAttempt = attempt === policy.maxAttempts;

    if (!isRetryable || isLastAttempt) return lastResult;

    // Emit retry event
    emit?.("SERVICE_RETRY", {
      attempt,
      error: lastResult.error,
      nextDelayMs: computeDelay(attempt, policy),
    });

    await sleep(computeDelay(attempt, policy));
  }

  return lastResult!;
}

function computeDelay(attempt: number, policy: RetryPolicy): number {
  switch (policy.backoff) {
    case "none": return policy.baseDelayMs;
    case "linear": return Math.min(policy.baseDelayMs * attempt, policy.maxDelayMs);
    case "exponential": return Math.min(policy.baseDelayMs * 2 ** (attempt - 1), policy.maxDelayMs);
  }
}
```

#### Write Unavailability Handling

When a write fails due to the DuckDB actor being busy (single-writer) or the server returning 503:

```typescript
// In DuckDbService.execute(), DuckDbService.batch(), etc.

async execute(sql: string, params?: DuckDbValue[], options?: DuckDbExecuteOptions): Promise<Result<ExecuteResponse>> {
  return this.withTelemetry("execute", sql, async () => {
    if (!this.requireAuth()) {
      return err(authRequiredError("duckdb"));
    }

    return withRetry(
      async (attempt) => {
        const response = await this.invokeOperation("duckdb", "write", {
          action: "execute", sql, params, schema: options?.schema,
        }, options?.signal);

        if (!response.ok) {
          return this.mapHttpError(response);
        }
        return ok(await response.json());
      },
      {
        ...this.context.retryPolicy,
        retryableErrors: [
          ErrorCodes.NETWORK_ERROR,
          ErrorCodes.TIMEOUT,
          ErrorCodes.SERVICE_UNAVAILABLE,
          ErrorCodes.WRITE_UNAVAILABLE,
        ],
      },
      (event, data) => this.context.emit(event, data),
    );
  });
}
```

HTTP status → error code mapping in the service:

```typescript
private mapHttpError(response: Response): Result<never> {
  switch (response.status) {
    case 400: return err(serviceError(ErrorCodes.DUCKDB_PARSE_ERROR, ...));
    case 403: return err(serviceError(ErrorCodes.PERMISSION_DENIED, ...));
    case 404: return err(serviceError(ErrorCodes.NOT_FOUND, ...));
    case 413: return err(serviceError(ErrorCodes.DUCKDB_RESPONSE_TOO_LARGE, ...));
    case 429: return err(serviceError(ErrorCodes.DUCKDB_WRITE_FAILED, ...));
    case 503: return err(serviceError(ErrorCodes.SERVICE_UNAVAILABLE, ...));
    default:  return err(serviceError(ErrorCodes.NETWORK_ERROR, ...));
  }
}
```

### 15.4 Service Registration

Both services register in `sdk-core/src/TinyCloud.ts`:

```typescript
// Feature-gated via /version endpoint
const features = await this.fetchFeatures();

if (features.includes("sql")) {
  this.context.registerService("sql", new SQLService());
}
if (features.includes("duckdb")) {
  this.context.registerService("duckdb", new DuckDbService());
}
```

Access:
```typescript
const sql = tc.getService<ISQLService>("sql");
const duckdb = tc.getService<IDuckDbService>("duckdb");

// Query
const result = await duckdb.query("SELECT * FROM people WHERE status = ?", ["active"]);
if (result.ok) {
  console.log(result.data.rows);
}

// Execute with schema bootstrap
const writeResult = await duckdb.execute(
  "INSERT INTO logs (event) VALUES (?)",
  ["login"],
  { schema: ["CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, event TEXT)"] }
);

// Arrow format for large results
const arrowResult = await duckdb.query(
  "SELECT * FROM events",
  [],
  { format: "arrow" }
);
// arrowResult.data is ArrayBuffer (Arrow IPC stream)
```

### 15.5 Implementation Plan (SDK additions)

Add to the main implementation plan:

### Phase 6: WASM bindings
23. Add `sql.rs` to `tinycloud-sdk-wasm/src/` with `sql_invoke()` function
24. Add `duckdb.rs` to `tinycloud-sdk-wasm/src/` with `duckdb_invoke()` function
25. Export new functions in `tinycloud-sdk-wasm/src/lib.rs`
26. Update `web-sdk/packages/sdk-rs/Cargo.toml` git rev

### Phase 7: TypeScript SDK
27. Add `withRetry()` utility to `sdk-services/src/retry.ts`
28. Add SQL and DuckDB error codes to `sdk-services/src/types.ts`
29. Create `sdk-services/src/sql/` — `ISQLService.ts`, `SQLService.ts`, `types.ts`
30. Create `sdk-services/src/duckdb/` — `IDuckDbService.ts`, `DuckDbService.ts`, `types.ts`
31. Feature-gated registration in `sdk-core/src/TinyCloud.ts`
32. Wire WASM invoke helpers into service `invokeOperation()` methods

---

## 16. Remaining Open Question

- **Concurrent writers**: The actor model serializes writes. Multiple browser tabs / devices queue through one actor. For CRM workloads this is fine — but if a write is rejected because the actor is overloaded, the SDK retry logic handles it automatically via `WRITE_UNAVAILABLE` → exponential backoff.
