![TinyCloud Protocol header](/docs/tinycloudheader.png)

[![](https://img.shields.io/badge/License-EGPL--1.5-green)](https://github.com/TinyCloudLabs/tinycloud-node/blob/main/LICENSE.md)
[![](https://img.shields.io/badge/Version-1.0.0-blue)](https://github.com/TinyCloudLabs/tinycloud-node/releases)

# TinyCloud Node

TinyCloud Node is the server component of the TinyCloud Protocol — a framework for creating interoperable software applications where users retain full sovereignty over their data. It provides a decentralized or user-controlled "cloud" that can serve as the backend for multiple apps, allowing users to maintain control over their data without ceding ownership or privacy to third parties.

TinyCloud Node hosts user data spaces, processes delegations, and serves the KV storage API. It is a descendant of [Kepler](https://github.com/spruceid/kepler) and is architected as a decentralized storage system that uses DIDs and Authorization Capabilities to define TinyCloud Spaces, where your data lives and who has access.

## Protocol Version

TinyCloud Node v1.0.0 introduces a protocol version system for SDK-node compatibility. The node exposes a public `/version` endpoint:

```
GET /version
```

```json
{
  "protocol": 1,
  "version": "1.0.0",
  "features": ["kv", "delegation", "sharing"]
}
```

The SDK checks this endpoint during sign-in and requires an exact protocol version match. This ensures clients and servers are always running compatible versions.

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/version` | No | Protocol version and feature discovery |
| `POST` | `/invoke` | Yes | Execute KV/SQL/DuckDB operations or read storage usage |
| `POST` | `/signed/kv` | Yes | Create an expiring signed URL for an exact KV object read |
| `GET` | `/signed/kv/<ticketId>` | Signed URL ticket | Fetch a KV object, including single byte ranges |
| `POST` | `/delegate` | Yes | Create capability delegations |
| `GET` | `/peer/generate/<space>` | No | Generate space host key pair |
| `GET` | `/healthz` | No | Health check |

### Storage usage and full-space writes

Send `POST /invoke` with a normal signed invocation granting
`tinycloud.space/info` on the target space's `space` service, for example
`tinycloud:pkh:eip155:1:<address>:<space>/space`. The body may be `{}`.
The target comes from the signed resource, not the body; all capabilities
in this invocation must be `space/info` for the same space. Normal delegation,
expiry, revocation and replay checks apply. No admin credential is needed.

The `200 application/json` response is:

```json
{
  "space": {"usedBytes": 123, "limitBytes": 456},
  "account": {"usedBytes": 789, "limitBytes": 1000, "plan": "free"},
  "manageUrl": "https://account.tinycloud.xyz/billing"
}
```

All sizes are bytes. `space.limitBytes` is `null` when unlimited; empty spaces
report zero usage. `account` is omitted unless billing supplied both account
totals in a non-degraded answer. `plan` is omitted when older billing omits it.
Account numbers use the quota cache's existing stale-while-revalidate policy.
Clients must explicitly request `tinycloud.space/info` in their session
authority; existing SDK default sessions do not include it. The node does not
expand existing grants.

Storage rejections use `application/json` with `error`, `message`, `space`,
and the same optional `account` object. HTTP 402 uses
`"error":"storage_quota_exceeded"` and preserves the message
`Storage quota exceeded. Used: X bytes, Limit: Y bytes`.
HTTP 413 uses `"error":"storage_limit_reached"` and preserves
`Write exceeds remaining storage. Used: X bytes, Limit: Y bytes`.
Other 413 errors, such as oversized query responses, are not storage errors.
Delegated authority is rechecked against the current time after quota fetching
or upload staging delays a storage rejection. Expired authority receives 403
without space or account totals.

Reads remain available on full spaces. SQLite writes run in a savepoint:
page growth or a failed request rolls back all its mutations. Caller transaction
control is forbidden, including extra statements hidden after a PRAGMA.
Deletes, drops, no-op schema initialization and writes that reuse existing pages
can succeed. Guarded SQLite and DuckDB writes replace the durable checkpoint
without accumulating WAL charges, but are refused if the serialized checkpoint
would exceed the existing artifact's charged size. No-ops against absent
databases do not create charged artifacts. DuckDB uses a conservative
transactional guard for deletes, drops and existing `IF NOT EXISTS` objects;
other writes remain refused while full.
Deletion need not shrink the physical database immediately. Below the limit,
the existing database one-write overshoot policy is unchanged.

Exports do not persist checkpoints or change storage charges. Both engines
return `DatabaseNotFound` when no durable artifact exists, even if a query
created a temporary actor. Rejected guarded requests close absent-database
actors. DuckDB exports replay durable WAL in a disposable copy, leaving the
live actor's WAL base unchanged for subsequent writes.

Set `TINYCLOUD_QUOTA_URL` to billing's base URL. The node fetches
`GET /api/quota/<space>` with `Authorization: Bearer <TINYCLOUD_ADMIN_SECRET>`
when that shared service secret is configured. The same secret protects
`/admin/quota`; never expose it to browser clients. Old billing responses
containing only `storage_limit_bytes` remain supported. Local testing can
set an in-memory limit with authenticated
`PUT /admin/quota/<space>` and `{"limit_bytes":1}`; overrides reset on restart.

### Signed KV URLs

`POST /signed/kv` accepts a normal TinyCloud invocation whose authorized capabilities include a `tinycloud.kv/get` capability that can be attenuated to the requested `{space, path}`. The invocation may include other capabilities. The JSON body is:

```json
{
  "space": "tinycloud:...",
  "path": "transcripts/audio.wav",
  "ttlSeconds": 60
}
```

The response includes a short relative `url`, opaque `ticketId`, and RFC3339 `expiresAt`:

```json
{
  "url": "/signed/kv/JUWkXuA4mqnxDVXcaxXoVME8uYUTumgmuwbllQFxHnQ",
  "ticketId": "JUWkXuA4mqnxDVXcaxXoVME8uYUTumgmuwbllQFxHnQ",
  "expiresAt": "2026-05-12T16:25:00Z"
}
```

The node stores the ticket durably in its database with the exact KV scope, issuer/subject DID, ability, service, creation and expiry timestamps, content hash/ETag binding, parent expiry metadata, and proof metadata. If the request omits `contentHash` and `etag`, the node binds the ticket to the current object hash. The bearer URL does not contain the space, path, or signed claims. Reads load the ticket, validate expiry and scope, then perform a private KV read; signed KV URLs are not limited to public spaces.

Ticket expiry is the earliest of the requested TTL, node maximum TTL, invocation expiry, and parent delegation expiry when known. `maxUses` is rejected in v1 because limited-use URLs need durable counters and replay protection to stay correct across restarts and multi-node deployments.

Signed KV reads support one standard HTTP byte range at a time:

```http
GET /signed/kv/JUWkXuA4mqnxDVXcaxXoVME8uYUTumgmuwbllQFxHnQ
Range: bytes=1048576-2097151
If-Range: "blake3-<64 hex characters>"
```

A satisfiable range returns `206 Partial Content` with `Accept-Ranges: bytes`, `Content-Range`, `Content-Length`, and the strong TinyCloud `ETag`. An out-of-bounds range returns `416 Range Not Satisfiable`. If `If-Range` does not match, the node returns the full object. Filesystem reads seek to the requested offset and S3 reads use an object-store range request, so the node does not read or proxy the omitted bytes.

With telemetry enabled, backend time-to-first-byte is recorded under the `server.signed_kv.kv_get_range` span. `tinycloud_signed_kv_bytes_total{measure="object"}` and `{measure="served"}` expose the transfer reduction from range reads.

## Quickstart

To run TinyCloud Protocol locally, install [Rustup](https://rustup.rs). The
repository selects the reviewed Rust `1.97.1` toolchain automatically through
`rust-toolchain.toml`; do not substitute a floating `stable` compiler.


You will need to create a directory for TinyCloud Protocol to store data in:
```bash
mkdir data
```

Within this directory, create one more directories `blocks` and a database file `caps.db`:
```bash
mkdir data/blocks
touch data/caps.db
```

To setup local data storage you can also run `./scripts/init-tinycloud-data.sh`

You will then need to set the environment variables to point to those directories:
```bash
export TINYCLOUD_STORAGE_BLOCKS_PATH="data/blocks"
export TINYCLOUD_STORAGE_DATABASE="data/caps.db"
```

Finally you can run TinyCloud Protocol using `cargo`:
```bash
cargo build
cargo run
```


## Configuration

TinyCloud Protocol instances are configured by the [tinycloud.toml](tinycloud.toml) configuration file, or via environment variables. You can either modify them in this file, or specify them through environment variable using the prefix `TINYCLOUD_`.

The following common options are available:

| Option              | env var                      | description                                                                |
|:--------------------|:-----------------------------|:---------------------------------------------------------------------------|
| log_level           | TINYCLOUD_LOG_LEVEL           | Default log verbosity: "off", "critical" (warnings and errors), "normal" (info) or "debug". Used when `RUST_LOG` is unset. Request URIs are never logged at any level; each request is logged once by route template, status and latency |
| (n/a)               | RUST_LOG                      | Override the log verbosity with a `tracing` `EnvFilter`, e.g. `debug` or `tinycloud=debug` |
| address             | TINYCLOUD_ADDRESS             | Set the listening address of the TinyCloud Protocol instance                           |
| port                | TINYCLOUD_PORT                | Set the listening TCP port for the TinyCloud Protocol instance                         |
| storage.blocks.type | TINYCLOUD_STORAGE_BLOCKS_TYPE | Set the mode of block storage, options are "Local" and "S3"                |
| storage.limit        | TINYCLOUD_STORAGE_LIMIT        | Set a maximum limit on storage available to Spaces hosted on this instance. Limits are written as strings, e.g. `10 MiB`, `100 GiB`                                                                           |
| storage.database    | TINYCLOUD_STORAGE_DATABASE    | Set the location of the SQL database                                       |
| storage.staging     | TINYCLOUD_STORAGE_STAGING     | Set the mode of content staging, options are "Memory" and "FileSystem"     |
| keys.type           | TINYCLOUD_KEYS_TYPE           | Set the type of host key store, options are "Static"                       |
| spaces.allowlist    | TINYCLOUD_SPACES_ALLOWLIST    | Set the URL of an allowlist service for gating the creation of Space Peers |
| telemetry.enabled   | TINYCLOUD_TELEMETRY__ENABLED  | Enable Prometheus latency metrics on the configured Prometheus port        |
| (n/a)               | ROCKET_MAX_BLOCKING           | Set Rocket's blocking-thread-pool cap (default 512). Note the `ROCKET_` prefix, not `TINYCLOUD_` — Rocket builds its tokio runtime from its own Figment before TinyCloud's config is loaded, so `TINYCLOUD_MAX_BLOCKING` is silently ignored for this setting |

### Database Config

The SQL database can be configured with `storage.database` or the `TINYCLOUD_STORAGE_DATABASE` environment variable. It supports Sqlite, MySQL and PostgresSQL. For example:

| Type     | Example                                       | Description                                                                         |
|:---------|:----------------------------------------------|:------------------------------------------------------------------------------------|
| Sqlite   | "sqlite:./data/caps.db"                     | Set TinyCloud Protocol to use a local Sqlite file at the relative path `./data/caps.db`       |
| MySQL    | "mysql://root:root@localhost:3306/example"    | Use the MySQL instance deployed at `localhost:3306`, with database name `example`   |
| Postgres | "postgres://root:root@localhost:5432/example" | Use the Postgres instance deployed at `localhost:5432` with database name `example` |

This will default to an in-memory Sqlite database (i.e. `sqlite::memory:`).

#### PostgreSQL pool limits

These bound how long one PostgreSQL round trip can block a request (TC-1054). Each can be set in `[global.database]` or with the `TINYCLOUD_DATABASE__<NAME>` environment variable (for example `TINYCLOUD_DATABASE__STATEMENT_TIMEOUT_MS`).

| Option | Default | Description |
|:-------|:--------|:------------|
| database.max_connections | `100` | Pool size. |
| database.idle_timeout_secs | `240` | Close a connection idle this long, so it is recycled before a NAT, load-balancer or proxy idle cutoff drops it silently. 240 s sits below the common 4-minute middlebox cutoff, AWS NAT Gateway's 350 s and PlanetScale PSBouncer's 600 s `server_idle_timeout`. Also applies to MySQL. |
| database.max_lifetime_secs | `1800` | Close a connection this long after it opened. PlanetScale asks for at most 24 h; PSBouncer's `server_lifetime` is 3600 s. Also applies to MySQL. |
| database.tcp_keepalive | `true` | Set TCP keepalive and `TCP_USER_TIMEOUT` on every connection's socket (Linux only; elsewhere a logged no-op), so a connection the network silently drops fails within about 30 s instead of the kernel's ~15-minute retransmission timeout. A connection whose socket cannot be configured is refused and reopened, never used. |
| database.tcp_keepalive_idle_secs | `15` | Idle time before the first keepalive probe. |
| database.tcp_keepalive_interval_secs | `5` | Time between unanswered probes. |
| database.tcp_keepalive_retries | `3` | Unanswered probes before the connection is dropped (15 + 3 × 5 = 30 s). |
| database.tcp_user_timeout_ms | `30000` | `TCP_USER_TIMEOUT`: how long sent data may go unacknowledged before the connection is dropped. `0` keeps the kernel default. |
| database.statement_timeout_mode | `session` | How PostgreSQL's `statement_timeout` is applied: `session` sets it once on each new connection (no per-request cost; covers every statement); `local` sets it with `SET LOCAL` in each explicit transaction (safe behind a transaction-pooling proxy, but one more round trip per transaction, and autocommit statements are not covered); `off` disables it. |
| database.statement_timeout_ms | `30000` | `statement_timeout` for every statement. `0` disables it. |
| database.bulk_statement_timeout_ms | `120000` | `statement_timeout` for statements on a whole SQL or DuckDB artifact larger than 8 MiB (or of unknown size): hydration loads and checkpoint saves, whose server-side work on a ~100 MiB value can outlast the base limit. PostgreSQL does not cancel a statement while it writes a row to the client, so the download itself is not limited by either value. |
| database.retry_window_ms | `10000` | A read (or `BEGIN`) whose connection is lost is retried once only if that attempt failed within this window. A connection found dead at once is retried; one whose loss took a keepalive expiry to detect is not, so a request waits for at most one detection plus this window (about 40 s), under the 60 s ingress timeout. |

Schema migrations always run with no statement timeout. Customer SQL (`tinycloud.sql/*`) runs in the node's local SQLite engine, never on PostgreSQL, so `statement_timeout` does not limit it.

A database failure gets one of two responses, which clients must tell apart by the body's leading code:

| Status | Body starts with | `Retry-After` | Meaning |
|:-------|:-----------------|:--------------|:--------|
| `503` | `unavailable_retryable:` | `1` | No write of the request can have taken effect: no connection could be had, the request only read, or PostgreSQL refused the statement (statement timeout, serialization failure, deadlock). A fresh request is safe. |
| `500` | `outcome_unknown:` | none | The connection was lost after a write or `COMMIT` was sent: the write may have been applied. Read the state back before deciding to retry; re-sending the identical signed request is answered `409` (replay protection), except a delegation, which is idempotent. |

Other `503`s (for example the identity-cutover fence) carry neither code.

With `session`, behind a transaction-pooling proxy (PgBouncer, PlanetScale PSBouncer on port 6432) the per-connection `SET` lands on whichever server connection served it, so coverage becomes best-effort and the setting can reach other clients of the same proxy. The scoped limits (no limit for migrations, the bulk limit) use `SET LOCAL` and stay inside their transaction. Use `local` there if full coverage matters.

The keepalive setting is a stopgap (TC-1061): sqlx 0.8 can't set socket options, so when the pool opens a connection the node configures every TCP socket of its process whose peer port is the database port and whose keepalive is still off (`tinycloud-node-server/src/pg_keepalive.rs`). Nothing else in the node connects to that port (webhooks must use HTTPS on 443). The startup line `PostgreSQL pool connection limits` reports `sockets_configured`, `connections_opened` and `keepalive_missed`; after a deploy, `sockets_configured >= connections_opened` with no `PostgreSQL TCP keepalive missed a connection's socket` warning means every connection in use is protected.

#### Migrations

TinyCloud Protocol will automatically apply the relevant migrations to your chosen SQL database. Use caution if you are sharing this database with another application.

### Staging Config

TinyCloud Protocol will temporarily stage files it receives before writing them. It can do this in memory or in temporary files. This can be configured by setting `storage.staging` to `Memory` or `FileSystem`. Default is `Memory`.

### Storage Config

Storage can be configured for Blocks depending on it's `type`.

#### Local Storage

When `storage.blocks.type` is `Local`, the local filesystem will be used for application content storage. The following config option will become available:

| Option               | env var                       | description                                                    |
|:---------------------|:------------------------------|:---------------------------------------------------------------|
| storage.blocks.path  | TINYCLOUD_STORAGE_BLOCKS_PATH  | Set the path of the block storage                              |

#### AWS Storage

When `storage.blocks.type` is `S3` the instance will use the S3 AWS service for application storage. The following config options will become available:

| Option               | env var                       | description                                                    |
|:---------------------|:------------------------------|:---------------------------------------------------------------|
| storage.blocks.type  | TINYCLOUD_STORAGE_BLOCKS_TYPE  | Set the mode of block storage, options are "Local" and "S3"    |
| storage.blocks.bucket  | TINYCLOUD_STORAGE_BLOCKS_BUCKET  | Set the name of the S3 bucket    |
| storage.blocks.endpoint  | TINYCLOUD_STORAGE_BLOCKS_ENDPOINT  | Set the URL of the S3 store    |

Additionally, the following environment variables must be present: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_DEFAULT_REGION`.

### Keys Config

TinyCloud Protocol hosts require key pairs to provide replication. The `keys` config fields specify how a TinyCloud Protocol instance generates and stores these key pairs.

#### Static Secret Derivation

When `keys.type` is `Static` the instance will use an array of bytes as a static secret from which it will derive key pairs on a per-Space basis. The following config options will be available:

| Option      | env var              | description                                                                  |
|:------------|:---------------------|:-----------------------------------------------------------------------------|
| keys.secret | TINYCLOUD_KEYS_SECRET | Unpadded base64Url-encoded byte string from which key pairs will be derived. |

The secret MUST contain at least 32 bytes of entropy (either randomly generated or derived in a cryptographically secure way). It is STRONGLY RECOMMENDED that the secret be given via environment variables and NOT in the `tinycloud.toml` config file. Additionally it is STRONGLY RECOMMENDED that the secret be backed up in a secure place if used in production. Loss of the secret will result in total loss of function for the TinyCloud Protocol instance.

## Running

TinyCloud Protocol instances can be started via command line, e.g.:

``` sh
TINYCLOUD_PORT=8001 tinycloud
```

If the TinyCloud Protocol instance is not able to find or establish a connection to the configured storage, the instance will terminate.

## Usage

TinyCloud Protocol is most easily used via the TinyCloud Protocol SDK. See the example DApps and tutorials for detailed information.
