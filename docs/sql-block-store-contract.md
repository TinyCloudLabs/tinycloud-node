# SQL block-store contract (TC-1491, design B, slice 0)

Status: **draft for design review.** No behaviour change ships with this
document; the types, config and migration that follow it are inert unless
`[sql_store] enabled = true`.

Sources: `.context/storage-pricing/design-b/SCOPING.md` (TC-1265), the
10-15 / 10-17 decisions recorded there, node `a742ab8` (1.21.2). Sam's
10-19 18:07Z decision funds P (TC-822), slice 0, slice 1a and an
**unencrypted shadow upload**. It does not fund encryption (slice 2) or any
phase in which the store is master.

## 1. Scope and invariant of the funded phase

1. **Postgres stays master.** `database_artifact` (checkpoint + WAL delta) is
   the only source of truth for a SQL database's content. A SQL write is
   acknowledged exactly when it is today: after the artifact save commits.
   Slice 1a hardens the local copy (`synchronous=FULL`, reservation before
   commit); it does not change what the ack means.
2. **The store copy is a shadow.** A background uploader writes snapshots and
   change segments to the block store (section 3) and records them in the
   manifest tables (section 4). Nothing reads them to serve a request, to
   hydrate, to decide quota, or to authorize.
3. **The manifest is advisory and droppable.** Dropping both tables, or
   deleting the whole `sql/v1/` area, changes no user-visible behaviour. The
   uploader then starts a new lineage and re-snapshots from Postgres.
4. **Unencrypted.** Objects are plaintext SQLite bytes, exactly as they are in
   Postgres today. Until slice 2, the flag is for our own and pilot spaces
   only; an operator turning it on for everyone must accept that the store
   then holds a second plaintext copy of every uploaded database.
5. **Out of scope here:** DuckDB (stays on Postgres artifacts), reads from the
   store, restore tooling beyond the nightly check (section 8), leases and
   epochs as running code (section 9), GC, quota metering of store bytes.

Anything in this document marked **[store-master]** describes the contract the
later phase must meet. It is defined now so the shadow types do not have to be
reshaped; it is not built or enabled.

## 2. Acknowledgement and outcome contract

Every SQL request ends in exactly one of three outcomes. These are the same
three words the API uses today; this section fixes their meaning per phase.

| Outcome | Shadow phase (funded, Postgres master) | [store-master] phase |
|---|---|---|
| **Rejected** | Verified rollback before the artifact save committed. No effect on the local copy or Postgres. Includes `sql_busy`, `request_timeout`, reservation refusal (slice 1a), `StaleLineage`. | Verified rollback before the local COMMIT. No effect. |
| **Committed** | The artifact save committed in Postgres (and, from 1a, the local COMMIT was fsynced under `synchronous=FULL`). The store may lag by up to one upload window; this is invisible to the caller. | Local SQLite COMMIT fsynced and the epoch's response gate released the success. Store lags by at most one window (60 s / 8 MiB default) or the backlog cap. **This is the documented loss window.** |
| **Outcome unknown** | The existing TC-1274 error: HTTP 500, body prefix `outcome_unknown:` (`routes::OUTCOME_UNKNOWN`), no `Retry-After`. Used when the connection died after the save or COMMIT was sent. Clients read state back; a re-sent signed request is answered 409 by replay protection. | Same error and client rule. Additionally returned when authority is uncertain during COMMIT (lost PG session, epoch not provable), when the post-commit intent record failed, or when the response gate closed after COMMIT. Local WAL and request identity are retained; never reported as a definite failure and never replayed blindly. |

Rules, both phases:

- The upload and the manifest CAS **never** change an outcome. A failed or
  slow upload cannot turn a committed write into an error, and cannot be
  cited as the reason for `outcome_unknown`.
- No new error code or HTTP status is introduced in the funded phase. The one
  new refusal, the backlog cap (section 5), reuses `sql_busy` (503 with
  `Retry-After`) with stage `store_backlog`, which is a *rejected* outcome: it
  is raised before any write starts.
- [store-master] only: the current `SqlService` discards local state when
  persistence fails (`persist_write` error path). That is correct while
  Postgres is master and **wrong** once the local commit is the ack: an
  acknowledged or unknown commit must never be discarded because an upload
  failed. The store-master phase must remove that path first; the shadow
  phase keeps it.
- Honest loss-window copy (for docs and the owner status; not shown to
  callers): *"Your database is acknowledged once the node has it safely on its
  own disk. It is copied to storage at least every 60 seconds. If the node's
  disk is destroyed, you can lose the writes since the last copy. A restart,
  crash or planned deploy with the disk intact loses nothing."* In the funded
  phase this copy does **not** apply yet, because Postgres is still master;
  it must not appear in user docs until a database is cut over.

## 3. Store layout

### 3.1 Namespace

SQL objects live in a **private namespace** that KV code cannot address:

```
sql/v1/{space_enc}/{db_enc}/{lineage}/snap/{at_seq:020}-{content_hash}
sql/v1/{space_enc}/{db_enc}/{lineage}/seg/{base_seq:020}-{from_seq:020}-{to_seq:020}-{content_hash}
```

- **Backend mapping.** S3: the same bucket, key exactly as above. Filesystem:
  a sibling root `{datadir}/sql-store/` (not under `blocks.path`). KV keys are
  `{space}/{base64url(hash)}` (`S3BlockStore::key`), and the filesystem KV store
  is `{path}/{suffix}/{name}/{hash}`. No KV key starts with `sql/`, because a
  space ID starts with `tinycloud:`; a property test asserts this (section 8).
- **Never in the KV index or sync feed.** No `current_kv`, `kv_write`, epoch,
  event-order, hook or `kv/sync` row is written for these objects. They have no
  KV key and no KV grant can name them. Access is by node code only; the SQL
  authorization (route, authorizer, caveats) is untouched.
- **Existing S3 start-up size scan.** `S3BlockStore::new_` lists the whole
  bucket and attributes `key.rsplit_once('/')` to a space only if it parses as a
  `SpaceId`. `sql/v1/…/snap` does not parse, so SQL objects are ignored by the
  KV size totals. A test pins this. Cost note for slice 4: the scan still pages
  over SQL keys, so a large SQL area slows boot; slice 4 moves to a manifest
  inventory.
- `at_seq`, `base_seq`, `from_seq`, `to_seq`: zero-padded to 20 digits so keys
  sort numerically. `seq` is the database's commit counter within a lineage,
  assigned under the per-database operation lock. In the shadow phase
  `seq = database_artifact.revision` (incremented by one per save in `database_artifacts.rs`). (The plan used `rev`; renamed to `seq`
  so it cannot be confused with the manifest's `revision`, the publication
  counter.)
- `content_hash`: lowercase hex SHA-256 of the object bytes.
- `lineage`: 128 random bits, lowercase hex, created by the uploader at the
  first publication of a database and again whenever history may have
  diverged (3.3).

### 3.2 `space_enc`, `db_enc`: why `db_id` and how it is encoded

- **`db_id` is the physical artifact name**, the `name` column of
  `database_artifact (service='sql', space, name)`: `v2d<sha256 hex>` / `v2n`
  for TC-780 identities, or the legacy final-segment name when an explicit
  `database_alias` points at a legacy artifact. It is not the user-visible path
  (not recoverable from it, and aliasing means two paths can never share a
  physical artifact). It is the key the actor, hydration and lineage maps
  already use `(space, name)`, so the store follows the same identity as
  everything that mutates the database. If an alias is re-pointed to another
  physical artifact, the new artifact has a new `db_id` and therefore a new
  manifest row and an unrelated store prefix; it does not inherit or overwrite
  the old one.
- **Encoding.** A component may contain `/` and `:` (space IDs) or arbitrary
  bytes (legacy names), so each component is escaped: bytes in `[A-Za-z0-9_-]`
  are kept; every other UTF-8 byte becomes `.` followed by two lowercase hex
  digits (`.` itself is `.2e`). The result is injective (decodable), never
  contains `/`, and never equals `.` or `..`. Empty `db_id` is rejected.
  Max encoded length 255 per component; longer is a hard error, not truncation.
- Service is not in the key: `v1` is SQL only. DuckDB would need `duckdb/v1/`
  and its own review.

### 3.3 Immutability, generations and orphans

- **Keys are never overwritten and never reused with different bytes.** The
  content hash in the key plus the lineage and sequence range make a key a
  pure function of its content and position. Two uploaders (a stale node, a
  retry, a duplicate) producing the same range with different bytes produce
  different keys.
- `put_if_absent(key, bytes, expected_sha256)`: if the key exists, `head`
  must show the same length and stored SHA-256 metadata, else the call fails
  with `Conflict` (loud; never replace). It uses a conditional PUT
  (`If-None-Match: *`) where the provider supports it, otherwise HEAD then PUT:
  safe here only because the key encodes the hash, so a lost race rewrites
  identical bytes.
- **Orphan = an object not referenced by any published manifest frontier.** A
  PUT that completed but whose CAS did not (crash, lost response, lost the
  race) is an orphan. It is never read by anything. In this phase orphans are
  only counted and marked, never deleted (section 4.3).
- A **new lineage** is started when the shadow copy can no longer be
  continued from the manifest: no manifest row; manifest `last_seq` is greater
  than the artifact's current revision (Postgres restored from backup,
  database recreated); the artifact's checkpoint was replaced out of band
  (import, TC-780 alias migration); or the manifest's epoch/lineage CAS fails
  because someone else published. Because Postgres is master, the manifest
  never "wins" a disagreement; it is simply abandoned for a new lineage.

### 3.4 TC-735 cross-check: why the KV block store's layer is not reusable as is

TC-735 (PR #301, still open) fixes generation problems in the KV blob path.
The relevant behaviours on `main` that SQL must **not** inherit:

| KV behaviour (`tinycloud-node-server/src/storage/s3.rs`) | Why unsafe for SQL |
|---|---|
| Key is bare `{space}/{base64(hash)}` (`key()`) | Two logical objects with equal bytes share one key; a delete for one removes the other. SQL keys are lineage/position-qualified. |
| `persist` does `contains` (HEAD) then PUT, `increment_size` | Dedup is correct for an immutable content-addressed body but means "exists" is treated as "mine". SQL needs the length/hash check in `put_if_absent`, and it must not touch KV `sizes`. |
| `remove` does `object_size` then unconditional `DELETE` | A late or ambiguous delete can remove an object a newer reference needs (the TC-735 hazard). SQL has no delete in this phase; the trait has none. GC (slice 4) will need its own generation-safe protocol. |
| `sizes` map seeded by listing the bucket | SQL bytes must not enter `StoreSize`/quota totals (double counting with `SqlSizes`); see 3.1. |

So `SqlObjectStore` (section 6) shares the S3 **client and credentials
construction** and the filesystem **atomic temp-file+rename helpers**, but has
its own key function, no `contains`-as-ownership shortcut, no `remove`, and no
size bookkeeping.

## 4. Manifest tables

Created by one SeaORM migration in the control database (Postgres in
production, SQLite on self-host). Both tables are valid DDL on both backends:
plain types only (`string`, `big_integer`, `integer`, `binary`/`blob`), no
arrays, no JSON operators, no sequences, no partial indexes, no FKs.

```
sql_store_manifest
  space              string      not null
  db_id              string      not null     -- physical artifact name (3.2), unencoded
  lineage            string      not null     -- 32 hex chars
  epoch              big_integer not null     -- shadow phase: always 0; see 4.4
  revision           big_integer not null     -- publication counter, 0-based, +1 per publish
  base_snapshot_key  string      not null     -- full object key of the chain's snapshot
  last_seq           big_integer not null     -- last commit covered by the recoverable chain
  published_at       string      not null     -- RFC 3339, same convention as database_artifact
  frontier_bytes     big_integer not null     -- total bytes of snapshot + segments in the chain
  PRIMARY KEY (space, db_id)

sql_store_object
  space, db_id       string      not null
  key                string      not null     -- full object key, PRIMARY KEY with (space, db_id)
  kind               string      not null     -- 'snapshot' | 'segment'
  bytes              big_integer not null
  content_hash       string      not null
  state              string      not null     -- 'uploaded' | 'published' | 'orphan'
  created_at         string      not null
  PRIMARY KEY (space, db_id, key)
```

(The plan said PK `key`; `key` already embeds space and db, so the composite
is redundant but gives the prefix lookup an index on both backends.)

### 4.1 Publish = upload first, CAS second

1. Seal the object bytes (snapshot of the artifact checkpoint, or a segment
   covering `from_seq..=to_seq` on `base_seq`), compute SHA-256.
2. `put_if_absent`; on success `INSERT sql_store_object … state='uploaded'`
   (`ON CONFLICT DO NOTHING`: a retry re-inserts the same row).
3. In **one metadata transaction**, publish:
   ```
   UPDATE sql_store_manifest
      SET revision = :rev + 1, base_snapshot_key = :snap, last_seq = :last,
          frontier_bytes = :bytes, published_at = :now
    WHERE space = :s AND db_id = :d
      AND epoch = :epoch AND lineage = :lineage AND revision = :rev
      AND last_seq <= :last
   ```
   Exactly one affected row means this publisher won. Zero means stale epoch,
   stale/other lineage, a concurrent publisher, or a regressing `last_seq`; the
   caller re-reads `current` and decides (retry on the new revision, or open a
   new lineage). First publication is `INSERT` and loses on PK conflict.
   In the same transaction the objects of the new chain flip
   `uploaded → published`.
4. A **lost CAS response** is reconciled by `current()`: if the row shows
   `revision = :rev + 1` and the expected `base_snapshot_key`/`last_seq`, the
   publish happened; the uploader never re-runs the UPDATE blindly.

The CAS needs only single-row compare-and-set, which behaves the same under
Postgres READ COMMITTED and SQLite (`rows_affected`). It does not depend on
`SELECT … FOR UPDATE`, and holds no lock across the PUT.

### 4.2 Recoverable frontier

The **recoverable frontier** of a database is `(lineage, last_seq)` of its
manifest row, valid only if the chain is complete: the object at
`base_snapshot_key` exists in `sql_store_object` as `published`, and
`published` segments with `base_seq = snapshot.at_seq` cover
`snapshot.at_seq+1 ..= last_seq` contiguously with no gaps or overlaps. An
object that is `uploaded` (PUT done, not published) is **not recoverable**,
whatever its bytes say; neither is any object whose key is not in the chain.
If a published chain has a gap (a bug or a deleted object), the frontier is
the last contiguous `seq`, and the restore check reports the shortfall; it is
never "repaired" by picking up an orphan.

### 4.3 States and inventory

- `uploaded`: PUT confirmed, not in a published chain (also the state of an
  in-flight upload).
- `published`: part of the manifest's current chain, or of a previous chain
  that was published and later superseded by a newer snapshot (still needed
  for history under the retention policy).
- `orphan`: set by the reconciler for `uploaded` objects older than
  `orphan_after` (default 24 h) that no published chain references, and for
  every object of a superseded lineage. **Marking only. This phase never
  deletes an object**; operators remove the area with a prefix delete if they
  turn the feature off. An object whose inventory row was never written (crash
  between PUT and INSERT) is the same as an orphan but unregistered; it is
  found only by prefix listing. Slice 4 owns listing, charging and GC.

### 4.4 Epoch and lease

`epoch` exists in the schema now so slice 3 needs no second migration. In the
funded phase it is the constant `0`, one node owns every database, and the CAS
`epoch = 0` clause is already in the UPDATE. The lease, drain and
response-gate protocol (SCOPING "Ordered writer handover") is **defined
there, not built here**; slice 3 must meet it before a second node may
publish or any database may become store-master.

## 5. Upload and retention policy

### 5.1 Node settings

```toml
[sql_store]
enabled         = false      # master switch; false = nothing below runs, tables untouched
upload_interval = "60s"      # also: TINYCLOUD_SQL_STORE__UPLOAD_INTERVAL
upload_bytes    = "8 MiB"    # size trigger; TINYCLOUD_SQL_STORE__UPLOAD_BYTES
backlog_cap     = "64 MiB"   # per node, un-uploaded bytes; TINYCLOUD_SQL_STORE__BACKLOG_CAP
orphan_after    = "24h"
enforce_backlog_cap = false  # shadow phase: count and log only (5.2)
snapshot_every  = "24h"      # a new snapshot at most this often (cost: 1 per day per active db)
[sql_store.retention]
history_days    = {}         # tier id -> days; absent = keep all. TINYCLOUD_SQL_STORE__RETENTION__HISTORY_DAYS__FREE=7
```

Env uses the repo's `TINYCLOUD_` prefix with `__` for nesting
(`TINYCLOUD_EPOCH_HEAD_BACKFILL__ENABLED` is the precedent). Defaults are
**60 s / 8 MiB for every tier**, a node setting changeable without a release,
per Sam 10-19. Validation at boot only when `enabled`: interval ≥ 1 s,
`upload_bytes` ≥ 1 MiB, `backlog_cap ≥ upload_bytes`.

### 5.2 Behaviour

- **Trigger.** A database is eligible when it has committed since its last
  published `last_seq` and either `upload_interval` has elapsed since its first
  un-uploaded commit, or un-uploaded bytes ≥ `upload_bytes`.
- **Size trigger is checked between transactions.** A single transaction may
  exceed 8 MiB (TC-1012 caps the request body at 95 MiB, not the changes it
  causes); the trigger never splits a transaction and never delays an
  in-flight one. The next eligibility check runs after the operation lock is
  released.
- **Idle database uploads nothing.** No timer upload without a commit; no
  empty segments; no heartbeat object.
- **No wait-for-store on commit.** The write path never awaits an upload or a
  CAS, in any tier (Sam 10-19, v1).
- **Drain on planned stop.** On SIGTERM the uploader stops taking new work,
  uploads and publishes every database with an un-uploaded commit, bounded by
  the shutdown grace period; what is left is logged by count only. In the
  shadow phase an incomplete drain loses nothing (Postgres is master); in
  [store-master] it is the data-loss boundary.
- **Backlog cap pauses writes.** When un-uploaded bytes across the node reach
  `backlog_cap`, new SQL writes are refused *before they start* with
  `503 sql_busy: store_backlog` and `Retry-After`, and resume below 75 % of the
  cap. In the shadow phase this refusal would be a pure availability cost with
  no durability benefit, so **the funded shadow phase only counts and logs the
  breach (metric `sql_store_backlog_cap_exceeded_total`) and does not refuse**;
  enforcing it is a store-master requirement and a single config bool
  (`enforce_backlog_cap`, default `false` until cutover).
- **Store down.** Upload failures back off (1 s doubling to 60 s, jittered),
  keep the backlog, never fail a request, and never delete local state. A
  single log line per transition (healthy ↔ failing), SQLSTATE/HTTP class only.
- **Logging** follows TC-961: never a space ID, DID, key or object key. Counts,
  byte totals and error classes only. The unencrypted objects make this rule
  stricter, not looser.

### 5.3 Retention

`RetentionPolicy` is data only in this slice (parsed, validated, tested; no
deleter). Shape: `history_days: Option<u32>` per tier id (`free`, `paid`, the
ids `quota.rs` already uses) plus an absent-means-keep-all default. History is
one snapshot per `snapshot_every` plus the segments since, so a restore point
exists at every published `to_seq` inside the window. **Default: keep all**
until Sam confirms tier numbers (open decision D2). Nothing is deleted in the
funded phase whatever the setting says; slice 4 consumes it with a
reference-safe collector.

## 6. Rust interfaces

Module `tinycloud-core/src/sql/store/` (`mod.rs`, `key.rs`, `object.rs`,
`manifest.rs`, `policy.rs`, `memory.rs`). Config structs live in
`tinycloud-node-server/src/config.rs` next to `EpochHeadBackfillConfig` and
convert into the core policy types. All async traits use `async_trait` like
`storage/mod.rs`.

```rust
/// Pure functions, no I/O. The only way to build a SQL object key.
pub struct DbRef<'a> { pub space: &'a str, pub db_id: &'a str }
pub struct ObjectKey(String);                      // opaque, validated, Display
impl ObjectKey {
    pub fn snapshot(db: &DbRef, lineage: &Lineage, at_seq: u64, sha256: &[u8; 32]) -> Result<Self, KeyError>;
    pub fn segment(db: &DbRef, lineage: &Lineage, base_seq: u64, from_seq: u64, to_seq: u64, sha256: &[u8; 32]) -> Result<Self, KeyError>;
    pub fn db_prefix(db: &DbRef) -> Result<String, KeyError>;   // "sql/v1/{space}/{db}/"
}

#[async_trait]
pub trait SqlObjectStore: Send + Sync {
    /// Create the object unless it exists. Existing with the same length and
    /// sha256 => Ok(AlreadyPresent). Existing with different => Err(Conflict).
    async fn put_if_absent(&self, key: &ObjectKey, body: ObjectBody, sha256: [u8; 32])
        -> Result<PutOutcome, SqlStoreError>;
    async fn get_range(&self, key: &ObjectKey, range: ByteRangeSpec)
        -> Result<Option<ObjectRange>, SqlStoreError>;   // reuses storage::ByteRangeSpec
    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError>;
    // deliberately no delete, no list-all, no overwrite
}

pub struct Frontier { pub lineage: Lineage, pub epoch: i64, pub revision: i64,
    pub base_snapshot_key: String, pub last_seq: u64, pub published_at: String, pub frontier_bytes: u64 }

#[async_trait]
pub trait SqlManifest: Send + Sync {
    async fn current(&self, db: &DbRef) -> Result<Option<Frontier>, SqlStoreError>;
    /// Compare-and-set (4.1). Ok(Published(new)) or Ok(Lost(current)) -- losing is not an error.
    async fn publish_cas(&self, db: &DbRef, expected: Option<&CasToken>, next: PublishRequest)
        -> Result<PublishOutcome, SqlStoreError>;
    async fn record_object(&self, db: &DbRef, obj: &ObjectRecord) -> Result<(), SqlStoreError>; // state=uploaded, idempotent
    async fn list_objects(&self, db: &DbRef, state: Option<ObjectState>) -> Result<Vec<ObjectRecord>, SqlStoreError>;
}

pub struct UploadPolicy { pub interval: Duration, pub max_bytes: u64, pub backlog_cap: u64,
    pub snapshot_every: Duration, pub orphan_after: Duration, pub enforce_backlog_cap: bool }
impl UploadPolicy { pub fn due(&self, st: &PendingState, now: Instant) -> bool; pub fn backlog_exceeded(&self, total: u64) -> bool; }

pub struct RetentionPolicy { default_days: Option<u32>, per_tier: BTreeMap<String, u32> }
impl RetentionPolicy { pub fn history_days(&self, tier: &str) -> Option<u32>; }
```

**Backing layers** (implementations land in slice 1b, not 0; slice 0 ships the
traits plus an in-memory implementation for tests):

- `SqlManifest`: `sea_orm::DatabaseConnection` on the same control database as
  `database_artifact`, models `models/sql_store_manifest.rs`,
  `sql_store_object.rs`. Same pool the artifact repository uses.
- `SqlObjectStore`, S3: built from the existing `S3BlockConfig` (bucket,
  endpoint, credentials via `aws_config()`/`new_client`) through a small
  `S3SqlObjectStore` that reuses the client but not `S3BlockStore`'s methods.
  Filesystem: `FsSqlObjectStore` rooted at `{datadir}/sql-store`, writing via
  temp file + `fsync` + `rename` (no-clobber via `link`/`O_EXCL`) + dir fsync.
  `storage::either::Either` style selection from the existing
  `BlockStorage::{Local,S3}` config, so a self-hosted node's choice of
  bucket-or-disk applies unchanged and needs no second credential.

## 7. Migration safety

Migration `m20261021_000000_sql_store_manifest` (sorts after
`m20261018_000000_epoch_head`; PR #374 adds `m20261020_000000…`, no conflict).
Rules from #341 / #343 / #374 applied:

- `CREATE TABLE IF NOT EXISTS` for both tables; **no foreign keys** (an FK to
  `space` or `database_artifact` would lock those tables against writers
  during the boot transaction); **no index on any existing table**; **no
  backfill** and no statement that scans or locks an existing table. The only
  lock taken is on the two new, empty tables. #341's problem (a plain `CREATE
  INDEX` under a write-blocking lock inside the boot transaction) cannot occur
  because nothing is created on a populated table.
- Nothing long in the boot transaction: two `CREATE TABLE`s on the 30 s
  `lock_timeout` from #316. Any later work (reconciler, orphan marking) runs
  after the node serves, paced like the `epoch_head` backfill.
- Idempotent: re-run, existing tables, and a database where an operator
  pre-created the tables are all no-ops.
- `down` drops both tables. Tables hold only advisory state, so this loses
  nothing that Postgres master does not have. Objects in the store remain and
  are removed by deleting the `sql/v1/` prefix.
- **Tables are created at boot regardless of the flag** (a migration cannot
  depend on a runtime setting, and creating empty tables is free), but with
  `enabled = false` no code reads or writes them. A test asserts zero queries
  against them with the flag off.
- Downgrade hazard (from #374): a node refuses to start with a recorded
  migration it does not ship. Rolling back past this release needs
  `DELETE FROM seaql_migrations WHERE version = 'm20261021_000000_sql_store_manifest'`
  first; the release note says so. Dropping the tables alone is not enough.
- Tests: fresh, existing-database, and re-run (`up` twice) on SQLite; the same
  on Postgres where the repo has a Postgres harness; `down` then `up`; the
  versions list in `migrations/mod.rs` tests extended.

## 8. Crash matrix and test plan (shadow uploader)

State key: `P` = Postgres artifact (master), `O` = object in store, `I` =
`sql_store_object` row, `M` = manifest row.

| Crash / fault point | State after | Required behaviour on restart |
|---|---|---|
| Before PUT | none | Re-plan from `P` and `M`; nothing lost. |
| **PUT done, before `I` insert** | `O` unregistered | Same key is recomputed (content-addressed); `put_if_absent` returns AlreadyPresent; insert `I`; continue. If the content changed meanwhile, the new key differs and `O` stays an unregistered orphan (found by prefix list, slice 4). |
| **PUT done, `I` uploaded, before CAS** | `O`,`I=uploaded`, `M` old | Not recoverable (4.2). Restart re-reads `M`, re-derives the next range from `P`, reuses `O` if identical, CASes. Orphan if superseded. |
| **CAS committed, response lost** | `M` new | `current()` shows `revision+1` with expected `last_seq`; treat as success, do not re-issue. |
| CAS lost to another publisher | `M` differs | Re-read; same lineage and epoch: retry on the new revision (idempotent range check); different lineage or epoch: abandon, open a new lineage. Own `O` becomes orphan. |
| Store down / 5xx / timeout | `P`, `M` unchanged | Back off; backlog grows; requests unaffected (shadow). |
| PUT returns OK but `head` shows a different length or hash | `O` wrong | `I` is not written. Deleting is not allowed (no delete in the trait), and the key is hash-derived so a rewrite is impossible. Report `Conflict`, stop uploading this database until an operator clears the area, alert. |
| **Duplicate uploader** (two nodes, a restart overlap) | two PUTs, one CAS wins | Same range with the same bytes => same key, harmless. Different bytes => different keys; loser's objects orphan. Neither can regress `M` (`last_seq <=` clause). Single-node deployments never see this; multi-node is slice 3. |
| `P` restored from backup behind `M` | `M.last_seq > P.revision` | New lineage, fresh snapshot, old lineage orphaned (3.3). |
| `kill -9` mid-snapshot read | partial local temp | Temp file discarded; snapshots are taken from the already-materialized checkpoint, not by copying the live file. |
| Metadata DB briefly down | `O` exists | Same as "before CAS". |

**Tests, slice 1a (reservation + durability, separate PR):** `kill -9` at each
step of write: before reservation, after reservation before COMMIT, after COMMIT
before artifact save, after save before response; assert no acknowledged write is
lost and an oversized transaction is rejected before COMMIT. Counted against an
external ack log.

**Tests, slice 1b (shadow uploader, separate PR):** fault-injecting
`SqlObjectStore`/`SqlManifest` wrappers drive every row of the matrix above in
process; plus `kill -9` of a real node process at each of PUT, `I`, CAS, drain.
Nightly **restore check**: for sampled databases, rebuild from the published
chain onto an empty disk and compare with Postgres: `PRAGMA integrity_check`
= `ok`, and per-table row-count + ordered row digest equality at the manifest's
`last_seq` (the shadow may be behind `P`; compare against `P` replayed to the
same `seq`, or restrict the nightly job to databases quiescent for one window).
Flag-off test: no store requests, no manifest queries.

**Tests, slice 0 (this PR):** key properties (injective over the generated
space/db/lineage/seq/hash domain; immutable: same inputs give same key, any
changed field changes it; never equal or prefixed like a KV key; no `/`
in components; `..` impossible), config parse/defaults/env override/validation,
manifest CAS (stale epoch rejected, stale lineage rejected, concurrent
publishers produce exactly one winner, `last_seq` regression rejected,
first-publish PK conflict) on SQLite and, where `tests/` has a Postgres
harness, Postgres, and migration idempotence (section 7).

## 9. Open decisions

| # | Decision | Owner | Blocks |
|---|---|---|---|
| D1 | **Key custody** for slice 2: enclave/KMS vs owner-held, escrowed recovery wrap (TC-887; dstack KMS derives from app-id). Nothing in this contract assumes an answer; the object format has a `v1` prefix so an encrypted format is `v2`. | Sam / security | Slice 2; shadow upload for all users |
| D2 | **Retention numbers** per tier (last wording: 100 MB / 7 days, 1 GB / 30 days; paid not restated). Config shape is fixed here; default is keep-all. | Sam | Slice 4 |
| D3 | **Lease / epoch / drain**: defined in SCOPING, constant `epoch = 0` here. Which store (PG row vs other) holds the authority lock is slice 3's decision. | Naomi / node authority | Slice 3, any second node |
| D4 | **Segment payload format**: cumulative WAL since checkpoint (today's artifact shape, simple, re-sends) vs sealed committed-frame ranges (SCOPING, bounded). The contract fixes only: contiguous `from_seq..=to_seq`, bytes opaque, `seq` monotonic. Decide in a 1b design note before 1b code. | Naomi | Slice 1b |
| D5 | Provider conditional-write support (`If-None-Match`) on the production store; HEAD→PUT is the safe fallback. | Ops check | Slice 1b |
| D6 | Whether an in-place deploy keeps the data disk (SCOPING "not verified"); affects whether drain is merely nice or load-bearing. | Ops | Cutover |
| D7 | Pilot-only gating of the unencrypted shadow: allowlist of spaces vs node-wide flag. Recommended: node-wide flag plus `sql_store.spaces` allowlist for the first weeks. | Naomi / Sam | Slice 1b rollout |
| D8 | Who accounts for store bytes (physical orphans, history) in quota. None of it is metered in the funded phase. | Slice 4 | Slice 4 |
