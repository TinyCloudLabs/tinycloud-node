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
3. **[shadow only] The manifest is advisory and droppable.** Dropping both tables, or
   deleting the whole `sql/v1/` area, changes no user-visible behaviour. The
   uploader then starts a new lineage and re-snapshots from Postgres. In
   [store-master] the manifest is authoritative and this does not hold (3.3).
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
  physical artifact). It is the `(space, name)` key the actor, hydration and
  lineage maps already use, so the store follows the identity of everything
  that mutates the database. If an alias is re-pointed to another physical
  artifact, the new artifact has a new `db_id`, a new manifest row and an
  unrelated prefix; it does not inherit or overwrite the old one.
- **Encoding `enc(x)`.** Space IDs contain `:` and mixed-case base58/EIP-55
  text; legacy names are arbitrary bytes. Bytes in `[a-z0-9_-]` are kept;
  **every other UTF-8 byte, uppercase letters included**, becomes `.` plus two
  **lowercase** hex digits (`.` itself is `.2e`, `A` is `.41`). Output alphabet
  is therefore `[a-z0-9_-.]` only, so keys are also injective as paths on
  case-insensitive filesystems (APFS/Windows self-host, TC-1441).
  - *Injective:* `.` appears only as an escape introducer, so a left-to-right
    decoder is unambiguous; the decoder rejects uppercase hex and a `.` not
    followed by two hex digits (canonical form only).
  - No component contains `/`, so the `/`-joined tuple splits uniquely
    (`lineage` is 32 hex, seqs are 20 fixed digits, the hash is 64 hex).
  - `.` and `..` cannot occur (a `.` is always followed by two hex digits).
  - Empty `space` or `db_id` is rejected.
  - If `enc(x)` exceeds 255 bytes, the component becomes `~` + 64 hex of
    SHA-256 of the raw bytes. `~` is outside the alphabet, so the two forms
    never collide; the manifest row keeps the real names. (Uppercase escaping
    triples some bytes, so this is reachable for long space names.)
- Service is not in the key: `v1` is SQL only. DuckDB would need `duckdb/v1/`
  and its own review.
- **Boot check (slice 1b):** `{datadir}/sql-store` must not be inside
  `blocks.path`; `store_sizes` fails boot on any non-DID directory in the KV
  root.

### 3.3 Immutability, generations and orphans

- **Keys are never overwritten and never reused with different bytes.** The
  content hash in the key plus the lineage and sequence range make a key a
  pure function of its content and position. Two uploaders (a stale node, a
  retry, a duplicate) producing the same range with different bytes produce
  different keys.
- `put_if_absent(key, bytes, expected_sha256)`: if the key exists, `head`
  must show the same length and the SHA-256 stored in object user metadata,
  else `Conflict` (loud; never replace). It uses a conditional PUT
  (`If-None-Match: *`). A HEAD-then-PUT fallback is acceptable **only while
  nothing in the system deletes SQL objects** (this phase); slice 4 must
  require the conditional PUT, or a generation/pin fence, before
  `AlreadyPresent` may count toward a publish (the race TC-735 had).
- **Orphan = an object not referenced by any published manifest frontier.** A
  PUT that completed but whose CAS did not (crash, lost response, lost the
  race) is an orphan. Nothing reads it. This phase counts and marks orphans,
  never deletes them (4.3).
- **[shadow only] Postgres wins.** Because Postgres is master, the manifest
  never "wins" a disagreement with the artifact. The uploader continues the
  existing lineage with a **new snapshot** when the artifact's checkpoint
  differs from `base_checkpoint_cid` (4.1), and uses the lineage-switch CAS
  (4.1) only when the lineage cannot be continued: `last_seq` is above the
  artifact's revision (defensive; M and P share one database, so a PITR rolls
  both back together and this does not occur in practice), or a CAS loss
  showed another lineage whose `base_checkpoint_cid` does *not* match the
  artifact. The manifest may be dropped at any time: the next upload creates
  a fresh lineage.
- **[store-master] The manifest is authoritative.** Four rules replace the
  shadow rules above:
  1. A lineage switch is allowed only for the **current epoch holder**,
     publishing from its **own** local disk, and never merely because a CAS
     was lost. A stale node that loses a CAS stops and reports; it must not
     repoint the manifest at its older state (that would drop the new owner's
     acknowledged commits out of the recoverable frontier).
  2. `seq` is persisted inside the SQLite file (e.g. a one-row table updated in
     each transaction), so a crash-restart never re-issues a `seq` with
     different content.
  3. Dropping the tables, or running `down`, is destructive.
  4. Divergence between disk and manifest is resolved by the epoch protocol
     (SCOPING "Ordered writer handover"), never by the uploader.

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
production, SQLite on self-host, **MySQL**: `mysql` is a default feature and
recent migrations branch on `DbBackend::MySql`). Plain types only; no arrays,
JSON, sequences, partial indexes or FKs. MySQL limits shape the columns:
`.string()` is `varchar(255)`, and an InnoDB key is capped at 3072 bytes
(utf8mb4: 4 bytes/char). So the object key's fields are **structured columns**
and the full key is a `text` column outside every index.

```
sql_store_manifest                                  -- PK (space, db_id)
  space              string(255)  not null
  db_id              string(255)  not null          -- physical artifact name (3.2), unencoded
  lineage            string(32)   not null          -- lowercase hex
  epoch              big_integer  not null          -- shadow phase: always 0 (4.4)
  revision           big_integer  not null          -- publication counter, +1 per publish, never reset
  base_snapshot_key  text         not null          -- full key of the chain's snapshot
  base_seq           big_integer  not null          -- that snapshot's at_seq
  base_checkpoint_cid string(255) not null          -- = database_artifact.checkpoint_content_hash it was cut from
  last_seq           big_integer  not null          -- last commit covered by the recoverable chain
  publish_id         string(32)   not null          -- random per publish attempt
  published_at       string       not null          -- RFC 3339, as database_artifact
  frontier_bytes     big_integer  not null          -- bytes of the snapshot + the segment(s) needed to restore

sql_store_object                                    -- PK (space, db_id, lineage, kind, base_seq, from_seq, to_seq, content_hash)
  space, db_id       string(255)  not null
  lineage            string(32)   not null
  kind               string(16)   not null          -- 'snapshot' | 'segment'
  base_seq           big_integer  not null          -- snapshot: at_seq
  from_seq, to_seq   big_integer  not null          -- snapshot: both = at_seq
  content_hash       string(64)   not null          -- lowercase hex SHA-256
  format             string(16)   not null          -- 'sqlite-v1' | 'wal-cum-v1' (D4)
  key                text         not null          -- full object key, derivable from the columns, not indexed
  bytes              big_integer  not null
  state              string(16)   not null          -- 'uploaded' | 'published' | 'orphan'
  created_at         string       not null
```

Largest PK on MySQL: `(255+255+32+16+64)` chars × 4 + 3×8 = 2,512 bytes,
under 3,072. Because the key fields are columns, frontier validation (4.2) is
a query, not key parsing. A test asserts the generated MySQL DDL (section 7).

### 4.1 Publish = upload first, CAS second

Capture is defined in 5.2; sealing, hashing and `put_if_absent` happen off the
operation lock. Then:

1. `record_object`: `INSERT … ON CONFLICT DO NOTHING` the `uploaded` row. If
   a row exists, read its state: `uploaded`/`published` with equal `bytes` and
   `content_hash` is fine (idempotent reuse); `orphan` must be **explicitly
   revived** with `UPDATE … SET state='uploaded' WHERE <pk> AND state='orphan'`
   (rows_affected checked) before reuse, otherwise use a fresh key.
2. Publish in **one metadata transaction**. The three statements, all
   compare-and-set, each checked by `rows_affected`:

   - **First publish** (no manifest row): `INSERT … ON CONFLICT DO NOTHING`
     (not a raw insert: a PG unique violation aborts the whole transaction,
     including the state flip). 0 rows = lost.
   - **Snapshot publish** (new chain in the current lineage; used when
     `base_checkpoint_cid` differs from the artifact's, or on the first
     snapshot of the day):
     ```
     UPDATE sql_store_manifest SET revision=revision+1, base_snapshot_key=:snap,
            base_seq=:at_seq, base_checkpoint_cid=:cid, last_seq=:at_seq,
            publish_id=:pid, frontier_bytes=:bytes, published_at=:now
      WHERE space=:s AND db_id=:d AND epoch=:e AND lineage=:l AND revision=:rev
        AND last_seq <= :at_seq
     ```
   - **Segment publish** (append; allowed only if the artifact's checkpoint
     hash equals `base_checkpoint_cid`):
     ```
     UPDATE sql_store_manifest SET revision=revision+1, last_seq=:to_seq,
            publish_id=:pid, frontier_bytes=:bytes, published_at=:now
      WHERE space=:s AND db_id=:d AND epoch=:e AND lineage=:l AND revision=:rev
        AND base_snapshot_key=:snap AND base_checkpoint_cid=:cid
        AND last_seq >= :from_seq - 1 AND last_seq < :to_seq
     ```
     For a delta format `from_seq = last_seq+1`, i.e. the strict
     `last_seq = :from_seq - 1`: contiguity is a DB invariant. For
     `wal-cum-v1` (D4, cumulative WAL since the checkpoint) `from_seq =
     base_seq+1` always, so the clause is "no gap, and strictly advances".
   - **Lineage switch** (cannot continue, 3.3 shadow rule):
     ```
     UPDATE sql_store_manifest SET lineage=:new, revision=revision+1,
            base_snapshot_key=:snap, base_seq=:at_seq, base_checkpoint_cid=:cid,
            last_seq=:at_seq, publish_id=:pid, frontier_bytes=:bytes, published_at=:now
      WHERE space=:s AND db_id=:d AND epoch=:e AND lineage=:old AND revision=:rev
     ```
     `revision` is never reset; `epoch` is unchanged.
3. In the same transaction, flip the published object(s):
   `UPDATE sql_store_object SET state='published' WHERE <pk> AND state='uploaded'`.
   A publish adds exactly one object (the snapshot, or the one segment); the
   transaction **rolls back unless rows_affected = 1**. So a concurrently
   orphaned or already-published row cannot be silently published.

**On a lost CAS (0 rows):** re-read `current()`.
- `publish_id` equals ours: the publish happened (lost response); done.
- Same epoch and lineage, newer revision: re-derive the range from
  `current.last_seq + 1` (new key, new bytes if needed). Never republish an
  object whose range overlaps the new frontier.
- Different lineage whose `base_checkpoint_cid` matches the artifact:
  **continue that lineage** (do not open another one). Without this, two
  instances (TC-1471) each orphan a snapshot per cycle and livelock.
- Different lineage that does not match: lineage-switch CAS on top of it,
  bounded retries (3), then back off for one interval.
- Different epoch: stop (cannot occur while epoch is constant 0).

The CAS needs only single-row compare-and-set, with the same behaviour under
Postgres READ COMMITTED (the WHERE is re-checked after a concurrent update)
and SQLite (writers serialized), and holds no lock across the PUT.

### 4.2 Recoverable frontier

The **recoverable frontier** of a database is `(lineage, last_seq)` of its
manifest row, valid if the object at `base_snapshot_key` is `published` and
published segments of the same `lineage` and `base_seq` cover
`base_seq+1 ..= last_seq` (one cumulative segment for `wal-cum-v1`; contiguous
delta segments otherwise). The check is a query over the structured columns.
An `uploaded` object (PUT done, not published) is **not recoverable**, nor is
any object outside the chain. On a gap the frontier is the last contiguous
`seq` and the restore check reports the shortfall; it is never repaired by
adopting an orphan.

### 4.3 States and inventory

- `uploaded`: PUT confirmed, not in a published chain (also in flight).
- `published`: in the manifest's current chain, or in an earlier chain that
  was superseded (kept for history under the retention policy).
- `orphan`: set by the reconciler for `uploaded` objects older than
  `orphan_after` (24 h) not referenced by a published chain, and for objects
  of a superseded lineage. Every transition is conditional on the **current
  state**: `SET state='orphan' WHERE <pk> AND state='uploaded'`. The
  reconciler never overwrites `published`; slice 4's GC consumes `orphan`, so
  a race here would delete a chain member.
- **This phase never deletes an object.** Operators remove the area with a
  prefix delete (runbook). An object with no inventory row (crash between PUT
  and INSERT) is an unregistered orphan found only by prefix listing (slice 4).
- Deleting a database or space does **not** remove its store copy in this
  phase (R8; see 5.2).

### 4.4 Epoch and lease

`epoch` is in the schema now so slice 3 needs no second migration. In the
funded phase it is the constant `0` and the CAS clause `epoch = 0` is already
present. The lease, drain and response-gate protocol (SCOPING "Ordered writer
handover") is **defined there, not built here**. D3's recommendation: the
authority is a row in the same control database, so the epoch check and the
manifest CAS commit in one transaction.

## 5. Upload and retention policy

### 5.1 Node settings

```toml
[sql_store]
enabled              = false   # master switch; false = nothing below runs, tables untouched
upload_interval_secs = 60      # TINYCLOUD_SQL_STORE__UPLOAD_INTERVAL_SECS
upload_bytes         = "8 MiB" # size trigger; TINYCLOUD_SQL_STORE__UPLOAD_BYTES
backlog_cap          = "64 MiB"# per node, un-uploaded bytes; TINYCLOUD_SQL_STORE__BACKLOG_CAP
snapshot_every_secs  = 86400   # a new snapshot at most this often (1 per day per active db)
orphan_after_secs    = 86400
enforce_backlog_cap  = false   # shadow phase: shed and count only (5.2)
spaces               = []      # allowlist of space IDs; EMPTY = NOTHING UPLOADS even if enabled (fail-closed)
[sql_store.retention]
# default_history_days = 30   # optional; absent = keep all
history_days         = {}      # tier id -> days. TINYCLOUD_SQL_STORE__RETENTION__HISTORY_DAYS__FREE=7
```

Env uses the repo's `TINYCLOUD_` prefix with `__` for nesting
(`TINYCLOUD_EPOCH_HEAD_BACKFILL__ENABLED` is the precedent). Defaults are
**60 s / 8 MiB for every tier**, a node setting changeable without a release,
per Sam 10-19. Validation at boot only when `enabled`: interval ≥ 1 s,
`upload_bytes` ≥ 1 MiB, `backlog_cap ≥ upload_bytes`. The uploader runs for a space only if `enabled`
and the space is in `spaces` (R8).

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
- **Backlog cap.** [store-master] When un-uploaded bytes reach `backlog_cap`,
  new SQL writes are refused *before they start* with `503 sql_busy:
  store_backlog` and `Retry-After`, resuming below 75 % of the cap; that is a
  rejected outcome. **In the shadow phase refusing buys no durability** (Postgres
  is master), so the cap only **sheds** the spool (section 8), counts it
  (`sql_store_backlog_cap_exceeded_total`) and never blocks or refuses a write;
  enforcement is `enforce_backlog_cap`, default `false` until cutover.
- **Store down.** Upload failures back off (1 s doubling to 60 s, jittered),
  keep the backlog, never fail a request, and never delete local state. A
  single log line per transition (healthy ↔ failing), SQLSTATE/HTTP class only.
- **Logging** follows TC-961: never a space ID, DID, key or object key. Counts,
  byte totals and error classes only. The unencrypted objects make this rule
  stricter, not looser.
- **Deletion semantics (R8).** In this phase deleting a database or a space
  does **not** remove its plaintext copy from the store (there is no delete).
  Pilot spaces must accept that; the prefix-delete procedure
  (`sql/v1/{space_enc}/…`) goes in the runbook before 1b is enabled.

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
    pub base_snapshot_key: String, pub base_seq: u64, pub base_checkpoint_cid: String,
    pub last_seq: u64, pub publish_id: String, pub published_at: String, pub frontier_bytes: u64 }
/// One of: FirstPublish | Snapshot | Segment | LineageSwitch (the four statements of 4.1).
pub enum PublishRequest { /* … */ }

#[async_trait]
pub trait SqlManifest: Send + Sync {
    async fn current(&self, db: &DbRef) -> Result<Option<Frontier>, SqlStoreError>;
    /// Compare-and-set (4.1). Ok(Published(new)) or Ok(Lost(current)) -- losing is not an error.
    async fn publish_cas(&self, db: &DbRef, expected: Option<&CasToken>, next: PublishRequest)
        -> Result<PublishOutcome, SqlStoreError>;
    async fn record_object(&self, db: &DbRef, obj: &ObjectRecord) -> Result<(), SqlStoreError>; // state=uploaded, idempotent
    async fn list_objects(&self, db: &DbRef, state: Option<ObjectState>) -> Result<Vec<ObjectRecord>, SqlStoreError>;
    /// `uploaded -> orphan` only (conditional on current state); returns rows changed.
    async fn mark_orphans(&self, db: &DbRef, older_than: &str) -> Result<u64, SqlStoreError>;
    /// Explicit `orphan -> uploaded` before an object is reused; false if not orphan.
    async fn revive_object(&self, db: &DbRef, key: &ObjectKey) -> Result<bool, SqlStoreError>;
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

Migration `m20261021_000000_sql_store_manifest`. Other pending migrations:
#374 adds `m20261020_000000_current_kv_key_c_index`; #301 (TC-735) carries
`m20261017_020000_kv_orphan_candidates`. SeaORM applies out-of-order
versions; none touches these tables. Rules from #341 / #343 / #374:

- `CREATE TABLE IF NOT EXISTS` for both tables; **no foreign keys** (an FK to
  `space` or `database_artifact` would lock those tables against writers
  during the boot transaction); **no index on any existing table**; **no
  backfill** and no statement that scans or locks an existing table. #341's
  failure (a plain `CREATE INDEX` under a write-blocking lock) cannot occur:
  nothing is created on a populated table.
- **MySQL-safe (R1):** `string_len` columns and a `text` key as in section 4;
  the widest PK is 2,512 bytes. Like `m20261018_000000_epoch_head`, the
  migration branches on `DbBackend::MySql` where the column type differs. A
  test asserts the MySQL DDL from sea-query's MySQL backend: every PK column is
  a bounded `varchar`/`bigint`, `key` is `text`, and no indexed column exceeds
  the 3,072-byte limit; it runs live against MySQL if the repo has such a setup.
- Nothing long in the boot transaction: two `CREATE TABLE`s under the 30 s
  `lock_timeout` from #316. Later work (reconciler) runs after the node
  serves, paced like the `epoch_head` backfill.
- Idempotent: re-run, existing tables, and operator-pre-created tables are
  no-ops.
- **`down` drops both tables. [shadow only]** The tables hold only advisory
  state in this phase. In [store-master] `down` is destructive (3.3) and must
  be replaced by a refusing `down`.
- **Tables are created at boot regardless of the flag** (a migration cannot
  depend on a runtime setting), but with `enabled = false` no code reads or
  writes them. (Slice 0 ships no reader or writer outside tests; the
  "zero queries with the flag off" test lands with the uploader in 1b.)
- **Downgrade (from #374):** a node refuses to start with a recorded migration
  it does not ship. Rolling back past this release means dropping **both
  tables and** `DELETE FROM seaql_migrations WHERE version =
  'm20261021_000000_sql_store_manifest'`; deleting the row alone would let a
  later re-upgrade inherit stale rows (which `base_checkpoint_cid` also
  guards against). The release note says so.
- Tests: fresh, existing-database, re-run (`up` twice), `down` then `up`, on
  SQLite and, where the repo has a Postgres harness, Postgres; MySQL DDL as
  above; `migrations/mod.rs` versions list extended.

## 8. Crash matrix and test plan (shadow uploader)

State key: `P` = Postgres artifact (master), `O` = object in store, `I` =
`sql_store_object` row, `M` = manifest row.

**Capture point and spool (R7).** The uploader captures *inside the per-DB
operation lock, only after `persist_write` returns Ok*, from the checkpoint /
WAL bytes already in memory for that save, together with the artifact's
`revision` and `checkpoint_content_hash`. It never reads `P` (that would bring
back TC-822 whole-row loads and add TC-1274 load) and never captures before
`P` commits. Segments must apply to `P`'s exact checkpoint bytes, so a
`VACUUM INTO` / backup-API copy is not a valid snapshot. The lock is never held
across PUT or CAS. The spool is bounded: at `backlog_cap` the uploader
**sheds**: it drops pending captures, marks the database `needs_snapshot` (the
next window cuts a full snapshot), and counts it. It never grows disk without
limit and never blocks or refuses a write. `discard_local_state` and idle
eviction remove the local copy, so the next window after either may need a
snapshot.

| Crash / fault point | State after | Required behaviour on restart |
|---|---|---|
| Before PUT | none | Re-plan from the next capture; nothing lost (`P` is master). |
| **PUT done, before `I` insert** | `O` unregistered | Same key is recomputed (content-addressed); `put_if_absent` returns AlreadyPresent; insert `I`. If content changed, the new key differs and `O` stays an unregistered orphan. |
| **PUT done, `I=uploaded`, before CAS** | `O`,`I`, `M` old | Not recoverable (4.2). Restart re-reads `M`, re-derives the range, reuses `O` if identical (revive if `orphan`), CASes. Orphan if superseded. |
| **CAS committed, response lost** | `M` new | `current().publish_id` equals ours: success; never re-issue. |
| CAS lost to another publisher | `M` differs | Per 4.1: same lineage re-derive from `last_seq+1`; matching other lineage continue it; non-matching lineage-switch (bounded). Own `O` becomes orphan. |
| Reconciler vs publisher race | `I` flips | Both writes are `WHERE state='uploaded'`; the loser sees 0 rows. A publish whose flip hits 0 rows rolls back its CAS. |
| Store down / 5xx / timeout | `P`, `M` unchanged | Back off; backlog grows, then sheds; requests unaffected. |
| PUT OK but `head` shows different length/hash | `O` wrong | `I` is not written. No deletes; report `Conflict`, stop uploading this database, alert. |
| **Duplicate uploader** (restart overlap, TC-1471 instance) | two PUTs, one CAS wins | Same range, same bytes: same key, harmless. Different bytes: different keys; loser orphans. Neither regresses `M` (`last_seq` clauses). |
| Manifest stale after downgrade / re-upgrade or import | `base_checkpoint_cid` ≠ `P` | Next capture publishes a new snapshot in the same lineage; no segment is appended to the old base. |
| `kill -9` mid-capture | partial temp | Discarded; capture is from in-memory save bytes. |
| Metadata DB briefly down | `O` exists | As "before CAS". |

**Slice 1a tests (separate PR):** `kill -9` before reservation; after
reservation before COMMIT; after COMMIT before artifact save; after save
before response. Assert no acknowledged write is lost and an oversized
transaction is rejected before COMMIT, counted against an external ack log.

**Slice 1b tests (separate PR):** fault-injecting `SqlObjectStore` /
`SqlManifest` wrappers drive every row above in process; `kill -9` of a real
node at PUT, `I`, CAS and drain. Nightly **restore check**: rebuild sampled
databases from the published chain onto an empty disk, `PRAGMA
integrity_check` = `ok`, and per-table row count + ordered row digest equal to
`P` replayed to the same `seq` (or restricted to databases quiescent for a
window). Flag-off test: no store requests, no manifest queries. Allowlist test:
empty allowlist uploads nothing even with `enabled = true`.

**Slice 0 tests (this PR):** key properties (injective over the generated
space/db/lineage/seq/hash domain; **also injective after ASCII case folding**;
immutable: same inputs same key, any changed field changes it; never equal or
prefixed like a KV key; no `/` in a component; `.`/`..` impossible; decoder
rejects non-canonical input; over-long component uses the `~` form); config
parse/defaults/env override/validation; manifest CAS on SQLite and, where the
repo has a Postgres harness, Postgres: stale epoch rejected, stale lineage
rejected, concurrent publishers yield exactly one winner, segment gap and
`last_seq` regression rejected, segment-CAS retry re-derives, lineage switch
keeps `revision` monotonic, first publish is `ON CONFLICT DO NOTHING`, a
conditional state flip with 0 rows rolls the CAS back, orphan revive;
migration idempotence and MySQL DDL (section 7).

## 9. Open decisions and gates

| # | Decision | Owner | Needed by |
|---|---|---|---|
| D1 | **Key custody** (TC-887): enclave/KMS plus escrowed recovery wrap vs owner-held. The `v1` prefix means plaintext; an encrypted format is a new prefix. | Sam / security | Slice 2 code, and before the shadow goes beyond pilot spaces |
| D2 | **Retention numbers** per tier (last wording 100 MB/7 d, 1 GB/30 d; paid not restated). Keep-all meanwhile; each continuously written database adds ~43k objects/month, which the S3 boot scan pages over (consider a separate SQL bucket option). | Sam | Slice 4 |
| D3 | **Authority/epoch/drain**: recommended a PG row in the same control database, so the epoch check and the manifest CAS commit together. | Naomi | Slice 3; before any second node publishes |
| D4 | **Segment format**: 1b uses cumulative WAL since the checkpoint, byte-identical to `delta_payload` (`wal-cum-v1`); restore = snapshot + highest segment. Sealed frame ranges arrive with the encrypted format. Recorded per object in `format`. | Naomi | Before 1b code |
| D5 | **Conditional PUT** (`If-None-Match: *`) on the production provider, SHA-256 in user metadata. HEAD→PUT fallback only while nothing deletes. [INFERENCE: S3 supports it since 2024; R2/MinIO not verified here.] | Ops | Before 1b; mandatory before slice 4 |
| D6 | In-place deploy keeps the data disk. | Ops | Before cutover (slice 5) |
| D7 | **Gating**: `sql_store.spaces` allowlist, **fail-closed: empty = nothing uploads** even when `enabled = true`. | decided (R8) | Before 1b is enabled |
| D8 | **Store-byte accounting**: a `sql_store_bytes` gauge for cost only; no quota until slice 4; `SqlSizes`/`StoreSize` unchanged. | Slice 4 | Slice 4 |

None of D1–D8 blocks slice 1a, which does not touch the store.

## 10. Review checklist (from the Opus design review of `7a47666`)

Tick as each lands. R1–R5 gate the slice-0 merge (doc and code). R6/R7 gate 1b
code. R8 gates enabling 1b on any node.

- [x] R1 MySQL-safe schema: structured columns, `key` as `text` outside the PK (doc)
- [x] R1 migration + MySQL DDL test (code; MySQL asserted from sea-query's MySQL output, the repo has no MySQL harness)
- [x] R2 `base_checkpoint_cid` + `publish_id`; append only on checkpoint match; dead trigger dropped (doc)
- [x] R2 columns + CAS tests (code)
- [x] R3 segment/snapshot/lineage-switch CAS written out; re-derive on loss; continue a matching lineage; first publish `ON CONFLICT DO NOTHING` (doc)
- [x] R3 CAS tests (code; also run against a real PostgreSQL 14, 8-way concurrent publishers)
- [x] R4 conditional state flips, reconciler, explicit revive (doc)
- [x] R4 conditional-flip tests (code)
- [x] R5 lowercase-only alphabet, canonical decoder, proof sketch (doc)
- [x] R5 key code + case-folding property test (code)
- [x] R6 shadow-only labels and [store-master] rules (doc; gates 1b code)
- [x] R7 capture point and bounded spool (doc; gates 1b code)
- [x] R8 fail-closed allowlist and deletion disclosure (doc; gates 1b enablement; runbook entry still owed in 1b)
- [x] D1–D8 timing recorded (section 9)
- [ ] CI green on the slice-0 PR
- [ ] Opus delta review at the PR's exact head, after CI is green

## 11. Slice 1b PR A: format, timestamp, gating and settings rules

This section applies from slice 1b PR A. Where sections 4.1, 5.1 or 5.2 differ from it, this section governs. Sections 11.1 to 11.4 are the rules PR A enforces. Sections 11.5 to 11.8 are the rules that the uploader and object store follow in the slices that add them.

### 11.1 Object format and kind

- A snapshot is accepted only with `format = "sqlite-v1"`. A segment is accepted only with `format = "wal-cum-v1"`. Any other pairing is rejected as invalid.
- A segment publish whose `from_seq` is not `base_seq + 1` loses the CAS. The manifest does not change, the object row stays `uploaded`, and the caller re-derives from the current manifest. The publish is reported as lost, not as an error.
- A publish moves its object row from `uploaded` to `published` only when the row's `format` is the one its kind requires.

### 11.2 Timestamps

- `created_at` is stored as a fixed-width UTC RFC 3339 string with microseconds, `YYYY-MM-DDTHH:MM:SS.ffffffZ`. Input with another offset is converted to UTC before it is stored.
- Input that is not RFC 3339, or whose year is outside 0 to 9999, is rejected as invalid.
- Reviving an orphan object sets `created_at` to the current time. The orphan age is therefore measured from the most recent revive.

### 11.3 Backend and gating

- When `enabled = true`, boot refuses a database URL that starts with `mysql://`, with the error `sql_store supports PostgreSQL and SQLite control databases`.
- When `enabled = true`, boot refuses to start in this build, because the uploader is not part of it. `enabled = false` is unaffected.
- When `enabled = true`, every `sql_store.spaces` entry must be a canonical space ID, for example `tinycloud:pkh:eip155:1:0x<40 hex>:default`. Boot refuses any other value. The error does not repeat the value.

### 11.4 Settings

These keys sit under `[sql_store]`. They are checked at boot only when `enabled = true`.

- `drain_secs`, default 8, at least 1: time budget for draining pending uploader work at shutdown. It is set explicitly and is not derived from the HTTP server's shutdown grace or the container stop timeout.
- `pg_concurrency`, default 2, from 1 to 4: maximum number of concurrent Postgres operations made by the uploader. Manifest reads and CAS, the sweep and bootstrap reads share this limit.
- `snapshot_min_interval_secs`, default 900, at least 1: minimum interval between two snapshots of one database.
- `daily_upload_byte_budget`, default 2 GiB, nonzero: bytes the uploader may upload for one database in one day. Captures over the budget are shed and counted. They are not queued.
- `spool_cap`, default 1 GiB, at least `upload_bytes`: upper bound on the local spool.

### 11.5 Rules for the uploader: spool and disk

- The spool reserves its bytes through the node's disk budget. Spooling does not cause a user write to fail for lack of space.
- The capture channel is bounded in bytes, not in items.
- The shed decision is taken before the copy. A capture that will be shed is not copied.
- A node with `enabled = false` deletes leftover spool files at boot. Spool file names include the process ID. A lock file refuses a second process on the same data directory.

### 11.6 Rules for the uploader: bootstrap

- The checkpoint is read guarded by `checkpoint_content_hash` only, not by `revision`. The delta is read separately, so a database that keeps committing does not block the bootstrap.
- The snapshot is published as `seq = R-1` and the delta as segment `R..R`, where `R` is the current revision. Both come from one consistent read pair. If the checkpoint hash changes between the two reads, the pair is retried once and then backed off. A snapshot is never labelled with a revision it was not taken at.
- One database is bootstrapped at a time. The bootstrap is paced, hash-verified against `checkpoint_content_hash`, run off the request path, and counted against `pg_concurrency`.

### 11.7 Rules for the uploader: revision regression

- If `checkpoint_content_hash` or the checkpoint CID no longer matches the manifest, the uploader starts a new lineage. A revision that moved backwards, for example after point-in-time recovery, does not leave the database idle.

### 11.8 Rules for the object store: conditional writes

- Immutable objects are written with `If-None-Match: *`.
- A 412 response is accepted only after the stored object is checked for matching length and hash.
- A startup probe under `sql/v1/_probe/` selects the write mode. If the provider rejects the header, the uploader uses a check-then-write fallback. The probe result is logged and is never fatal.

### 11.9 Tests for this section

PR A tests: `object_format_must_match_its_kind`, `segment_from_must_follow_base_seq` and `object_state_flip_checks_the_format` (11.1); `created_at_is_stored_canonically` and `revive_restarts_the_orphan_clock` (11.2); `sql_store_refuses_enable_mysql_and_non_canonical_spaces` (11.3); `sql_store_defaults_match_the_contract`, `sql_store_settings_are_checked_only_when_enabled` and `sql_store_new_settings_are_bounded_when_enabled` (11.4). The manifest tests run against SQLite and PostgreSQL.

