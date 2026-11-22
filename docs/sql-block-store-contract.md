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
| **Outcome unknown** | The existing TC-1274 error: HTTP 500, body prefix `outcome_unknown:` (`routes::OUTCOME_UNKNOWN`), no `Retry-After`. Used when the connection died after the save or COMMIT was sent. Clients read state back; a re-sent signed request is answered 409 by replay protection if the write committed (SQL spends its replay row before the write; only a KV put or delete spends it in its own transaction, so a rolled-back KV write applies when re-sent). | Same error and client rule. Additionally returned when authority is uncertain during COMMIT (lost PG session, epoch not provable), when the post-commit intent record failed, or when the response gate closed after COMMIT. Local WAL and request identity are retained; never reported as a definite failure and never replayed blindly. |

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
- `put_file(key, path, size)`: streams a local file to the key. The file's
  length must equal `size` (else `Invalid`) and its SHA-256 the one in the
  key (else `BodyMismatch`); both are checked before anything is stored. If
  the key exists, `head` must show the same length and the SHA-256 stored in
  object user metadata, else `Conflict` (loud; never replace). It uses a
  conditional PUT (`If-None-Match: *`). A HEAD-then-PUT fallback is acceptable
  **only while nothing in the system deletes SQL objects** (this phase);
  slice 4 must require the conditional PUT, or a generation/pin fence, before
  `AlreadyPresent` may count toward a publish (the race TC-735 had).
  `get_to_file(key, path, max_bytes)` is the streaming read; it verifies the
  SHA-256, stops with `Oversize` once more than `max_bytes` arrive (a caller
  passes the inventory's recorded size), and empties the target file on any
  error, so a refused download is never read.
- **Orphan = an object not referenced by any published manifest frontier.** A
  PUT that completed but whose CAS did not (crash, lost response, lost the
  race) is an orphan. Nothing reads it. This phase neither marks nor deletes
  orphans; there is no orphan state, and GC (slice 4) derives them by query
  (4.3).
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
| `persist` does `contains` (HEAD) then PUT, `increment_size` | Dedup is correct for an immutable content-addressed body but means "exists" is treated as "mine". SQL needs the length/hash check in `put_file`, and it must not touch KV `sizes`. |
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
  state              string(16)   not null          -- 'uploaded' | 'published' (an 'orphan' value is never written, 4.3)
  created_at         string       not null
```

Largest PK on MySQL: `(255+255+32+16+64)` chars × 4 + 3×8 = 2,512 bytes,
under 3,072. Because the key fields are columns, frontier validation (4.2) is
a query, not key parsing. A test asserts the generated MySQL DDL (section 7).

### 4.1 Publish = upload first, CAS second

Notices and the pull from Postgres are defined in 5.2; streaming to scratch,
hashing and `put_file` happen off the operation lock and off the request
path. Then, in **one control-database transaction** (`publish_chain`):

1. `record_object` for every object of the publish: `INSERT … ON CONFLICT DO
   NOTHING` the `uploaded` row. If a row exists with equal `bytes` it is
   reused (idempotent; `content_hash` is part of the key); different `bytes`
   fail the publish with `Conflict`. The inventory is committed even when
   the CAS below is lost, so an uploaded object keeps its row.
2. Publish in the same transaction. The three statements, all
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
   A publish step adds exactly one object (the snapshot, or the one segment);
   the transaction **rolls back unless rows_affected = 1**. So an
   already-published or missing row cannot be silently published.
4. A bootstrap or a new checkpoint with a WAL publishes a snapshot and a
   segment as one chain: the snapshot CAS, then the segment CAS on the
   snapshot's result, in the same transaction. Only a loss of the first CAS
   is reported as lost (with the inventory kept); a later step that does
   not apply rolls the whole transaction back.

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
adopting an object outside the chain.

**Restore is defined only at the recoverable frontier.** A snapshot alone is
not a restore point unless its `at_seq` is the frontier: a bootstrap snapshot
published with a segment is labelled `at_seq = 0` (11.6) because Postgres
does not record the revision its checkpoint was cut at, so its `seq` is
unknown and nothing may restore "at 0".

### 4.3 States and inventory

- `uploaded`: PUT confirmed, not in a published chain (also in flight).
- `published`: in the manifest's current chain, or in an earlier chain that
  was superseded (kept for history under the retention policy).
- There is **no `orphan` state** in this phase. The column still accepts the
  value from the slice-0 migration (no migration drops it), but nothing
  writes it and nothing reads it. An orphan is derived when needed: an
  `uploaded` object older than `orphan_after` that no published chain
  references, or an object of a superseded lineage. Slice 4's GC must derive
  it by query, under its own reference-safe protocol.
- **This phase never deletes an object.** Operators remove the area with a
  prefix delete (runbook). Because the inventory row is committed with the
  publish (4.1), an object with no row is one whose PUT completed while the
  publish transaction did not commit (crash, lost race on a new key); it is
  found only by prefix listing (slice 4).
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
- **[shadow] Metadata-only notice, pull from Postgres.** After a save
  commits, the write path calls `ShadowSink::notify(Notice { space, db_id,
  revision, cid })`: synchronous, never fails, never blocks, copies no
  bytes. The sink max-merges by revision into a map and wakes the scheduler;
  spaces outside the allowlist are dropped there. The scheduler pulls the
  bytes from Postgres when an upload is due (`ShadowSource`: `head`,
  `checkpoint_to` verified against the expected cid while streaming, and
  `wal_to`, which refuses if the artifact moved on; a move-on is a transient
  failure and the next attempt re-reads the head). A lost notice costs
  latency only: a keyset-paginated lag scan (no manifest row, `revision ≠
  last_seq`, or a different checkpoint, over the allowlisted spaces, one
  space at a time and no `IN` list) runs at startup and every `scan_every`,
  and is also how a database with no frontier is bootstrapped (11.6). A
  `revision` below `last_seq` is a regression (11.7). In the shadow phase the trigger
  is `upload_interval` after the first notice; the `upload_bytes` size
  trigger is not used, because the notice carries no sizes.
- **Drain on planned stop.** On SIGTERM the uploader stops taking new work,
  uploads and publishes every database with an un-uploaded commit, bounded by
  the shutdown grace period; what is left is logged by count only. In the
  shadow phase an incomplete drain loses nothing (Postgres is master); in
  [store-master] it is the data-loss boundary. [shadow] `ShadowHandle::drain`
  stops scheduling, waits for in-flight uploads up to the deadline and
  reports, per database, `last_seq` against the newest revision it learned.
- **Backlog cap.** [store-master] When un-uploaded bytes reach `backlog_cap`,
  new SQL writes are refused *before they start* with `503 sql_busy:
  store_backlog` and `Retry-After`, resuming below 75 % of the cap; that is a
  rejected outcome. **In the shadow phase refusing buys no durability** (Postgres
  is master), and there is no spool to shed: the uploader bounds the bytes it
  streams at once with a byte semaphore charged before streaming, and its
  scratch files with a disk budget released on drop. It never blocks or
  refuses a write; enforcement is `enforce_backlog_cap`, default `false`
  until cutover.
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
    /// Stream the file at `path` (exactly `size` bytes, SHA-256 = the key's)
    /// to the key unless it exists. Existing with the same length and sha256
    /// => Ok(AlreadyPresent). Existing with different => Err(Conflict).
    async fn put_file(&self, key: &ObjectKey, path: &Path, size: u64)
        -> Result<PutOutcome, SqlStoreError>;
    /// Stream the whole object into `path`, verified; None when absent.
    /// More than `max_bytes` => Err(Oversize). On any Err `path` is emptied.
    async fn get_to_file(&self, key: &ObjectKey, path: &Path, max_bytes: u64)
        -> Result<Option<ObjectMeta>, SqlStoreError>;
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
    async fn record_object(&self, db: &DbRef, obj: &ObjectRecord) -> Result<ObjectState, SqlStoreError>; // state=uploaded, idempotent
    async fn list_objects(&self, db: &DbRef, state: Option<ObjectState>) -> Result<Vec<ObjectRecord>, SqlStoreError>;
    /// record_object for every object, then one CAS per object, in one
    /// transaction (4.1); a lost first CAS keeps the inventory.
    async fn publish_chain(&self, db: &DbRef, expected: Option<&Frontier>, chain: PublishChain)
        -> Result<PublishOutcome, SqlStoreError>;
}

/// [shadow] Where the uploader reads from (5.2). `PgArtifactSource` reads the
/// artifact repository, chunked and external layouts included, in bounded
/// chunks.
#[async_trait]
pub trait ShadowSource: Send + Sync {
    async fn head(&self, db: &DbRef) -> Result<Option<ArtifactHead>, SourceError>;
    async fn checkpoint_to(&self, db: &DbRef, expected_cid: &str, file: &mut File)
        -> Result<Copied, SourceError>;                  // MovedOn on a cid mismatch
    async fn wal_to(&self, db: &DbRef, head: &Head, file: &mut File)
        -> Result<Copied, SourceError>;                  // MovedOn once the row moved
}

/// [shadow] The save hook. Sync; never fails, never blocks.
pub trait ShadowSink: Send + Sync {
    fn notify(&self, notice: Notice);                  // Notice { space, db_id, revision, cid }
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
`m20261023_010000_kv_orphan_candidates`. SeaORM applies out-of-order
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

**Pull point (P1; replaces the R7 capture and spool).** The save hook sends a
metadata-only notice after `persist_write` returns Ok (5.2); it copies no
bytes and never touches disk. When an upload is due the uploader reads `P`
itself through `ShadowSource`, off the request path and the operation lock,
bounded by `pg_concurrency`: the checkpoint is streamed to a scratch file and
verified against the expected `checkpoint_content_hash`, the cumulative WAL
is read only for the exact head it planned from, and both are read in bounded
chunks (never a whole-row load, so TC-822 is not brought back). Segments must
apply to `P`'s exact checkpoint bytes, so the snapshot is those bytes and a
`VACUUM INTO` / backup-API copy is never used. Scratch space is reserved
through a disk budget released on drop and in-flight bytes through a byte
semaphore, both charged before streaming; there is no spool and nothing to
shed. Lock and transactions are never held across PUT or CAS.

| Crash / fault point | State after | Required behaviour on restart |
|---|---|---|
| Before PUT | none | The startup lag scan finds the database again; nothing lost (`P` is master). |
| **PUT done, before `I` insert** | `O` unregistered | Same key is recomputed (content-addressed); `put_file` returns AlreadyPresent; insert `I` with the publish. If content changed, the new key differs and `O` stays an unregistered orphan. |
| **PUT done, publish transaction not committed** | `O`, `M` old | Not recoverable (4.2). Restart re-reads `M`, re-derives the range, reuses `O` if identical, records and CASes in one transaction. |
| **CAS committed, response lost** | `M` new | `current().publish_id` equals ours: success; never re-issue. |
| CAS lost to another publisher | `M` differs, `I` kept | Per 4.1: same lineage re-derive from `last_seq+1`; matching other lineage continue it; non-matching lineage-switch (bounded). Own `O` stays `uploaded`, unreferenced. |
| Store down / 5xx / timeout | `P`, `M` unchanged | Back off; the breaker opens after repeated failures; requests unaffected. |
| PUT OK but `head` shows different length/hash | `O` wrong | `I` is not written. No deletes; report `Conflict`, stop uploading this database, alert. |
| **Duplicate uploader** (restart overlap, TC-1471 instance) | two PUTs, one CAS wins | Same range, same bytes: same key, harmless. Different bytes: different keys; the loser's object stays unreferenced. Neither regresses `M` (`last_seq` clauses). |
| Manifest stale after downgrade / re-upgrade or import | `base_checkpoint_cid` ≠ `P` | The next upload publishes a new snapshot in the same lineage (a lineage switch at `at_seq = 0` if a WAL rides on it); no segment is appended to the old base. |
| `kill -9` mid-stream | partial scratch file | Discarded (temporary file, budget released); the next attempt re-reads `P`. |
| `P` moved on mid-stream | scratch for an old head | `MovedOn`: a transient failure; the next attempt plans from the new head. |
| Metadata DB briefly down | `O` exists | As "publish transaction not committed". |

**Slice 1a tests (separate PR):** `kill -9` before reservation; after
reservation before COMMIT; after COMMIT before artifact save; after save
before response. Assert no acknowledged write is lost and an oversized
transaction is rejected before COMMIT, counted against an external ack log.

**Slice 1b tests (separate PR):** fault-injecting `SqlObjectStore` /
`SqlManifest` wrappers drive every row above in process; `kill -9` of a real
node at PUT, `I`, CAS and drain. Nightly **restore check**: see 8.1. Flag-off
test: no store requests, no manifest queries. Allowlist test: empty allowlist
uploads nothing even with `enabled = true`.

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

### 8.1 Restore check (TC-1491 P2)

`tinycloud node sql-store restore-check` (`shadow::restore` in the core,
`sql_restore_check` in the node) gates turning the shadow on for a space. It
samples up to `--sample` databases (reservoir sampling over keyset pages of
the manifest primary key) from `[sql_store] spaces`, which it reads whether
or not the store is enabled, and checks each:

1. **Frontier only.** It reads the manifest row and resolves the chain of
   4.2 by primary-key lookups in `sql_store_object`: the base snapshot by its
   full key (rebuilt from the frontier's columns and the hash its key ends
   in), and for `last_seq > base_seq` the published `wal-cum-v1` segment
   `base_seq+1 ..= last_seq` by the key prefix `(space, db_id, lineage,
   'segment', base_seq, from_seq, to_seq)`. Restore = snapshot + that one
   segment. A frontier at `last_seq = 0` is `unreadable` (a snapshot at
   `at_seq = 0` is never a restore point, 4.2 and 11.6). Without the segment,
   the reason names the highest published `to_seq` on the base (the
   shortfall). Every key read from the manifest or the inventory must start
   with the database's own `{db_prefix}{lineage}/`, else `unreadable: key
   outside db prefix`. The formats, `published` state and `frontier_bytes`
   must agree with the inventory.
2. **Same revision or nothing.** Postgres's head must be at revision
   `last_seq` with the frontier's checkpoint CID; otherwise the database is
   `not_comparable` ("not comparable at this revision") and nothing is read.
   The check never compares across revisions.
3. **Restore.** Scratch space for both copies is reserved from a disk budget
   (`--scratch-dir`, `--scratch-bytes`) before streaming. Scratch holds
   tenant databases in plaintext: every scratch directory is `0700`, every
   file `0600`, and each directory is removed by its drop guard on every exit
   path (success, error, early return). The snapshot and the
   segment are streamed with `get_to_file`, capped at their recorded sizes; a
   refused download is removed and never opened. Before SQLite opens the
   pair, the database header and the WAL are checked: page sizes equal (the
   guard against RUSTSEC-2026-0459, libsqlite3-sys < 0.39), WAL magic,
   version, header checksum, every frame's salts, page number and cumulative
   checksum, whole frames ending on a commit. SQLite would otherwise ignore a
   bad header or stop at the first bad frame and silently restore an older
   state. Then `wal_checkpoint(PASSIVE)` must have replayed every frame,
   `wal_checkpoint(TRUNCATE)` must report `busy = 0` and `log =
   checkpointed` and leave the WAL empty, and `PRAGMA integrity_check` must
   be exactly `ok`.
4. **Compare.** Postgres's checkpoint and WAL are streamed through
   `ShadowSource` and materialised the same way; the SHA-256 of the two
   materialised files must be equal.

Results per database: `ok`; `mismatch` (a sound restore that differs from
Postgres); `not_comparable`; `unreadable` (missing or refused objects, chain
faults, a refused WAL, an SQLite error or an integrity failure). Reasons are
fixed phrases with numbers; the report carries no keys, SQL or payload
bytes. `segments_unverified` = segments the frontier needs minus segments
streamed, checked and replayed; it is computed per database and summed.
Metrics (`--metrics-file`, a node-exporter textfile):
`sql_store_restore_checks_total{result}`,
`sql_store_restore_segments_unverified_total`,
`sql_store_restore_check_seconds`. The command fails (exit 1) when any
database is `mismatch` or `unreadable`; `not_comparable` is reported, not
failed.

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

This section applies from slice 1b PR A. Where sections 4.1, 5.1, 5.2, 5.3 or 8 differ from it, this section governs. Sections 11.1 to 11.4 are the rules PR A enforces. Sections 11.5 to 11.8 are the rules that the uploader and object store follow in the slices that add them.

### 11.1 Object format and kind

- A snapshot is accepted only with `format = "sqlite-v1"`. A segment is accepted only with `format = "wal-cum-v1"`. Any other pairing is rejected as invalid.
- A segment publish whose `from_seq` is not `base_seq + 1` is rejected as invalid. The manifest does not change, and the object row stays `uploaded`. This is a request error, not a lost CAS.
- A publish moves its object row from `uploaded` to `published` only when the row's `format` is the one its kind requires.

### 11.2 Timestamps

- `created_at` is stored as a fixed-width UTC RFC 3339 string with microseconds, `YYYY-MM-DDTHH:MM:SS.ffffffZ`. Input with another offset is converted to UTC before it is stored.
- Input that is not RFC 3339, or whose year is outside 0 to 9999 after conversion to UTC, is rejected as invalid.
- There is no revive (4.3): `created_at` is set once, when the row is first recorded.

### 11.3 Backend and gating

- When `enabled = true`, boot refuses a database URL whose scheme is not `postgres`, `postgresql` or `sqlite` (case-insensitive), with the error `sql_store supports PostgreSQL and SQLite control databases`.
- When `enabled = true`, boot refuses to start in this build, because the uploader is not part of it. `enabled = false` is unaffected.
- When `enabled = true`, every `sql_store.spaces` entry must be a canonical space ID: it parses as a space ID and renders back to the same string, for example `tinycloud:pkh:eip155:1:0x<checksummed 40 hex>:default`. Boot refuses any other value. The error does not repeat the value.

### 11.4 Settings

These keys sit under `[sql_store]`. They are checked at boot only when `enabled = true`.

- `drain_secs`, default 8, at least 1: time budget for draining pending uploader work at shutdown. It is set explicitly and is not derived from the HTTP server's shutdown grace or the container stop timeout.
- `pg_concurrency`, default 2, from 1 to 4: maximum number of concurrent Postgres operations made by the uploader. Manifest reads and CAS, the sweep and bootstrap reads share this limit.
- `snapshot_min_interval_secs`, default 900, at least 1: minimum interval between two snapshots of one database. It applies together with `snapshot_every` in section 5.3.
- `daily_upload_byte_budget`, default 2 GiB, nonzero: bytes the uploader may upload for one database per UTC day. An upload that would exceed it is not started; the database is blocked until the UTC day changes and then catches up from Postgres. Nothing is queued.
- `spool_cap`, default 1 GiB, at least `upload_bytes`: in the shadow phase, the bytes uploads may stream at once and hold in scratch files (11.5).

### 11.5 Rules for the uploader: scratch and disk

- There is no spool and no capture channel (section 8, pull point). Uploads stream from Postgres into scratch files under the node's data directory.
- Scratch space is reserved through the node's disk budget before the copy and released when the scratch file is dropped. A reservation that does not fit is a transient failure for that database; a user write never fails for lack of space.
- In-flight upload bytes are bounded by a byte semaphore charged before streaming, not by a count of items.
- Scratch files are anonymous temporary files: a crash leaves nothing that a later boot must recognise.

### 11.6 Rules for the uploader: bootstrap

- Bootstrap is the ordinary upload of a database without a manifest row; the lag scan finds it (at startup, then periodically). It reads `P` like every other upload (section 8).
- The snapshot is the artifact's exact checkpoint bytes, streamed and verified against `checkpoint_content_hash`. There is no `VACUUM INTO` and no materialised copy: a segment must apply to those exact bytes.
- Postgres does not record the revision a checkpoint was cut at, so the snapshot cannot be labelled with it. With no delta, the checkpoint is the database at the current revision `R`, and the snapshot is `at_seq = R`. With a delta, the snapshot is `at_seq = 0` and the cumulative WAL is one segment `1..=R` on it, published in the same transaction (4.1 step 4). Only `R` is a restore point (4.2); `0` names no revision. The same rule applies when a new checkpoint carries a WAL later: that publish is a lineage switch at `0`.
- The WAL is read only for the exact head the upload planned from. If the artifact moved on (new revision or new checkpoint), the read is refused and the upload fails transiently; the next attempt plans from the new head after a backoff.
- Bootstraps share the uploader's limits with other uploads: the job count, the byte semaphore and `pg_concurrency`. They run off the request path.

### 11.7 Rules for the uploader: revision regression

- If `checkpoint_content_hash` or the checkpoint CID no longer matches the manifest, the uploader starts a new lineage. A revision that moved backwards, for example after point-in-time recovery, does not leave the database idle.

### 11.8 Rules for the object store: conditional writes

- Immutable objects are written with `If-None-Match: *`.
- A 412 response is accepted only after the stored object is checked for matching length and hash.
- A startup probe under `sql/v1/_probe/` selects the write mode. If the provider rejects the header, the uploader uses a check-then-write fallback. The probe result is logged and is never fatal.

### 11.9 Tests for this section

PR A tests: `object_format_must_match_its_kind`, `segment_from_must_follow_base_seq` and `object_state_flip_checks_the_format` (11.1); `created_at_is_stored_canonically` and `created_at_out_of_range_is_invalid_not_a_panic` (11.2; `revive_restarts_the_orphan_clock` went with the orphan state in TC-1491 P1); `sql_store_refuses_enable_mysql_and_non_canonical_spaces` (11.3); `sql_store_defaults_match_the_contract`, `sql_store_new_setting_defaults_and_pg_concurrency_floor`, `sql_store_new_settings_parse_and_are_bounded`, `sql_store_settings_are_checked_only_when_enabled` and `sql_store_new_settings_are_bounded_when_enabled` (11.4). The manifest tests run against SQLite and PostgreSQL.

## 12. Object store backends

Slice 1b PR B adds the two backends of the object store trait in `tinycloud-node-server/src/storage/sql_object.rs`. Neither is started by the node yet.

### 12.1 S3

- The store uses the block store's bucket and client settings. The object key is the key of section 3.1, unchanged. The object carries its lowercase hex SHA-256 as user metadata `sha256`.
- A body that does not hash to the key is refused with `BodyMismatch` before any request is sent.
- In conditional mode an object is created with one PUT carrying `If-None-Match: *`. A 412 answer is accepted only after a HEAD shows the stored object has the same length and the same `sha256` metadata (`AlreadyPresent`); any other stored object gives `Conflict`. A stored object without the metadata is a backend error, never a match.
- The startup probe writes a fixed small body to `sql/v1/_probe/v1` twice with `If-None-Match: *`. A 412 on the second request selects conditional mode. A second success, or a 501 or NotImplemented answer for the header, selects check-then-create mode. Any other failure, any other status included, is an error and the store does not start. The result is logged once at info level (target `tinycloud::sql_store`) with the mode and the status and code of the answer that decided it. The probe object is not deleted.
- In check-then-create mode the store sends a HEAD first. An absent object is created with an unconditional PUT; an existing one is compared as above. Creators of one key in one process run one at a time in both modes; creators in different processes can each report `Created` for the same key in check-then-create mode, and each stores the bytes the key names.
- In conditional mode a 409 `ConditionalRequestConflict` answer (another conditional write of the key is in flight) is retried up to 5 times; any other status is a backend error with its status and code.

### 12.2 Filesystem

- The root is `{datadir}/sql-store`. A relative root or block store root is made absolute against the current directory first (a lexical step that reads nothing from the filesystem; `..` components are refused). Boot then refuses a root that is equal to, inside, or a parent of the block store root. The filesystem store is not supported on Windows.
- The path of an object is the root joined with its key. Every key component must be an ordinary file name, and the resulting path must stay under the root.
- A create writes the body to a `.tmp-` file in the target directory, fsyncs it, and publishes it with a hard link, which fails instead of replacing an existing file. An existing file with the same length and SHA-256 gives `AlreadyPresent`, any other gives `Conflict`. The directory is fsynced and the temporary file is removed in every outcome. Each new directory and its parent are fsynced when created, and the parent of a directory that already exists is fsynced too. A leftover temporary file does not affect a later create.

### 12.3 Ranges and head

Both backends answer a range as the in-memory store does: the range is resolved against the object size and clamped to it, and a range that selects no byte (start at or beyond the end, an inverted range, a zero-length suffix, any range of an empty object) and a missing object both give `None`. `head` returns the length and SHA-256; the filesystem store hashes the file in bounded chunks.

### 12.4 KV size scan

The S3 block store's start-up size scan lists objects with the prefix `tinycloud:`. Space ids start with `tinycloud:`, and only keys whose part before the last `/` is a space id count towards a space, so the computed sizes are the same as for a scan of the whole bucket and `sql/v1/` objects are not listed.
