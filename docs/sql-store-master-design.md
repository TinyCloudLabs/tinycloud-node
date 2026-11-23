# SQL store-as-master (TC-1491 P4): design for Sam

Status: **Design for Sam; read by Bobbie (14:07Z: all MUSTs closed).** Nothing here is built. Author: node lead (aa33b25c). Date: 2026-11-23. Naomi ruled the decisions in section 13 at 13:12Z.
Items marked [INFERENCE] are not verified against code or production.

## 0. The ask, in four lines

- **What:** make the object store (S3 / block store) the *master* copy of a SQL database, with the node's local disk as the working copy, instead of PostgreSQL holding the master bytes. This is the last step of Sam's 10-19 design B.
- **Why it matters to you:** it is a one-way door. Once a database is store-master, going back to PostgreSQL master is a copy job with its own size limit (section 8), and a mistake can lose acknowledged writes.
- **What this document is:** the plan we recommend, what it does to the 64 MiB limit (section 9) and to the Inbox per-source databases (section 10), and the decisions we need from Sam (section 13).
- **What it is not:** an estimate-backed schedule. Section 12 gives slice order and relative size only.
- **Terminology (read this first).** The **durable master** of a store-master database is the object store (the same S3 block store that backs KV blocks): a checkpoint plus WAL segments with a manifest. The node's local disk holds the **working copy** the SQL engine runs on, and it can be up to about 60 s / 8 MiB **ahead of** the store because of Sam's 10-19 ruling (no wait-for-store on commit). This document never calls the local file "the master"; it calls it the working copy, and says it must never be overwritten because it may hold the newest acknowledged writes. SQL still runs on a SQLite file; this design does not turn rows into KV entries.

## 1. Where we are today (verified in code, node main cae89736)

| Piece | State |
|---|---|
| PostgreSQL `database_artifact` | **Master** for every SQL database (checkpoint + WAL delta). A write is acknowledged after the artifact save commits. |
| P0/slice 1a (local durability) | Merged, live since 1.26.x: local `synchronous=FULL`, reservation before COMMIT (`docs/sql-local-durability.md`). Postgres still master. |
| P1 (#704) | Merged. Pull-based per-database uploader (Clean/Dirty/InFlight/Backoff/Blocked), metadata-only hook, lag scan, streamed bodies. Ships **off**: `[sql_store] enabled` is refused by a build gate. |
| P2 (#707) | Merged. Restore check: replay every segment and compare with Postgres at the same revision. Gates shadow for any space. |
| P3 (#725, cae89736) | Merged. Per-interval WAL deltas (`wal-delta-v1`, `sql_wal_mark`), cumulative fallback every 64th publish, one autocommit CTE for unfenced PG saves. Ships with the next node release. |
| Manifest tables | `sql_store_manifest`, `sql_store_object`, `sql_wal_mark`. `epoch` is the constant `0` today (contract 4.4). |
| Settings / gating | `[sql_store]` allowlist, fail-closed (empty = nothing uploads) (contract D7). |
| What reads the store | **Nothing.** The store copy is a shadow. Dropping it changes no behaviour (contract 1.3, shadow only). |

Facts that shape this design (all from the repo):

- A database below `memory_threshold` (10 MiB) is in-memory SQLite: no local file, durability = the Postgres save (`docs/sql-local-durability.md`).
- On any failed Postgres save the node **discards local state** and re-hydrates (`SqlService::discard_local_state`, `persist_write`). Correct while Postgres is master; wrong once the local commit is the ack (contract section 2).
- The PostgreSQL artifact path has a 64 MiB single-statement save limit (`DEFAULT_MAX_ARTIFACT_WRITE_BYTES`, TC-2961), a 64 MiB default read limit, and an 8 MiB WAL-delta cap (`MAX_WAL_DELTA_BYTES`, `sql/service.rs:35`). Production runs `max_database_bytes` and `max_artifact_read_bytes` at 320 MiB (section 14).

## 2. What changes for a user, in plain words

- Today: your database is saved in the main database before the node says "done". If the node dies, nothing is lost.
- After P4 (for databases that have been cut over): "done" means the node has it safely on its own disk. It is copied to storage about every 60 seconds (or every 8 MiB), and at worst a per-database bound of 2 windows (section 5.4). **If the node's disk is destroyed you can lose up to that bound of writes.** A restart, crash or planned deploy with the disk intact loses nothing, provided the data directory is a persistent volume (it is not today; section 14).
- The loss window is a *documented product change*, decided by Sam on 2026-10-19 ("no wait-for-store on commit in v1", 60 s / 8 MiB default). This document keeps that decision and does not add a wait-for-store option. [DECISION 1 below asks whether that still holds for paid tiers.]
- Honest copy for docs and the owner status is the paragraph in contract section 2. It must not appear in user docs until a database is actually cut over.

## 3. Hard preconditions (nothing cuts over until all are true)

1. **Encryption of the store copy (contract D1, slice 2).** Today's funded phase is an *unencrypted shadow*; store objects are plaintext SQLite bytes (contract 1.4). A store-master database means the object store is the only durable copy of plaintext user data. We recommend **no cutover of any non-owned space before encryption ships** [DECISION 2].
2. **File-backed.** In-memory databases (< `memory_threshold`) move to local files first; a restore drill passes for that class before any cutover (council plan).
3. **Conditional PUT (contract D5).** The store must run in *conditional* mode (the startup probe, contract 12.1); a node in check-then-create mode refuses to cut anything over. Which mode production selects is a readable log line; Ops to read it (section 14).
4. **Data directory survives a deploy and a crash (contract D6). NOT met in production today:** the datadir is in the container's writable layer and is lost on the container recreate (section 14). Needs a named volume that persists across deploys and across a crash or OOM kill. A drain-and-publish step before recreate helps but does not count on its own: a crash skips it. Proof is a staging deploy drill: write, redeploy (and kill -9), read back every acknowledged write.
5. **P2 restore check green for that database at the exact revision** (not "recently").
6. **Authority record and epoch (D3).** The per-database mode and epoch live in the control database (section 4), so the epoch check and the manifest CAS can commit in one transaction.
7. **The local working file is never overwritten or deleted on any path** (section 5.2) and a **local-file uploader** exists (section 5.3). Without both, a worker rebuild overwrites the freshest acknowledged writes with a stale Postgres copy and nothing uploads to the store.
8. **Freeze enforced in every artifact save, lease and epoch fence, purge/quota wiring** (sections 6.1, 7, 8b).

## 4. The per-database mode record (the heart of the design)

One durable row per SQL database, in the control Postgres (same database as `database_artifact` and `sql_store_manifest`, so a mode change and a manifest/epoch change can commit atomically):

```
sql_store_mode                               -- PK (space, db_id)
  space, db_id        string(255)
  mode                string(16)             -- pg_master | shadow | cutting_over | store_master | copying_back | owner_lost
  epoch               big_integer            -- bumped on every owner change; never reset
  owner_node          string(255)            -- the node that holds the working copy (store_master only)
  lease_holder        string(255)            -- the node that currently holds the lease (store_master)
  lease_expires_at    string                 -- RFC 3339; the owner stops acking before this (section 7)
  mode_changed_at     string                 -- RFC 3339
  cutover_revision    big_integer            -- the database_artifact.revision the cutover froze (audit)
```

(Plain columns only, same MySQL rules as contract section 4. Absent row = `pg_master`, so the migration is inert.)

States and who may leave them:

| From | To | Trigger | Guard |
|---|---|---|---|
| (no row) / pg_master | shadow | operator allowlists the space | `[sql_store]` enabled + allowlist (existing D7) |
| shadow | pg_master | operator removes the space | none; shadow is advisory |
| shadow | cutting_over | operator starts cutover for one database | preconditions 1-8 hold; no other cutover in flight for this node's budget |
| cutting_over | store_master | cutover step 5 commits (the flip) | restore check at the frozen revision matched |
| cutting_over | shadow | any step fails or times out | frozen writes released; Postgres artifact never changed |
| store_master | copying_back | operator starts rollback | section 8 size guard passes |
| copying_back | pg_master | copy verified, flip committed | restore check equals the store's frontier |
| copying_back | store_master | copy aborted | store still master |
| store_master | owner_lost | lease expired and the owner is stopped or has not renewed; operator confirms | epoch bumped; a new owner must claim after expiry + margin (section 7) |
| owner_lost | store_master | the same node reclaims from its intact disk with local seq >= the frontier, or another node claims from the store frontier | epoch + 1; the claim logs the loss window, zero for the same-disk case |
| any | (none) | a transition not in this table | refused; the call returns an error, never a guess |

Rules:

- The mode row, not the presence of local files or manifest rows, decides where a request is served from. A node that has not read the row (or cannot) **refuses** the SQL request for that database (503, retryable) rather than guessing.
- Every mode transition is one conditional UPDATE `WHERE mode = :from AND epoch = :e`, with `rows_affected` checked (same pattern as the manifest CAS, contract 4.1).
- The mode record never says `store_master` while the Postgres artifact is writable: cutover step 5 freezes the artifact in the same transaction that flips the mode (section 6).

## 5. Acknowledgement contract and the local working file

### 5.1 Outcomes

Outcomes keep their three names (contract section 2). The changes:

- **Committed** = the local SQLite COMMIT is fsynced (`synchronous=FULL`), the node's lease is valid (section 7), and the response gate is released. The store lags by at most the bounds in 5.4. This is the documented loss window.
- **Rejected** = verified rollback before COMMIT, or a reservation refusal (`sql_disk_headroom`, owner budget), as today.
- **Outcome unknown** (existing `outcome_unknown:` 500) is additionally returned when: authority is uncertain during COMMIT (lease not provable), the post-commit intent record failed, or the response gate closed after COMMIT. Clients read state back; a re-sent signed request is answered 409 by replay protection if the write committed (SQL spends its replay row before the write). **No safe-to-retry claim is added.**
- The uploader never changes an outcome (contract 2, unchanged).

### 5.2 No path may delete or overwrite the local working file

Removing `discard_local_state` from `persist_write` is not enough (Bobbie, MUST 1). Today **every worker rebuild runs `seed_cache`, which deletes the local files and rewrites them from the Postgres artifact** (`sql/service.rs` `hydrate`/`seed_cache`, ~984-1030, 1066). Under store-master that artifact is frozen, so a rebuild would overwrite the freshest acknowledged writes with a stale copy. Rebuilds happen on idle exit after 5 minutes, restart, dead-worker respawn, and reset-failure retire. Two more paths discard local state: `CommitFailed` and a missing lineage.

Rule: **for a database in `store_master`, no code path deletes, truncates, replaces or re-seeds the local file from Postgres.** The object store is the durable master; the local file is the working copy and, for up to the loss window, the only holder of the newest acknowledged writes, which is why it must not be touched.

| Path | Store-master behaviour |
|---|---|
| Worker rebuild (idle exit, restart, respawn, reset-failure retire) | Opens the existing local file as is. Never calls `seed_cache` from Postgres. |
| Local file missing or unreadable | The database is **fenced** (503). Recovery is an explicit operator action (`recover_from_store`, section 7), which logs the loss window; it is never automatic. **There is no eviction in v1:** a store-master local file is never removed while the database is store-master, so "file missing" always means loss or damage, never "evicted". Automatic hydrate-from-frontier on a missing file is forbidden: it is exactly the loss path. (If eviction is added later it may only happen when the database is Clean, local seq = frontier, recorded on the mode row as "evicted at seq S"; auto-hydrate is then allowed only when the row says evicted at S = frontier, and every other missing file stays fenced.) |
| `CommitFailed` (fsync error after WAL frames were written) | Outcome unknown. The file is kept; the database is marked suspect and refused until an integrity check passes. An fsync error can leave the page cache and the disk disagreeing, so a `quick_check` on the same handle proves nothing: **close and reopen the file first** (then `PRAGMA quick_check`, seq vs the manifest frontier), or treat it as a disk fault for the operator. No discard. |
| Persist error / missing lineage | These are Postgres-artifact concepts; on the store-master path they do not exist. A persist error cannot occur because nothing is persisted to Postgres. |

One test per row, plus idle exit, restart and respawn each with an acknowledged write present (section 12, P4.2).

### 5.3 Where `seq` lives and what the uploader reads

Today's shadow uploader reads **Postgres** (`PgArtifactSource`), is woken only by a Postgres save, and sets `seq` to the Postgres artifact revision (`store/shadow/`). Once Postgres is frozen, **nothing would upload**, and no slice in the first draft built a local-file uploader. Corrected:

- A new **local-file source** (slice P4.2a) captures the checkpoint and WAL bytes from the local files, under the per-database operation lock and only after COMMIT returned, never holding the lock across PUT or CAS (contract 11.5/R7).
- `seq` is a counter **persisted inside the SQLite file in the same transaction as the write** (a reserved internal table hidden from user SQL by the authorizer; alternatives such as `user_version` are rejected because users may use them). A crash-restart therefore never reissues a seq with different content. At cutover `seq` starts at the frozen Postgres revision R.
- The manifest lineage anchor (contract R2, `base_checkpoint_cid` = Postgres `checkpoint_content_hash`) is **redefined for store-master** as the checkpoint hash of the local file at cutover, because the Postgres artifact no longer moves. Needs its own migration-safe column semantics; Bobbie to read in P4.2a.

### 5.4 The loss window is bounded per database and by time

The shadow backlog cap is **node-wide** (64 MiB un-uploaded, no time bound; `store/shadow/policy.rs`). That is not a bound on loss for a store-master database. Store-master adds, per database:

- **max un-uploaded age** (proposed 2 windows, 120 s) and **max un-uploaded bytes** (proposed the 8 MiB window figure x 2), both enforced *before* a write starts: refusal is `sql_busy` 503 with stage `store_backlog`, a *rejected* outcome. Both bounds are measured since the last successful publish and apply to every store-master database whatever its size: production allows databases up to 320 MiB (`max_database_bytes`), and without these bounds the exposure after a node loss would be up to a whole database, not the 8 MiB window. The worst case is the bound **plus one write's WAL**, because the bound is checked before a write starts; the user-facing copy and the alert thresholds use that figure.
- A store outage longer than the age bound makes the database read-only; reads continue.
- The user-facing copy states the worst case, not the typical case: "copied about every 60 seconds; at worst up to [age bound] of writes can be lost if the node's disk is destroyed".

## 6. Cutover: fenced, one database at a time

**No dual-write.** Sam's council plan (2026-11-22) declines Decision 13's dual-write exception. Dual-write has two masters and no atomic commit across them; it can ack a write that only one side has. The cutover below never has two writers or two masters: it freezes, copies, verifies, flips, in that order.

### 6.1 The freeze is enforced inside every artifact save

Bobbie's MUST 3: a save acked at R+1 between steps 3 and 5 would be lost if step 5 only flips a mode row. So:

- Step 5's flip is a **conditional UPDATE of the artifact row** `WHERE revision = :R AND checkpoint_content_hash = :h`, setting a `frozen` marker. If a save committed R+1, it matches zero rows and the cutover aborts to `shadow`.
- **Every artifact save statement** (the unfenced CTE, `save_delta`, the fenced transactional writers, chunked-part publishes: `database_artifacts.rs`, `chunks.rs`) carries the `frozen` check, the same pattern as the purge fence (`database_artifacts.rs` ~942-961). A save against a frozen artifact fails.
- **Old binaries:** during a deploy overlap an old binary does not know the marker. Cutover is refused unless every node reports a version >= the one that carries the check (a version gate row), and on PostgreSQL a trigger on `database_artifact` that rejects updates to a frozen row is the defence in depth (DB-enforced, not code-enforced). Self-host SQLite/MySQL: version gate only; documented.

Per database, run by an operator-initiated, single-flight job (one cutover per database; a global limit on concurrent cutovers):

1. **Preflight.** Preconditions 1-8 (section 3), mode = `shadow`, the uploader is `Clean` (no backlog), restore check green for the current revision.
2. **Fence writes.** Set mode `cutting_over` (conditional UPDATE). New write requests for this database are refused with 503 `Retry-After` (bounded, a few seconds); in-flight writes finish. Reads continue from the local worker.
3. **Final publish.** One uploader publish from the Postgres artifact at revision R (read R after in-flight writes finished). Record `cutover_revision = R`.
4. **Verify.** Restore from the store (snapshot + segments) into scratch and compare with Postgres at R (the P2 check, same code). **Also hash the local working file against R**, because it becomes the working copy the node serves from at step 5. Mismatch on either = abort to `shadow`, unfreeze, report.
5. **Flip, one control-DB transaction:** (a) the conditional artifact UPDATE of 6.1 (revision still R) sets `frozen`; (b) mode `cutting_over -> store_master`, epoch + 1, `owner_node` = this node, lease granted; (c) manifest lineage re-anchored at the local file's checkpoint hash (5.3).
6. **Open the gate.** Serve from the local working copy (already verified equal to R in step 4) and release the fence.
7. **Soak.** Postgres artifact retained (frozen) for 30 days (ruling 4).

Crash matrix (one test per row; same shape as contract section 8):

| Crash after step | Result |
|---|---|
| 2 (fenced) | Mode `cutting_over`; on boot the node aborts to `shadow`; no data change. |
| 3 / 4 (published, not verified) | Same: abort to `shadow`. Extra store objects are orphan-by-query, never read. |
| 5 commit not durable | Transaction did not commit: still `cutting_over` -> abort to `shadow`. |
| 5 committed, before 6 | Mode `store_master`, artifact frozen, epoch bumped. On boot the node checks its local file hash against R and the manifest frontier. If it matches, it opens the gate. If the file is missing or differs, the database is fenced and recovery is the operator `recover_from_store` (loss window logged). |
| after 6 | Normal store_master operation. |

Rollback at any point before step 5 is free. After step 5 the rollback is `copying_back` (section 8).

## 7. Single writer, lease, epoch fence and `owner_lost`

Bobbie's MUST 4: the manifest epoch is not a fence (the expected epoch is read from the manifest row itself, and a lost check reloads and retries), and no fence exists on the local COMMIT. Corrected design:

- **The node's epoch comes from its own mode row**, read when it acquires the lease, never from the manifest. The manifest CAS carries that epoch. A mismatch (the manifest or mode row shows a higher epoch) **stops the database on this node** (state `fenced`, 503) and is never retried.
- **A lease with an expiry** (`lease_holder`, `lease_expires_at` columns in `sql_store_mode`, added in section 4; the first draft assumed a lease that no column provided). The owner renews it on a heartbeat (proposed 10 s renew, 30 s lease) and **stops acking writes when its own remaining lease, measured on its monotonic clock, is below a safety margin**. The pre-commit gate checks lease validity, so the local COMMIT is fenced too.
- **A claim waits for expiry + a margin** bounding clock skew. An operator "mark dead" does **not** shorten that unless the old node is *provably stopped* (the CVM stopped by Amos, evidence recorded on the row). Otherwise an operator could mark a live node dead while it keeps acking.
- Availability consequence, stated plainly: a store-master database cannot ack writes if its node cannot renew the lease (control DB unreachable for longer than the margin). Postgres is already needed for every write today, so this is not a new dependency, but it is a new *failure mode*: a short control-DB outage that the current path survives mid-request can now trigger the lease refusal.
- Exactly one node holds a store-master database. TC-1471 (multi-instance) is out of scope.
- A **lineage switch** is permitted only for the current lease holder, from its own disk, never because a CAS was lost.
- `owner_lost`: a new owner claims with `epoch + 1` after expiry, hydrates from the manifest frontier, and accepts the loss window since the last publish; the claim logs the frontier `seq`. **No auto-claim** in v1: an operator decides (ruling 5, proposed).
- **The original owner may reclaim from its intact disk** (Bobbie NOTE): `owner_lost -> store_master` on the same node after expiry, with `epoch + 1`, if its local seq is >= the store frontier. The local file then stays the working copy and the uploader resumes; nothing is lost. Without this a restart after a long control-DB outage would needlessly roll back to the store frontier.
- Mode-row reads on every SQL request need a **cache with an invalidation spec**: cached for the lease's remaining validity, invalidated on any epoch change; a node that cannot prove its lease refuses (section 4 rules).

## 8. Rollback (copy-back) and its size limit

- `copying_back` restores a store-master database into the Postgres artifact and flips the mode to `pg_master`.
- **Copy-back starts from the local working file, not the store frontier** (Bobbie MUST 6): the store frontier lags and would drop un-uploaded writes. Steps: fence writes, wait for the uploader to reach `Clean` (everything on the store), hash the local file against the frontier seq, then copy and flip. If the node is lost (`owner_lost`), copy-back starts from the store frontier and accepts that loss window, logged.
- **The Postgres artifact path has the 64 MiB save limit.** A store-master database above 64 MiB **cannot be copied back** unless the opt-in PG parts store (`chunked_artifacts`, off in production; section 14) is on for it, or the TC-3764 WAL-parts slice covers it. This is what makes P4 a one-way door for large databases.
- **Ruled (13.3): (a).** For the pilot a store-master database may not exceed the PG copy-back limit (64 MiB). **This is not enforced today**: `max_database_bytes` defaults to 0 and is 320 MiB in production, so P4.4 adds a **per-database growth guard** for store-master databases (a 64 MiB `max_page_count` applied in the pre-commit gate for those databases only). Said plainly: the pilot therefore does not yet write databases above 64 MiB; that is unlocked later by decision 13.6.
- Copy-back is also the recovery path if the store provider is lost: it needs the Postgres artifact retained (soak period, step 7) or the store reachable.

## 8b. Authorization, quota, purge and revocation

Bobbie's MUST 7. Store-master moves data off the paths that these controls watch.

- **Authorization and read scoping are unchanged:** every SQL request is still authorized at `/invoke` per request (the capability check; `key.rs` is only object-key scoping); revocation takes effect at the next request exactly as today. Reads of a store-master database go through the same path.
- **Quota and billing (`SqlSizes`):** metering today updates only on Postgres saves (`sql_sizes.rs`, `db.rs` ~2104-2111), and `SqlSizes` seeds from `database_artifact.size_bytes` (`sql_sizes.rs:26`), which is frozen after cutover, so a store-master database would **escape quota and billing** and restart with a stale size. Required: a post-commit size update from the local file (size after COMMIT) feeding the same `SqlSizes` accounting, and seeding from the local file (or the frontier `frontier_bytes`) for store-master databases. Test: a store-master write that exceeds the account budget is refused before COMMIT, as the owner-budget gate does today.
- **Purge:** the purge fence is bypassed by local commits and uploads (neither touches an artifact save), and a first publish recreates the manifest row (`manifest.rs` ~456), which could **resurrect a purged space**. Required: add `sql_store_mode` to `PURGED_BY_SPACE` (`space_purge_database.rs`), have the uploader's publish and the local commit gate check the purge fence, and make purge of a store-master space **delete the local file and the store objects**. The contract (R8) says deletion is not implemented in the shadow phase and the plaintext store copy is not removed; for store-master the store copy is the *only* copy, so delete capability must exist before any **non-owned** cutover.
- **Test list:** purge during store-master (no resurrection, files and objects removed); revocation mid-window; quota refusal; old binary against a frozen artifact; stale node after a claim.

## 9. What P4 means for the 64 MiB limit

Plain answer: **P4 removes the 64 MiB *save* limit for store-master databases, but does not make size stop mattering.** It replaces one limit with several, and the limit returns at copy-back.

| Limit | Today (PG master) | Store-master |
|---|---|---|
| 64 MiB single-statement artifact save (`DEFAULT_MAX_ARTIFACT_WRITE_BYTES`, TC-2961, the 11-13 crash guard) | Binds: databases with a checkpoint above 64 MiB refuse every write (507 since #664, TC-3763). | **Not applicable** to a store-master database: its checkpoint goes to the object store as one streamed PutObject (no resume), not as a `bytea` parameter on the primary. The crash class (a ~575 MiB `bytea` bind on the primary) does not exist on that path. |
| 8 MiB WAL-delta cap (`MAX_WAL_DELTA_BYTES`) | A write whose WAL exceeds it falls back to a whole-checkpoint save, which the 64 MiB limit then refuses. | Not applicable: P3 publishes bounded `wal-delta-v1` intervals. |
| Per-database max size (`max_database_bytes`: 0 by default, **320 MiB in production**) and owner/account budget | Applies. | **Still applies.** It is a policy limit, not a PG limit. Raising it is a separate decision (13.6). |
| Local disk: reservation before COMMIT, `min_free_bytes`, `DiskBudget` | Applies to the local cache copy. | Applies **more**: the local file is now the working copy. A database must fit on the node's disk; sum of working copies is bounded by disk. |
| Hydration time (cold start downloads snapshot + segments) | Bounded by the 64 MiB read limit, one PG read. | Grows with size: a 300 MiB database hydrates from the store only on an explicit operator recovery or a new node (section 5.2: no automatic hydrate for a missing file, no eviction in v1). Needs an explicit hydration timeout and a status "hydrating" outcome (503 `Retry-After`), not a hung request. |
| Upload size per window | n/a | The uploader PUTs one streamed object per publish with no resume (`sql_object.rs`): a failed multi-hundred-MiB PUT restarts from zero. Bounded by the per-database byte limit and backlog rules (section 5.4). |
| Request/response caps (SQL `/invoke` 2 MiB body, 10 MiB / 4 MiB response, 1,000 rows) | Unchanged. | **Unchanged.** These are API limits, independent of storage. |
| Copy-back to PG | n/a | **64 MiB** (section 8). |

So "SQL moves into KV, the size limit stops mattering" is true for the *save* limit only. The recommended product statement: *"Databases up to [X] MiB are supported; X is a policy number we choose from disk and hydration-time measurements"*, not "unlimited".

An alternative that fixes the 64 MiB save limit **without** P4 is TC-3764 (WAL-parts on PostgreSQL master): append-only WAL segments + occasional chunked checkpoint. It is smaller and reversible, keeps PG master, but keeps the PG capacity bound. It is Backlog and unscheduled. P4 and TC-3764 are not exclusive; TC-3764 also supplies the copy-back path that makes P4 reversible for large databases [DECISION 3 ties them].

## 10. What P4 means for Inbox

Facts [from TC-1628 / TC-3763 text, not verified in the Inbox repo]:

- Inbox v2 (#59/#60) stores messages in several SQL databases under `xyz.tinycloud.inbox/db/` (`db/main`, `db/main-2`, `db/state`), with **size rollover**: when a shard reaches a threshold, writes continue in the next shard. Reads union shards. Media goes in KV.
- Sam's old Inbox database (`xyz.tinycloud.inbox/data` / `messages` space, checkpoint 300,666,880 B, revision 9796) has been read-only since the 64 MiB save limit; the v2 fresh start (Naomi ruled 12:50Z: restart as built) retires it. P4 does not matter for that database.
- The next Inbox change (TC-3998) is **one SQLite database per source** (Gmail, Telegram, Signal) instead of size-only rollover.

What P4 means:

1. **No dependency.** Inbox v2/v3 is designed to stay under the 64 MiB limit by rollover and per-source databases. It works on PostgreSQL master today and on store-master later without a change. Do **not** wait for P4.
2. **Per-source databases fit the cutover model well.** Cutover is per database; a small per-source database is the cheapest first cutover candidate (fast verify, fast hydrate). Many small databases cost more than one large one in *object count*: each continuously written database adds about 43k objects a month at a 60 s interval (contract D2); N sources = N times that. Retention (DECISION 4) must be set before many databases cut over, and the S3 boot scan that pages those objects is an existing risk (contract D2).
3. **Rollover remains the right mechanism.** Even in store-master, a single huge shard is slow to hydrate and is capped by disk and `max_database_bytes`. Per-source + rollover keeps each database small; P4 only removes the PG-specific failure (a write refused at 507), not the case for small shards.
4. **The Inbox access pattern is a good fit:** append-heavy, receive-only, one writer (the Inbox service). That matches the single-writer-per-database rule (section 7).
5. **Constraints that stay:** each ingest batch still has to fit the 2 MiB SQL request body (TC-1628 R2-S1); bodies above a threshold go to KV. P4 does not change that.
6. **Loss window:** if Inbox commits an external offset (for example a Telegram `getUpdates` offset) in the same database as the rows it covers, a lost window cannot be refetched [INFERENCE, not verified in the Inbox repo]. The loss-window copy (section 2) must be shown to Sam for this class before Inbox is cut over. Under ruling 2, owned spaces go first with plaintext store copies, so **Sam's mail will sit unencrypted in the object store**; Sam should see that sentence explicitly.

Recommendation: after P4 is built and soaked, cut Inbox's per-source databases over *last among the pilot*, behind Sam's own sign-off.

## 11. Observability and kill switches

- Metrics per database: mode, epoch, un-uploaded bytes, backlog age, last publish age, hydration duration/outcome, local disk reservation, cutover step reached.
- Alert: any store-master database with backlog age > 2 windows; any `owner_lost`; any cutover aborted.
- Kill switches (runtime-settable without a node restart where the existing settings mechanism allows it [to verify in P4.1]; otherwise a restart is the cost and the doc must say so): (a) stop *new* cutovers; (b) refuse writes to store-master databases with a 503 once un-uploaded age or bytes pass the bounds in section 5.4, and when the store is unreachable beyond a **stated deadline**; (c) force `copying_back` for one database.
- Loss detection: a local-seq vs store-frontier drill (the P2 restore check compares against frozen Postgres, which says nothing once Postgres is stale); metrics for `local_seq - frontier_seq` per database and for epoch mismatches.
- Logs carry no database names or content (TC-961 style), only ids/hashes and counts.
- Better Stack classification for the new mode events must ship **before** the first cutover (so they are not `unclassified` warnings): the TC-3973 lesson.

## 12. Slices (order and relative size; no schedule)

| Slice | Content | Size (relative) | Gate |
|---|---|---|---|
| P4.0 | This doc approved; decisions in section 13 | - | Sam |
| P4.1 | `sql_store_mode` table + state machine + refusal rules, no behaviour change (everything `pg_master`/`shadow`); property test over the transition table | S-M | Bobbie |
| P4.2a | **Local-file uploader source.** Today's uploader reads Postgres (`PgArtifactSource`), is woken only by a Postgres save, and `seq` is the Postgres revision. Store-master needs a source that reads the local checkpoint + WAL under the per-DB lock after COMMIT, wakes on local commits, and takes `seq` from the in-file counter (section 5.3). Redefines the manifest lineage anchor for store-master. SQLite auto-checkpoint can reset the WAL between publishes and lose the delta; either disable auto-checkpoint under store-master or snapshot instead. | L | Bobbie + Naomi |
| P4.2 | Local working file is never overwritten (section 5.2): no path deletes or overwrites it (`seed_cache`, idle exit, restart, respawn, reset-failure retire, `CommitFailed`, missing lineage, persist error), one test per path; outcome-unknown additions; in-file `seq` | M-L | Bobbie + Naomi |
| P4.2b | **Deploy and crash keep the working copy:** SQL datadir on a named volume in the production compose, plus a drain-and-publish step before container recreate (prod change; Naomi/Amos, normal GO). The drain is a courtesy, not the protection: a crash or OOM kill skips it, so the volume is what guarantees survival. **Exit proof, in two parts.** (1) A **local container-recreate drill** (Naomi 14:42Z), first with today's Postgres-master layout and then with the volume: write, recreate the container, read back every acknowledged write; this also proves the rehydrate path that section 14 says is unproven on prod by log. (2) A staging deploy drill: write, redeploy (and a kill -9 variant, and a CVM restart / OS-image upgrade variant), then read back every acknowledged write. Found by the read-only check in section 14. | S (compose) + M (drain step) | Naomi GO, Amos |
| P4.2c | **Freeze enforced in every artifact save** (section 6.1) and the version gate / DB-enforced check against old binaries; lease and epoch fence (section 7); purge, quota and revocation wiring (section 8b) | L | Bobbie + Naomi |
| P4.3 | Hydration from the store (snapshot + segments) for operator recovery and new nodes, hydration timeout/status, in-memory → file-backed migration + restore drill. **No eviction in v1** (section 5.2). | M-L | Bobbie |
| P4.4 | Fenced cutover job (section 6) + crash matrix tests + copy-back job + size gate + per-database growth guard | L | Bobbie + Naomi |
| P4.5 | Encryption of store objects (slice 2 / D1) | L | Sam (key custody) |
| P4.6 | Pilot: our own/owned spaces, one database at a time, then Inbox (section 10), then others | - | Sam per cohort |

P4.1-P4.3 can be built and merged with no database cut over (no user-visible change). **Nothing after P4.4 is enabled in production without Sam's explicit go for the named databases.** Sizes are relative only; Bobbie's read (section 15) made P4.2a and P4.2c necessary, so the work is larger than the first draft said.

## 13. Decisions (ruled by Naomi 2026-11-23 13:12Z; Sam answered 5, 6 and 8 on 2026-11-23 21:37Z)

| # | Decision | Ruling |
|---|---|---|
| 1 | Loss window | **60 s / 8 MiB, no wait-for-store** (the 10-19 decision stands). |
| 2 | Encryption | **Required before any non-owned cutover.** |
| 3 | Large databases | **(a): store-master databases are capped at the PG copy-back limit for the pilot.** Consequence: the pilot does not yet use P4's main benefit, writing databases above 64 MiB. That needs the later policy decision below. |
| 4 | Frozen PG artifact retention | **30 days** after cutover. Store history per tier stays with contract D2. |
| 5 | `owner_lost` | **Sam (21:37Z): approved.** A manual operator takeover of a database, **only after the dead node's lease has expired, and with the loss logged.** Automatic takeover waits for TC-1471. |
| 6 | Supported maximum size after the pilot | **Sam (21:37Z): approved the recommendation: a 64 MiB per-database pilot cap, which keeps the Postgres copy-back as the rollback.** A higher cap is a later decision from disk and hydration measurements (P4.3), not "unlimited"; lifting it needs a copy-back path: the opt-in PG parts store (section 8) with capacities set, or TC-3764. |
| 7 | Pilot order | **Owned spaces, then Inbox per-source, then opt-in users.** |
| 8 | Write-through instead of the 60 s window | **Sam (21:37Z): approved the recommendation: keep the asynchronous window, 60 s or 8 MiB ahead; no write-through** (it would reverse the 10-19 ruling). |

**End state Sam confirmed (21:37Z):** the object store is the master of the same KV; Postgres is not the master; the node's disk file is a working copy. The old Postgres copy stays for 30 days as the rollback (decision 4). **First step: a persistent volume for the node's SQL working copy (P4.2b); the staging proof is a separate production change with its own GO.** This confirmation is not a merge, deploy or migration GO; each slice below keeps its own gate.

## 14. What was unknown, and how each was resolved

Resolved by reading code and docs on main (cae89736); no production access.

- **Conditional PUT (D5):** the code does not assume it. A startup probe (contract 12.1) writes `sql/v1/_probe/v1` twice with `If-None-Match: *` and selects *conditional* mode (412 on the second write) or *check-then-create* mode (second success, or 501). Any other answer = the store does not start. The mode is logged. **P4 requirement added:** store-master must run in conditional mode, and a node in check-then-create mode must refuse to cut anything over (check-then-create can report `Created` twice for one key across processes; harmless while nothing deletes, not acceptable once the store is master and GC exists).
- **Per-database size settings (code):** `max_database_bytes` defaults to 0 (no cap); `max_artifact_write_bytes` and `max_artifact_read_bytes` default to 64 MiB (`sql/durability.rs:285`; `docs/sql-local-durability.md`). Production overrides are in the table below.
- **Parts / chunked saves:** exist and are **opt-in, off by default**: `chunked_artifacts = false`, with explicit `chunked_artifact_max_bytes` and `chunked_account_max_bytes` required (`docs/operations/chunked-sql-artifacts.md`). Each payload statement carries at most 1 MiB, hydration streams the parts, and a database in parts is not held to the 64 MiB read limit; the capacities bound its size. This is the realistic copy-back path for a store-master database above 64 MiB, and works only if that setting is on, with capacities, for the owner when copy-back runs.
- **DuckDB:** stays on Postgres artifacts; not covered (contract 1.5).

**Production readings (Amos, read-only, 13:33Z, live compose on the node CVM, image 183b1479):**

| Setting | Production value |
|---|---|
| `max_database_bytes` | **320 MiB** (compose env) |
| `max_artifact_write_bytes` | 64 MiB (code default) |
| `max_artifact_read_bytes` | **320 MiB** (compose env) |
| `chunked_artifacts` / `chunked_artifact_max_bytes` / `chunked_account_max_bytes` | false / 0 / 0 (code defaults): **the PG parts store is OFF in production** |
| `synchronous` | Full (default) |
| `min_free_bytes` | 1 GiB (compose env) |
| Block store | `TINYCLOUD_STORAGE_BLOCKS_TYPE=S3`; endpoint, bucket and region are encrypted env, so the vendor was not read. A custom endpoint is set, which suggests an S3-compatible provider rather than the AWS default [INFERENCE]. |
| Data disk | `dstack/data`, 18.9 GB, 352.6 MB used (2%) at boot 08:31Z; the current figure needs a shell and was not read. |
| `tinycloud::sql_store` log lines | 0 over 5 h (weak evidence: container logs are not public and Better Stack ships only errors and slow requests; the build gate is the real guarantee). |

Consequences recorded in this doc:

- **D6 is NOT met today (precondition 4).** The tinycloud container's only mounts are the dstack socket and the deletion-ledger volume; the datadir (`/data/sql`) is in the container's **writable layer**. The 1.26.22 deploy logged `Container dstack-tinycloud-1 Recreate → Recreated`, so **the local SQL cache does not survive a deploy** today. That is harmless while Postgres is master (it re-hydrates), but for a store-master database it would **destroy the working copy on every deploy and lose every write since the last publish**. So P4 needs the SQL datadir on a named volume (and a deploy procedure that drains and publishes before the container is recreated) before any cutover. Added as slice P4.2b below. Naomi/Amos to schedule the compose change; it is a prod change, gated by the normal GO.
- **Re-hydration after a recreate is unproven on prod by log.** The claim "nothing is lost on a deploy today" rests on code and docs: Postgres is the master (`docs/sql-local-durability.md`), a write is acknowledged only after its artifact save commits (`docs/sql-block-store-contract.md` section 2), and `seed_cache` rebuilds the cache from the Postgres artifact. It is not confirmed from production logs: Better Stack receives only `ingress_request`, `node_request` (errors/slow), `node_warning`, `logship_gate_summary_total` and `node_storage_headroom`, so the plain "Loaded database artifact" info line is never shipped (Amos, 14:42Z: 0 rows, uninformative), and reading the CVM's own container log is deliberately not done. The proof is the **local container-recreate drill** in slice P4.2b (write, recreate, read back every acknowledged write).
- **Pilot cap and the 320 MiB policy:** production allows databases up to 320 MiB to be read and held; the pilot's copy-back cap (13.3 a) is 64 MiB. Parts are off in production, so the copy-back path for a database above 64 MiB does not exist today.
- **Disk:** 18.9 GB total for everything on the node (blocks, caches, images share the ZFS dataset [INFERENCE]); the pilot's working copies must be budgeted against it, and `min_free_bytes` (1 GiB) already refuses writes below that.

Cannot be known before building:

- **Hydration time** for a 300 MiB database from the store: no store reader exists yet, so there is nothing to measure. **P4.3 exit criterion:** measured hydration time and memory at 64, 128 and 300 MiB on the production-like object store, before any hydration timeout or size policy (decision 6) is set.
- **Object count and S3 boot-scan paging** at many per-source databases: from the contract's estimate (about 43k objects per month per continuously written database), not measured. Retention must be set before many databases cut over.
## 15. Review history

- **Bobbie, 13:35Z (design read, code refs at cae89736): not ready for Sam as first drafted; 7 MUSTs, 5 SHOULDs, 3 NOTEs.** The first three MUSTs lose acknowledged writes in normal running (a worker rebuild overwriting the local working file from the frozen Postgres copy; no uploader once Postgres is frozen; a save acked between cutover steps 3 and 5). All folded in above: sections 5.2, 5.3, 6.1, 7, 8, 8b, 11, 12. Net effect: two slices were added (P4.2a local-file uploader, P4.2c freeze/lease/purge wiring), so the work is larger than the first draft said.
- **Bobbie, 14:06Z (section 14 read): card input, not a gate; adds to precondition 4 / P4.2b and replaces none of the 7 MUSTs.** Folded in: (1) the datadir must be on a persistent volume that survives deploys *and* crashes/OOM kills; a pre-stop drain alone does not count (precondition 4, P4.2b); (2) proof is a staging deploy drill: write, redeploy, read back every acknowledged write (P4.2b exit); (3) with prod `max_database_bytes` at 320 MiB the exposure to un-uploaded data is not "64 MiB", so the un-uploaded bytes and time-since-last-publish bounds in 5.4 apply to every store-master database regardless of its size.
- **Bobbie, 14:07Z (re-review, 313 lines): MUSTs 1-7 closed; one new MUST A, then OK to open the docs PR.** A (eviction vs the 5.2 fence) is fixed: **no eviction in v1**, so a missing local file always means loss or damage and is never auto-hydrated; any later eviction is allowed only when Clean and recorded as "evicted at seq S" on the mode row (5.2, section 9, P4.3). SHOULDs folded in: CommitFailed closes and reopens before `quick_check` (5.2); `SqlSizes` seeds from the local file or `frontier_bytes` (8b); the WAL auto-checkpoint caveat (P4.2a); the CVM restart / OS-image-upgrade drill variant (P4.2b); worst case is the bound plus one write's WAL (5.4). Notes fixed: preconditions 1-8, flip at step 5, reads come from the local worker, `key.rs` is object-key scoping.
- **Not yet verified by a second reader:** the Inbox facts in section 10 (Bobbie checked the 287 MiB size only; the shard names, #59/#60 and the 12:50Z ruling come from the TC-1628 ticket text), and the parameter values proposed in 5.4 and 7 (2 windows, 10 s renew / 30 s lease), which are starting points to be set from measurement.
- **Open mechanics flagged for the slice that owns them:** in-file `seq` storage (reserved table vs alternatives), runtime-settable kill switches, the PostgreSQL trigger for the frozen artifact, and the lineage-anchor redefinition (5.3).

Details: TC-1491
