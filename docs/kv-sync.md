# `tinycloud.kv/sync` wire contract

`tinycloud.kv/sync` (TC-732) is an ordered, resumable, delete-aware feed of
the latest state of every key under one KV prefix. The KV root resource,
`{space}/kv` (also accepted as `{space}/kv/`), selects every key in the space.
A device uses it to keep a local read replica: the feed says which keys
changed and what they now hold (ETag, metadata, or deleted); content is still
read with `tinycloud.kv/get` and checked against the ETag. Nodes that serve
root feeds advertise `kv-sync-root` alongside `kv-sync-v1` in `/info`.

## Authorization

- The invocation goes to `POST /invoke` like any KV read, and must carry
  **exactly one** capability: `tinycloud.kv/sync` on
  `{space}/kv/{prefix}` or the root resource `{space}/kv`. The root resource
  reads the whole space; a prefix-scoped grant does not authorize that feed.
  Anything else is a 400, checked before any other capability is dispatched.
- Pathless `{space}/kv` and empty-path `{space}/kv/` are equivalent for sync
  authorization, attenuation, and retention containment. This root equivalence
  does not widen non-empty prefix boundaries or affect other services.
- `tinycloud.kv/sync` is never implied: no other action, `*`, or
  `tinycloud.kv/*` grants it, and default session builders do not include it.
  A device bundle that syncs is typically `get,list,metadata,sync` on the
  prefix.
- Prefixes match by whole path segments and byte-exactly: a grant on `notes`
  covers `notes` and `notes/a`, not `notes-secret/x` or `NOTES/x`; a grant on
  `notes/` covers everything under `notes/` but not `notes` itself. Neither
  scoped grant covers the root feed.

## Request headers

| Header | Meaning |
|---|---|
| `x-tinycloud-limit` | Page size, 1–1000. Default 500. |
| `x-tinycloud-cursor` | The `cursor` from the previous response. Omit it to bootstrap. |
| `x-tinycloud-retention-grant` | Optional CID of a delegation carrying `tinycloud.kv/retain` on the prefix or the whole-space root (see `authority.retainUntil`). |

## Response (200)

```json
{
  "changes": [
    {"key": "notes/a", "deleted": false, "etag": "\"blake3-<hex>\"", "metadata": {"content-type": "text/plain"}},
    {"key": "notes/b", "deleted": true}
  ],
  "more": false,
  "cursor": "<opaque>",
  "source": {"nodeDid": "<the /info nodeId>", "space": "<space id>", "prefix": "notes/"},
  "authority": {"notBefore": null, "expiresAt": "2026-10-05T11:12:08Z", "retainUntil": null}
}
```

- For a whole-space feed, `source.prefix` is the empty string.

- `changes` holds each changed key's **latest** state, in the order the
  changes committed. A key appears again only if it changes again. `etag` is
  the same strong ETag `kv/get` returns.
- `more: true` means more changes are available now; ask again with the new
  cursor. `more: false` means the replica is caught up.
- `cursor` is opaque, sealed by the node, and bound to the space and prefix.
  It is not bound to the caller; authorization is checked on every request.
  Its length does not depend on any key or on how much the space has
  changed.
- An empty poll (`changes: []`) returns the request's cursor **byte for
  byte**. Writes outside the selected prefix never change it; for the root
  feed, all writes in the selected space are in scope.
- A page can transiently come back with `changes: []` **and** `more: true`:
  the event that would have ended the page was overwritten or deleted between
  the node's reads. It is not an error. Keep paging with the returned cursor;
  the next request makes progress.

### Pages and `limit`

All keys written or deleted by one invocation (for example a batch put) share
one position, and a page never splits them: a page holds at most
`limit - 1` changes plus all the changes of its last invocation, and usually
at least `limit` when more are available (see the transient empty page
above). Within one invocation, changes are ordered by key bytes.

Since this release, one invocation carries at most 4096 KV mutations (larger
ones are refused with 400 `{"error":{"code":"TOO_MANY_MUTATIONS","max":4096}}`),
so a page of invocations written by this node version holds at most
`limit + 4095` changes. Invocations written by earlier node versions were
bounded only by transport limits (HTTP/1 request headers of about 400 KB;
HTTP/2 over TLS allows header lists of up to 16 MiB), so a page ending on one
of them can be larger. Clients must accept pages larger than `limit`.

### Bootstrap

The first request (no cursor) starts from the beginning of the selected prefix;
for a root feed, that is the beginning of the space. Keys deleted before that
first request are not reported; deletions after it are.

## `authority`

The node attests the window in which the caller's authority holds:

- `notBefore` / `expiresAt`: the latest `nbf` and the earliest `exp` across
  the invocation's proof and **every** delegation it rests on. `null` when
  nothing in that chain sets one (for example, the space owner invoking
  directly). A replica should stop serving local reads outside this window
  unless it holds a retention attestation.
- `retainUntil`: present only with a valid `x-tinycloud-retention-grant`. It
  is the earliest `exp` across the retention grant's own proof chain, so it is
  not capped by the sync grant. `null` means **no retention**: either no
  retention grant was presented, or the grant's chain sets no `exp` at all,
  which is treated as granting none rather than unlimited retention.

A retention grant must be held by the invoker, be unrevoked along its whole
chain, be inside its chain's validity window, and carry `tinycloud.kv/retain`
on a resource the sync prefix extends. For a root feed, only a root-scoped
retention grant covers the feed. `tinycloud.kv/retain` is never invoked and
never implied.

## Errors

| Status | Body | When |
|---|---|---|
| 400 | text | More than one capability; a sync resource that is not a KV resource or has a query/fragment; `x-tinycloud-limit` outside 1–1000; a cursor that is not a cursor (empty, longer than 4096 characters, or not base64url); a retention header that is not a CID. |
| 401 | text, e.g. `delegation-revoked: ...` | The caller is not authorized, including a revoked or expired grant. Checked before the cursor is opened, so an unauthorized caller never sees 410. |
| 403 | `{"error":{"code":"RETENTION_GRANT_REFUSED","reason":"<reason>"}}` | The retention grant is refused. Reasons: `retention-grant-not-found`, `retention-grant-holder-mismatch`, `retention-grant-revoked`, `retention-grant-ancestor-revoked`, `retention-grant-not-yet-valid`, `retention-grant-expired`, `retention-grant-not-covering`. The sync is not served without retention. |
| 410 | `{"error":{"code":"RESET_REQUIRED","reason":"cursor-invalid"}}` | The cursor was not minted by this node for this space and prefix, or is from an older cursor version. |
| 410 | `{"error":{"code":"RESET_REQUIRED","reason":"position-unknown"}}` | The cursor names a position this space does not have, for example after the node was restored from a backup. |

On 410 the replica must discard its sync state and bootstrap again without a
cursor.

## Polling

Read audit records every poll. Poll on demand, or no more often than every
60 seconds.

## Write ordering and blob recovery

KV puts stage and authorize content before upload. A short preparatory
transaction checks authorization and hosting, then commits an active
`(space, content hash, generation)` fence and a separate claim for each
writer. The first generation is zero and retains the original bare-hash
storage key; a generation above zero is allocated only after a prior
generation's physical deletion is confirmed. Ordinary writes release every
pooled connection and database lock before S3 or filesystem I/O. A
four-minute upload deadline stays below the five-minute DB-clock GC grace.
After upload, an ordinary writer takes the per-space sequence guard, starts
a fresh commit transaction and takes
the DB sequence lock; it verifies its own active claim, then rechecks
authorization and conditional-write preconditions. The guards stay through
commit, so `seq` and sync cursors remain commit-ordered even when same-space
uploads finish out of order. An unauthorized write uploads nothing.

For a single node process, each `(space, hash, generation)` serializes its
physical existence check, upload or deletion, and quota settlement without
holding a database connection. Filesystem memory staging writes into a
same-directory temporary file and atomically renames only complete bytes to
the hash key. A process crash can leave an incomplete stage; startup counts
its physical bytes, and the hash candidate's GC pass removes and refunds it.
SQLite preparatory writes reserve the database writer before authorization
reads, so a separate collector connection cannot invalidate the read snapshot.

Protected legacy meeting paths are the TC-1260 exception: the durable freeze
row and its pooled transaction remain locked across upload until commit or
abort. A freeze acknowledgement drains earlier uploads; a later protected
write is refused before upload. A stalled writer causes the freeze attempt
to fail after 30 seconds rather than acknowledge an incomplete drain.

Before upload, a lost pooled connection retries the preparatory transaction
with the same attempt ID. The registration is idempotent; neither an upload
nor a committed write is replayed on an uncertain outcome. A missing claim
or a fence already deleting returns a retryable error, never a reference to
a potentially removed object.

A failed upload, precondition or database write removes only its own claim.
If another claim or a current or historical KV reference exists, it leaves
the shared generation's blob alone. Otherwise it commits a `deleting` fence
and byte entitlement, releases the DB connection, then deletes that
generation's object. A writer seeing `deleting` cannot deduplicate or
upload over it. Only confirmed physical absence refunds the per-process
quota exactly once; only then is the fence retired and the next generation
made available. Each delete targets its original generation's storage key,
so even a delayed second delete cannot remove a later committed generation.
A lost DELETE response or a crash mid-delete leaves the fence for
idempotent GC retry. Reads get the generation from their existing KV lookup,
without another database query; generation zero reads the bare key. A
rolled-back binary cannot read records with generation above zero, which
can occur after a failed upload is collected and its content is saved again.

The collector runs every 60 seconds, aging attempts after five minutes by
DB time and draining eligible work in batches of 256. On S3 startup the
same object-listing snapshot reconstructs both `SpaceSizes` and which
`deleting` fences counted physical bytes; a deletion before the listing
needs no refund, while a deletion afterward refunds once. Orphans present
at restart count until GC. Quota is conservative physical accounting,
**not commit-only accounting**: pending uploads and crash leftovers can
temporarily over-count. `SpaceSizes` remains in-memory and per process; other
nodes' writes and deletes do not synchronize it. Globally exact multi-node
accounting requires a separate shared byte ledger (TC-1162).
