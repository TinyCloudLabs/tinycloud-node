# `tinycloud.kv/sync` wire contract

`tinycloud.kv/sync` (TC-732) is an ordered, resumable, delete-aware feed of
the latest state of every key under one KV prefix. A device uses it to keep a
local read replica: the feed says which keys changed and what they now hold
(ETag, metadata, or deleted); content is still read with `tinycloud.kv/get`
and checked against the ETag. Nodes that serve it advertise the `kv-sync-v1`
feature in `/info`.

## Authorization

- The invocation goes to `POST /invoke` like any KV read, and must carry
  **exactly one** capability: `tinycloud.kv/sync` on
  `{space}/kv/{prefix}`, with a non-empty prefix. Anything else is a 400,
  checked before any other capability is dispatched.
- `tinycloud.kv/sync` is never implied: no other action, `*`, or
  `tinycloud.kv/*` grants it, and default session builders do not include it.
  A device bundle that syncs is typically `get,list,metadata,sync` on the
  prefix.
- Prefixes match by whole path segments and byte-exactly: a grant on `notes`
  covers `notes` and `notes/a`, not `notes-secret/x` or `NOTES/x`; a grant on
  `notes/` covers everything under `notes/` but not `notes` itself.

## Request headers

| Header | Meaning |
|---|---|
| `x-tinycloud-limit` | Page size, 1–1000. Default 500. |
| `x-tinycloud-cursor` | The `cursor` from the previous response. Omit it to bootstrap. |
| `x-tinycloud-retention-grant` | Optional CID of a delegation carrying `tinycloud.kv/retain` on the prefix (see `authority.retainUntil`). |

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

- `changes` holds each changed key's **latest** state, in the order the
  changes committed. A key appears again only if it changes again. `etag` is
  the same strong ETag `kv/get` returns.
- `more: true` means more changes are available now; ask again with the new
  cursor. `more: false` means the replica is caught up.
- `cursor` is opaque, sealed by the node, and bound to the space and prefix.
  It is not bound to the caller; authorization is checked on every request.
- An empty poll (`changes: []`) returns the request's cursor **byte for
  byte**. Writes outside the prefix never change it.

### Pages and `limit`

All keys written or deleted by one invocation (for example a batch put) share
one position, and a page never splits them: a page holds at least `limit`
changes when more are available, and at most `limit - 1` plus all the changes
of its last invocation. One invocation carries at most 1000 KV mutations
(larger ones are refused with 400), so a page holds at most `limit + 999`
changes. Within one invocation, changes are ordered by key bytes.

### Bootstrap

The first request (no cursor) starts from the beginning of the prefix. Keys
deleted before that first request are not reported; deletions after it are.

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
on a resource the sync prefix extends. `tinycloud.kv/retain` is never invoked
and never implied.

## Errors

| Status | Body | When |
|---|---|---|
| 400 | text | More than one capability; an empty prefix; `x-tinycloud-limit` outside 1–1000; a cursor that is not a cursor (empty, longer than 4096 characters, or not base64url); a retention header that is not a CID. |
| 401 | text, e.g. `delegation-revoked: ...` | The caller is not authorized, including a revoked or expired grant. Checked before the cursor is opened, so an unauthorized caller never sees 410. |
| 403 | `{"error":{"code":"RETENTION_GRANT_REFUSED","reason":"<reason>"}}` | The retention grant is refused. Reasons: `retention-grant-not-found`, `retention-grant-holder-mismatch`, `retention-grant-revoked`, `retention-grant-ancestor-revoked`, `retention-grant-not-yet-valid`, `retention-grant-expired`, `retention-grant-not-covering`. The sync is not served without retention. |
| 410 | `{"error":{"code":"RESET_REQUIRED","reason":"cursor-invalid"}}` | The cursor was not minted by this node for this space and prefix, or is from an older cursor version. |
| 410 | `{"error":{"code":"RESET_REQUIRED","reason":"position-unknown"}}` | The cursor names a position this space does not have, for example after the node was restored from a backup. |

On 410 the replica must discard its sync state and bootstrap again without a
cursor.

## Polling

Read audit records every poll. Poll on demand, or no more often than every
60 seconds.
