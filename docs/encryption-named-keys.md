# Named encryption keys

Named keys are served only while `[global.encryption_network] named_keys_v1` is
on (default off). With it off the key routes are not mounted and key resources
are refused.

A key is named by `urn:tinycloud:encryption:<owner>:<network>/<path>`. A prefix
grant is the same URN with one trailing `/`.

## Key paths

A path is 1 to 8 segments of `[a-z0-9][a-z0-9._-]{0,63}` joined by `/`, at most
255 bytes.

The first segment `apps` is reserved. A path whose first segment is exactly
`apps` must be `apps/<app id>/<name>[/<more>]` for a key (at least three
segments) and `apps/<app id>/[<more>/]` for a prefix (at least two segments
before the trailing `/`). `apps`, `apps/<app id>` and the prefix `apps/` are
refused in delegations and invocations. `appsx/...` and `apps.x/...` are
ordinary paths. An app id matches `^[a-z0-9][a-z0-9._-]{0,63}$` as a whole
string; it is validated, never changed.

## Key kinds

The kind follows from the path.

| Path | Kind | Secret |
| --- | --- | --- |
| first segment `apps` | `deletable` | HKDF-SHA256(ikm = HKDF-Extract(salt = seed, ikm = network secret), salt = `tinycloud.encryption.named-key/v1`, info = `seeded\n` + key URN) |
| any other | `deterministic` | HKDF-SHA256(ikm = network secret, salt = `tinycloud.encryption.named-key/v1`, info = `deterministic\n` + key URN) |

The seed of a deletable key is 32 bytes from the operating system's random
source, made at `key.create`, sealed with the same column key as the network
secret and stored in `encryption_network_key.sealed_seed`. A seed is opened only
with the strict unseal. A deletable row that is not `deleted` and has no
seed, and a row whose kind the path does not imply, is a corrupt row (500).

## Create

`POST /encryption/networks/<network>/keys` with `{ "keyPath": "...", "deletable": bool }`.
`deletable` must equal the kind the path implies (`true` under `apps/`, `false`
elsewhere), otherwise 400 `key_path_invalid`. Unknown fields are refused with
400. Per network at most 1000 key rows, and per `apps/<app id>/` prefix at most
100, count towards `key_limit_exceeded`; `deleted` rows count until they are
reused.

- A new path creates the row (`keyVersion` 1, state `active`).
- An existing `active` deterministic key answers with its descriptor.
- Any other existing row answers `key_exists` (409). A `blocked` row is not
  changed.
- A `deleted` deletable row is reused: new seed, state `active`, `keyVersion` + 1.
- A `deleted` deterministic row answers `key_deleted` (403).

## State guards

Create, block and unblock run under the network row lock. Block and unblock
write only while the stored state is `active` or `blocked`; on a `deleted` row
they answer 403 `key_deleted` and change nothing.

## Public key GET

`GET /encryption/networks/<network>/keys/<path>` without `Authorization`:

- Under `apps/` every path answers 404 `key_not_found`, with the same body and
  headers whether the key exists, is blocked or deleted, is missing, or
  belongs to another owner or network.
- Elsewhere it answers the derived public key for every valid path on an active
  network.

The authenticated GET (a `key-describe/v1` invocation) returns the full
descriptor, including `kind` (`deterministic` or `deletable`) and `state`
(`active`, `blocked` or `deleted`).

## Decrypt

`POST /invoke` with `decrypt` on the exact key. For a deletable key the
request's `keyVersion` must equal the row's version, otherwise 403
`key_deleted`; a `deleted` row answers 403 `key_deleted`.

## SIWE roots under `apps/<app id>`

A SIWE (CACAO) delegation issued by the key owner that carries any ability
other than `key.block` on a key or prefix under `apps/<app id>` requires the
app id to be bound to the SIWE `domain`. The SIWE `scheme` is absent or
`https`. The domain has no port (and no empty port or user info), is a DNS name
of at least two labels (no IP literal, no `localhost`, no trailing dot), and the
app id equals its labels reversed and joined with `.`, or starts with that and
`.` (the domain is compared in its lowercase ASCII form). UCAN delegations are
not checked. A refusal answers `app_id_not_bound`.

## Delete

`POST /encryption/networks/<network>/key-actions/delete` with body
`{ "keyPath": "<path>" }`. The network owner signs the request; it is never a
delegation and `key.delete` is refused in every delegation.

- `keyPath` without a trailing `/` deletes one key. A deterministic key (a path
  outside `apps/`) answers 409 `key_not_deletable`; a missing key answers 404
  `key_not_found`.
- `keyPath` `apps/<app id>/` (exactly two segments and one trailing `/`) deletes
  every key under it. Any other path ending in `/` answers 400
  `key_path_invalid`. Keys are selected by an exact byte comparison of the
  prefix, so `apps/foo_bar/` never selects `apps/foo.bar/…`. If a selected row
  is not a deletable key, nothing changes and the answer is 409
  `key_not_deletable`.
- A deleted key keeps its row with state `deleted` and no seed. `keyVersion` is
  unchanged until the path is created again.
- The response is `{ keyPath, state: "deleted", deleted, alreadyDeleted,
  count }`; `deleted` lists the keys this call deleted (in path order),
  `alreadyDeleted` those that already were, and `count` is the length of
  `deleted`. Repeating a delete changes nothing.
- Each deleted key adds one `encryption_audit` row (outcome `deleted`, request
  hash `sha256(credential CID || 0x00 || key path)`) and one line in the
  deletion ledger.

Credential for a `did:key` owner: a UCAN invocation by the owner, no proofs,
one capability `tinycloud.encryption/key.delete` on the exact key or prefix URN
(a prefix keeps its trailing `/`), `key-admin/v1` facts naming this node, the
network, the body `keyPath`, the action and the body hash, and a nonce.

Credential for a `did:pkh:eip155` owner: a SIWE CACAO signed by the owner whose
ReCap is exactly `{ <key or prefix URN>: ["tinycloud.encryption/key.delete"] }`,
whose only resource is that ReCap, whose `uri` is
`urn:tinycloud:encryption:key-delete:<node DID>`, and whose statement is
`Delete all TinyCloud keys under <prefix URN>.` (a prefix) or
`Delete the TinyCloud key <key URN>.` (one key), then a space and the ReCap
text. The URL network and the body `keyPath` must name the ReCap URN.

Both credentials last at most 300 seconds. A SIWE credential measures
`exp - iat`, with `iat` and `nbf` at most 30 seconds ahead. A UCAN has no `iat`,
so it must carry `nbf` (the time it was signed): `nbf` at most 30 seconds
ahead, `now < exp` and `exp - nbf` at most 300 seconds. The `(owner, nonce)`
pair is consumed before the keys are touched, so a delete that fails after
verification still uses up the signature; it is kept until 30 seconds after
`exp`, and pairs past that are removed. Credential refusals answer 403
`owner_only`.

### Deletion ledger

`[global.encryption_network] deletion_ledger_path` names an append-only file
outside the database; it is required while `named_keys_v1` is on. The file is
created with mode 0600 and is never rotated. One JSON line per delete
operation: `{ "op", "networkId", "keys": [{ "keyPath", "keyVersion" }],
"deletedAt" }`, where `op` is the CID of the owner's credential. The line is
written and fsynced after the delete's database changes and before the
transaction commits. After the commit the node appends `{"committed": <op>}`.
If the commit fails, the node reads the rows again and appends `committed`
when every key is `deleted` at that version and `aborted` only when the commit
did not happen; when the rows cannot be read the operation stays open. If the
ledger cannot be written, or the file was renamed or removed, the delete is
rolled back and answers 500 `deletion_ledger_unavailable`. An append whose write
or fsync fails is cut back to the file's length before it, so the file never
holds a partial line before a later one.

The node image contains the directory `/var/lib/tinycloud/ledger`, owned by
uid 1000 (the node's user) with mode 0700; a volume mounted there is writable
by the node.

At every start, before any route is served, the node replays the ledger onto
the database (as `tinycloud node deletion-ledger replay` does) and closes each
operation that was still open with a `committed` line. If the ledger cannot be
opened or replayed, the named-key routes stay off, as with `named_keys_v1` off,
the node logs the event `deletion_ledger_open_failed` or
`deletion_ledger_replay_failed` with an `error_kind`, and the rest of the node
serves.

Before restoring a database, stop the node and disable its automatic restart.
After the restore, before the node starts, run
`tinycloud node deletion-ledger replay [--config <file>] [--ledger <file>]`. It
sets every key of every committed or still-open operation to `deleted` with no
seed. It skips aborted operations, rows that are not deletable keys, rows with
a newer `keyVersion`, and entries whose network or key path is not valid
(reported as `refused`; the command then exits non-zero after applying the rest).
A final line that is not a whole record is reported as `tornTail`; a malformed
line anywhere else stops the replay. Replay is idempotent.

## Startup check

The node does not start while a row in `encryption_network_key` under `apps/`
(or at the path `apps`) has a kind other than `deletable`. List such rows with:

```sql
SELECT network_id, key_path, kind FROM encryption_network_key
WHERE (key_path = 'apps' OR substr(key_path, 1, 5) = 'apps/') AND kind <> 'deletable';
```

The node deletes no data; remove or move the rows, then start the node.
