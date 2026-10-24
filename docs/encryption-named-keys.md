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

## Startup check

The node does not start while a row in `encryption_network_key` under `apps/`
(or at the path `apps`) has a kind other than `deletable`. List such rows with:

```sql
SELECT network_id, key_path, kind FROM encryption_network_key
WHERE (key_path = 'apps' OR substr(key_path, 1, 5) = 'apps/') AND kind <> 'deletable';
```

The node deletes no data; remove or move the rows, then start the node.
