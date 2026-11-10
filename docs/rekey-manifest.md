# TC-2713 snapshot identity manifest

One manifest covers network and named-key public identities. Its authority is
the separately pinned SHA-256 in the rotation owner's authenticated custody
record, not a hash generated from the target database during migration.

## Source and custody

The source is a dated, trusted PlanetScale backup snapshot of
`tinycloud-node-production-usw`. The custodian records the backup ID, RFC3339
snapshot timestamp, archive SHA-256, exporter identity, storage location and
custody record reference. Restore the checked archive into an isolated local
database with no other writers. For PostgreSQL, use a different local database
name; the exporter refuses the live database name and non-loopback endpoints.
No production endpoint is queried by the exporter.

The custodian must verify that the restored source corresponds to the recorded
archive, authenticate the export, and record the manifest SHA-256 in the separate
access-controlled custody record before the offline window. A checksum supplied
beside an untrusted file without that custody process is not an authenticated pin.
The runner takes the file and the independently obtained pin; it never chooses
the pin by hashing whichever file it receives.

Networks or seeds created after the snapshot are not covered. Take a fresh
trusted snapshot immediately before the migration window. Missing identities
are blocking categories, never exemptions. Client-held authenticated key pins
are a possible later second source, not an implemented fallback.

## Canonical version 1 encoding

The file is compact UTF-8 JSON without a BOM, spaces between tokens or trailing
newline. Strings use normal JSON escaping with non-ASCII characters encoded as
UTF-8. Field order is fixed:

- Top level: `version`, `provenance`, `rows`.
- Provenance: `source_database`, `backup_id`, `snapshot_timestamp`,
  `snapshot_sha256`, `exported_by`, `storage_location`, `custody_record`.
- Each row: `kind`, `network_id`, `key_path`, `key_version`, `public_key`.

`version` is the integer 1. `source_database` is exactly
`tinycloud-node-production-usw`. Custody fields must be nonempty. The snapshot
timestamp must be valid RFC3339 and cannot be in the future. `snapshot_sha256`
is the lowercase 64-character SHA-256 hex digest of the archive bytes.

Rows use `kind` equal to `network` or `seed`. A network row has `key_path: null`;
a seed row has its canonical key path. Network IDs are canonical TinyCloud
encryption-network URNs. Key versions are positive signed 64-bit integers.
Public keys are 32-byte X25519 public keys encoded as 64 lowercase hex characters.
No private keys, sealed values or plaintext secrets belong in this file.

Sort rows by kind (`network` before `seed`), network ID in UTF-8 byte order,
key path (`null` before text, then UTF-8 byte order), then numeric key version.
Duplicate identities are rejected even if their public keys agree. Unknown or
duplicate JSON fields, malformed values and noncanonical serialization are
rejected. SHA-256 covers every byte of the final canonical file.

## Read-only exporter

Run `python3 tools/export-rekey-manifest.py` in the checkout. It requires Python 3
and, for a restored PostgreSQL snapshot, `psql`. Supply these explicit arguments:

| Argument | Meaning |
| --- | --- |
| `--restored-postgres-url` | Loopback-only restored PostgreSQL database; URL query options are refused. |
| `--schema` | Restored schema, default `public`. |
| `--sqlite-snapshot` | Alternative read-only SQLite image; must also be `--snapshot-file`. |
| `--snapshot-file` | Actual checked backup archive whose bytes the exporter hashes. |
| `--backup-id` | PlanetScale backup identifier from the custody record. |
| `--snapshot-timestamp` | Snapshot's RFC3339 timestamp. |
| `--exported-by` | Authenticated custodian/exporter identity. |
| `--storage-location` | Snapshot archive's recorded storage location. |
| `--custody-record` | Reference to the separate authenticated custody record. |
| `--output` | New manifest file; existing files are never overwritten. |

The exporter selects only public-key metadata in a read-only snapshot
transaction. It does not select sealed private keys or seeds. Its terminal output
contains only the manifest hash and network/seed counts; failures are generic.
No key values, row identifiers, connection strings or custody metadata are logged.

## Runner contract

The rotation integration calls `reencrypt::manifest::run_offline` with the
manifest file, its separately pinned digest, injected overlap rings and batch
size. It verifies the file before any database call or fence activation. A valid
file is converted into private network/seed maps inside `VerifiedManifest`; there
is no raw-map conversion into that type. Coverage runs in bounded pages and
reports only missing/mismatched network and seed counts. Any nonzero category
blocks activation. Per-row migration checks remain mandatory after coverage.

This entry point does not provide a production root source or stop serving.
Do not deploy #541 standalone on nodes with v1 rows. It ships only within the
TC-2713 rotation event once the production-integrated runner, verified manifest
and offline migration window exist; serving resumes only after migration and
authenticated final verification complete.
