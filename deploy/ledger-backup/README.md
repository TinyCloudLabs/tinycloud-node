# Deletion-ledger backup (TC-887)

The production node (`docker-compose.dstack-postgres.yaml`, Postgres + S3)
keeps one thing that exists only on the CVM's disk: the named-keys deletion
ledger, `/var/lib/tinycloud/ledger/deletions.jsonl` on the `deletion-ledger`
volume. Phala keeps no copy of CVM disks. Everything else the node writes
locally is a cache (SQL files rehydrated from `database_artifact`), temporary
(upload staging), per process (`runtime/control.*`) or re-issuable (TLS
certificates).

## Why the ledger matters

Every delete under `apps/` is appended to the ledger before the database
commit (`docs/encryption-named-keys.md`, "Deletion ledger"). After a database
restore, `tinycloud node deletion-ledger replay` (also run at every node start)
sets each key it lists back to `deleted` with no seed. Losing the ledger alone
changes nothing visible: the node starts a new, empty one. But if the database
is later restored from a backup taken before some deletes, those rows carry
the sealed seeds again, the deleted keys can be derived again, and data that
was crypto-shredded can be decrypted. The ledger is the only record that
cancels that.

## What the sidecar does

`ledger-backup` (`Dockerfile`, `ledger-backup.sh`) runs next to the node:

- mounts `deletion-ledger` **read-only**, as the node's uid 1000, with a
  read-only root filesystem, no capabilities and a 32 MiB tmpfs `/tmp`. The
  plaintext copy exists only in that tmpfs and is deleted after encryption;
- takes no lock (the node holds `deletions.jsonl.lock` while it runs). It
  copies the file's current length, keeps whole lines only, waits 5 s and
  accepts the copy only if the live file still starts with exactly those
  bytes; otherwise it copies again (an append whose write or fsync fails is
  cut back by the node);
- encrypts with `age -r <NODE_BACKUP_AGE_RECIPIENT>` (an `age1…` public
  recipient; it refuses to start with an `AGE-SECRET-KEY-…`) and PUTs
  `ledger/deletions-<UTC timestamp>.jsonl.age` to the R2 bucket
  `tinycloud-node-backups` with `If-None-Match: *` (never overwrites). The R2
  credentials reach curl on stdin, never in argv;
- checks every 300 s and uploads when the content changed, and at least once
  every 24 h even if it did not, so a stopped sidecar shows as a gap in the
  bucket. A failed attempt logs `backup: FAILED` and retries after 60 s.

Every backup is the whole ledger (it is append-only), so the newest object is
enough for a restore. The objects are small; no lifecycle rule is needed. If
one is added, it must never delete the newest objects.

Sealed env (one card): `NODE_BACKUP_R2_ENDPOINT`, `NODE_BACKUP_R2_ACCESS_KEY_ID`,
`NODE_BACKUP_R2_SECRET_ACCESS_KEY`, `NODE_BACKUP_AGE_RECIPIENT`, delivered by
`docker.yml` from the `production` secrets `PROD_TINYCLOUD_NODE_BACKUP_*`
(`docs/releasing.md`, "Deletion-ledger backup sidecar").

## What is in a backup

One JSON line per delete operation and per outcome, exactly the node's format:
`{"op","networkId","keys":[{"keyPath","keyVersion"}],"deletedAt"}`,
`{"committed": op}` and `{"aborted": op}`. `op` is the CID of the owner's
signed delete credential; `networkId` names the owner's DID; key paths name
app ids and key names. No key material, seeds or user data. It is still user
metadata, hence the encryption.

## Restore drill

Run by an operator, never on the CVM (it needs the identity):

```sh
umask 077
export TMPDIR="$(mktemp -d -p /var/tmp)"          # private scratch area
export AGE_IDENTITY_FILE=/path/to/node-ledger-backup.agekey
export NODE_BACKUP_R2_ENDPOINT=... NODE_BACKUP_R2_BUCKET=tinycloud-node-backups
export NODE_BACKUP_R2_ACCESS_KEY_ID=... NODE_BACKUP_R2_SECRET_ACCESS_KEY=...   # a read key
sh deploy/ledger-backup/ledger-restore-drill.sh            # newest object
sh deploy/ledger-backup/ledger-restore-drill.sh --expect known.jsonl
```

It decrypts into a fresh scratch directory, checks that every line is a whole
record of exactly the node's schema, prints the line count, the record counts
(intents, committed, aborted, still open) and the last entry, optionally
compares with a known sample (`--expect` byte for byte, `--expect-prefix`),
and removes the scratch directory (`RESTORE_KEEP=1` keeps it and prints its
path). Needs `age`, `jq` and curl 8 or newer.

To put a restored ledger back on a node: stop the node, place the file at
`deletion_ledger_path` (uid 1000, mode 0600), and start the node; it replays
the ledger before serving. After a database restore, run
`tinycloud node deletion-ledger replay` before the node starts.

## Key custody

- The CVM holds only the public recipient (sealed `NODE_BACKUP_AGE_RECIPIENT`).
  `docker.yml` and the sidecar both refuse an identity in that place.
- The identity (`AGE-SECRET-KEY-1…`) is generated off the CVM by its holder,
  with `age-keygen -o node-ledger-backup.agekey` on a trusted machine, and is
  never sealed, committed, pasted into CI or sent through chat.
- The holder, where the identity is stored, and its escrow copy (a second
  person or place, so one loss does not end recovery) are approved by security
  review (Naomi) and recorded on TC-887 before the first deploy. The recipient
  sealed on the CVM must be the one derived from that identity
  (`age-keygen -y node-ledger-backup.agekey`).
- If every copy of the identity is lost, every backup made with it is
  unreadable. Generate a new identity, reseal the recipient and redeploy: the
  next backup is complete again, because each backup is the whole ledger.
- The R2 key sealed on the CVM is scoped to the `tinycloud-node-backups` bucket
  only; a leaked key exposes ciphertext only. R2 object tokens that can write
  can also delete, so a bucket lock rule on `ledger/` (retention in days) is
  what stops a compromised CVM from deleting earlier backups.

## CI

`.github/workflows/ledger-backup.yml`: `scripts` runs `ledger-backup.test.mjs`
(an S3 stub; misconfiguration, failed uploads, a torn final line, an append cut
back during the copy, appends during the copy, the loop's change/unchanged
schedule, the drill's schema checks). `image` builds the sidecar and, for
same-repository runs, publishes `ghcr.io/tinycloudlabs/tinycloud-node-ledger-backup:<revision>`
labelled with the sha256 of its sources. `pinned` requires the compose's
pinned digest to carry this revision's sources and runs `ci-e2e.sh` with it:
MinIO for R2, the compose service's flags, a fresh volume first mounted by the
sidecar, a refused private key, no write to the container filesystem, backups
while a writer appends, and the restore drill.
