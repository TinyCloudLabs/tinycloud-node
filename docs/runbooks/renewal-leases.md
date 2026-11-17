# Renewal lease operations

This runtime slice supports owner-signed lease registration, node-internal scheduled renewal, the existing revocation flow, and read-only status. There is no external renewal trigger or route: the node scheduler signs renewals with its dedicated renewer key, which is never returned to clients. External clients register owner-signed leases and read status.

An owner can stop and re-enable renewal of one lease with an owner-signed control (`tinycloud-core/src/renewal/control.rs`). Revocation remains the irreversible off switch.

The node persists a monotonic renewer epoch beginning at 1. A lease and its stamps are usable only while both the lease's renewer DID and epoch match the node's current identity. If a KMS key change produces a new renewer DID, old leases and their stamps stop extending grants; owners must register new leases. This is an availability consequence, not a security failure.

A database restore can roll the persisted epoch back. An old-epoch lease could become usable again only if the old renewer key also returns, producing the matching DID and epoch. Keep the restored database and node key state consistent; do not treat a database restore alone as revocation.

## Pausing all renewals (STOP-ALL)

An operator can pause every scheduled renewal on a node with one admin call. The switch is a single row in the node database (`renewal_switch`), so it survives restarts and applies to every node process that shares that database. A node with its own database is switched on its own.

```sh
# Pause. Put the secret in TINYCLOUD_ADMIN_SECRET first; never paste or echo it.
curl -fsS -X PUT "$NODE/admin/renewals" \
  -H "Authorization: Bearer $TINYCLOUD_ADMIN_SECRET" \
  -H 'Content-Type: application/json' -d '{"paused":true}'
# Resume: the same call with {"paused":false}. Read the state:
curl -fsS "$NODE/admin/renewals" -H "Authorization: Bearer $TINYCLOUD_ADMIN_SECRET"
```

Both answer `{"paused":<bool>,"changedAt":<unix seconds or null>}`; `changedAt` moves only when the state changes. A missing or wrong secret answers 401; a node without `TINYCLOUD_ADMIN_SECRET` answers 503. Each PUT logs one warning, `renewals paused node-wide` or `renewals resumed node-wide`, in the node container log. The log shipper does not map these messages yet, so Better Stack shows them as an `unclassified` `node_warning`.

While paused:

- No renewal stamp is issued. The stamp transaction re-reads the switch, so once the pause call returns, no stamp commits, even from a scheduler pass already running.
- Stamps already issued stay valid until their end, at most one renewal period.
- Lease registration is unchanged: apps, OpenKey and the SDK see no new error, and new leases wait for resume.
- Lease rows are kept. On resume the next scheduler pass (within 5 minutes) renews every grant that is still live, with no new consent.
- A grant whose end passes while paused expires and is **not** revived on resume: the scheduler never renews past an ended grant. Its owner grants again.

