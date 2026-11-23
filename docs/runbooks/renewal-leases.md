# Renewal lease operations

This runtime slice supports owner-signed lease registration, node-internal scheduled renewal, the existing revocation flow, and read-only status. There is no external renewal trigger or route: the node scheduler signs renewals with its dedicated renewer key, which is never returned to clients. External clients register owner-signed leases and read status.

An owner can stop and re-enable renewal of one lease with an owner-signed control (`tinycloud-core/src/renewal/control.rs`). Revocation remains the irreversible off switch.

The node persists a monotonic renewer epoch beginning at 1. A lease and its stamps are usable only while both the lease's renewer DID and epoch match the node's current identity. If a KMS key change produces a new renewer DID, old leases and their stamps stop extending grants; owners must register new leases. This is an availability consequence, not a security failure.

A database restore can roll the persisted epoch back. An old-epoch lease could become usable again only if the old renewer key also returns, producing the matching DID and epoch. Keep the restored database and node key state consistent; do not treat a database restore alone as revocation.

## What `renewal_lease.state` means, and the audit query

`renewal_lease.state` is a registration state, not a liveness flag. The node writes it in three places only: `active` when a lease is registered, `active` to `expired` when a replacement lease is issued for the same original and renewer epoch, and `active` to `stopped` and back through the owner's stop/enable control. Nothing writes `revoked`, and nothing marks a lease `expired` when its time simply passes. A revoked lease, or a lease whose original or any ancestor delegation is revoked, therefore keeps `state = 'active'`, and so does a lease past `lease_expiry` that was never replaced.

Revocation (including aliases through `delegation_cid_alias`: revoking one encoding of a delegation revokes every encoding with the same canonical id, TC-1071), joined through `parent_delegation`, is the source of truth for revocation. The renewer, stamp issue and stop/enable all use it (`is_revoked_chain` and `live_chain_effective_ends` in `tinycloud-core/src/renewal.rs`), and they also require `lease_expiry` in the future. A lease is renewable only when all of these hold (the node also checks `not_before`, ancestor expiry, a retired holder and STOP-ALL, which this query does not):

- `state = 'active'`;
- `lease_expiry` is in the future;
- neither the lease nor the original, nor any ancestor of either, is in `revocation`;
- its `renewer_did` and `renewer_epoch` are the node's current identity (compare with `renewal_identity`).

Counting `state = 'active'` alone over-counts. For an audit or dashboard count use this read-only query (PostgreSQL; it runs on a replica). It counts the three groups apart and writes nothing:

```sql
WITH RECURSIVE lease_chain(lease_cid, id) AS (
  SELECT lease_cid, lease_cid FROM renewal_lease
  UNION
  SELECT lease_cid, original_canonical FROM renewal_lease
  UNION
  SELECT c.lease_cid, p.parent
    FROM parent_delegation p JOIN lease_chain c ON p.child = c.id
),
revoked AS (
  SELECT DISTINCT c.lease_cid FROM lease_chain c JOIN revocation r ON r.revoked = c.id
  UNION
  SELECT c.lease_cid FROM lease_chain c
    JOIN delegation_cid_alias a ON a.id = c.id
    JOIN delegation_cid_alias o ON o.canonical = a.canonical
    JOIN revocation r ON r.revoked = o.id
)
SELECT
  count(*) FILTER (WHERE l.state = 'active' AND l.lease_expiry > now()
                     AND rv.lease_cid IS NULL)                   AS active_unrevoked_unexpired,
  count(*) FILTER (WHERE l.state = 'active' AND rv.lease_cid IS NOT NULL) AS active_but_revoked,
  count(*) FILTER (WHERE l.state = 'active' AND l.lease_expiry <= now()
                     AND rv.lease_cid IS NULL)                   AS active_but_past_expiry
FROM renewal_lease l LEFT JOIN revoked rv ON rv.lease_cid = l.lease_cid
WHERE l.renewer_epoch = (SELECT epoch FROM renewal_identity WHERE id = 1)
  AND l.renewer_did = (SELECT renewer_did FROM renewal_identity WHERE id = 1);
```

The query counts only leases of the node's current renewer identity and epoch, as the scheduler does. `active_unrevoked_unexpired` is necessary, not sufficient, for a lease to be renewed: a retired holder, `not_before`, an expired ancestor and STOP-ALL also stop renewal. `active_but_revoked` and `active_but_past_expiry` are expected to be non-zero and need no action: the renewer skips both. Do not "fix" them by updating `state`.

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

A failed scheduler pass logs `internal renewal scheduler pass failed` with a fixed `code`, never the raw error: `renewal_switch_unavailable` (the switch could not be read, so the pass issued nothing), `renewal_db_unavailable` (another database error) or `renewal_tick_failed` (anything else). The pass retries on the next tick.

### Renewals switch workflow (production)

To pause or resume renewals on the production nodes, use the `Renewals switch` GitHub Actions workflow (`.github/workflows/renewals-switch.yml`). It makes the calls above with `PROD_TINYCLOUD_ADMIN_SECRET` from the `production` environment, so nobody reads or handles the secret. Run it only with an engineering lead's approval.

```sh
# Read the switch on both nodes (host defaults to both).
gh workflow run renewals-switch.yml --repo TinyCloudLabs/tinycloud-node -f action=status
# Pause: confirm must repeat the action. Each host gets a PUT, then a GET that must agree.
gh workflow run renewals-switch.yml --repo TinyCloudLabs/tinycloud-node -f action=pause -f confirm=pause
# Resume, here on one node only.
gh workflow run renewals-switch.yml --repo TinyCloudLabs/tinycloud-node \
  -f action=resume -f confirm=resume -f host=tee.node.tinycloud.xyz
gh run watch --repo TinyCloudLabs/tinycloud-node "$(gh run list --repo TinyCloudLabs/tinycloud-node \
  --workflow renewals-switch.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

`host` is `both` (default), `node.tinycloud.xyz` or `tee.node.tinycloud.xyz`. Run from `main` (the default); the `production` environment admits only `main` and `v*` tags. The log prints one line per call, such as `node.tinycloud.xyz GET: HTTP 200, paused=true`, and nothing else from the response. The run fails, after trying every selected host, if any call fails or a node's final state differs from the requested one; the error line names those hosts. A pause or resume without the matching `confirm` fails before any call.

