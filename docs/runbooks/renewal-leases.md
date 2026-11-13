# Renewal lease operations

This runtime slice supports owner-signed lease registration, node-internal scheduled renewal, the existing revocation flow, and read-only status. There is no external renewal trigger or route: the node scheduler signs renewals with its dedicated renewer key, which is never returned to clients. External clients register owner-signed leases and read status.

Stopping and re-enabling a lease are deferred to a later slice. Until then, the owner's only off switch is revocation, which is irreversible.

The node persists a monotonic renewer epoch beginning at 1. A lease and its stamps are usable only while both the lease's renewer DID and epoch match the node's current identity. If a KMS key change produces a new renewer DID, old leases and their stamps stop extending grants; owners must register new leases. This is an availability consequence, not a security failure.

A database restore can roll the persisted epoch back. An old-epoch lease could become usable again only if the old renewer key also returns, producing the matching DID and epoch. Keep the restored database and node key state consistent; do not treat a database restore alone as revocation.
