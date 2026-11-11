# Renewal lease v1 signed UCAN vector

This is the real signed-lease companion to `renewal-stamp-v1.md`. It pins an existing TinyCloud UCAN representation for the approved exact-CID renewal grant; it does not introduce a new lease encoding or any runtime behavior.

## Vector contract

`tinycloud-node-server/tests/fixtures/renewal-lease-v1.json` pins the signed original and lease UCANs, their exact serialized bytes as ASCII/UTF-8 strings and raw-Blake3 CIDs, and a first signed renewal stamp linked to the real lease CID. `tinycloud-node-server/tests/renewal_lease_v1_vectors.rs` deterministically rebuilds all three using the repository signing/encoding paths and compares every field, byte sequence, signature, and CID with the fixture.

The original token is signed by the test owner and grants `tinycloud.kv/get` to the test holder on the fixed `urn:cid:` content resource. The owner-signed lease token grants the derived node-renewer DID exactly one capability:

- Ability: `tinycloud.delegation/renew`
- Resource: `urn:cid:bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4`
- Original delegation CID: `bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4`
- Lease UCAN CID: `bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq`
- Lease audience / renewer DID: `did:key:z6MkjS5oMpzSoPXDb7kCoRYCDRSNZBuijD8NjVntygpKxdwz`
- Owner issuer DID: `did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S`

The original and lease CIDs are CIDv1 raw (`0x55`) with Blake3-256 over the exact token bytes returned by `TinyCloudDelegation::decode`. The lease's resource is derived from the canonical CID of the signed original UCAN, not from a client-provided digest. The full lease bytes are the exact `leaseToken` string in the fixture encoded as UTF-8; the original's exact bytes are its `originalToken` string encoded as UTF-8.

The period in v1 is the owner's signed original grant `exp - nbf`. Only for a CACAO original, if `nbf` is absent, the signed issued-at value is the anchor; a UCAN without `nbf` is rejected. Missing expiry, missing CACAO anchors, malformed dates, or a non-positive period are rejected. This vector's original period is 30 days (`2,592,000` seconds). V1 has no lease period override. The owner-signed lease expiry is a separate upper bound: this vector's lease lifetime is 365 days (`31,536,000` seconds). Renewal issuance computes `newEnd = min(now + period, lease expiry, each ancestor's effective end)`. At issuance and stamp verification, `newEnd` must not exceed the lease expiry or any ancestor's effective end; at acceptance it must also satisfy `newEnd <= verifier_now + period`. The period is derived from signed claims, not a caller value.

The `firstStamp` entry is signed by the derived renewer key and pins canonical DAG-CBOR bytes, detached signature, and CID. Its `leaseCid` and non-null `previousStampCid` both equal the actual signed lease CID `bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq`; the test asserts both links.

The audience key is derived from the fixed test-only node static secret using `StaticSecret::derive_key(b"tinycloud/node/renewer/v1")`; its resulting `did:key` is pinned in the fixture. Owner, holder, and node-secret seed values in that fixture are public test data, not credentials. The timestamps are deterministic serialization-vector inputs, not a currently active grant or a production lease.

`nodeIdentityDid` is the stable node identity from `StaticSecret::node_did()`, serialized as the stamp's `nodeDid`. It is intentionally distinct from `renewerDid`, which is the lease audience and the DID of the separate key derived with `tinycloud/node/renewer/v1`; that renewer key signs the detached stamp.

The signed lease vector and its linked first-stamp vector, together with the frozen stamp vector, pin the lease authority, signer/identity distinction, stamp bytes, and their CIDs. They do not assert that the production node accepts or stores a lease; that behavior is covered only by the later runtime implementation and tests.
