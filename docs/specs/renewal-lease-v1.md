# Renewal lease v1 signed UCAN vector

This is the real signed-lease companion to `renewal-stamp-v1.md`. It pins an existing TinyCloud UCAN representation for the approved exact-CID renewal grant; it does not introduce a new lease encoding or any runtime behavior.

## Vector contract

`tinycloud-node-server/tests/fixtures/renewal-lease-v1.json` contains two signed UCAN tokens, their exact serialized bytes as ASCII/UTF-8 strings, and their raw-Blake3 CIDs. `tinycloud-node-server/tests/renewal_lease_v1_vectors.rs` deterministically rebuilds both tokens using the repository's `Payload::sign(Algorithm::EdDSA, …).encode()` path and compares every field with the fixture.

The original token is signed by the test owner and grants `tinycloud.kv/get` to the test holder on the fixed `urn:cid:` content resource. The owner-signed lease token grants the derived node-renewer DID exactly one capability:

- Ability: `tinycloud.delegation/renew`
- Resource: `urn:cid:bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4`
- Original delegation CID: `bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4`
- Lease UCAN CID: `bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq`
- Lease audience / renewer DID: `did:key:z6MkjS5oMpzSoPXDb7kCoRYCDRSNZBuijD8NjVntygpKxdwz`
- Owner issuer DID: `did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S`

The original and lease CIDs are CIDv1 raw (`0x55`) with Blake3-256 over the exact token bytes returned by `TinyCloudDelegation::decode`. The lease's resource is derived from the canonical CID of the signed original UCAN, not from a client-provided digest. The full lease bytes are the exact `leaseToken` string in the fixture encoded as UTF-8; the original's exact bytes are its `originalToken` string encoded as UTF-8.

The audience key is derived from the fixed test-only node static secret using `StaticSecret::derive_key(b"tinycloud/node/renewer/v1")`; its resulting `did:key` is pinned in the fixture. Owner, holder, and node-secret seed values in that fixture are public test data, not credentials. The timestamps are deterministic serialization-vector inputs, not a currently active grant or a production lease.

This vector and the frozen stamp vector together pin signed token representation, owner-to-renewer audience, exact ability/resource, stamp bytes, and their CIDs. They do not assert that the production node accepts or stores a lease; that behavior is covered only by the later runtime implementation and tests.
