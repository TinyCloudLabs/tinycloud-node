# Renewal stamp v1 wire contract

This file records the exact v1 signed-stamp representation pinned by fixture commit `377c0cd9269c982bb2e71b60a51bc77367718031`, the owner-signed lease and linked first stamp pinned by #546 commit `bd2f95ca02ff25f4c67890ad0770ff0451c25295`, and the Bobbie-reviewed design `1635acfc1c4d9f965a58101eb5f8a0dcb45f39ef0996225021597157ac757a53`. Runtime code must enforce the validity bounds below.

## Renewal lease authority

A renewal lease is a real owner-signed UCAN/CACAO DAG delegation addressed to the node renewer DID. Its exact control capability is:

- Ability: `tinycloud.delegation/renew`
- Resource: `urn:cid:<canonical original delegation CID>`

The #546 fixture pins the signed lease token and CID. Its linked first stamp sets both `leaseCid` and `previousStampCid` to that real lease CID. The signed original grant supplies the renewal period; the owner-signed lease expiry is a separate upper bound. For UCAN, `nbf` is required. Only CACAO may use its signed issued-at claim when `nbf` is absent.

## Signed stamp bytes

The signed byte sequence is the deterministic DAG-CBOR encoding of exactly this two-entry map:

```text
{
  "domain": "tinycloud/node/renewal-stamp/v1",
  "unsigned": {
    "type": "TinyCloudRenewalStamp",
    "version": 1,
    "originalCid": <canonical CID string>,
    "leaseCid": <canonical CID string>,
    "leaseGeneration": <unsigned integer>,
    "previousStampCid": <canonical CID string>,
    "nodeDid": <DID string>,
    "renewerEpoch": <unsigned integer>,
    "newEnd": <RFC3339 UTC string>
  }
}
```

`previousStampCid` is non-null. The first stamp sets it to that lease's CID. `leaseGeneration` records the issuance generation; it is not a use-time equality check. `renewerEpoch` is the current renewer identity epoch. `newEnd` is serialized as a UTC RFC3339 string. The domain value has no NUL terminator; there is no additional domain prefix outside the encoded map.

Encode with the repository's deterministic `serde_ipld_dagcbor` representation. The detached Ed25519 signature is over the exact encoded bytes above; it is not embedded in those bytes. The stamp CID is CIDv1 with raw codec `0x55` and Blake3-256 over those exact bytes; the detached signature is excluded from the CID input.

Derive the renewer signing seed from the node's `StaticSecret` with the exact context bytes `tinycloud/node/renewer/v1`, using `StaticSecret::derive_key` (Blake3-256 of the static secret followed by the context). This is distinct from the node's identity-key context and storage-key generation.

Verification uses the public key for the renewer DID in the exact owner-signed lease audience; the stable `nodeDid` is not a signing key. A stamp is valid only when its signature verifies under that audience key and its original CID, lease CID, epoch, and previous-stamp link match the registered chain. At creation, `newEnd` is `min(now + signed original period, lease expiry, every ancestor's effective end)`. At creation and verification, `newEnd` MUST be no later than the lease expiry or any ancestor's effective end; at acceptance it MUST also be no later than verifier time plus the signed original period.

## Pinned linked lease and stamp vector

The signed lease, original grant, linked first stamp, and assertions are in `tinycloud-node-server/tests/fixtures/renewal-lease-v1.json` and `tinycloud-node-server/tests/renewal_lease_v1_vectors.rs`. The exact lease and first-stamp vectors were independently verified for #546 at `bd2f95ca02ff25f4c67890ad0770ff0451c25295`.

- Original CID: `bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4`
- Lease CID and first `previousStampCid`: `bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq`
- First stamp CID: `bafkr4iewc5ewhaccw5xh3cvxokvkehjvf76atyhvftq4i4eq7ayneimt3e`
- Signer DID: the dedicated renewer DID in the lease audience, distinct from the stable node identity DID.

The separate `renewal-stamp-v1.json` vector remains a stamp-only canonical-byte test. It is not the linked lease vector.
The linked vector's exact DAG-CBOR bytes, detached signature, signer key and recomputed CIDs are pinned in `renewal-lease-v1.json`; the stamp-only fixture is not authoritative for lease linkage.

## Current node slice boundary

The current node slice implements renewal issuance/use with existing revoke and status behavior. It does not expose STOP or re-enable operations; those are deferred until their owner-authenticated exact-CID control contract is separately frozen and reviewed. Until then, the owner's only way to turn renewal off is to revoke the lease. Revocation is irreversible and immediately invalidates renewed access; it cannot be re-enabled. This delivery boundary does not change the D13/D18 target behavior.
