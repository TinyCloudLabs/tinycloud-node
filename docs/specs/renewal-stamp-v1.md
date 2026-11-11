# Renewal stamp v1 wire contract

This file records the exact v1 signed-stamp representation pinned by fixture commit `377c0cd9269c982bb2e71b60a51bc77367718031`, based on main `d63d4c44ef274d24f67a7f889379226e4769e261`. The selected architecture is the Bobbie-reviewed design `1635acfc1c4d9f965a58101eb5f8a0dcb45f39ef0996225021597157ac757a53`. This specification freezes the wire contract only; it does not implement runtime renewal behavior.

## Renewal lease authority

A renewal lease is an existing owner-authorized UCAN/CACAO delegation. This specification does **not** define a new lease serialization, lease signature format, or a real signed lease vector. Its exact control capability is:

- Ability: `tinycloud.delegation/renew`
- Resource: `urn:cid:<canonical original delegation CID>`

The CIDs named `originalCid` and `leaseCid` in the known-answer fixture are generated from synthetic DAG-CBOR placeholder artifacts. They test stamp encoding and the non-null root link only; they are not signed UCAN/CACAO delegation records and do not freeze the lease's actual bytes.

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

## Pinned vector

The synthetic fixture is `tinycloud-node-server/tests/fixtures/renewal-stamp-v1.json`; its assertions are in `tinycloud-node-server/tests/renewal_stamp_v1_vectors.rs`. The fixture's fixed master-secret bytes (`42` repeated 32 times) are public test data only.

- Original placeholder CID: `bafkr4ifaiwrq52xkndrm7jbwqvywq3tkilydyxrj24oofckit6ink7f6hy`
- Lease placeholder CID and first `previousStampCid`: `bafkr4iaiwsgu3x5bvuigtms3hrlhrwpshbv5lxar5oj7uhh5dfg2sbcl4q`
- Stamp CID: `bafkr4ibtywvyzwld56wljgytygpis2dddualt6h6b343e52rzmsegyw5nq`
- Signer public key (hex): `49fd44f3fe8930b0e89f61c51333195578deacaf22105a78f647d8c05afc7c5d`
- Detached signature (hex): `34caf6cc60615a4c0d4f4e934c0263dde1c17fdd5becfa0f693337987b0250f0b430d7fe4518db41a882cc26ee979603736b883798fb83bbc95fb61af077020d`

Exact canonical DAG-CBOR bytes (hex):

```text
a266646f6d61696e781f74696e79636c6f75642f6e6f64652f72656e6577616c2d7374616d702f763168756e7369676e6564a964747970657554696e79436c6f756452656e6577616c5374616d70666e6577456e6474323033302d30312d30325430333a30343a30355a676e6f646544696478386469643a6b65793a7a364d6b7058766555796a7043446536503833724e5971415a6d6f546339716f704a364742755251526f747a337a46376776657273696f6e01686c65617365436964783b6261666b7234696169777367753378356276756967746d733368726c6872777073686276356c786172356f6a3775686835646667327362636c34716b6f726967696e616c436964783b6261666b7234696661697772713532786b6e64726d376a6277717679777133746b696c79647978726a32346f6f66636b697436696e6b37663668796c72656e6577657245706f6368076f6c6561736547656e65726174696f6e037070726576696f75735374616d70436964783b6261666b7234696169777367753378356276756967746d733368726c6872777073686276356c786172356f6a3775686835646667327362636c3471
```
