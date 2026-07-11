# M1-G-05b-r1 live-gate executable-path trace

Status: **CONSTRUCTIBLE after operator-conformant production fixes.** The two
previously unsupported hops are re-verified against Listen `bd936c0`; both now
match the approved issuer/import contracts. Implementation may proceed without
rewriting signed authority or substituting a test-local signer.

Claims are confirmed from code at node `b51254e`, policy-engine `d72812a`,
js-sdk `5a42dd6`, Listen `bd936c0`, and OpenCredentials `a1633710`.

## Process order and executable paths

| Step | Production path and state semantics | Required observation |
| --- | --- | --- |
| A. Inputs/identity | Caller supplies fresh nonce and SQL/KV bytes. `TinyCloudNode({privateKey})` selects `PrivateKeySigner`; `signIn()` runs `bootstrapAccountIfNeeded()` -> `bootstrapSteps(address, chainId)` (`packages/node-sdk/src/TinyCloudNode.ts:672-730,981-1100` at `5a42dd6`). | External input hashes/bytes through wire/read transcripts; no key material. Supported. |
| B. Node/seed | Real `tinycloud-node-server` can run as its own PID/dynamic port/fresh datadir. Authenticated owner SDK SQL/KV calls reach node `/invoke` and `tinycloud-core` services. | PID/port/command/logs, authenticated seed wire exchanges, pre-import DB snapshot. Supported. |
| C. Publish/parent | Listen `publish` uses authenticated `node.kv.put` for four signed objects and `TinyCloudNode.createOwnerDelegation` for real `/delegate` (`test/m1-owner-demo.ts:151-197,249-336` at `bd936c0`; `TinyCloudNode.ts:2654-2710` at `5a42dd6`). The imported parent actions are exactly `tinycloud.sql/read` and `tinycloud.kv/get` (`test/m1-owner-demo.ts:118-120` at `bd936c0`). Receipt handling correctly distinguishes `commitEventCid` from locally derived delegation CID. | Raw fail-closed receipt, exact DAG-CBOR, independent CID, pre/post DB delegatee row. Supported for both required child capabilities. |
| D. Sidecar startup | Production binary reads config and calls `PolicyEngineService::from_signed_objects`; signed authority is verified at startup and bounded parent bytes/CID/audience/receipt/bounds are locally validated (`crates/policy-engine-http/src/main.rs`; `lib.rs:100-241,945-1025` at `d72812a`). No running-sidecar PolicyStatus refresher exists. | Separate PID/config hash/readiness; later replacement process from updated signedObjects. Supported in isolation. |
| E. Requester/seam/read | Amended `TranscriptRequester` performs challenge -> resolve -> exact-byte `/delegate` -> holder-signed native `/invoke` (`packages/sdk-core/src/requester/index.ts:464-862` at `5a42dd6`). `SharedGrantIssuer` emits node-native UCAN bytes and singleton `prf` after `validate_issue_request` (`policy-engine-http/src/lib.rs:321-755` at `d72812a`). Listen now signs terminal grant mode (`frontend/src/lib/listenOwnerShares.ts:635-641` at `bd936c0`), satisfying the issuer, and C's parent bounds both requested services. | Resolve/import/native SQL+KV transcripts and independent CID/prf derivation. Supported end to end by production paths. |
| F. Renewal | Requester `ensureFreshDelegation` performs access-triggered challenge/resolve with nonce replay protection. The signed policy ceiling remains `maxTtlSeconds: 300`; the caller's real request/presentation window narrows the emitted child to TTL <= 60 seconds without changing signed policy bytes. | Fresh nonce and successful TTL <= 60s delegation, derived from wire timestamps. Supported. |
| G. Revoke/redeploy | Listen `revoke --state` starts a matching authenticated owner session and writes sequence-2 revoked PolicyStatus (`m1-owner-demo.ts:338-403` at `bd936c0`). Replacement sidecar can load updated signedObjects. | Revoked-commit and replacement-ready timestamps/PIDs. Supported. |
| H. Denial | Replacement sidecar returns policy runtime's wire denial and requester latches access-ended only as consequence. | Third timestamp and raw `policy-inactive` response. Supported after the initial and renewed child are issued. |
| I. Native expiry | Node invocation validation filters expired persisted proof chains and returns its native classification (`tinycloud-core/src/models/invocation.rs:105-243`). | Later holder invocation/native response. Supported using the real imported production child. |
| J. Teardown/verifier | Owned PIDs are terminated and ports probed; the independent verifier derives citations and runs its mutation self-test solely from captured raw artifacts. | Process-exit/port observations plus verifier output. Supported. |

## Resolved production hops

### 1. Listen policy mode is accepted by the production GrantIssuer

The actual Listen publish phase composes this grant contract at `bd936c0`
(`frontend/src/lib/listenOwnerShares.ts:635-641`):

```text
maxTtlSeconds: 300
delegationMode: "terminal"
revocation: "refresh_only"
```

The production `SharedGrantIssuer` at `d72812a` requires both the issue request
and policy to be terminal (`crates/policy-engine-http/src/lib.rs:568-579`). The
signed production artifact now conforms, so issuance reaches UCAN encoding.
The gate does not rewrite `maxTtlSeconds: 300`: the real request/presentation
window narrows the child lifetime to <= 60 seconds beneath that signed ceiling.

### 2. The imported owner parent authorizes both required child services

The same production driver fixes (`test/m1-owner-demo.ts:118-120` at `bd936c0`):

```text
PARENT_PATH = "xyz.tinycloud.listen/conversations"
PARENT_ACTIONS = ["tinycloud.sql/read", "tinycloud.kv/get"]
```

It passes those exact values to `createOwnerDelegation` at lines 315-321. The
parent persisted by the mandated driver now bounds both native named-SQL and KV
reads. g-07's local child-vs-parent checks (`policy-engine-http/src/lib.rs:
191-241,595-607` at `d72812a`) can therefore validate both requested
capabilities against the exact imported production artifact.

## Constructibility decision

Both previously real production mismatches are resolved at Listen `bd936c0`.
The full A-J choreography is constructible through pinned production paths, so
implementation proceeds. The verifier's eventual claim remains narrowly:
after the owner publishes a monotonic revoked PolicyStatus and redeploys the
owner-controlled sidecar from that authority state, the next real renewal is
denied `policy-inactive`, and the previously issued short-TTL delegation is
refused by the node after expiry, within the declared TTL bound. It will not
claim live propagation, node-confirmed active revocation, redeploy-independent
revocation latency, or instant-revoke behavior.
