# M1-G-05b-r1 live-gate executable-path trace and park report

Status: **PARKED at the constructibility checkpoint.** No live-gate
implementation follows this trace. This correction supersedes the preliminary
constructible verdict in the required first trace commit: source-level review
of the exact composed artifacts exposed two fail-closed contract mismatches.

Claims are confirmed from code at node `b51254e`, policy-engine `d72812a`,
js-sdk `5a42dd6`, Listen `aada92d`, and OpenCredentials `a1633710`.

## Process order and executable paths

| Step | Production path and state semantics | Required observation |
| --- | --- | --- |
| A. Inputs/identity | Caller supplies fresh nonce and SQL/KV bytes. `TinyCloudNode({privateKey})` selects `PrivateKeySigner`; `signIn()` runs `bootstrapAccountIfNeeded()` -> `bootstrapSteps(address, chainId)` (`packages/node-sdk/src/TinyCloudNode.ts:672-730,981-1100` at `5a42dd6`). | External input hashes/bytes through wire/read transcripts; no key material. Supported. |
| B. Node/seed | Real `tinycloud-node-server` can run as its own PID/dynamic port/fresh datadir. Authenticated owner SDK SQL/KV calls reach node `/invoke` and `tinycloud-core` services. | PID/port/command/logs, authenticated seed wire exchanges, pre-import DB snapshot. Supported. |
| C. Publish/parent | Listen `publish` uses authenticated `node.kv.put` for four signed objects and `TinyCloudNode.createOwnerDelegation` for real `/delegate` (`test/m1-owner-demo.ts:151-197,249-336` at `aada92d`; `TinyCloudNode.ts:2654-2710` at `5a42dd6`). Receipt handling correctly distinguishes `commitEventCid` from locally derived delegation CID. | Raw fail-closed receipt, exact DAG-CBOR, independent CID, pre/post DB delegatee row. The import path is supported, but its bounds are insufficient for E; see mismatch 2. |
| D. Sidecar startup | Production binary reads config and calls `PolicyEngineService::from_signed_objects`; signed authority is verified at startup and bounded parent bytes/CID/audience/receipt/bounds are locally validated (`crates/policy-engine-http/src/main.rs`; `lib.rs:100-241,945-1025` at `d72812a`). No running-sidecar PolicyStatus refresher exists. | Separate PID/config hash/readiness; later replacement process from updated signedObjects. Supported in isolation. |
| E. Requester/seam/read | Amended `TranscriptRequester` performs challenge -> resolve -> exact-byte `/delegate` -> holder-signed native `/invoke` (`packages/sdk-core/src/requester/index.ts:464-862` at `5a42dd6`). `SharedGrantIssuer` emits node-native UCAN bytes and singleton `prf` after `validate_issue_request` (`policy-engine-http/src/lib.rs:321-755` at `d72812a`). | Would require resolve/import/native SQL+KV transcripts and independent CID/prf derivation. **Unsupported for the actual C artifacts; issuance fails before output.** |
| F. Renewal | Requester `ensureFreshDelegation` performs access-triggered challenge/resolve with nonce replay protection. | Fresh nonce and successful TTL <= 60s delegation. Blocked by E. |
| G. Revoke/redeploy | Listen `revoke --state` starts a matching authenticated owner session and writes sequence-2 revoked PolicyStatus (`m1-owner-demo.ts:338-403` at `aada92d`). Replacement sidecar can load updated signedObjects. | Revoked-commit and replacement-ready timestamps/PIDs. Supported in isolation. |
| H. Denial | Replacement sidecar would return policy runtime's wire denial and requester would latch access-ended only as consequence. | Third timestamp and raw `policy-inactive` response. Cannot establish the required “next renewal” claim because no valid initial/renewed child can be issued. |
| I. Native expiry | Node invocation validation filters expired persisted proof chains and returns its native classification (`tinycloud-core/src/models/invocation.rs:105-243`). | Later holder invocation/native response. Cannot exercise with the required production child because E is unconstructible. |
| J. Teardown/verifier | Owned PIDs can be terminated and ports probed; an independent verifier could derive citations and run mutation self-test. | No artifact/verifier is authored because behavioral prerequisites are absent; existence cannot substitute for them. |

## Unsupported production hops

### 1. Listen policy mode cannot be issued by the production GrantIssuer

The actual Listen publish phase composes this grant contract at `aada92d`
(`frontend/src/lib/listenOwnerShares.ts:635-640`):

```text
maxTtlSeconds: 300
delegationMode: "attenuable"
revocation: "refresh_only"
```

The production `SharedGrantIssuer` at `d72812a` requires both the issue request
and policy to be terminal (`crates/policy-engine-http/src/lib.rs:568-579`). A
policy whose `grant.delegation_mode` is not `Terminal` is rejected with the
runtime reason `missing-terminal-mode-fact` before UCAN encoding. Therefore the
real sidecar cannot emit any delegation for the four signed objects published
by the mandated m1-f-02 driver.

Changing the signed Policy in the gate, publishing a replacement object,
directly mutating sidecar state, or substituting another GrantIssuer would all
violate the ticket. The requested TTL <= 60 seconds also cannot be obtained by
rewriting the driver's signed `maxTtlSeconds: 300`; only a real request/runtime
ceiling could narrow it after the mode mismatch is fixed.

### 2. The imported owner parent cannot authorize the required KV child

The same production driver fixes (`test/m1-owner-demo.ts:79-80` at `aada92d`):

```text
PARENT_PATH = "xyz.tinycloud.listen/conversations"
PARENT_ACTIONS = ["tinycloud.sql/read"]
```

It passes those exact values to `createOwnerDelegation` at lines 315-321. The
parent persisted in C therefore contains no `tinycloud.kv/get` authority. The
ticket requires the production sidecar child to authorize both native named-SQL
and KV reads of injected bytes. g-07 locally checks every child capability
against configured parent bounds (`policy-engine-http/src/lib.rs:191-241,
595-607` at `d72812a`) and returns `issue-time-parent-containment-failure` for a
capability with no matching parent bound.

The parent receipt and DB row can prove persistence only for the SQL-only
artifact actually imported. Adding a KV bound only in sidecar config would
misrepresent that artifact and is rejected by the local-validation contract;
importing a second gate-authored parent is not the mandated m1-f-02 parent.

## Stop decision

Both failures are production contract mismatches, not missing harness glue.
The acceptance flow would require rewriting signed authority, substituting a
GrantIssuer, or claiming behavior from artifact existence. The binding STOP
RULE therefore parks this lane to Patrick with this trace as the complete park
artifact. No gate script, runner, verifier, canned evidence, or product change
is included.

No claim is made about live propagation, node-confirmed active revocation,
redeploy-independent revocation latency, instant revoke, renewal denial, or
post-expiry refusal. The narrowed intended claim remains untested until the
Listen signed-policy mode and owner-parent capability bounds are compatible
with the production g-07 issuer and required SQL+KV flow.
