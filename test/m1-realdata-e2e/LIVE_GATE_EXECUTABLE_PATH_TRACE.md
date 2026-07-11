# M1-G-05b-r1 live-gate executable-path trace

Status: **CONSTRUCTIBLE — no unsupported production hop found.** This is the
constructibility-checkpoint artifact and was committed before gate
implementation. Claims are confirmed from code at node `b51254e`, policy-engine
`d72812a`, js-sdk `5a42dd6`, Listen `aada92d`, and OpenCredentials `a1633710`.
The retired wave-10f trace is used only as the required unsupported-hop
checklist; none of its workarounds or claims carry forward.

## Process order, production paths, and observations

| Step | Production path and runtime dependency | Raw observation from runner; verifier derivation |
| --- | --- | --- |
| A. External identity and data | The caller supplies a unique run nonce and random SQL/KV seed bytes. Owner bootstrap uses an ephemeral or secret-provisioned Ethereum key through `TinyCloudNode({privateKey})` -> `PrivateKeySigner` -> `signIn()` -> `bootstrapAccountIfNeeded()` -> `bootstrapSteps(address, chainId)` (`packages/node-sdk/src/TinyCloudNode.ts:672-730,981-1100` at `5a42dd6`). Requester and grant issuer remain did:key. | Raw invocation metadata records run id and hashes/lengths of inputs, never the key. HTTP/native-read transcripts carry the run id and exact seed bytes. Secret-pattern scan covers every bundle file. |
| B. Real node, bootstrap, and seed | `tinycloud-node-server` starts as its own PID on a caller-selected dynamic port with fresh `TINYCLOUD_STORAGE_DATABASE` and `TINYCLOUD_STORAGE_BLOCKS_PATH`. The authenticated owner SDK creates its account/space and writes Listen data through native signed invocation paths. Node `/invoke` dispatches authenticated SQL/KV capabilities in `tinycloud-node-server/src/routes/mod.rs`; storage is in `tinycloud-core` SQL/KV services. | Command/PID/port/readiness and raw stdout/stderr; signed seed requests/responses; pre-import SQLite snapshot after bootstrap/seed. Verifier baselines bootstrap authority rows, associates later authority-row deltas only with `/delegate`, and compares native read bytes to external inputs. |
| C. Publish and parent import | Listen `test/m1-owner-runner.ts` loads production packages and invokes `runOwnerPublish`. `liveContext` constructs/signs in `TinyCloudNode`; `publishListenOwnerShare` writes policy, engine record, active status, and bootstrap through authenticated `node.kv.put`. `createOwnerDelegation` constructs the owner-signed subdelegable SIWE/CACAO parent and calls production `/delegate` (`m1-owner-demo.ts:151-197,249-336` at `aada92d`; `TinyCloudNode.ts:2654-2710` at `5a42dd6`). The driver requires target space in `activated` and absent from `skipped`, stores exact DAG-CBOR, a locally derived delegation CID, delegatee, and raw response CID labelled only `commitEventCid`. | Driver stdout/stderr/artifact/state; raw parent `/delegate` response; exact parent bytes; pre/post DB snapshots. Verifier independently derives the node CID (raw codec + BLAKE3), never compares response commit-event CID to delegation CID, proves post-row delegatee equals grantIssuer DID, and later proves the imported child has exactly one `prf` equal to this parent CID. |
| D. Production sidecar startup | `policy-engine-http` binary reads `POLICY_ENGINE_HTTP_CONFIG`; `FileConfig::into_service_config` rejects authority in unsigned preload fields and passes `signedObjects` to `PolicyEngineService::from_signed_objects` (`crates/policy-engine-http/src/main.rs` at `d72812a`). Startup verifies signed objects and authority, and locally validates parent artifact bytes, expected CID, audience/delegatee, validity, non-terminal mode, receipt fields, and capability bounds (`lib.rs:100-241,945-1025`). There is no runtime PolicyStatus refresher; only redeploy loads later status. | Config with signing seeds redacted from evidence, a public config projection, signed-object bytes/hashes, PID/port/command, stdout/stderr, and readiness wire exchange. Verifier derives startup ordering and active authority state from raw artifacts and successful wire behavior. |
| E. Real requester, import, and native reads | Production `TranscriptRequester.create` verifies bootstrap owner-node endpoint contract and signed engine record before egress. Access obtains `/policy/v0/challenge`, holder-signs the presentation, and posts `/policy/v0/resolve` (`packages/sdk-core/src/requester/index.ts:464-793` at `5a42dd6`). Production `SharedGrantIssuer` validates bounds and emits a node-native EdDSA UCAN whose `prf` is `[parent.expected_cid]`; `delegationId` is the node CID over the exact compact-JWS bytes (`policy-engine-http/src/lib.rs:321-535,562-755` at `d72812a`). The requester submits the exact `encoded` bytes as `/delegate` Authorization, requires HTTP success plus target in `activated` and absent from `skipped`, independently derives the CID, then holder-signs native `/invoke` SQL/KV reads using that CID as proof parent (`requester/index.ts:533-632,796-862,1314-1338`). | Raw bootstrap/challenge/resolve/delegate/invoke exchanges with correlation ids. Verifier proves resolve encoded bytes equal Authorization bytes, independently derives CID equal to engine `delegationId`, decodes singleton `prf` equal to C's CID, proves fail-closed receipt, attributes DB row delta to import, and compares SQL/KV results byte-for-byte to A. First invoke Authorization is decoded to show the derived child CID as proof parent. |
| F. Access-triggered renewal | Once the short delegation enters the SDK renewal window, `ensureFreshDelegation` obtains a new challenge and resolve on the next read; challenge nonces are single-use (`requester/index.ts:633-795`). | Raw second challenge/resolve/import/read exchanges. Verifier proves the nonce differs and the second access succeeded with TTL no greater than 60 seconds. |
| G. Revoke and owner-controlled redeploy | Listen `revoke --state` starts a new authenticated owner session, verifies owner/space continuity, and calls `revokeListenOwnerShare`, writing only sequence-2 revoked PolicyStatus (`m1-owner-demo.ts:338-403` at `aada92d`). Runner stops the old sidecar and starts a new production process from updated signedObjects. The restart interval is only unreachable/redeploying. | Timestamp 1: revoked status committed. Timestamp 2: replacement sidecar ready. Raw revoke driver output, updated signed object/hash, old/new PIDs, stop/start/readiness exchanges. Verifier proves monotonic sequence and ordering without making a live-refresh claim. |
| H. Wire denial and SDK latch | The next real renewal reaches the replacement `/policy/v0/resolve`; policy runtime evaluates the startup-loaded revoked status and the sidecar returns its native `policy-inactive` denial. `TranscriptRequester.recordAccessEnded` latches only from that response-derived access-ended error (`requester/index.ts:633-682`). | Timestamp 3: raw replacement-sidecar HTTP denial response, then requester state. Verifier derives the denial code from the wire JSON and proves the latch is subsequent consequence; runner authors no expected denial artifact. |
| I. Native post-expiry refusal | After TTL expiry, a holder-signed invocation carrying the previously imported child reaches node `/invoke`. Invocation verification validates signature/time and persisted proof chain; expired parents are filtered at invocation time and the node returns its native classification (`tinycloud-core/src/models/invocation.rs:105-243`). | Later timestamp, exact invocation and native node response, child issued/expiry fields, and TTL derivation. Verifier preserves the node classification and never relabels it as engine denial. |
| J. Teardown and independent verification | Runner terminates every owned PID and probes recorded ports. A separate verifier reads only the raw bundle, reconstructs all verdicts with `{transcript, producerPid, runId, correlationId, byteOffset-or-jsonPath, derivationRule}`, and performs its negative self-test against a copied bundle. | Exit records and no-survivor port probes. Verifier output is outside runner facts. A copied real bundle with one critical field mutated must fail verification while the original passes. |

## Dependency ordering and state-loading invariants

The strict order is external inputs -> node -> headless owner bootstrap and seed
-> pre-import snapshot -> Listen publish plus parent import -> post-parent
snapshot -> sidecar startup from active signedObjects and parent config -> real
requester resolve/import/native reads -> renewal -> owner revoke -> old-sidecar
stop -> replacement startup from updated signedObjects -> wire denial -> native
post-expiry refusal -> teardown -> verifier and mutation self-test. Sidecar
authority is startup-only. The parent receipt is persistence evidence only in
combination with the DB row delta and successful singleton-parent child import;
its response CID is a commit-event id, not delegation identity.

## Previously unsupported-hop checklist

- **Owner publication and phase separation:** supported by Listen `publish` and
  `revoke` verbs using authenticated SDK KV writes.
- **Bounded owner parent import:** supported by
  `TinyCloudNode.createOwnerDelegation`; raw fail-closed receipt, local CID,
  exact bytes, and delegatee are exposed without private key material.
- **Production GrantIssuer to node import:** supported. `SharedGrantIssuer`
  emits a three-segment node-native UCAN; the requester forwards those exact
  bytes to `/delegate`. No issuer substitution or transformation exists.
- **Requester node import and native reads:** supported by the amended
  `TranscriptRequester` `/delegate` and holder-signed `/invoke` paths.
- **Parent persistence seam:** supported behaviorally when the node accepts the
  emitted child whose singleton proof is the parent CID, plus pre/post DB row
  provenance. Artifact existence alone is not used.
- **Revocation propagation:** supported only by owner-controlled sidecar
  redeploy. A running-sidecar refresher remains unsupported and is not claimed.

No acceptance flow requires a mock transport, direct authority mutation,
canned evidence, GrantIssuer substitution, or artifact-existence substitution.
If any cited path fails at build or live execution, the gate fails closed; the
runner and verifier may not synthesize or reinterpret the missing observation.

## Claim boundary

The gate may claim only: after the owner publishes a monotonic revoked
PolicyStatus and redeploys the owner-controlled sidecar from that authority
state, the next real renewal is denied policy-inactive, and the previously
issued short-TTL delegation is refused by the node after expiry within the
declared TTL bound. It does not claim live propagation into a running sidecar,
node-confirmed active revocation, revocation-to-denial latency independent of
redeploy, or instant revocation.
