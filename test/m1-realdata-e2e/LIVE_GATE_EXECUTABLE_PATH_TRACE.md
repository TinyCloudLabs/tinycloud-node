# M1-G-05b live-gate executable-path trace and park report

Status: **PARKED at the constructibility checkpoint**. No live-gate
implementation may follow this trace until Patrick resolves the production
delegation-envelope contract described below.

This trace uses the ticket context pack as its source of truth. Policy-engine
citations are to pinned revision `ba318116365171f3be19de4e3efa1a5eafd842d2`;
node citations are to this ticket's clean base `2b2eddf`. The retired
`m1-wave-10b` implementation was not consulted or adopted.

## Required process order and observations

| Step | Required production path and state semantics | Raw observation required from a future runner |
| --- | --- | --- |
| A. Inputs | The wrapper, not `scripts/m1-gate-demo.sh`, must supply a fresh run nonce and randomized SQL/KV seed bytes. | Wrapper environment/argv capture, run id, and hashes of the supplied bytes; later HTTP and native-read transcripts must carry the same run id and bytes. |
| B. Node and seed | Start the real node binary as its own PID on a dynamic port with a fresh datadir. Native node routes ultimately dispatch through `tinycloud-node-server/src/routes/mod.rs` and `tinycloud-core` SQL/KV services. Initial space provisioning remains a disclosed storage precondition because the pinned node has no production initial-space route; it must not create delegation or ability rows. | Node command line/PID/port/stdout/stderr, readiness exchange, seed requests/responses, exact returned seed bytes, and a pre-import database snapshot showing zero delegation/ability authority rows. |
| C. Owner composition/publish | The vendored g-04 `m1-owner` driver calls `composeListenOwnerShareDraft` and `publishListenOwnerShare` (`vendor/listen/test/m1-owner-demo.ts:249-265`). Its live `kv.put` adapter sends unsigned JSON `{ownerDid,path,value}` to one configured endpoint (`m1-owner-demo.ts:163-203`), which is not a request accepted by the node's native `/invoke` route. The same indivisible `runOwnerDemo` call then immediately calls `revokeListenOwnerShare` (`m1-owner-demo.ts:267-272`), so it cannot leave active authority published while D-F run. These are explicit unsupported hops, detailed below. | A future production-capable driver must provide separate publish/revoke operations. The runner would capture its command line/PID/stdout/stderr plus every native node request/response and signed-object byte hash. Artifact existence alone is not evidence of publication. |
| D. Sidecar startup | Start the production `policy-engine-http` service as a separate PID only after C. At the pin, `PolicyEngineService::from_signed_objects_at` verifies and loads authority from `signedObjects` at startup. There is no production runtime PolicyStatus refresher; redeploy is the only in-scope v0 update mechanism. | Sidecar command line/PID/port/stdout/stderr, signed-object input hashes, and readiness exchange correlated to the active status. |
| E. SDK flow | The requester verifies bootstrap before egress, obtains a challenge, and posts the presentation to `/policy/v0/resolve` (vendored archive `package/dist/requester/index.js:1711-1736,1849-1916`). The production sidecar mounts that exact route and its handler returns `Json(ResolveResponse { delegation })` (`crates/policy-engine-http/src/lib.rs:1269-1278,1388-1392,1632-1640`). The SDK method named `importPortableDelegation` only validates and stores response JSON locally (`requester/index.js:1918-1978`); it does not call node `/delegate`. Its read methods call `/read/sql/named` and `/read/kv/exact` on the policy-engine endpoint (`requester/index.js:1750-1790`), routes the production sidecar does not mount. Node import and native read bridging are therefore explicit unsupported hops, detailed below. | A future production path would capture every HTTP request/response with correlation id and byte offsets/JSON paths; resolve-to-node-import envelope provenance; native SQL/KV responses byte-equal to the wrapper inputs; and a post-import database snapshot showing rows created only by `/delegate`. |
| F. Renewal | A fresh access nonce drives a second real challenge/resolve cycle while active. | Sidecar wire response and SDK state transition correlated to the new nonce; positive TTL at most 60 seconds. |
| G. Revoke/redeploy | The owner driver publishes a higher-sequence revoked PolicyStatus. Stop the active sidecar and start a new production sidecar from the updated `signedObjects`; the interval is classified only as unreachable/redeploying. | Separate timestamps for revoked status committed and redeployed sidecar ready; old/new PIDs; updated signed-object hashes; no `revoked` or `policy-inactive` classification during the restart interval. |
| H. Denied renewal | After successful redeploy, the next real renewal reaches the new sidecar and is denied `policy-inactive`; SDK access-ended is only the consequence. | Third timestamp for the sidecar response, raw response body/status, request id, and subsequent SDK latch transition. The verifier derives the denial; the runner does not author it. |
| I. Native expiry refusal | At the first holder-signed `/invoke` read after the imported delegation expires, the node verifies the invocation's own signature/time and validates its persisted parent chain (`tinycloud-core/src/models/invocation.rs:105-142`). It filters expired persisted parents at the actual invocation time (`invocation.rs:200-209`); the requested delegated capability then has no qualifying parent and returns native `UnauthorizedAction` (`invocation.rs:218-243`). Import-time validation in `models/delegation.rs` is not this observation. | Fourth timestamp, expired delegation id/TTL bound, node `/invoke` request/response, and database snapshots. Preserve the node's native unauthorized-action classification; never relabel it as a policy-engine denial. |
| J. Teardown and verification | Terminate all owned PIDs. A separate verifier reads only raw artifacts, reconstructs every verdict, cites file/PID/run/request plus byte offset or JSON path and derivation rule, and rejects direct `caps.db` authority insertion. | Process-exit records, no-survivor probe, verifier output kept outside the runner facts, and a negative self-test that removes/mutates a critical field in a copied real bundle and observes verifier failure. |

## Unsupported production hops

### Owner driver -> native node, with publish/revoke separation

The pinned g-04 driver does compose the required owner objects, but it cannot
execute the required live choreography against the pinned node:

1. Its live `kv.put` implementation posts unsigned JSON containing
   `ownerDid`, `path`, and `value` to the supplied endpoint
   (`vendor/listen/test/m1-owner-demo.ts:187-200`). The real node's data write
   path is an authenticated native invocation: `invoke_impl` receives an
   `AuthHeaderGetter<InvocationInfo>` and dispatches by signed capabilities
   (`tinycloud-node-server/src/routes/mod.rs:687-751`). There is no production
   node route consuming the driver's JSON shape.
2. `runOwnerDemo` publishes at lines 249-265 and then, without returning or
   exposing a phase boundary, revokes at lines 267-272. Thus the mandated
   sidecar-start/read/renew interval cannot occur between the driver's active
   publish and revoked-status publish.

A test-local HTTP adapter, direct signed-object-state write, or interception
that delays one of the driver's writes would substitute a gate-local path for
the required real driver-to-node behavior. The STOP RULE therefore marks both
driver hops unsupported.

### Real resolve envelope -> real node import

This binding hop is not constructible at the pinned production revisions:

1. The production sidecar's `SharedGrantIssuer::issue` puts
   `SignedPortableDelegation::encode()` directly in
   `PortableDelegation.encoded`
   (`policy-engine-http/src/lib.rs:217-244`). That encoder produces
   `tc-pdel-v0.<base64url(JCS JSON)>` (`lib.rs:257-343`). This is the real
   `/resolve` output; substituting another `GrantIssuer` is prohibited.
2. The real node `/delegate` route receives
   `AuthHeaderGetter<DelegationInfo>` and calls `TinyCloud::delegate`
   (`tinycloud-node-server/src/routes/mod.rs:206-241`). The request guard reads
   the `Authorization` header through `TinyCloudDelegation`
   (`tinycloud-node-server/src/authorization.rs:14-38`).
   `TinyCloudDelegation` has only `Ucan` and `Cacao` variants. Any dotted
   string is passed directly to `Ucan::decode`; undotted input is decoded as
   DAG-CBOR CACAO (`tinycloud-auth/src/authorization.rs:27-68`).
3. Consequently `tc-pdel-v0.<payload>` is treated as a UCAN/JWT even though it
   is a two-segment policy-engine envelope containing JCS JSON, not a UCAN.
   It cannot reach native delegation signature/time/parent/capability
   enforcement (`tinycloud-core/src/models/delegation.rs:145-190`).
4. Searches of the pinned policy-engine and this clean node base find no
   production transformation from `tc-pdel-v0` to UCAN or CACAO. The only
   occurrences in policy-engine are the producer/decoder local to
   `policy-engine-http`; the node has no `tc-pdel-v0` consumer.

Identity provenance is therefore impossible, and no documented production
transformation exists. A test-local converter, pinned-trait signer, direct
delegation/ability insertion, canned import receipt, or relabeled denial would
violate the ticket's prohibitions.

### Vendored SDK requester -> node import and native reads

The requester is real but does not itself traverse the required node hops:

1. After `/policy/v0/resolve`, `importPortableDelegation` schema-checks the
   response and retains it in requester memory; it sends no `/delegate`
   request (`package/dist/requester/index.js:1908-1978` inside the pinned SDK
   archive).
2. `readSql` and `readKv` send `/read/sql/named` and `/read/kv/exact` requests
   to `bootstrap.policyEngine.endpoint` (`requester/index.js:1750-1790`). The
   pinned production policy-engine router mounts only `/policy/v0/challenge`,
   `/policy/v0/resolve`, and the demo active-cutoff route
   (`policy-engine-http/src/lib.rs:1269-1278`).

No vendored or pinned production adapter turns those requester read requests
into holder-signed node `/invoke` requests, and no production adapter imports
the resolve envelope into `/delegate`. A gate-local `RequesterTransport`
implementation performing those authority-bearing operations would be the
prohibited test-local conversion/mock transport, not observation of a
production hop.

## Park decision

The GRANTISSUER-SEAM CLOSURE says that a non-importable production
`tc-pdel-v0` result parks the ticket and goes to Patrick as a gate/architecture
decision. Independently, the pinned owner driver has no native-node
publication or publish/revoke phase boundary, and the pinned requester has no
production node-import/native-read bridge. The constructibility STOP RULE
forbids reinterpreting or working around any of these acceptance hops.
Therefore this trace is the complete ticket artifact for this attempt: no
runner, verifier, gate script, fabricated evidence, or behavioral tests are
added.

The claim that remains unimplemented is narrowly: after the owner publishes a
monotonic revoked PolicyStatus and redeploys the owner-controlled sidecar from
that authority state, the next real renewal is denied policy-inactive, and the
previously issued short-TTL delegation is refused by the node after expiry,
within the declared TTL bound. This trace makes no claim of live sidecar
propagation, node-confirmed active revocation, redeploy-independent latency, or
instant revocation.
