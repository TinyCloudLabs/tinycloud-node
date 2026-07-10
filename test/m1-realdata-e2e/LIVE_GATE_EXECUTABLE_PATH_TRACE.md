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
| C. Owner composition/publish | The vendored g-04 `m1-owner` driver calls `composeListenOwnerShareDraft`, then `publishListenOwnerShare`; live writes are attempted by `kv.put` in `vendor/listen/test/m1-owner-demo.ts`. It composes share-related Policy, active PolicyStatus, engine record, and bootstrap material, then publishes before sidecar startup. | Driver command line/PID/stdout/stderr plus each node HTTP write request/response and signed-object byte hash. Artifact existence alone is not evidence of publication. |
| D. Sidecar startup | Start the production `policy-engine-http` service as a separate PID only after C. At the pin, `PolicyEngineService::from_signed_objects_at` verifies and loads authority from `signedObjects` at startup. There is no production runtime PolicyStatus refresher; redeploy is the only in-scope v0 update mechanism. | Sidecar command line/PID/port/stdout/stderr, signed-object input hashes, and readiness exchange correlated to the active status. |
| E. SDK flow | The real vendored SDK requester must perform bootstrap -> challenge -> resolve -> import -> named SQL reads and KV read over HTTP. Policy-engine `POST /v1/resolve` serializes `ResolveResponse { delegation: PortableDelegation }` (`crates/policy-engine-http/src/lib.rs:1388-1392`). | Every HTTP request/response with correlation id and byte offsets/JSON paths; resolve/import envelope provenance; native SQL/KV responses byte-equal to the wrapper inputs; post-import database snapshot showing rows created only by `/delegate`. |
| F. Renewal | A fresh access nonce drives a second real challenge/resolve cycle while active. | Sidecar wire response and SDK state transition correlated to the new nonce; positive TTL at most 60 seconds. |
| G. Revoke/redeploy | The owner driver publishes a higher-sequence revoked PolicyStatus. Stop the active sidecar and start a new production sidecar from the updated `signedObjects`; the interval is classified only as unreachable/redeploying. | Separate timestamps for revoked status committed and redeployed sidecar ready; old/new PIDs; updated signed-object hashes; no `revoked` or `policy-inactive` classification during the restart interval. |
| H. Denied renewal | After successful redeploy, the next real renewal reaches the new sidecar and is denied `policy-inactive`; SDK access-ended is only the consequence. | Third timestamp for the sidecar response, raw response body/status, request id, and subsequent SDK latch transition. The verifier derives the denial; the runner does not author it. |
| I. Native expiry refusal | At the first read after the previously imported delegation expires, the real node validates the delegation chain/time and refuses it. Node import validation is `tinycloud-core/src/models/delegation.rs:145-180`; the native classification must remain node-layer. | Fourth timestamp, expired delegation id/TTL bound, node request/response, and database snapshots. Never relabel this as a policy-engine denial. |
| J. Teardown and verification | Terminate all owned PIDs. A separate verifier reads only raw artifacts, reconstructs every verdict, cites file/PID/run/request plus byte offset or JSON path and derivation rule, and rejects direct `caps.db` authority insertion. | Process-exit records, no-survivor probe, verifier output kept outside the runner facts, and a negative self-test that removes/mutates a critical field in a copied real bundle and observes verifier failure. |

## Unsupported hop: real resolve envelope -> real node import

This binding hop is not constructible at the pinned production revisions:

1. The production sidecar's `SharedGrantIssuer::issue` puts
   `SignedPortableDelegation::encode()` directly in
   `PortableDelegation.encoded`
   (`policy-engine-http/src/lib.rs:217-244`). That encoder produces
   `tc-pdel-v0.<base64url(JCS JSON)>` (`lib.rs:257-343`). This is the real
   `/resolve` output; substituting another `GrantIssuer` is prohibited.
2. The real node `/delegate` request guard converts the Authorization header
   through `TinyCloudDelegation` (`tinycloud-node-server/src/authorization.rs`
   and `routes/mod.rs:213-230`). `TinyCloudDelegation` has only `Ucan` and
   `Cacao` variants. Any dotted string is passed directly to `Ucan::decode`;
   undotted input is decoded as DAG-CBOR CACAO
   (`tinycloud-auth/src/authorization.rs:27-68`).
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

## Park decision

The GRANTISSUER-SEAM CLOSURE says that a non-importable production
`tc-pdel-v0` result parks the ticket and goes to Patrick as a gate/architecture
decision. The constructibility STOP RULE also forbids reinterpreting or
working around this acceptance hop. Therefore this trace is the complete
ticket artifact for this attempt: no runner, verifier, gate script, fabricated
evidence, or behavioral tests are added.

The claim that remains unimplemented is narrowly: after the owner publishes a
monotonic revoked PolicyStatus and redeploys the owner-controlled sidecar from
that authority state, the next real renewal is denied policy-inactive, and the
previously issued short-TTL delegation is refused by the node after expiry,
within the declared TTL bound. This trace makes no claim of live sidecar
propagation, node-confirmed active revocation, redeploy-independent latency, or
instant revocation.
