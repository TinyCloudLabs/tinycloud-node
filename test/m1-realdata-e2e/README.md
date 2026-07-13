# M1 real-data in-process contract proof

This excluded crate proves the deterministic m1-g-05a contract and the
m1-g-08 grant-output compatibility contract. It loads
verified composed policy authority, resolves the vendored launch-profile
credential with the pinned policy runtime, reads that resolve's issuance
record, imports its signed UCAN through the node delegation route, and observes
native Listen SQL/KV behavior. It also observes the deterministic mounted
runtime and native denial mappings required by the ticket.

The grant compatibility extension pins the g-06b vector generator and the
g-07 `SharedGrantIssuer` implementation at policy-engine `d72812a`. Frozen
bytes are the signature/CID and default-instant oracle. A temporary
`--output-dir` receives time-valid material for the real node plane. The suite
imports the bounded parent and grants through `/delegate`, exercises every
node-import and node-invocation classification, and invokes named SQL and KV
through `/invoke`. Four independent production-emitter grants cover SQL+KV,
named-statement caveats, and the minimum/maximum TTL bounds. Producer and audit
cases remain explicitly assigned to m1-g-07 in `vendor/grant-output/
SKIP_MANIFEST.json`.

The pinned node has no production route for initial space creation. Following
the W5 recipe, this test directly provisions one space row and its storage
directory solely as a node-storage precondition, then proves delegation and
ability tables are still empty. That setup is not authority evidence; the
authority rows asserted by this proof originate only from the subsequent real
`/delegate` import.

It does not use sockets or claim any correlation with m1-g-05b live issuance.
The only subprocess is the pinned g-06b Python generator, whose current-time
output is written to a temporary directory and checked for semantic
correspondence with every frozen case.

Run it explicitly with the pinned private git dependency:

```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --manifest-path test/m1-realdata-e2e/Cargo.toml
```

## Live M1 gate runner and independent verifier

`scripts/m1-gate-demo.sh` is the A-J real-process runner. It receives all
nonces, randomized SQL bytes, keys, candidate checkouts, and production
commands from the PM. It does not create or rewrite any of them. It records
unmodified stdout/stderr, commands, PIDs, repository SHAs/dirty state, input
hashes, database snapshots, and timestamps under a new raw-bundle directory.
The production commands write their structured raw exchanges through
`$M1_BUNDLE`:

| Command | Required raw JSON path |
| --- | --- |
| `M1_DRIVER_PUBLISH_CMD` | `driver/publish.json` |
| `M1_REQUEST_INITIAL_CMD` | `requester/initial.json` |
| `M1_REQUEST_RENEW_CMD` | `requester/renewal.json` |
| `M1_DRIVER_REVOKE_CMD` | `driver/revoke.json` |
| `M1_REQUEST_DENIED_CMD` | `requester/renewal-denied.json` |
| `M1_POST_EXPIRY_READ_CMD` | `requester/post-expiry-read.json` |

Each exchange is raw producer output with this envelope:

```json
{"runId":"...","requestId":"...","producerPid":123,"request":{},"response":{},"observedAt":"RFC3339"}
```

The initial response carries `/delegation`, `/import/delegation`, `/issuedAt`,
`/expiresAt` and `/reads/sql/sha256`. Renewal carries
`/renewed`. Revoke carries `/disposition`. The denied renewal carries the raw
sidecar `/error/code` plus the SDK consequence `/accessEnded`. The final native
read carries `/layer` and `/refused`. These are producer facts, not
runner-authored verdict fields.

The independent verifier is:

```sh
cargo run --manifest-path test/m1-realdata-e2e/Cargo.toml \
  --bin m1-gate-verify -- RAW_BUNDLE --self-test
```

It derives a pass only from the closed raw bundle, emits per-assertion
citations, and removes the real bundle's renewal-denial code from a temporary
copy to prove it fails closed. Its claim is exactly: after the owner publishes
a monotonic revoked PolicyStatus and redeploys the owner-controlled sidecar
from that authority state, the next real renewal is denied policy-inactive,
and the previously issued short-TTL delegation is refused by the node after
expiry, within the declared TTL bound. It does not claim live propagation into
a running sidecar, node-confirmed active revocation, revocation-to-denial
latency independent of redeploy, or instant-revoke behavior. The bound starts
at successful redeploy.
