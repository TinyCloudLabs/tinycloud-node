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
