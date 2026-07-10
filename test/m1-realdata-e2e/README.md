# M1 real-data in-process contract proof

This excluded crate proves the deterministic m1-g-05a contract. It loads
verified composed policy authority, resolves the vendored launch-profile
credential with the pinned policy runtime, reads that resolve's issuance
record, imports its signed UCAN through the node delegation route, and observes
native Listen SQL/KV behavior. It also observes the deterministic mounted
runtime and native denial mappings required by the ticket.

The pinned node has no production route for initial space creation. Following
the W5 recipe, this test directly provisions one space row and its storage
directory solely as a node-storage precondition, then proves delegation and
ability tables are still empty. That setup is not authority evidence; the
authority rows asserted by this proof originate only from the subsequent real
`/delegate` import.

It does not use subprocesses, sockets, or claim any correlation with m1-g-05b
live issuance.

Run it explicitly with the pinned private git dependency:

```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --manifest-path test/m1-realdata-e2e/Cargo.toml
```
