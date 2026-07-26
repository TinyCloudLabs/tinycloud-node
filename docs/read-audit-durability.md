# Authenticated read audit durability

TinyCloud separates successful non-mutating invocations from the mutation
epoch graph.

## Response contract

- Authorization, including current leaf and ancestor revocation state, is
  checked for every request while its chain guard is held.
- KV and capability reads run on ordinary database connections and do not
  acquire the database writer lock.
- A successful response is not acknowledged until the invocation,
  invoked abilities, and parent-delegation references have committed to the
  database.
- Concurrent read audits are group committed. A failed audit transaction fails
  every response in that group; an uncommitted audit is never acknowledged.
- Missing values, authorization failures, and failed reads are not recorded as
  successful read audits, matching the previous transaction rollback behavior.

## Mutation contract

KV writes/deletes, delegations, and revocations retain their existing atomic
epoch/event transaction. They commit before acknowledgment and share one writer
lock with audit batches on SQLite. Read audits are deliberately absent from the
mutation epoch graph, so read traffic cannot advance or contend on per-space
mutation sequence numbers.

SQLite runs in WAL mode with a reader pool. The shared writer lock prevents
writer-upgrade deadlocks while WAL readers continue to authorize and fetch data.
PostgreSQL keeps its normal connection pool; the same response and audit
durability contract applies.

### `synchronous=NORMAL` and the durability contract (TC-284)

The SQLite capability database runs with `PRAGMA synchronous = NORMAL` under
WAL mode rather than the compiled-in default `FULL`. Under WAL, `NORMAL`
cannot corrupt the database, but it fsyncs less often: a commit can be
acknowledged to the application before it is durable to disk, and a subset of
the most recent committed transactions can be lost on power loss, an abrupt
host crash, or a CVM kill. This weakens "committed to the database" and
"commit before acknowledgment" above from durable-to-disk to durable-to-OS
(the transaction has been handed to the OS's page cache and will survive a
process crash, but not a hardware/host-level failure) for KV writes/deletes,
delegations, and revocations alike — losing an acknowledged revocation on
crash is a security-relevant regression, not merely a data-loss one, and this
matters more on dstack/Phala CVM deployments where abrupt host loss is
plausible. This trade-off should be reviewed and explicitly signed off by a
human before it ships; see the TC-284 PR description.
