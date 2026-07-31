---
name: chain-guard-contention
description: Chain-guard lock contention (not the DB) is the tinycloud-node scaling bottleneck; why, and the two follow-on gaps TC-324 deliberately left open
metadata:
  type: project
---

The first prod stage telemetry (node 1.11.0, 2026-07-29) showed the invocation
bottleneck is **in-process lock contention, not the database**:
`chain_guard_wait` n=242 avg=2.852s total=690.1s, against `db_tx_body` 1.542s,
`chain_closure_query` 0.133s, `db_pool_acquire` 0.068s.

**Why:** prod's dominant writer runs all of its traffic under a single account,
so every request cites the same root delegations, hits the same ancestor
closure, and serializes against itself node-wide. This is structural, not a
tuning problem — any per-account workload shape reproduces it.

**How to apply:** When reasoning about tinycloud-node throughput, suspect the
chain guards and the account/space fan-out shape before suspecting SQL. Two
gaps were left open on purpose by TC-324 (PR #183, "take chain guards shared
for invocations", part of the TC-318 scaling review wave):

1. **These guards are process-local.** Multi-node deployment still needs
   Postgres advisory locks to enforce revocation ordering across processes.
   Nothing today provides that. Flag it on any horizontal-scaling proposal.
2. **The guard key set is computed outside the guard.** The invocation path
   runs `load_closure_edges` on `self.conn`, *then* acquires guards, so a
   concurrent delegation can extend the closure in between and the guard set
   can be a strict subset of the real closure. Pre-existing and unchanged; the
   authoritative re-walk happens inside the transaction via
   `AuthGraphSnapshot::load`. Worth a dedicated issue, not a drive-by fix.

Also settled while reviewing this: invocations write `parent_delegations` rows,
but only **leaf** edges whose `child` is the invocation's own hash, and nothing
in the codebase traverses that table downward (no `Column::Parent.eq(..)`
anywhere). That is what makes shared guards safe for invocations — re-verify
that downward-traversal claim if anyone adds a descendant/cascade query.

Related: [[concurrency-test-mutation-check]]
