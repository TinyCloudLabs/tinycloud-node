# `/invoke` per-request DB statement budget (TC-411)

This document records the exact SQL statement budgets enforced for a single
`/invoke` request. The budgets are checked in as counting-seam tests
(`tinycloud-core/src/auth_graph.rs`, `tinycloud-core/src/db.rs`); a regression
in any of these numbers is a test failure, not just a benchmark regression.

## Authorization graph load

Before TC-411, `validate` re-walked the proof closure once for chain-lock key
derivation and again (per ancestor) for revocation checks and chain-window
validation. TC-411 builds one invocation-scoped `AuthGraphSnapshot` after the
shared chain guards are acquired:

1. Derive the guarded closure on the guarded connection and require it to
   match the pre-guard `lock_keys` **exactly** (`AuthGraphSnapshot::load_guarded`).
   A mismatch is treated the same as a database failure: fail closed.
2. Batch-load, one query each, for every node in the bounded closure (not
   just the cited proof roots): delegation rows, ability/caveat rows, and
   revocation rows.
3. Run all chain, revocation, and caveat-containment checks against that one
   in-memory snapshot for the rest of the request.

Ability/caveat rows are loaded for the whole closure — cited roots *and*
their ancestors — because `constrained_statement_caveat_candidates` walks
each root's ancestor chain looking for a caveat. An ancestor-only caveat (the
descendant delegation carries none of its own) must still be visible, and it
is already part of the bounded, already-loaded closure, so this costs no
extra statement.

### Structural statement counts

| Depth | Closure query | Delegation | Ability | Revocation | Total |
|-------|---------------|------------|---------|------------|-------|
| 0 (no proof) | 0 | 0 | 0 | 0 | **0** |
| 1 (delegated) | pre-guard + guarded (2) | 1 | 1 | 1 | **5** |
| 4 (delegated)| pre-guard + guarded (2) | 1 | 1 | 1 | **5** |

Depth 4 equals depth 1: statement count is independent of chain depth
because every node in the closure is loaded in one `IN (...)` query per
table, not one query per ancestor. Counts are asserted directly in
`auth_graph::tests::snapshot_depths_zero_one_and_four_match_per_node_traversal`
and `auth_graph::tests::snapshot_query_batches_are_bounded_versus_depth_amplified_traversal`.

The closure itself is capped at `MAX_CHAIN_TRAVERSAL_NODES`; traversal beyond
that limit is rejected (`ChainTraversalError::LimitExceeded`), never
truncated, so these batched queries stay bounded in size regardless of chain
shape.

## KV operation statement shapes

These counts cover the request body only (pool acquisition, transaction
begin/body, closure/graph load, replay, and audit remain as before — see
below — and are not re-counted here):

| Operation | Index/read work | Notes |
|-----------|------------------|-------|
| `kv/get` | 1 statement | Single current-state read; batched via `batch_get_kv_entities` so an N-item batch of `get`/`metadata` capabilities in one invocation still costs 1 statement, not N. |
| `kv/head` (metadata) | 1 statement | Same batched read path as `get`, object body not fetched from block store. |
| `kv/list` | 1 statement | Single bounded index scan regardless of result page size. |
| `kv/put` | graph load + 1 persistence | Object bytes are written to the object store *before* the DB transaction begins (see "Transaction boundaries" below); history (`kv_write`) and projection (`current_kv`) persistence for every put in the invocation is batched into exactly 2 statements independent of item count (`invocation::save`, via `kv_write::Entity::insert_many` + `upsert_current_kv_batch`). |
| `kv/delete` | 0 extra statements when reused | `db.rs` already loads the current `current_kv` row (including its owning `invocation` id) for the precondition/version check; that id is threaded through `VersionedOperation::KvDelete::deleted_invocation_id` and `invocation::resolve_deleted_invocation_id` returns it directly instead of re-querying `kv_write`. Falls back to one lookup only when deleting a key with no live current row (never written, or already deleted). |

### Batch and multipart statement counts

| Operation | Statement count | Test |
|-----------|------------------|------|
| Batch get/head, 1 item | 1 statement | `db::test::batch_get_kv_entities_issues_one_statement_regardless_of_item_count` |
| Batch get/head, 10 items | 1 statement | same test |
| Batch put (multipart history/projection), 1 item | 2 statements | `models::invocation::tests::multipart_put_persistence_is_two_statements_regardless_of_item_count` |
| Batch put (multipart history/projection), 10 items | 2 statements | same test |
| `kv/delete` with pre-loaded current state | 0 statements | `models::invocation::tests::delete_reuses_preloaded_invocation_id_without_extra_kv_write_query` |
| `kv/delete` without pre-loaded current state (fallback) | 1 statement | same test |

Each test wraps a real `sea_orm::DatabaseConnection` with `set_metric_callback`
to count every SQL statement executed, so these are exact counts, not
estimates.

## Replay and audit

- **Replay protection** remains exactly one durable, atomic uniqueness
  insert attempt performed before any side effect. This is unchanged by
  TC-411: timestamps only bound retention and are never the replay decision.
- **Isolated read-audit persistence** is at most four statements per
  committed batch.
- `event_spaces` only performs a revocation lookup when the batch actually
  contains a `Revocation` event; a batch with none skips the round trip
  entirely instead of issuing an empty `IN (...)` query.

## Transaction boundaries

No explicit database transaction spans an object-store read/write or
tenant-SQL execution:

- Immutable blobs are persisted to the object store before publication in
  the DB. If the object-store write fails, publication never happens. If the
  object store succeeds but the following database write fails, the result
  is an unreachable content-addressed blob — never one that is addressable
  through committed KV state.
- Tenant SQL execution (the SQL capability path) is likewise kept outside
  the KV authorization/mutation transaction boundary.

## Unaffected stages

The following per-request stages retain their existing shape and are
explicitly out of scope for this change: pool acquire, transaction
begin/body, guard wait, replay, and audit wait. The periodic pool probe is a
pool-level background operation, not a per-request statement, and is not
counted against any request's budget.

## Out of scope / excluded from these budgets

Setup, migrations, retention pruning, telemetry probes, object-store calls,
and cold SQL hydration are excluded from the counts above and are reported
separately (see `tinycloud-core/src/telemetry.rs` stage labels).

## Security invariants preserved

- Revocation remains immediate and fail-closed: the shared chain guards
  cover the full closure through authorization and mutation commit, and a
  guarded-state mismatch (or a database failure while re-deriving it)
  rejects the request rather than falling back to the pre-guard read.
- No pre-guard snapshot is ever used to authorize a request; only the
  guarded, re-verified snapshot is used for authorization/mutation
  decisions.
- Ancestor caveats and caveat containment remain binding: a uniquely
  tightest contained caveat wins, and incomparable candidates return 403.
- A caveat that declares itself `constrained-statements` (directly or nested
  under a `"constrained-statements"` key) but fails to parse is a malformed
  *declared* caveat, not an unrelated one:
  `AuthGraphSnapshot::constrained_statement_caveat_candidates` returns an
  error for it (`TxError::MalformedSqlCaveat`, mapped to `403 Forbidden`)
  instead of silently dropping it as if the grant were unconstrained. See
  `auth_graph::tests::constrained_statement_caveat_candidates_fails_closed_on_malformed_direct_caveat`,
  `..._malformed_nested_caveat`, and `..._malformed_ancestor_caveat`.
- A cyclic `parent_delegations` closure is rejected outright
  (`load_closure_edges` runs a cycle check over the loaded closure before it
  is used to derive lock keys or the snapshot) rather than being silently
  accepted because a per-node visited-set traversal would otherwise
  terminate against the cycle. See
  `auth_graph::tests::load_closure_edges_fails_closed_on_cyclic_proof`.
- Closure memory and cycle-detection recursion are bounded by distinct node
  count, not edge count: a wide (fan-out) graph can hold far more distinct
  nodes than `MAX_CHAIN_TRAVERSAL_NODES` while its edge count stays far
  below `edge_cap` (`MAX_CHAIN_TRAVERSAL_NODES^2`), since each node may have
  only one edge. `load_closure_edges` rejects on distinct-node count before
  `has_cycle`'s recursion ever runs over it. See
  `auth_graph::tests::load_closure_edges_fails_closed_on_wide_over_limit_graph`.
- No cross-request authorization cache is introduced by this change.
