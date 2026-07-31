---
name: concurrency-test-mutation-check
description: Mutation-check lock/concurrency tests in both directions before calling them a deliverable — a passing suite proves nothing about a lock
metadata:
  type: feedback
---

When tests for a locking or concurrency change are part of the deliverable,
mutation-check them in **both** directions before reporting: revert the
optimization (does the perf/concurrency test fail?) and break the security
invariant (do the safety tests fail?). Report the mutation results, not just
"tests pass".

**Why:** Sam framed TC-324 as "these tests are the deliverable as much as the
code" and "precision matters more than speed here." A concurrency test that
passes under both the old and new lock mode is theater. Doing this on TC-324
surfaced something that would otherwise have been missed: the pre-existing
`revoke_winner_serializes_before_descendant_issue_and_use_checks` test **still
passed** when the revocation guard was deliberately weakened to shared — it
only ever exercised exclusive-vs-exclusive, so it could not detect the exact
regression that mattered. That gap justified the new tests and became the most
persuasive paragraph in the PR.

**How to apply:** For any lock, ordering, isolation-level, or race-condition
change. Cheap recipe: `cp` the file, apply the mutation with `perl -0pi -e`,
run the targeted tests, restore from the copy. Also prefer assertions that are
*unsatisfiable* without the property (a `tokio::sync::Barrier` inside the
guarded section proves overlap in time; `assert!(all_succeeded)` does not), and
assert durable state (`is_revoked` is still false) rather than scheduler state
(`!handle.is_finished()`) wherever possible.

Related: [[shared-repo-use-worktrees]]
