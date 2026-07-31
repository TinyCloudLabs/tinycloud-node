# Memory Index

- [Mutation-check concurrency tests](feedback_concurrency_test_mutation_check.md) — for lock/ordering changes, break the code both ways and prove the tests catch it
- [Shared repo: use worktrees](feedback_shared_repo_use_worktrees.md) — don't switch branches in the shared tinycloud-node checkout; worktree + shared CARGO_TARGET_DIR
- [Chain-guard contention](project_chain_guard_contention.md) — locks, not SQL, are the node bottleneck; plus the process-local and closure-TOCTOU gaps left open
