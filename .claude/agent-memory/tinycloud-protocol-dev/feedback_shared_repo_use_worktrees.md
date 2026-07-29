---
name: shared-repo-use-worktrees
description: When another agent may be active in the tinycloud-node checkout, branch into a separate worktree and share CARGO_TARGET_DIR instead of switching branches in place
metadata:
  type: feedback
---

The `repositories/tinycloud-node` checkout inside a tc-workspace is **shared**
— other agents work in it concurrently and it can be sitting on someone else's
feature branch. Do not `git checkout` a new branch there. Create a worktree
instead, matching the established convention:

`nassau/worktrees/tinycloud-node/<branch-name>` (see `git worktree list`)

Then point `CARGO_TARGET_DIR` at the main checkout's existing `target/`.

**Why:** Switching branches in the shared checkout silently breaks whatever the
other agent is mid-flight on. A fresh worktree gets a cold target dir, and a
full tinycloud-node debug build is expensive (the shared one is ~22GB, and the
disk was at 93% with ~132GB free). Sharing the target dir reuses all the
compiled dependencies, so only the workspace crates rebuild — a full
`cargo build -p tinycloud-core` took ~19s instead of a cold build. Cargo locks
the target dir, so concurrent builds serialize rather than corrupt; the only
cost is fingerprint churn when two source trees alternate.

**How to apply:** Check `git status --porcelain` (clean?), `ps aux | grep cargo`
(active build?), and recent non-target file mtimes before deciding the other
agent is idle. Even when idle, prefer the worktree. Verify the new worktree's
base actually matches expectations — `origin/main` can move mid-session, as it
did during TC-324 when the other agent's PR merged between the initial fetch
and `git worktree add`.

Related: [[concurrency-test-mutation-check]]
