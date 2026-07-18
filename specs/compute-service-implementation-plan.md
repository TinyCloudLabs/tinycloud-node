# Compute Service — Lean Implementation Plan (Smithers)

**Date:** 2026-07-10 (rev 2026-07-18, Codex review applied — all 12 findings)
**Companion to:** `specs/compute-service.md` (design; referenced as §N, not restated)
**Review:** `specs/compute-service-plan-codex-review.md` (C1–C12, all accepted)
**Execution model:** Smithers durable plan→implement→review→fix→verify.

Pipeline: **P0 skeleton → P1 deploy → P2 execute (KV CRUD + SQL) → P3-SDK
(node-SDK + cross-repo E2E)**. P4 is a deferred list, not executed. Exactly
**one** human gate (security review after P2); every other approval — including
P3-SDK's session-grant check — is a machine assertion (C12). Stages run as
**judged parallel implementations** (multiple implementers per stage in separate
worktrees, fable + codex judges pick the winner), so the gates are the arbiter.

Crate names: server = `tinycloud-node` (dir `tinycloud-node-server/`), core =
`tinycloud-core`. Integration tests live in `tinycloud-node-server/tests/`. The
`js-sdk` repo is a workspace member (P3-SDK).

---

## Smithers node template

```
node <phase>:
  task:    <one-line implementer prompt>
  verify:  <named commands; each MUST exist and exit 0>
  suffix:  cargo fmt -- --check
           cargo clippy --features compute -- -D warnings
           cargo test                                          # feature OFF stays green
           cargo test -p tinycloud-node --test compute_disabled  # named 501/not-supported gate (C5)
  fix_loop: verify fail → review diff+error → patch → re-verify (max 3, then escalate)
```

`--test` targets are **named files** (not name filters): `cargo test ... compute::x`
passes when zero tests match, so it is banned as a gate (C5). Use
`cargo test -p <crate> --test <file> --features compute`, which errors if the test
file is absent. The `suffix` block runs on **every** node.

---

## P0 — Walking skeleton (service exists, disabled by default)

- capabilities.json reserved entries `compute/{execute,deploy,list,*}` (§3.1,
  wildcard no `implies` while reserved) + `gen-capabilities.mjs` regen.
- `compute` cargo feature; stub `ComputeService`; dispatch branch + 501-disabled
  path (§7.1); `/version` feature (§11.2).
- **Request-variant → ability mapping** as a first-class deliverable (§7.1
  erratum, C1): `RoutineDid`/`Deploy`→`compute/deploy`, `Execute`→`compute/execute`,
  `List`→`compute/list`, via `ability_matches`. Lands here as the enforced gate
  even though only the enabled variants exist yet.

**verify**
- `node scripts/gen-capabilities.mjs --check`
- `cargo test -p tinycloud-core policy_capability` (drift guards)
- `cargo test -p tinycloud-node --test compute_skeleton --features compute` —
  asserts: `/version` lists `compute`; an enabled dispatch reaches the handler;
  **a wrong-ability request is rejected** (an `Execute` capability presenting a
  `Deploy` body → 403, and vice-versa); **a `List` body is rejected while reserved**
  (no server-side listing handler exists in the MVP — assert the reject path, C1).
- `cargo test -p tinycloud-node --test compute_disabled` — the named feature-off
  gate: with `compute` off, a `tinycloud.compute/*` request returns 501/not-supported
  (C5). Also runs in the shared suffix.
- suffix.

---

## P1 — Deploy path (transaction seam + handshake + hashed-space identity)

The transaction seam is a **core primitive**, not a service-module change (C2):
`TinyCloud::delegate` opens its own txn (`db.rs:513-535`),
`DatabaseArtifactRepository::save` owns a `DatabaseConnection` with no txn param
(`database_artifacts.rs:28-53`), and `SqlSizes` is an infallible in-memory mirror
(`sql_sizes.rs:108-120`). So P1 must:

- Add a **`RoutineKeyDeriver`** interface in `tinycloud-core` (C11), injected from
  the server crate with `dstack` (`dstack.rs:106-119`) and classic
  (`keys.rs:57-74` `StaticSecret::derive_key`) impls — `dstack::get_key` is
  server-only, so core cannot call it directly. Derivation **hashes the space
  component** (§6.2, C8); no global `Name` change (deferred to P4).
- `RoutineDid { content_cid }` handshake → returns the **public** `routine_did`
  (§7.2/F2). Gated by the C1 mapping (needs `compute/deploy`).
- A dedicated **core deploy primitive**: one SeaORM transaction that runs
  delegation validation/persistence + **transaction-aware** artifact persistence,
  commits, then updates the infallible `SqlSizes` mirror (mirror-after-commit).
  Revoke the superseded `D_fn` on re-deploy (§5.1).
- **Transport (C7):** JSON body + base64 WASM + **inline** encoded `D_fn` only.
  Raw streaming and pre-submitted grant CIDs are deferred (P4).

**verify**
- `cargo check --features compute,dstack` (the feature combo compiles — C11)
- `cargo test -p tinycloud-node --test compute_deploy --features compute` —
  asserts: **atomic rollback** (D_fn-verify-fails ⇒ no artifact row **and** no
  `SqlSizes` delta; artifact-persist-fails ⇒ no delegation row); **mirror only
  after commit**; **superseded-grant revocation** on re-deploy; **quota** (deploy
  bumps `store_size`, over-quota deploy → 402); **handshake** returns a stable
  public `routine_did`; **`RoutineDid` body with the wrong ability is rejected**
  (a non-`compute/deploy` capability presenting a `RoutineDid` body → 403, C1);
  **hashed-space** collision-freedom (two delimiter-laden space names never
  collide, §13.1).
- `cargo test -p tinycloud-core --test routine_key_deriver` — the `RoutineKeyDeriver`
  **trait** unit test with the **classic** impl only (core has no dstack adapter).
- `cargo test -p tinycloud-node --test compute_routine_key --features compute,dstack`
  (with `DSTACK_SIMULATOR_ENDPOINT` set) — the dstack-**simulator** adapter lives in
  the server crate, so its machine-checked determinism test lands there (C11, defect b).
- suffix.

> **Deployment-readiness gate (NOT a test, C11):** real cross-CVM-redeploy
> `routine_did` equality must be verified empirically on the target CVM (§6.2
> box). The simulator unit test does not prove it. Record as a release
> precondition, separate from the phase's machine gate.

---

## P2 — Wasmtime execute (KV CRUD + SQL host surface)

First end-to-end least-privilege slice. Scope expanded from the earlier
KV-read-only cut: the MVP host surface is **KV CRUD + SQL** (supersedes C4).

- **Pinned WASM ABI (C3) — stated, not "TBD":**
  - **core module** (NOT a component);
  - guest exports `alloc(len: i32) -> ptr: i32` (guest owns its linear memory;
    the host writes args into guest memory via `alloc`) and
    `run(ptr: i32, len: i32) -> (ptr: i32, len: i32)` (the single entrypoint);
  - **four host imports, module name `"tinycloud"`**, each
    `(ptr: i32, len: i32) -> (ptr: i32, len: i32)`: `storage_get`, `storage_put`,
    `storage_del`, `sql_query`;
  - **all payloads are JSON bytes** in guest memory: `run` in = JSON request,
    out = JSON result; `storage_{get,put,del}` arg = JSON key/value ref, return =
    JSON value/ack; `sql_query` arg = JSON request, return = JSON rows — aligned
    with the existing `SqlRequest` / `SqlResponse` shapes.
  (Names may change only if the same completeness bar — module names, signatures,
  memory ownership, encoding — stays fully stated.) The exact fixture — module
  shape, per-step request/response JSON, denial contract, and expected manifest —
  is pinned in **spec Appendix A (`compute_fixture`)**; both implementers build
  against it and both judges score against it. Gated by that checked-in WAT
  fixture (get/put/del/sql).
- **Mediated host surface + the SERVER-crate executor seam (supersedes C4):** each
  import is mediated under its `D_fn` ability — `storage_get`→`kv/get`,
  `storage_put`→`kv/put`, `storage_del`→`kv/del`, `sql_query`→`sql/read|write` per
  the existing SQL tiers (§9.1). The injected **internal-invocation executor** is
  **composed in the server crate** (`tinycloud-node-server`), because KV runs via
  `SpaceDatabase::invoke` (`db.rs:620-720`) but **`SqlService` lives behind the
  route layer, not in `tinycloud-core`** — both must be reachable from the seam, so
  it cannot be core-only (§8.2). `sql_query` runs through the existing
  `create_authorizer` path, so SQL statement/table restrictions still apply. A
  bare `process()` only persists+returns a hash and cannot return KV data or run
  SQL.
- Host mediator: caveat-echo verbatim (§6.2/F1); `(space, functionCid)` cite-all
  `D_fn` selection (§5.1/F3/F5).
- Full caveat enforcement (§10.1): fuel, epoch, `StoreLimits`, chain-derived
  `functions` allowlist, input schema, numeric ceilings, forbidden imports.
- `routine-identity-rotated` tripwire (§6.2/F1.5); execution manifest in outcome
  metadata (§9.1.1).
- `InvocationOutcome::ComputeResult` + responder arm (§7.3). (`ComputeList` NOT
  here — C9, deferred.)
- **Registry active-flip for `execute`+`deploy`** happens at the END of P2 (C10),
  per the spec's "when the handler ships" rule — reserved URNs are already
  exercisable by any caller (`accepted_actions` includes reserved,
  `gen-capabilities.mjs:121-127`), so the old deny-by-default rationale was wrong.
  `list` stays reserved. Extend `canonical_decisions_are_locked`.

**verify** (every advertised control gets a focused test — C6)
- `cargo test -p tinycloud-node --test compute_execute --features compute` —
  asserts EACH: **per-import allowed/denied** — `storage_get`/`storage_put`/
  `storage_del`/`sql_query` each SUCCEED under a granting `D_fn` (`kv/get`,
  `kv/put`, `kv/del`, `sql/read|write`) and FAIL CLOSED without it; **SQL
  statement-level authorizer** still rejects an out-of-policy statement via
  `create_authorizer` even with `sql/*`; caveat-echo reject
  (`invocation-caveats-not-subset-of-chain`) + invoker-side echo reject;
  cross-space isolation; rotation (`routine-identity-rotated`, not 403);
  `functions` allowlist; **fuel exhaustion** trap; **epoch/timeout** trap;
  **memory-growth** failure (`StoreLimits`); **input-schema** reject;
  **numeric-ceiling** reject; **forbidden import** reject; **full manifest shape**
  (per-call `(resource, ability, bytes_in/out, destination)` + granted-vs-exercised,
  incl. a granted-but-unexercised case, §9.1.1).
- `cargo test -p tinycloud-node --test compute_abi --features compute` — the WAT
  fixture exercises the pinned ABI: `run` export + all four imports
  (`storage_get`/`storage_put`/`storage_del`/`sql_query`) mediated.
- **E2E** (real server, the P2 acceptance gate — C6): `cargo test -p tinycloud-node
  --test compute_e2e --features compute` — boots a node on an ephemeral port,
  health-waits, a routine does a granted read AND a granted `storage_put` AND a
  granted `sql_query` (manifest shows each exercised) and is **denied** on an
  **ungranted** path (host call fails closed), invoker holds NO data caps
  throughout; tears the node down (timeout 60s).
- `node scripts/gen-capabilities.mjs --check` (active-flip regen committed).
- suffix.
- **HUMAN GATE (the only one, C12):** a security review of the completed P2 slice
  — the ability mapping, per-import mediation + SQL authorizer, caveat-echo
  enforcement, cross-space isolation, and the active-flip diff. All other checks
  above are assertions, not reviews.

---

## P3-SDK — node-SDK compute module + true cross-repo E2E

The js-sdk repo is a member of this workspace, so real end-to-end via the node
SDK is in scope (re-added). One page.

- **Minimal node-SDK compute module:** `deploy(wasm, grant)` and
  `execute(fn, input)`. `deploy` sends the MVP transport (JSON + base64 WASM +
  inline `D_fn`, §7.2); `execute` sends a `compute/execute` invocation and returns
  `{ result, manifest }`.
- **Session-grant rule (F9, enforced here):** the standard session grant
  enumerates **`compute/execute`** (and `compute/list` only once it ships) and
  **NEVER `compute/*`**. `deploy` is reachable **only via an explicit privileged
  flow** (a separately-minted `compute/deploy` grant), not the standard session.
- **E2E harness (the gate):** `<js-sdk>/test/compute_e2e` — start a
  compute-enabled node (`cargo run --features compute` or the P2 test binary) on
  an **ephemeral port**, health-wait; via the SDK: create a space, deploy the
  fixture routine, mint the routine grant (`D_fn`) + the invoker grant
  (`compute/execute` only), `execute`, then assert: **output** matches, **manifest**
  shows the exercised imports, and **≥1 denial** — an ungranted-path read fails
  closed AND a wrong-ability deploy (standard session, no `compute/deploy`) is
  rejected. **Teardown** the node. **120s timeout.**

**verify**
- `cargo build --features compute` (node builds for the harness)
- the E2E harness command (exact, from the js-sdk package — e.g.
  `bun test test/compute_e2e.ts` / `npm run test:compute-e2e`, whichever the
  js-sdk package defines), which boots the node on an ephemeral port, runs the
  scenario above, asserts output + manifest + the two denials, and tears down;
  **120s timeout**.
- suffix (node crate stays green).

> Cross-repo note: this stage spans two workspace members (node + js-sdk). It
> runs AFTER P2's active-flip so the abilities it grants are live. The session
> grant assertion (`compute/*` absent) is machine-checked by grepping the emitted
> grant in the harness, not by human review.

---

## P4 — Deferred (NOT executed in this plan)

One line each on *why*:

- **`compute/list`** (C9): no server-side listing exists (`DatabaseArtifactRepository`
  has only `load`/`save`, `database_artifacts.rs:28-44`); stays reserved (SDK
  `list` waits for it).
- **Streaming / multipart deploy transport + pre-submitted grant CIDs** (C7):
  contradicts inline atomic grant persistence; JSON/base64 suffices first.
- **Global `Name` hardening** (C8): a compatibility-sensitive auth-wide task,
  independent of compute (compute uses hashed-space derivation instead).
- **Cloudflare backend / ZK / container backend** (§9.2/§12.2/§9.4): second trust
  models; land the in-node wasmtime slice first.

> Note: KV-write and SQL host calls, previously deferred here, are now **in P2**
> (scope expansion).

## Sequencing

Pipeline: **P0 → P1 → P2 → P3-SDK**, a strict precondition chain (each gate is
the next stage's precondition); the registry active-flip is P2's final step and
P3-SDK depends on it. **Execution model:** stages are run as *judged parallel
implementations* — multiple implementers race each stage in separate worktrees
and fable + codex judges pick the winner — so the plan's gates are the arbiter,
not a single author. No hand-edits to `generated.rs`; registry changes go through
`gen-capabilities.mjs` + drift guards, in every stage.
