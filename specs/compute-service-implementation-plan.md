# Compute Service — Lean Implementation Plan (Smithers)

**Date:** 2026-07-10
**Companion to:** `specs/compute-service.md` (the design; this plan references
its sections — §N — instead of restating them)
**Execution model:** Smithers (`smithers.sh`) durable
plan→implement→review→fix→verify workflow, one node per phase, human approval at
each phase boundary.

Lean rules for this plan: smallest end-to-end vertical slice first; every phase
ends in a **machine-verifiable gate**; no phase does speculative work for a later
phase. Cloudflare / ZK / containers are **out of this plan's execution** (P4).

All `cargo` commands assume the worktree root
`worktrees/tinycloud-node/skgbafa/compute-service-spec`.

---

## Smithers node template (applies to every phase)

```
node <phase>:
  task:    <one-line implementer prompt>            # plan→implement
  verify:  <command(s)>; non-zero exit = fail       # machine gate
  fix_loop: on verify fail → review diff + error → patch → re-verify
            (max 3 iterations, then escalate)
  approve:  human approval gate at phase boundary    # blocking, before next node
```

Retry/fix is the standard Smithers loop; only the per-phase `task`, `verify`, and
any phase-specific gate note are given below.

---

## P0 — Walking skeleton (service exists, disabled by default)

The thinnest slice that compiles, gates on the feature flag, and passes drift
guards. No execution logic.

- capabilities.json reserved entries for `compute/{execute,deploy,list,*}` (§3.1,
  reserved-first, wildcard carries **no** `implies` while reserved).
- `node scripts/gen-capabilities.mjs` regen of `generated.rs` + `capabilities.ts`.
- `compute` cargo feature in `tinycloud-node-server/Cargo.toml`; empty
  `ComputeService` managed under `#[cfg(feature="compute")]` (§11.1).
- Dispatch branch + 501-when-disabled path (§7.1); `/version` feature (§11.2).

**Smithers node**
- task: "Add compute reserved registry entries + regen codegen; add the `compute`
  cargo feature, a stub `ComputeService`, the invoke dispatch branch, and the
  501-disabled path per §3.1/§7.1/§11."
- verify:
  - `node scripts/gen-capabilities.mjs --check`
  - `cargo test -p tinycloud-core policy_capability` (drift guards:
    `generated_module_matches_registry`, `canonical_decisions_are_locked`)
  - `cargo test` **feature off** AND `cargo test --features compute` **on**
  - `cargo clippy --features compute -- -D warnings`
- gate: both feature states green + drift guards green.
- approve: human confirms registry entries are reserved (not active) before P1.

---

## P1 — Deploy path (artifact + grant, atomic)

Deploy stores the WASM and binds its data grant, atomically, with quota — plus
the read-only identity handshake the client needs first.

- `RoutineDid { content_cid }` read-only action → derives + returns the **public**
  `routine_did` (§7.2/F2). Derivation string per §6.2 (`compute-key/v1/` +
  `<space>/compute/<cid>`). **Prereq:** space `Name` delimiter validation (or
  hash-the-space) — the blocking safety item in §6.2 (currently a stubbed TODO in
  `tinycloud-auth/src/resource.rs`).
- Deploy: `DatabaseArtifactRepository::save("compute", …)` + `D_fn` through the
  standard `/delegate` verify/persist path + `sql_sizes.update("compute", …)` —
  **all in one transaction** (§5.1/F4, §5/F8). Revoke superseded `D_fn` on
  re-deploy.

**Smithers node**
- task: "Implement the `RoutineDid` handshake (with the §6.2 space-name
  validation prereq) and the atomic deploy path (artifact + D_fn via /delegate +
  SqlSizes) per §5.1/§7.2."
- verify:
  - `cargo test --features compute compute::deploy` — the §13.1 **atomicity**
    (D_fn-fails ⇒ no artifact row / no SqlSizes entry, and vice-versa),
    **quota** (deploy bumps `store_size`; over-quota deploy 402s), **handshake**
    (returns a stable public `routine_did`), and **space-name-validation** tests.
  - `cargo clippy --features compute -- -D warnings`
- gate: those four §13.1 tests pass.
- approve: human confirms atomicity test genuinely exercises rollback (both
  failure directions) before P2.

---

## P2 — Wasmtime execute (the core slice)

The first end-to-end "run a function over space data under least privilege."

- Host mediator: mints internal invocations under the selected `D_fn`, **echoing
  its caveat map verbatim** (§6.2/F1), entering via core `process()` not the HTTP
  route (§8.2). `(space, functionCid)` cite-all `D_fn` selection (§5.1/F3/F5).
- `WasmtimeBackend::run`: fuel + epoch + `StoreLimits` caveat enforcement (§10.1);
  no WASI net/fs.
- `routine-identity-rotated` compare-on-execute tripwire (§6.2/F1.5).
- Execution manifest in `InvocationOutcome` metadata (§9.1.1).
- `InvocationOutcome::ComputeResult`/`ComputeList` + responder arms (§7.3).

**Smithers node**
- task: "Implement the wasmtime execute path: host mediator with caveat-echo +
  (space,cid) selection, fuel/epoch/StoreLimits enforcement, rotation tripwire,
  and the execution manifest, per §6.2/§9.1.1/§10.1."
- verify:
  - `cargo test --features compute compute::execute` — §13.1 **caveat-echo**
    (non-echoed internal invocation rejected `invocation-caveats-not-subset-of-
    chain`), **cross-space isolation** (space-B execution can't cite space-A
    `D_fn`), **rotation** (`routine-identity-rotated`, not 403), **manifest**
    (granted-vs-exercised present).
  - **E2E fixture** (integration test, real server): a routine reads a *granted*
    KV path (succeeds, manifest shows it exercised) and is denied on an
    *ungranted* path (host call fails closed, invoker holds no data caps
    throughout).
  - `cargo clippy --features compute -- -D warnings`
- gate: the §13.1 execute tests + the E2E granted/denied fixture pass.
- approve: human reviews the E2E fixture output (granted read succeeds, ungranted
  read denied, invoker never held data caps) before P3.

---

## P3 — SDK surface (typed access, safe defaults)

Make the service usable from the TS SDK without handing browser sessions deploy
rights.

- `execute` / `list` on the compute service (mirror the KV/SQL service class
  pattern); the standard session grant enumerates **`compute/execute` +
  `compute/list`**, and **NEVER `compute/*`** (§3/F9).
- Deploy exposed only via an explicit **privileged** flow (not the standard
  session), consistent with the deploy-tier decision (§3).

**Smithers node**
- task: "Add the compute SDK service (execute/list) and wire the standard session
  grant to enumerate execute+list only — never compute/* — with deploy behind an
  explicit privileged path, per §3/F9."
- verify:
  - SDK integration test against a running compute-enabled node: standard session
    can `execute`/`list`; a standard-session `deploy` attempt is rejected; a
    privileged deploy succeeds.
  - `cargo test --features compute` (node regression stays green)
- gate: SDK integration test passes; the "standard session cannot deploy"
  assertion is present and green.
- approve: human confirms the session grant does not contain `compute/*`
  (grep the emitted grant) before closing the run.

---

## P4 — Explicitly deferred (NOT executed in this plan)

- **Cloudflare backend** (§9.2): needs the Outbound-Worker egress mediation,
  ephemeral `D_worker` mechanics, and a CF account in the TCB — a second backend
  with its own trust model; land the wasmtime slice first.
- **ZK verification** (§12.2): prover can't run in a Worker; needs a RISC-V build
  + async two-phase `verify()`; no consumer yet.
- **Container/VM backend** (§9.4, iron-proxy pattern): future egress-mediated
  backend; not needed for the in-node slice.

---

## Cross-cutting gates (every phase)

- `cargo clippy --features compute -- -D warnings` (no new warnings).
- `cargo test` with the feature **off** must stay green in every phase (the 501
  path and gating must never regress).
- No phase edits `generated.rs` by hand; registry changes go through
  `gen-capabilities.mjs` and the drift guards.

## Sequencing note

P0→P1→P2 is a strict chain (each gate is the next phase's precondition). P3
depends on P2's wire shapes being final. The registry **flip to `active`** (add
wildcard `implies`, extend `canonical_decisions_are_locked`, §13 step 7) happens
at the **start of P3**, not earlier — the concretes stay reserved while only the
node can exercise them, and go active exactly when the SDK begins to grant them.
