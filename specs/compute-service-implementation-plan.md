# Compute Service — Lean Implementation Plan (Smithers)

**Date:** 2026-07-10 (rev 2026-07-18, Codex review applied — all 12 findings)
**Companion to:** `specs/compute-service.md` (design; referenced as §N, not restated)
**Review:** `specs/compute-service-plan-codex-review.md` (C1–C12, all accepted)
**Execution model:** Smithers durable plan→implement→review→fix→verify.

Pipeline: **P0 skeleton → P1 deploy → P2 execute** (node work ENDS at P2). P4 is
a deferred list, not executed. Exactly **one** human gate (security review after
P2); every other former approval is now a machine assertion (C12).

Crate names: server = `tinycloud-node` (dir `tinycloud-node-server/`), core =
`tinycloud-core`. Integration tests live in `tinycloud-node-server/tests/`.

---

## Smithers node template

```
node <phase>:
  task:    <one-line implementer prompt>
  verify:  <named commands; each MUST exist and exit 0>
  suffix:  cargo fmt -- --check
           cargo clippy --features compute -- -D warnings
           cargo test            # feature OFF must stay green (501 path/gating)
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
  disabled build returns **501**; **a wrong-ability request is rejected** (an
  `Execute` capability presenting a `Deploy` body → 403, and vice-versa).
- suffix (note: `cargo test` feature-off must also exercise the 501 path).

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
  public `routine_did`; **hashed-space** collision-freedom (two delimiter-laden
  space names never collide, §13.1).
- `cargo test -p tinycloud-core --test routine_key_deriver --features compute` —
  classic + dstack-**simulator** derivation is deterministic and machine-checked.
- suffix.

> **Deployment-readiness gate (NOT a test, C11):** real cross-CVM-redeploy
> `routine_did` equality must be verified empirically on the target CVM (§6.2
> box). The simulator unit test does not prove it. Record as a release
> precondition, separate from the phase's machine gate.

---

## P2 — Wasmtime execute (KV-read-only slice; node work ends here)

First end-to-end least-privilege slice, deliberately narrow (C3/C4):

- **Pinned minimal WASM ABI (C3):** one guest export + one `storage.get` host
  import, with an **exact byte/JSON contract** (module name, signature, guest
  memory ownership, serialization), gated by a **checked-in WAT/WASM fixture**.
  The rest of the host-import surface is deferred.
- **KV-read-only, inline output (C4):** the injected **internal-invocation
  executor** (named seam) reads through `SpaceDatabase::invoke` (`db.rs:620-720`);
  a bare `process()` only persists and returns a hash (`invocation.rs:105-118`)
  and cannot return KV data. **KV writes and SQL host calls move to P4.**
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
  asserts EACH: caveat-echo reject (`invocation-caveats-not-subset-of-chain`) +
  invoker-side echo reject; cross-space isolation; rotation
  (`routine-identity-rotated`, not 403); `functions` allowlist; **fuel
  exhaustion** trap; **epoch/timeout** trap; **memory-growth** failure
  (`StoreLimits`); **input-schema** reject; **numeric-ceiling** reject; **forbidden
  import** reject; **full manifest shape** (per-call `(resource, ability,
  bytes_in/out, destination)` fields + granted-vs-exercised, incl. a
  granted-but-unexercised case, §9.1.1).
- `cargo test -p tinycloud-node --test compute_abi --features compute` — the WAT
  fixture executes against the pinned ABI (export called, `storage.get` mediated).
- **E2E** (real server, the P2 acceptance gate — C6): `cargo test -p tinycloud-node
  --test compute_e2e --features compute` — boots a node on an ephemeral port,
  health-waits, a routine reads a **granted** KV path (succeeds, manifest shows it
  exercised) and is **denied** on an **ungranted** path (host call fails closed),
  invoker holds NO data caps throughout; tears the node down (timeout 60s).
- `node scripts/gen-capabilities.mjs --check` (active-flip regen committed).
- suffix.
- **HUMAN GATE (the only one, C12):** a security review of the completed P2 slice
  — the ability mapping, the caveat-echo enforcement, cross-space isolation, and
  the active-flip diff. All other checks above are assertions, not reviews.

---

## P4 — Deferred (NOT executed in this plan)

One line each on *why*:

- **`compute/list`** (C9): no server-side listing exists (`DatabaseArtifactRepository`
  has only `load`/`save`, `database_artifacts.rs:28-44`); stays reserved.
- **KV-write / SQL host calls** (C4): need cross-layer executor wiring beyond the
  read-only `SpaceDatabase::invoke` slice.
- **Streaming / multipart deploy transport + pre-submitted grant CIDs** (C7):
  contradicts inline atomic grant persistence; JSON/base64 suffices first.
- **TS SDK (execute/list, session grant, privileged deploy)** (C10): the TS SDK is
  **not a member of this workspace** (only the generated TS mirror lives here,
  `gen-capabilities.mjs:31-34`). Runs as a **separate js-sdk worktree/workflow**
  with its own commands and release coordination — the session grant there MUST
  enumerate `compute/execute`(+`list` when it ships) and NEVER `compute/*` (§3/F9).
- **Global `Name` hardening** (C8): a compatibility-sensitive auth-wide task,
  independent of compute (compute uses hashed-space derivation instead).
- **Cloudflare backend / ZK / container backend** (§9.2/§12.2/§9.4): second trust
  models; land the in-node wasmtime slice first.

## Sequencing

P0→P1→P2 is a strict precondition chain (each gate is the next phase's
precondition). The active-flip is P2's final step. No hand-edits to
`generated.rs` — registry changes go through `gen-capabilities.mjs` + drift
guards, in every phase.
