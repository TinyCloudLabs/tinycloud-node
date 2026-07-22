# Codex Review — compute-service-implementation-plan.md

**Reviewer:** Codex (GPT-5.4, read-only pass, 2026-07-17)
**Verdict:** plan needs changes
**Transcribed verbatim by the team lead from the Codex session output.**

The P2 least-privilege E2E fixture belongs in P2, not a separate phase. The active flip and several gates need correction.

1. **The plan never binds request actions to their required abilities—a security blocker.**
   **Target:** P0 dispatch and P1–P2 handlers, plan lines 45–50.
   **Problem:** The spec's dispatch accepts any `tinycloud.compute/*` capability and then deserializes the body independently (spec §7.1). Existing invocation validation only proves that the presented capability follows its delegation chain; it knows nothing about `ComputeRequest::Deploy` versus `Execute` (invocation.rs:218). Without an explicit mapping, an `execute` or `list` holder could submit a deploy body. SQL has a separate request-sensitive authorization check precisely for this reason (routes/mod.rs:1232). P3's SDK-only "standard session cannot deploy" test is too late and does not secure non-SDK callers.
   **Suggested change:** Require and test an exact mapping in the server: `RoutineDid/Deploy → compute/deploy`, `Execute → compute/execute`, `List → compute/list`, using `ability_matches` for active wildcards. Add all wrong-ability/body combinations to the phase where each variant lands.

2. **P1's "one transaction" is much larger than the plan admits and cannot be implemented through the current APIs.**
   **Target:** P1 lines 72–89.
   **Problem:** `TinyCloud::delegate` opens and commits its own private transaction (db.rs:513–535). `DatabaseArtifactRepository::save` owns a `DatabaseConnection` and accepts no transaction/connection parameter (database_artifacts.rs:28–53). `SqlSizes` is an in-memory map updated after a successful repository save, with no failure or rollback operation (sql_sizes.rs:108–120). Therefore "artifact + `/delegate` + `SqlSizes`, all in one transaction" is not a service-module-sized change; it requires refactoring core transaction seams. The proposed "vice versa" SqlSizes failure test is not meaningful because `update` cannot fail.
   **Suggested change:** Make the transaction seam an explicit P1 deliverable: a dedicated core deploy primitive that begins one SeaORM transaction, calls delegation validation/persistence and transaction-aware artifact persistence, commits, then updates the infallible mirror. Gate durable artifact/delegation rollback plus "mirror changes only after commit." Also test superseded-grant revocation, which P1 promises but its four-test gate omits.

3. **P2 lacks a defined WASM ABI, so an unattended implementer cannot know what to build.**
   **Target:** P2 lines 93–109.
   **Problem:** The design says "component/core module" (spec line 63), references undefined `ComputeInput`/`ComputeOutput` types (spec §9), and names host imports without defining module names, signatures, guest memory ownership, serialization, exports, or core-module versus component semantics. The codebase has no existing Wasmtime convention to mirror; `tinycloud-core` currently has neither a compute feature nor Wasmtime dependency (Cargo.toml:7).
   **Suggested change:** Pin a single minimal ABI in P2's task and gate it with a checked-in WAT/WASM fixture. For the walking skeleton, support one export and one `storage.get` import with an exact byte/JSON contract. Defer the remaining host-import surface until that slice works.

4. **"Enter via core `process()`" does not provide the data operations the mediator needs.**
   **Target:** P2 lines 97–100 and spec §8.2.
   **Problem:** `invocation::process()` verifies and persists an invocation and returns only its hash (invocation.rs:105–118). KV reads/writes happen later inside `SpaceDatabase::invoke` (db.rs:620–720); SQL execution happens in the server route after authorization (routes/mod.rs:1279–1288). A core `HostMediator` cannot obtain KV results or invoke `SqlService` merely by calling `process()`.
   **Suggested change:** Explicitly inject a reusable internal-invocation executor into `ComputeService`. Keep the first slice KV-read-only through `SpaceDatabase::invoke`; defer KV writes and SQL host calls to P4 unless the plan adds the required cross-layer architecture.

5. **The verify commands can succeed with missing tests or are not commands at all.**
   **Target:** P0–P3 verify blocks, especially P1 lines 81–87, P2 lines 110–121, and P3 lines 142–148.
   **Problem:** `cargo test ... compute::deploy` and `compute::execute` are name filters; Cargo exits successfully when they match zero tests. The E2E fixture and SDK integration "tests" are prose with no executable command. P0 has no HTTP assertion for `/version`, enabled dispatch, or the disabled 501 path. The cross-cutting feature-off test is stated at lines 166–172 but omitted from P1–P3 node commands.
   **Suggested change:** Use named integration-test targets whose absence is an error, such as `cargo test -p tinycloud-node --test compute_deploy --features compute`. Give the E2E and SDK tests exact commands, startup/health/teardown behavior, ports, and timeouts. Append a shared feature-off/format/clippy command set to every actual node definition.

6. **P2's gate would pass while most promised caveat enforcement is absent.**
   **Target:** P2 lines 100–121.
   **Problem:** The task promises fuel, epoch deadlines, `StoreLimits`, and caveat enforcement, but the gate tests only caveat echo, space isolation, rotation, and a shallow manifest assertion. It does not test the chain-derived function allowlist, timeout, fuel exhaustion, memory growth failure, input schema, numeric ceilings, forbidden imports, or invoker-side caveat echo—all normative in spec §10.1 and §13.1. "Granted-vs-exercised present" also does not prove the per-call journal fields or granted-but-unexercised behavior required by spec lines 1263–1266.
   **Suggested change:** Add focused machine tests for every advertised control and the full manifest shape. Keep the granted/denied real-server fixture in P2—it is the correct P2 acceptance gate, not a separate phase.

7. **P1's deploy transport is internally contradictory.**
   **Target:** P1 deploy task, relying on spec §7.2.
   **Problem:** `ComputeRequest::Deploy` is a tagged JSON body containing `function`, `grant`, and `wasm_b64`, while the same spec says large WASM replaces that body with raw bytes (spec lines 662–687). Unlike DuckDB import, which is selected from the outer `import` ability before reading raw bytes (routes/mod.rs:1748–1769), raw compute bytes leave no defined channel for the deploy metadata and grant. Allowing a pre-submitted grant CID also contradicts atomic grant persistence.
   **Suggested change:** For the walking skeleton, accept only JSON/base64 plus an inline encoded `D_fn`; remove raw streaming and pre-submitted-CID grants from P1. Defer multipart/streaming transport.

8. **The space-name prerequisite is correctly ordered but wrongly sized; use the spec's local hashing option.**
   **Target:** P1 lines 67–85.
   **Problem:** It must be resolved before identities are minted, so its ordering before deploy is right. But global `Name` validation is broader and more subtle than the task admits. `Name::try_from` is stubbed (resource.rs:28–44), while `SpaceId` and `ResourceId` parsing construct `Name` directly and bypass that validator (resource.rs:306–369). A narrow test of `Name::from_str` could pass while real URI parsing remains unsafe. The spec explicitly permits hashing the space component instead (spec lines 386–396).
   **Suggested change:** Hash the canonical space string into a fixed-width component for compute derivation and remove global auth validation from P1. Treat global `Name` hardening as a separate compatibility-sensitive auth task.

9. **`list` is unimplemented work disguised as a response variant; defer it.**
   **Target:** P2's `ComputeList` bullet and P3's list expectation, plan lines 103–104 and 132–145.
   **Problem:** No phase task implements server-side listing, and `DatabaseArtifactRepository` exposes only `load` and `save`, not `list` (database_artifacts.rs:28–44). Adding an outcome enum arm does not create the operation. P3 then expects SDK `list` to work although its task is SDK-only.
   **Suggested change:** Keep `compute/list` reserved and move server listing plus SDK list to P4. It is not needed for the deploy→execute walking skeleton.

10. **P3 should be a separate SDK workflow, and the active flip should move to the end of P2.**
    **Target:** P3 lines 127–150 and sequencing lines 174–180.
    **Problem:** This repository contains only the generated TS mirror "destined for js-sdk" (gen-capabilities.mjs:31–34); the TS SDK service/session implementation is not a workspace member (root Cargo.toml:1–15). P3 therefore cannot run as written in this worktree. The sequencing rationale is also false: reserved actions are accepted at the policy boundary by design (spec lines 117–121), and codegen includes reserved actions in `accepted_actions` (gen-capabilities.mjs:121–127). Exact reserved URNs are exercisable by any caller, not "only the node."
    **Suggested change:** End the node plan after P2 and flip only actually implemented actions to active there, matching the spec's "when the handler ships" rule. Run SDK work in an explicit js-sdk worktree/workflow with its own commands and release coordination. This is the cleanest cut to P4 without losing the walking skeleton.

11. **The routine-key seam and dstack verification are underspecified.**
    **Target:** P1 handshake, plan lines 67–85.
    **Problem:** The planned compute module lives in `tinycloud-core`, but `dstack::get_key` exists only in the server crate (dstack.rs:106–119). Classic derivation exists through `StaticSecret::derive_key` (keys.rs:57–74), but the plan does not name an injected abstraction or verify the `compute+dstack` feature combination. A local "stable DID" unit test cannot satisfy the spec's required cross-CVM-redeploy empirical probe (spec lines 401–415).
    **Suggested change:** Name a `RoutineKeyDeriver` interface in P1, inject server-side classic/dstack implementations, add `cargo check --features compute,dstack`, and make the simulator test machine-checkable. Record real cross-redeploy equality as a deployment-readiness gate, not pretend the unit test proves it.

12. **Four human approvals are unnecessary and several merely repeat automatable checks.**
    **Target:** node template line 27 and each phase approval.
    **Problem:** Reserved status, rollback state, E2E outcomes, and emitted grant contents can all be asserted mechanically. "Human reviews fixture output" is weaker than an assertion and prevents unattended progress. It also contradicts the stated machine-verifiable-gate rule.
    **Suggested change:** Automate the P0 and SDK grep checks, assert the E2E behavior rather than review output, and retain at most one security review/approval after the complete P2 slice.
