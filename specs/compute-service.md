# Spec: Compute Service for TinyCloud-Node

**Date:** 2026-07-10
**Status:** Draft
**Service identifier:** `compute`
**Primary consumers:** Agent runtimes, data-exchange routines, app-defined functions over space data

---

## 1. Overview

Add a compute service (`tinycloud.compute/*`) to tinycloud-node that executes
**functions over space data under capability-based least privilege**. A
function is deployed once as a content-addressed WASM artifact and then invoked
by holders of a `tinycloud.compute/execute` capability. The service is designed
so that the *invoker* of a function needs no direct permission over the data the
function touches — the function carries its own attenuated data grant, minted at
deploy time and bound to the function's content identity.

The service is pre-reserved in the whitepaper: `appendix/appendix-j.md:92-118`
defines the `tinycloud.compute/{execute,deploy,list,*}` actions and the
`ComputeCaveats { functions, maxDuration, maxMemory, inputs }` shape, and
`appendix/appendix-i.md:299-301` reserves the SDK surface
`sp.compute.invoke(functionName, input)` / `sp.compute.deploy(wasmBinary)`. This
spec grounds those reservations in the actual node dispatch, storage, and
authorization code paths, following the same structure as
`specs/duckdb-service.md`.

### Goals

- Execute a deployed function over a space's data with the invoker holding only
  `tinycloud.compute/execute` — never the underlying `kv`/`sql` data caps.
- Content-addressed, versioned function storage that reuses the existing
  `DatabaseArtifactRepository` (same mechanism sql/duckdb use).
- A pluggable `ExecutionBackend` so the same function contract runs in-node
  (wasmtime) or on Cloudflare Workers, with a `verify` hook that is trivial
  today and becomes the plug for TEE-quote and ZK verification later.
- Least-privilege resource enforcement caveats (`ComputeCaveats`) mapped onto
  concrete backend controls (wasmtime fuel/epoch/`StoreLimits`, host-function
  mediation) — with an **honest statement** of what is *not* enforceable on the
  Cloudflare backend.

### Non-goals (explicitly out of scope)

- **Multi-node orchestration / scheduling / fan-out.** A single `/invoke`
  executes on a single node. Orchestration across nodes (retries, placement,
  DAGs) is handled by layers *above* this service — e.g. Smithers. This spec
  defines the per-node execution primitive only.
- **A general FaaS control plane** (autoscaling, cold-start pools, billing
  metering). Deferred.
- **TEE-quote and ZK verification are documented plugs, NOT built here.** §9
  specifies the `verify` interface and how the existing dstack attestation
  (`/attestation`) and a future ZK verifier slot in, but the initial backends
  ship `verify` = trivial (wasmtime) and verify = trust-the-deployment
  (Cloudflare).

---

## 2. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Function unit | WASM binary (wasmtime component/core module) | Portable, sandboxable, deterministic fuel metering; matches whitepaper "Function Types: WASM" |
| Function identity | Content CID (`hash(wasm).to_cid(0x55)`) | Same content-hash primitive `DatabaseArtifactRepository::save` already computes; deploy is idempotent by CID |
| Function storage | `DatabaseArtifactRepository` with service tag `"compute"` | Reuse the sql/duckdb persistence path (versioned, keyed `(service, space, name)`) — no new storage subsystem |
| Invoker authorization (layer a) | Existing chain check in `invocation.rs` `validate()` | `resource.extends() && ability_matches()` — free, no new engine code |
| Routine data access (layer b) | Deploy-time UCAN delegation `D_fn` bound to the function CID, delegatee = a node/TEE-derived routine DID | Reuses `did_principal_matches` + the existing chain walk; invoker needs no data caps; provably gated by function + node identity |
| Wire transport | Existing `POST /invoke` | Same envelope, dispatch, and replay cache as kv/sql/duckdb; a `service=="compute"` branch in `invoke_impl` |
| Request encoding | JSON `ComputeRequest` enum in the body (execute/deploy/list) | Mirrors `SqlRequest` / `DuckDbRequest` `serde_json::from_str` dispatch |
| Backend abstraction | `ExecutionBackend` trait (`run`/`output`/`verify`) | In-node wasmtime first; Cloudflare Workers as a second impl; future verifiers plug into `verify` |
| Enforced caveats source | The **validated delegation chain**, not invoker-supplied facts | Same W1 fail-closed principle the SQL service uses (`handle_sql_invoke` derives the constrained caveat from the chain; facts are a fallback only) |
| Outputs | Inline JSON return OR write to a KV path under the routine's grant | Inline for small results; KV path lets standard KV read delegations govern downstream access |
| Service gating | Disabled by default, behind a `compute` cargo feature; `501 NotImplemented` when absent | Exact precedent of the `#[cfg(feature="duckdb")]` gate + 501 branch in `invoke_impl` |

---

## 3. Abilities

Per whitepaper `appendix/appendix-j.md:96-102`:

```
tinycloud.compute/execute   — Run a deployed function
tinycloud.compute/deploy    — Upload / register a new function (+ bind its data grant)
tinycloud.compute/list      — List deployed functions in a space
tinycloud.compute/*         — Wildcard: all compute actions
```

### 3.1 `capabilities.json` diff (reserved first)

New services land as `status: "reserved"` — the same pattern `tinycloud.vfs/*`
uses (`capabilities.json:174-197`). A **reserved** service is accepted at the
policy boundary (so `accepted_actions("tinycloud.compute")` is `Some`, which
keeps it from regressing to unknown-service) but is not yet wired to a live
dispatch handler. When the handler ships, the entries flip to `active`.

Important codegen constraint: the `scripts/gen-capabilities.mjs` validator
(lines 106-118) requires a `/*` wildcard to `implies` **exactly the active
concrete actions of its service**. While the concrete actions are `reserved`,
the wildcard therefore must carry **no `implies`** (an empty/absent list). The
`implies` list is added in the same changeset that flips the concretes to
`active`.

Insert after the `tinycloud.duckdb/*` block and before
`tinycloud.capabilities/read` (keep entries grouped by service):

```json
    {
      "urn": "tinycloud.compute/execute",
      "service": "tinycloud.compute",
      "status": "reserved"
    },
    {
      "urn": "tinycloud.compute/deploy",
      "service": "tinycloud.compute",
      "status": "reserved"
    },
    {
      "urn": "tinycloud.compute/list",
      "service": "tinycloud.compute",
      "status": "reserved"
    },
    {
      "urn": "tinycloud.compute/*",
      "service": "tinycloud.compute",
      "status": "reserved",
      "notes": "Per-service wildcard. While the concrete actions are reserved this MUST carry no `implies` (gen-capabilities.mjs requires a wildcard to imply exactly the *active* concrete actions of its service). When execute/deploy/list flip to active, add: \"implies\": [\"tinycloud.compute/deploy\", \"tinycloud.compute/execute\", \"tinycloud.compute/list\"]."
    }
```

### 3.2 Regeneration + drift guards

After editing `capabilities.json`:

1. Run `node scripts/gen-capabilities.mjs` to regenerate
   `tinycloud-core/src/policy_capability/generated.rs` and
   `generated/capabilities.ts` (requires the Rust toolchain — the script runs
   the emitted Rust through `rustfmt`).
2. The drift-guard test `generated_module_matches_registry` in
   `tinycloud-core/src/policy_capability/mod.rs` verifies the generated Rust
   agrees with the checked-in registry at `cargo test` time. CI additionally
   runs `gen-capabilities.mjs --check`.
3. When flipping to `active`, extend `canonical_decisions_are_locked` in the
   same file with a compute-wildcard expansion assertion mirroring the existing
   `sql/*` and `duckdb/*` blocks (lines 774-797), so a future registry edit that
   drops a concrete from the wildcard is caught with a clear message.

No hand-editing of `generated.rs` — it is `// @generated`.

---

## 4. Resource Model

Compute resources are ordinary `ResourceId`s
(`tinycloud-auth/src/resource.rs`), with `compute` as the `Service` segment:

```
<space>/compute/<function-path>
```

Concretely: `tinycloud:pkh:eip155:1:0xabc…:myspace/compute/report-generator`.

`compute` is just a `Service(String)` — no parser change is needed. The
resource machinery already supports this:

- **Display / parse** — `ResourceId`'s `Display` (`resource.rs:268-282`) and
  `TryFrom<&UriStr>` (`resource.rs:339-375`) treat the first path segment after
  the space as the service and the remainder as the path. A function reference
  is expressed as the resource `path`.
- **Prefix authority** — `extends()` (`resource.rs:193-217`) does the
  space/service/fragment equality check plus the path-prefix-on-component-
  boundary check. So a grant on `<space>/compute/` (trailing slash) is a
  space-wide compute authority that extends to any concrete `compute/<fn>`,
  while `<space>/compute/report-generator` is a single-function authority. This
  is identical to how KV path prefixes work.

Path-containment for the compute service falls under the `_ =>` (non-SQL) arm of
`policy_capability::path_contains` (`policy_capability/mod.rs:410-431`):
trailing-slash prefix matches strict descendants on a component boundary;
no-slash matches exactly. No new path rule is required.

---

## 5. Function Storage Model

A deploy stores the WASM binary as a content-addressed, named, versioned
artifact via `DatabaseArtifactRepository`
(`tinycloud-core/src/database_artifacts.rs`), exactly as the sql and duckdb
services persist their database blobs.

```rust
// on deploy
let artifact = artifact_repo
    .save(
        "compute",              // service tag
        &space.to_string(),     // space
        function_name,          // name  (the `<function-path>` segment)
        wasm_bytes,             // payload
    )
    .await?;
// artifact.content_hash == the function CID  (hash(payload).to_cid(0x55))
// artifact.revision     == monotonically increasing version
```

Properties inherited from `SeaOrmDatabaseArtifactRepository::save`
(`database_artifacts.rs:86-146`):

- **Function identity = content CID.** `content_hash = hash(&payload).to_cid(
  0x55).to_string()`. Re-deploying identical bytes yields the same CID; the
  `(service, space, name)` row's `revision` bumps and `content_hash` is stable
  if the bytes are unchanged, or changes when the bytes change.
- **Named + versioned.** Keyed on `(service, space, name)` with an incrementing
  `revision`; `created_at` is preserved across updates, `updated_at` refreshed.
- **Size accounting.** `size_bytes` is recorded and folds into the space's
  `store_size` (so deploy is subject to the same quota pre-check as sql/duckdb
  writes — see §10).

**Whitepaper alignment.** `appendix/appendix-j.md:114-116` lists the function
types (WASM now, ZK VM future); `appendix/appendix-i.md:299-301` specifies
`sp.compute.deploy(wasmBinary) -> FunctionId` — the returned `FunctionId` is the
content CID from `artifact.content_hash`.

### 5.1 Deploy-time delegation binding

Alongside the artifact, deploy records the **routine data grant binding**:
`function_cid → D_fn` (the deploy-time delegation, see §6). Two storage options
are on the table (DECISION NEEDED, §12/D2):

- **Table-side (leaning):** a small `compute_function_grant(space, name,
  content_hash, delegation_cid)` row written in the same transaction as the
  artifact save. No wire/caveat change; the binding is internal node state.
- **Caveat-side:** the binding is expressed as a caveat on `D_fn` naming the
  `function_cid`, making the delegation self-describing but requiring the
  execute path to read it out of the delegation.

---

## 6. Two-Layer Permissioning

This is the novel part of the service. There are two independent authorization
layers, and they are deliberately decoupled.

### 6.1 Layer (a): invoker → function — FREE, no new engine code

To run a function, the invoker presents a `tinycloud.compute/execute`
invocation on the resource `<space>/compute/<fn>`. This is authorized by the
**existing** chain check in `tinycloud-core/src/models/invocation.rs`
`validate()` (lines 218-262):

```rust
c.resource.extends(&pc.resource)
    && crate::policy_capability::ability_matches(
        pc.ability.as_ref().as_ref(),
        c.ability.as_ref().as_ref(),
    )
```

The invoked `compute/execute` capability must be supported by a parent
delegation ability whose resource `extends` it and whose ability
`ability_matches` it (registry-aware: `compute/*` implies `compute/execute` once
active). No compute-specific authorization code is needed for layer (a) — a
compute cap flows through the same `validate()` path as every other service.

Crucially, **the invoker needs no data caps.** Holding `compute/execute` on the
function resource says nothing about `kv`/`sql` — those are layer (b).

### 6.2 Layer (b): the routine's OWN data access — the mechanism

The function must be able to read its inputs and write its outputs. It does so
under a grant **it owns**, minted at deploy time and bound to its content CID —
so the invoker never needs (and never gains) data permissions.

**Routine execution identity.** The function executes under a routine DID
derived by the node from the function CID:

```
routine_did = did:key( get_key("tinycloud/compute/" + function_cid) )
```

using the existing dstack hierarchical key derivation (`dstack::get_key`,
`dstack.rs:110-119`). The private key is derived inside the TEE and never
leaves it, so **only this node, running this exact function CID, can act as the
routine.** (Non-TEE / classic mode: the same derivation runs off the node's
static key material via `keys.rs`; the trust statement weakens to "the node" —
see §9.3.)

**Deploy-time binding.** At deploy, the deployer — who *does* hold data caps
(the space owner, or an attenuated delegate) — mints a UCAN delegation `D_fn`:

- `delegatee = routine_did`
- `capabilities =` the attenuated data grant the routine needs, e.g.
  `tinycloud.kv/get` on `inputs/` and `tinycloud.kv/put` on `outputs/`
- signed by the deployer, extending the deployer's own chain to the space owner

Because the CID is a pure function of the WASM bytes, the deployer can compute
`function_cid` (and therefore `routine_did`, given the node's derivation
convention exposed by the SDK) **before** deploy — no chicken-and-egg. `D_fn`
travels in the deploy request and is persisted bound to `function_cid` (§5.1).

**Execute-time flow.**

```
1. Invoker → POST /invoke  (compute/execute on <space>/compute/<fn>)
     layer (a): validate() authorizes via the chain. NO data caps required.
2. Node loads the WASM artifact + the bound D_fn for function_cid.
3. Node derives the routine key for function_cid, instantiates the backend
   (wasmtime), and runs the function.
4. On each host import the function calls (storage.get/storage.put/sql.query),
   the host mediator constructs an INTERNAL invocation SIGNED BY THE ROUTINE KEY,
   citing D_fn as its parent, and runs it through the normal invocation
   validate()/save() path.
     → the routine reads inputs / writes outputs under ITS OWN grant.
5. Function returns; node returns the result inline or writes it to a KV path
   (§8).
```

Nothing new is required in the authorization engine. `validate()` already
enforces (i) `delegatee`-match via `did_principal_matches` (the routine's
internal invocations are matched against `D_fn.delegatee == routine_did`), and
(ii) chain containment against the persisted delegation. The only new code is
the **host mediator** that mints and submits the routine's internal invocations,
and the deploy-time binding store.

**Why derived-key over a caveat-scoped self-delegation.** An alternative is to
let the routine act *as the deployer* under a new "only usable inside function
CID X" caveat. That needs a new caveat type *and* a new invocation-path check
("am I currently executing inside function CID X?"), which is exactly the kind
of trust-boundary state that is hard to make fail-closed. The derived-key
approach needs zero new caveat type and zero new invocation check; it reuses
`did_principal_matches` and the existing chain walk; and it binds data access to
**both** the function identity and the node identity, which is attestable via
`/attestation`.

### 6.3 Caveat source is the chain, not the facts

Following the same W1 fail-closed lesson the SQL service encodes
(`handle_sql_invoke`, `routes/mod.rs:1192-1246`: the constrained caveat is
derived from the *validated delegation chain*, and invocation facts are only a
fallback), the enforced `ComputeCaveats` (§7) — especially the `functions`
allowlist — MUST be read from the validated chain, not trusted from the
invoker's own invocation facts. An invoker cannot widen or drop the function
allowlist by editing the invocation envelope.

---

## 7. Wire Format

Compute rides the existing `POST /invoke` endpoint. The dispatch mirrors the sql
and duckdb branches in `invoke_impl` (`tinycloud-node-server/src/routes/mod.rs`,
SQL branch ~717, DuckDB ~757).

### 7.1 Dispatch branch

In `invoke_impl`, add a compute-capability filter alongside the sql/duckdb ones,
behind a `#[cfg(feature = "compute")]` gate and a mirrored
`#[cfg(not(feature = "compute"))]` 501 branch:

```rust
#[cfg(feature = "compute")]
{
    let compute_caps: Vec<_> = i.0 .0.capabilities.iter().filter_map(|c| {
        match (&c.resource, c.ability.as_ref().as_ref()) {
            (Resource::TinyCloud(r), ability)
                if r.service().as_str() == "compute"
                    && ability.starts_with("tinycloud.compute/") =>
            {
                Some((r.space().clone(), r.path().map(|p| p.to_string()), ability.to_string()))
            }
            _ => None,
        }
    }).collect();

    if !compute_caps.is_empty() {
        let result = handle_compute_invoke(
            i, data, tinycloud, compute_service, hook_runtime,
            quota_cache, config, &compute_caps,
        ).await;
        if let Some(timer) = timer { timer.observe_duration(); }
        return result;
    }
}

#[cfg(not(feature = "compute"))]
if i.0 .0.capabilities.iter().any(|c| matches!(
    (&c.resource, c.ability.as_ref().as_ref()),
    (Resource::TinyCloud(r), ability)
        if r.service().as_str() == "compute" && ability.starts_with("tinycloud.compute/")
)) {
    return Err((Status::NotImplemented,
        "Compute support is not enabled on this node".to_string()));
}
```

`compute_service` is threaded through `invoke_impl` as a
feature-gated `ComputeInvokeState<'a>` type alias exactly like
`DuckDbInvokeState` (`routes/mod.rs:390-393`):
`&'a State<ComputeService>` when the feature is on, `()` when off.

### 7.2 Request encoding — `ComputeRequest`

The request body is JSON, `serde_json::from_str` into a tagged `ComputeRequest`
enum (mirroring `SqlRequest`/`DuckDbRequest`):

```rust
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ComputeRequest {
    /// Run a deployed function.
    Execute {
        /// Function reference within the space — the `<function-path>` name.
        /// (The specific content CID is resolved via the artifact's current
        /// revision, or pinned explicitly.)
        function: String,
        /// Optional exact content CID to pin (defense against a re-deploy
        /// race); when present the loaded artifact's content_hash must match.
        content_cid: Option<String>,
        /// Inline input, inlined in the request body.
        input: Option<serde_json::Value>,
        /// OR: read the input from these KV paths (the routine reads them under
        /// its own grant; see §6.2). Mutually informative with `input`.
        input_refs: Option<Vec<String>>,
        /// Optional output KV path. When present, the result is written there
        /// (under the routine grant) instead of returned inline (§8).
        output_ref: Option<String>,
    },
    /// Register / upload a new function version. The WASM binary rides as the
    /// request body when large; `wasm_b64` is accepted for small inline
    /// deploys. `grant` carries the deploy-time delegation D_fn (§6.2).
    Deploy {
        function: String,
        wasm_b64: Option<String>,
        /// Encoded D_fn delegation header (or its CID if pre-submitted).
        grant: Option<String>,
        caveats: Option<ComputeCaveats>,
    },
    /// List deployed functions in the space.
    List,
}
```

Notes on encoding choices:

- **Inline inputs vs KV refs.** Small inputs ride inline in `input`. Larger or
  pre-existing data is referenced by `input_refs` (KV paths); the routine reads
  them via host imports under `D_fn`, so the invoker never needs `kv/get`.
- **Deploy body.** Like the duckdb `import` path (`routes/mod.rs:1748-1769`,
  which reads a binary body up to 100 MB before falling through to JSON), a
  large WASM binary is streamed as the raw request body; a small one may be
  inlined as `wasm_b64`. The deploy handler computes the CID from the received
  bytes.
- **Caveats via facts.** As with `sqlCaveats`/`duckdbCaveats`
  (`routes/mod.rs:1727-1739`), `ComputeCaveats` may also be supplied in
  invocation facts under key `computeCaveats` — but per §6.3 the *enforced*
  allowlist is the chain-derived one; facts are a non-authoritative fallback.

### 7.3 Response — new `InvocationOutcome` variants + Responder arms

Add to `InvocationOutcome` in `tinycloud-core/src/db.rs:725-740`:

```rust
    ComputeResult(serde_json::Value),   // inline function result (execute) or deploy ack
    ComputeList(serde_json::Value),     // list of deployed functions
```

Add the matching Responder arms in `tinycloud-node-server/src/auth_guards.rs`
(the `impl Responder for InvOut`, lines 79-140 — this is the real responder;
`routes/util.rs` is only the `LimitedReader`):

```rust
    InvocationOutcome::ComputeResult(json) => Json(json).respond_to(request),
    InvocationOutcome::ComputeList(json) => Json(json).respond_to(request),
```

The `handle_compute_invoke` function returns
`Ok(DataOut::One(InvOut(InvocationOutcome::ComputeResult(json))))` (execute /
deploy) or `ComputeList(json)` (list), exactly as `handle_sql_invoke` returns
`SqlResult` (`routes/mod.rs:1328`) and `handle_duckdb_invoke` returns its
variants (`routes/mod.rs:1781/1811/1870`).

> A binary compute output (e.g. raw bytes, not JSON) can either be base64'd into
> `ComputeResult` or written to a KV path (§8) and read back through the KV
> path. A dedicated `ComputeBytes(Vec<u8>)` variant + `application/octet-stream`
> responder arm (mirroring `SqlExport`/`DuckDbExport`,
> `auth_guards.rs:125-133`) is a future addition if inline binary returns become
> common — deferred to avoid speculative surface.

---

## 8. Outputs

A function result is delivered one of two ways, chosen by the presence of
`output_ref` on the `Execute` request:

1. **Inline return** (`output_ref` absent): the JSON result is returned in
   `InvocationOutcome::ComputeResult`. Bounded by the same JSON response-size
   ceiling the sql/duckdb services enforce (`ResponseTooLarge → 413`); large
   results should use a KV path instead.
2. **Write to a KV path** (`output_ref` present): the routine writes its result
   to the given KV path **under its own `D_fn` grant** (which must include
   `kv/put` on that prefix). Downstream access is then governed by ordinary KV
   read delegations — the compute service adds no special read path. This is the
   composable option: a function produces an artifact that other principals read
   via standard `kv/get` grants.

### 8.1 Caching / idempotency

- **Deploy is idempotent by CID.** Re-deploying identical bytes is a no-op on
  content (same `content_hash`); only `revision`/`updated_at` move
  (`database_artifacts.rs:108-135`).
- **Execute idempotency** is a function property, not a service guarantee. A
  pure function of `(function_cid, input)` is safe to cache/replay; a function
  that writes KV or reads mutable state is not. The service does not implicitly
  memoize results. A future `content_cid`-pinned, `input`-hashed result cache is
  possible but out of scope here.

### 8.2 Interaction with the invocation replay cache

The outer `compute/execute` invocation passes through
`invocation_replay_cache.check_and_insert(&i.0)` at the top of `invoke_impl`
(`routes/mod.rs:714`) like every other invocation — a replayed *outer*
invocation envelope is rejected as a duplicate. The routine's **internal**
invocations (§6.2 step 4) are freshly minted per execution (fresh nonce), so
they do not collide in the replay cache across repeated executions of the same
function. This means "execute the same function twice" is allowed (two distinct
outer envelopes, two distinct routine invocation sets); it is *not* an
accidental replay.

---

## 9. Pluggable ExecutionBackend

```rust
#[async_trait]
pub trait ExecutionBackend: Send + Sync {
    /// Execute `wasm` against `input`, mediating host imports through `host`
    /// (which issues the routine's data invocations under D_fn), enforcing
    /// `caveats`. Returns the raw function output.
    async fn run(
        &self,
        function_cid: &str,
        wasm: &[u8],
        input: ComputeInput,
        caveats: &ComputeCaveats,
        host: &dyn HostMediator,
    ) -> Result<ComputeOutput, ComputeError>;

    /// Post-process / package the output (e.g. write to KV path).
    async fn output(
        &self,
        out: ComputeOutput,
        sink: OutputSink,
        host: &dyn HostMediator,
    ) -> Result<serde_json::Value, ComputeError>;

    /// Produce (or check) an execution proof. Trivial for the trusted in-node
    /// backend; the plug point for TEE-quote and ZK verification.
    async fn verify(&self, ctx: &ExecutionContext) -> Result<Verification, ComputeError>;
}
```

### 9.1 WasmtimeBackend (in-node, default)

- **Runs** the WASM via `wasmtime` inside the node process. Host imports
  (`storage.get`/`put`/`list`, `sql.query`/`execute`) are provided by the
  `HostMediator`, which issues the routine's internal invocations under `D_fn`
  (§6.2). The WASM cannot reach the network or filesystem — only the mediated
  host imports.
- **`verify` is trivial** — the result is trusted because it executed inside
  this node's own process. There is nothing to check beyond "the node ran it."
- **Attestable context.** Nodes already run inside dstack TEEs with a live
  `/attestation` endpoint (`routes/attestation.rs`, backed by `dstack.rs`
  `get_quote` and `tee.rs::TeeContext { app_id, compose_hash, instance_id }`).
  So even though `WasmtimeBackend::verify` is trivial *per-execution*, a caller
  can independently attest that the node is a genuine TDX instance running the
  expected `compose_hash` via `GET /attestation?nonce=…`. This is the bridge to
  the future TEE-quote verifier (§9.3): the same quote that authenticates the
  node can, in a later iteration, be bound to the specific execution's
  `report_data`.

### 9.2 CloudflareWorkerBackend

- **Runs** the function as a Cloudflare Worker. The node acts as the
  orchestrator: it sends the function (or a pre-deployed Worker reference) and
  the input to the Worker, and the Worker returns the output.
- **What is sent:** the WASM/Worker script reference or bytes, the input
  payload, and a **scoped, short-lived credential** the Worker uses to call back
  into the node's `/invoke` for the routine's data access. That callback
  credential is a delegation whose delegatee is the Worker's identity, attenuated
  to `D_fn`'s grant (the Worker cannot exceed the routine's data caps because
  the node validates its callbacks through the normal chain check). The private
  routine key is **not** shipped to the Worker; the Worker holds only a
  narrower, revocable callback delegation.
- **What is returned:** the function output (JSON or bytes).
- **`verify` = trust-the-deployment.** There is no cryptographic execution proof
  from a stock Cloudflare Worker. The trust model is: you trust Cloudflare's
  runtime to have executed the deployed script faithfully, and you trust the
  node↔Worker transport. This is strictly weaker than the in-node TEE backend
  and MUST be surfaced to callers (a `verification: { mode: "trusted-deployment",
  backend: "cloudflare" }` field on the result).

### 9.3 Future verifiers (documented plugs, NOT built)

- **TEE-quote verifier.** Bind the execution to a TDX quote whose `report_data`
  commits to `(function_cid, input_hash, output_hash)`, then check the quote's
  `compose_hash` against the expected value. The plumbing already exists:
  `dstack::get_quote(report_data)` (`dstack.rs:122-130`) takes arbitrary
  `report_data`, and `/attestation?nonce=` (`routes/attestation.rs:17-63`)
  already returns a nonce-bound quote + `compose_hash`. A verifier would move
  from "attest the node" to "attest the node AND this specific execution."
- **ZK verifier.** Per whitepaper future-directions (`appendix-j.md:114-116`,
  "ZK VM: Zero-knowledge provable execution (future)"): a `verify(proof,
  function_cid, inputs, outputs) -> bool` check that requires no trust in the
  executor at all. This slots into `ExecutionBackend::verify` for a ZK-VM
  backend without touching the dispatch or authorization layers.

Neither verifier is implemented in this spec — the `verify` interface is defined
so they can be added as additional `ExecutionBackend` impls / verifier plugs.

---

## 10. Caveats

Per whitepaper `appendix/appendix-j.md:104-112`:

```rust
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeCaveats {
    /// Allowed function names (the `<function-path>` allowlist).
    pub functions: Option<Vec<String>>,
    /// Maximum execution time (ms).
    pub max_duration: Option<u64>,
    /// Maximum memory usage (bytes).
    pub max_memory: Option<u64>,
    /// Input validation schema.
    pub inputs: Option<serde_json::Value>,
}
```

Per §6.3, the enforced values come from the **validated delegation chain**, not
invoker facts.

### 10.1 Enforcement mapping (WasmtimeBackend)

| Caveat | Enforcement | Mechanism |
|--------|-------------|-----------|
| `functions` (allowlist) | Reject execute if the requested `function` is not in the chain-derived allowlist | String-set check before instantiation; a `403`/`UnauthorizedAction` |
| `maxDuration` (ms) | Kill the execution when the deadline passes | wasmtime **epoch interruption** — a background ticker bumps the engine epoch; the store's epoch deadline traps the guest deterministically |
| `maxMemory` (bytes) | Cap linear-memory growth | wasmtime **`StoreLimits`** (`limiter` with `memory_size`) — memory-growth requests past the cap fail inside the guest |
| CPU budget | Bound total work (belt-and-braces with `maxDuration`) | wasmtime **fuel** metering (`Store::set_fuel`); running out of fuel traps |
| Host reach | The guest can ONLY touch mediated host imports | No WASI net/fs; imports are exactly the `HostMediator` surface, each call gated by `D_fn` |
| `inputs` (schema) | Validate input before running | JSON-schema check of `input`/`input_refs` payload against `inputs` |

Numeric caveats are validated against sane ceilings on ingest (reject absurd
`maxMemory`/`maxDuration`) and applied with saturating/`try_from` conversions —
no silent truncation when mapping `u64` caveats onto wasmtime's `u64`/`usize`
limit setters.

### 10.2 Cloudflare backend — honest limits

On the CloudflareWorkerBackend, the node does **not** control the execution
sandbox, so the caveat enforcement story is materially weaker:

- **`functions`** — enforceable node-side (the node decides which function to
  dispatch), so the allowlist still holds.
- **Host reach / data caps** — enforceable, because the Worker's callbacks come
  back through the node's `/invoke` and are validated against the attenuated
  callback delegation. The Worker cannot exceed `D_fn`'s grant.
- **`maxDuration` / `maxMemory` / CPU** — **NOT enforceable by us**. These are
  governed by Cloudflare's own Worker limits (CPU-time/memory tiers), not by our
  caveats. We can pass them as hints, but we cannot guarantee them. The trust
  model (§9.2) is trust-the-deployment: callers who need enforced resource
  bounds must use the in-node WasmtimeBackend. This limitation MUST be stated in
  the result's `verification` block and in the node config docs.

---

## 11. Node Config & Service Gating

Compute is **disabled by default**, behind a `compute` cargo feature, following
the duckdb precedent precisely.

### 11.1 Cargo feature + service registration

- Feature `compute` in `tinycloud-node-server/Cargo.toml` (and any WASM/runtime
  deps like `wasmtime` gated under it).
- In `tinycloud-node-server/src/lib.rs`, construct and `.manage()` a
  `ComputeService` under `#[cfg(feature = "compute")]`, exactly as the duckdb
  service is registered (`lib.rs:264-305`):

```rust
#[cfg(feature = "compute")]
let compute_service = ComputeService::new(
    tinycloud_config.storage.compute.clone(),
    database_artifact_repository.clone(),
    tee_context_or_keys,            // for routine-key derivation
    /* backend registry: wasmtime + optional cloudflare */,
);
// ...
#[cfg(feature = "compute")]
let rocket = rocket.manage(compute_service);
```

- `ComputeService` holds the artifact repo, the backend registry, and the
  routine-key derivation handle. It does **not** need the actor/idle-timeout
  machinery the sql/duckdb services use — a function execution is request-scoped,
  not a long-lived per-space connection.

### 11.2 `/version` features

Extend the `features` vec in `routes/mod.rs:76-79` under the feature gate:

```rust
#[cfg(feature = "compute")]
features.push("compute");
```

so clients can feature-detect compute the way they detect `sql`/`duckdb`.

### 11.3 501 behavior

When the `compute` feature is not compiled in, a request carrying a
`tinycloud.compute/*` capability returns `501 NotImplemented` with
"Compute support is not enabled on this node" — byte-for-byte the same pattern
as the duckdb-less branch (`routes/mod.rs:800-816`). This is deliberate: no
silent fallback, the client gets a clear signal that the service is absent.

### 11.4 `tinycloud.toml`

```toml
[storage.compute]
# path is unused for pure in-node execution (artifacts live in the DB blob
# store), but kept for a future on-disk WASM cache.
enabled = true
default_backend = "wasmtime"     # "wasmtime" | "cloudflare"
max_wasm_bytes = "16 MiB"        # deploy artifact ceiling
default_max_duration_ms = 5000   # fallback when no caveat present
default_max_memory = "128 MiB"

[storage.compute.cloudflare]     # only when default_backend/allowed = cloudflare
account_id = "…"
# credentials via env, never in the toml
```

---

## 12. Open Questions

- **DECISION NEEDED (D1) — routine identity.** Deterministic TEE-derived key
  from the function CID (this spec's proposal — cleaner, no secret at rest, but
  a re-deploy on a different node yields a different `routine_did`, so `D_fn`
  must be re-minted per node) **vs.** a freshly-generated per-deploy session key
  persisted (encrypted) alongside the artifact (survives node migration, but
  adds a secret at rest and a key-management surface). *Which is primary?*
- **DECISION NEEDED (D2) — binding representation.** Store `function_cid → D_fn`
  as an internal table row (leaning: no wire/caveat change) **vs.** express it as
  a self-describing caveat on `D_fn` naming the `function_cid` (the delegation
  carries its own binding, at the cost of an execute-path read).
- **Deploy authorization tier.** Should `compute/deploy` require an
  admin-equivalent capability (like sql DDL requires `sql/schema`/`admin`), or is
  a plain `compute/deploy` grant sufficient? Deploy mutates executable code in a
  space — leaning toward a distinct, non-wildcard-implied tier, but this
  interacts with the `compute/*` wildcard semantics.
- **Cloudflare callback credential lifetime & revocation.** The short-lived
  callback delegation shipped to the Worker (§9.2) needs a concrete TTL and a
  revocation story if a Worker misbehaves mid-execution.
- **Result cache.** Whether to offer an opt-in `(content_cid, input_hash)`
  result cache (§8.1) for pure functions, and how a function declares itself
  pure.
- **Binary inline outputs.** Whether to add a `ComputeBytes` outcome variant +
  octet-stream responder now or defer until there is a concrete consumer (§7.3).
- **Multi-node execution.** Confirmed OUT of scope here; the escalation path is
  the orchestration layer (Smithers). Flagged so a reviewer does not expect it.

---

## 13. Implementation Plan (sketch)

Spec-only doc — no code lands here. When implementation begins, the ordered
steps are:

1. `capabilities.json` reserved entries + `node scripts/gen-capabilities.mjs` +
   drift-guard green.
2. `ComputeService`, `ExecutionBackend` trait, `WasmtimeBackend`, `HostMediator`
   in a new `tinycloud-core/src/compute/` module (feature `compute`).
3. Deploy path: artifact save (service tag `compute`) + `D_fn` binding store.
4. Execute path: routine-key derivation, backend `run`, host-mediated internal
   invocations, output inline/KV.
5. `InvocationOutcome::ComputeResult`/`ComputeList` + Responder arms +
   `handle_compute_invoke` dispatch branch + 501 gate + `/version` feature.
6. Flip registry entries to `active`, add wildcard `implies`, extend
   `canonical_decisions_are_locked`.
7. CloudflareWorkerBackend + callback-delegation minting.
8. (Later) TEE-quote verifier binding `report_data` to execution; ZK-VM backend.
