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

**DECIDED (deploy tier): capabilities stay specific — there is no
`tinycloud.compute/admin` URN for now.** `tinycloud.compute/deploy` IS the
privileged, code-mutating ability, analogous to `tinycloud.sql/schema` (which
standard-tier browser sessions do not receive — see the SQL schema-tier
precedent). Concretely:

- **Standard-tier session grants exclude `compute/deploy`.** A standard browser
  session may hold `compute/execute` (and `compute/list`) but not
  `compute/deploy`; deploying executable code requires an explicitly elevated
  grant, exactly as issuing DDL requires `sql/schema`.
- **F9 (MUST) — the SDK standard session grant must enumerate `compute/execute` +
  `compute/list`, and NEVER `compute/*`.** This is not automatic. Once the
  compute concretes flip to `active`, the codegen validator
  (`gen-capabilities.mjs:105-118`) *forces* `compute/*` to imply **every** active
  concrete — including `deploy`. So "standard sessions exclude deploy" is only
  real if the standard session grant also excludes the wildcard. The live
  precedent cuts the *wrong* way here: `sql/*` and `duckdb/*` ARE in today's SDK
  root delegation grant (`capabilities.json:69,107` → `TinyCloudNode.ts`
  ~2272/2279). If compute copies that habit, every browser session silently gets
  deploy rights. The SDK MUST list the two specific execute/list URNs, not the
  wildcard.
- **No `compute/admin` is introduced yet.** A future `compute/admin` would be
  added only once there is a genuinely admin-only surface (e.g. function
  deletion, backend configuration); at that point it would `implies`
  `compute/deploy` — mirroring `sql/admin ⊃ sql/schema` in the registry
  (`capabilities.json:59-63`) — rather than being minted speculatively now.

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
- **Named + versioned (revision counter, not KV-like history).** Keyed on
  `(service, space, name)` with an incrementing `revision`; `created_at` is
  preserved across updates, `updated_at` refreshed. **`save` *replaces* the
  payload in the single `(service, space, name)` row**
  (`database_artifacts.rs:100-135`) — `revision` counts, but prior payloads are
  NOT retained and are not executable. So the `content_cid` pin in §7.2 guards
  against a re-deploy *race*, not rollback: pinning a superseded CID fails by
  design (the old bytes are gone). Do not model this as KV-style version history.
- **Size accounting — F8: NOT automatic; the deploy path MUST update `SqlSizes`.**
  `DatabaseArtifactRepository::save` records `size_bytes` on the row only. The
  space's `store_size` (`db.rs:446-452`) sums block bytes **plus the `SqlSizes`
  registry**, and `SqlSizes` entries are written by the *services*
  (`sql_sizes.update(service, space, name, size)`), not by the artifact repo. The
  compute deploy path therefore MUST call `sql_sizes.update("compute", space,
  name, size)` after a successful save, or **deploys silently bypass the storage
  quota**. Deploy is a write-class request and is gated by the same
  `staged_batch_remaining` pre-check the sql/duckdb write paths use (§10.1).

**Whitepaper alignment.** `appendix/appendix-j.md:114-116` lists the function
types (WASM now, ZK VM future); `appendix/appendix-i.md:299-301` specifies
`sp.compute.deploy(wasmBinary) -> FunctionId` — the returned `FunctionId` is the
content CID from `artifact.content_hash`.

### 5.1 Deploy-time delegation binding

Alongside the artifact, deploy records the **routine data grant binding**:
`function_cid → D_fn` (the deploy-time delegation, see §6). **DECIDED (D2):** the
binding is a **self-describing caveat on `D_fn`** naming the `function_cid` —
`{ "computeFunctionBinding": { "functionCid": "<function_cid>" } }` — NOT an
internal node-side table. `D_fn` is an ordinary delegation event, so its caveat
is persisted and replayable through the normal delegation path. Rationale and the
way this composes with the derived-key identity are in §6.2.

**Caveat encoding (pin the shape).** `Caveats` is a `BTreeMap<String,
serde_json::Value>` and the containment engine compares raw maps, so the exact
shape is load-bearing (byte-equality in the echo rule of §6.2/F1 means key drift
fails closed). The `computeFunctionBinding` object is carried under a positional
map key exactly as the SQL caveat precedent uses (`"0"`), and it is attached to
**every capability row** of `D_fn` (caveats persist per ability —
`delegation.rs:466-476` — not per delegation).

**F4 — `D_fn` rides the standard delegation path, atomically with the artifact
save.** The deploy handler MUST process `D_fn` through the same
verification/persistence path `/delegate` uses (signature check, delegation-side
containment against the deployer's chain, per-ability caveat persistence —
`delegation.rs:275-327, 466-476`), NOT store it as opaque bytes. This is
required because the execute-time chain walk loads parents from the `delegation`
table by CID (`invocation.rs:160-169`); an unverified/unpersisted `D_fn` breaks
execute or defers the failure to the first host call. The artifact save
(`DatabaseArtifactRepository::save` **+ the `SqlSizes` update** of §5's F8 note)
and `D_fn` processing MUST succeed or fail **together, in one transaction** — a
partial deploy yields either a function with no grant (every execution fails) or
a live grant for an artifact that never landed.

**Selecting `D_fn` at execute time — F3 (space scope) + F5 (cite-all).** The
mediator resolves `D_fn` by `(space, functionCid)` where `space` is the space of
the outer `compute/execute` invocation — NOT by `functionCid` alone. It MUST
also verify every capability resource in the selected `D_fn` lives in that space
before citing it. (Identical WASM deployed in two spaces shares one CID; matching
on CID alone is a cross-space confused deputy — see §6.2/F3, which additionally
hardens the derivation path so this is cryptographically impossible.) When more
than one valid `D_fn` matches (a re-mint after key rotation, two deployers, a
re-grant with wider caps), the mediator **cites all matching valid `D_fn`s as
parents** — an invocation's `parents` is already a `Vec`, and `validate()`
authorizes each capability if *any* parent supports it
(`invocation.rs:226-236`). Cite-all degrades gracefully when an older grant is
revoked mid-life.

**Re-deploy hygiene.** A re-deploy with new bytes yields a new CID → a new
`routine_did` → the old `D_fn` is dormant (the old bytes are gone, §5, so the old
routine key is never derived again), but it remains a live-looking delegation
row. The deploy path SHOULD **revoke the superseded `D_fn`** on re-deploy so the
event graph does not accumulate live grants to identities that can no longer act.
Re-mint (recovering from a dstack seed rotation, §6.2/F1.5) is cheap by design:
deploy the identical bytes with a fresh `grant`, no artifact change.

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
derived by the node from the function's **canonical resource URI**, under a
versioned domain prefix:

```
resource_uri = <space>/compute/<function_cid>          (ResourceId display form, §4;
                                                        used by authorizer + binding caveat)
routine_did  = did:key( get_key("tinycloud/compute-key/v1/"
                                 + base32(blake3(space_canonical))
                                 + "/compute/" + <function_cid>) )
```

The **canonical resource URI** (`<space>/compute/<function_cid>`) remains the one
spelling shared by the authorizer and the binding caveat — the exact bytes the
resource machinery already produces (`resource.rs:268-282`), no second
serialization to keep in sync. The **key-derivation input**, however, hashes the
space component: `base32(blake3(space_canonical))` — a **fixed-width, lowercase
base32, delimiter-free** token (blake3 is already available in `tinycloud-core`
`hash.rs`) — so uniqueness does not depend on the still-stubbed `Name` grammar
(Codex C8, defect a); the `function_cid` is base32 and delimiter-free already. The derivation
uses the existing dstack hierarchical key derivation (`dstack::get_key`,
`dstack.rs:110-119`). The `compute-key/v1/` prefix is domain-separated and
version-tagged, so a future derivation-scheme change (e.g. `v2`) does not collide
with existing routine identities. The private key is derived inside the TEE and
never leaves it, so **only this node, running this
exact function CID in this exact space, can act as the routine.** (Non-TEE /
classic mode: the same derivation runs off the node's static key material via
`keys.rs`; the trust statement weakens to "the node" — see §9.3.)

**F3 — the space component is mandatory, and it is hashed into the derivation.**
The space component is not optional, and (per Codex C8/defect a) it enters the
derivation as `base32(blake3(space_canonical))` rather than as a validated raw
name — hashing REPLACES any "names must be validated first" requirement, so
compute does not block on the auth-wide `Name` grammar (global `Name` hardening is
a separate, deferred task, §12.2/P4). Deriving from the CID *alone* would give
identical
WASM deployed in space A and space B one shared `routine_did`, opening a
**cross-space confused deputy**: a space-B execution could cite space A's `D_fn`
(same delegatee, valid chain rooted in A's owner) and read/write space A's data
for a space-B invoker who holds nothing on A. Embedding the space in the resource
URI makes the routine identity per-`(space, function)`, so cross-space citation
is **cryptographically impossible** rather than merely policy-blocked — which
aligns with the strict-verifiability principle (cryptographically-impossible
beats policy-checked) and preserves the D1 choice (still TEE-derived, still no
secret at rest). This is defense-in-depth *with* the normative
`(space, functionCid)` selection rule of §5.1 — both layers ship.

> **Safety requirement (blocking before compute activates) — CHOSEN OPTION:
> hash the space component.** The derivation string's uniqueness depends on
> `<space>` and `<function_cid>` not colliding into one string across distinct
> `(space, function)` pairs. CIDs are base32 (no `/` or `:` delimiters) — safe.
> But **space `Name` validation is a stubbed `// TODO` in
> `tinycloud-auth/src/resource.rs`** (`Name::try_from` / `FromStr`,
> resource.rs:28-44), and `SpaceId`/`ResourceId` parsing constructs `Name`
> directly, bypassing that validator (resource.rs:306-369) — so a narrow
> `Name::from_str` check would not make real URI parsing safe. **Therefore the
> compute derivation hashes the canonical space string —
> `base32(blake3(space_canonical))`, fixed-width and delimiter-free** — before it
> enters the derivation string, making collisions impossible without depending on
> the global `Name` grammar. Global `Name` hardening remains desirable but is a
> **separate, compatibility-sensitive auth task** — NOT a compute precondition.
> Tracked as a test obligation in §13.1.

**DECIDED (D1): routine identity is this deterministic TEE-derived key.** It
needs no secret at rest and binds data access to both the function and the node.

> **Deployment risk — dstack key stability across CVM redeploys (VERIFY
> EMPIRICALLY).** This mechanism assumes `dstack::get_key(path)` returns a
> *stable* key for a given path across CVM redeploys. That stability is a known
> open question in this stack: a prior **DID-drift incident in OpenCredentials**
> showed dstack-derived key material shifting across deploys, which would change
> `routine_did` and silently invalidate every `D_fn` bound to the old identity.
> Before relying on derived-key identity in production, this MUST be verified
> empirically on the target CVM (derive `routine_did` for a fixed
> `function_cid`, redeploy the CVM, re-derive, assert equality). **Fallback if
> derivation proves unstable:** a freshly-generated per-deploy routine key
> persisted (encrypted) alongside the artifact — this survives node/CVM
> migration at the cost of a secret at rest and a key-management surface. The
> spec is written against the derived-key primary; switching to the persisted
> key is a localized change to the routine-key handle in `ComputeService`
> (§11.1) and does not affect the wire format, the binding caveat (§6.2/D2), or
> the authorization layers.

**Deploy-time binding.** At deploy, the deployer — who *does* hold data caps
(the space owner, or an attenuated delegate) — mints a UCAN delegation `D_fn`:

- `delegatee = routine_did`
- `capabilities =` the attenuated data grant the routine needs, e.g.
  `tinycloud.kv/get` on `inputs/` and `tinycloud.kv/put` on `outputs/`
- a **self-describing CID-binding caveat** naming the `function_cid` this
  delegation is for (see below)
- signed by the deployer, extending the deployer's own chain to the space owner

**F2 — the deployer obtains `routine_did` via a handshake, NOT client-side math.**
`get_key(...)` derives from the node's TEE-internal (or `keys.rs`) secret seed;
the public `routine_did` is **not** computable client-side from the CID (if it
were, the private key would be too and the scheme would be broken). Knowing the
derivation *convention* gives the deployer nothing. There is no chicken-and-egg —
the fix is a read-only handshake:

```
1. Client hashes the WASM locally → function_cid (the CID convention is public).
2. Client asks the node for the routine identity — a read-only, side-effect-free
   request `ComputeRequest::RoutineDid { content_cid }` (§7.2). The node derives
   the keypair for (space, content_cid) and returns the PUBLIC routine_did. No
   secret is exposed.
3. Client mints D_fn (delegatee = returned routine_did, binding caveat,
   attenuated data caps) and submits deploy(wasm, D_fn).
```

This handshake **doubles as the dstack-stability probe** (the boxed note above):
the same "derive and return" operation is exactly what you re-run after a CVM
redeploy to check `routine_did` is unchanged. `D_fn` then travels in the deploy
request (§5.1).

**F1.5 — compare-on-execute tripwire.** The deploy ack returns the expected
`routine_did` (already implied by `D_fn.delegatee`) and the SDK records it.
Before running a function, the node **re-derives** the key for
`(space, artifact CID)` and compares against `D_fn.delegatee`. On mismatch it
fails with a *distinct* error code `routine-identity-rotated` (mapped to 409 or
503 — NOT a generic 403), telling the deployer to re-mint `D_fn`. Without this, a
dstack seed rotation surfaces as `UnauthorizedInvoker` deep inside a host call,
indistinguishable from a bug.

**DECIDED (D2): the `function_cid → D_fn` binding is a self-describing caveat on
`D_fn`, NOT an internal node-side table.** The binding is expressed as a caveat
on `D_fn` naming the `function_cid`:

```json
{ "computeFunctionBinding": { "functionCid": "<function_cid>" } }
```

Rationale (per the decision): an internal lookup table is out-of-band node
state — unverifiable from the event graph and non-portable across nodes. The
caveat keeps the binding **auditable** (any party replaying the delegation
events sees exactly which function each `D_fn` authorizes) and **portable** (a
node migration carries the binding inside the signed delegation, not a private
side table). Note the binding is *enforced cryptographically already* by the
derived-key identity (D1): only the execution of `function_cid` can derive the
key that matches `D_fn.delegatee`, so the caveat is the auditable, self-
describing record of a binding that the key derivation makes unforgeable — the
two decisions compose, they do not overlap. The execute path reads
`function_cid` out of this caveat to locate the correct `D_fn` for the loaded
artifact.

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

No new *authorization-engine* code is required — `validate()` already enforces
(i) `delegatee`-match via `did_principal_matches` (the routine's internal
invocations are matched against `D_fn.delegatee == routine_did`), and (ii) chain
containment against the persisted delegation. The new code is the **host
mediator** that mints and submits the routine's internal invocations (and the
deploy-time processing of §5.1). But the mediator carries a non-obvious, MUST-DO
obligation that the "step 4" flow above hides:

**F1 (MUST) — the caveat-echo obligation.** Once `D_fn` carries the
`computeFunctionBinding` caveat (§6.2/D2), its ability rows have a non-empty,
non-SQL caveat map. The invocation-path containment helper
`caveats_contain_child` (`invocation.rs:271-289`) has exactly three outcomes for
a non-SQL parent caveat: pass if the parent map is empty, pass if
`parent.0 == child.0` (byte-equal JSON maps), otherwise **reject** with
`invocation-caveats-not-subset-of-chain`. Therefore **every internal invocation
the host mediator mints MUST echo `D_fn`'s caveat map verbatim on each
capability**, or every `storage.get`/`storage.put`/`sql.query` host call fails
closed on its first use. A mediator that mints caveat-less internal invocations
(the natural reading of step 4) ships a service where every function fails on its
first data access. The echo propagates down the Cloudflare chain (§9.2):
`D_worker` is a child of `D_fn` and — under the same equality rule on the
*delegation* side (`delegation.rs:336-364`) — must echo the binding caveat, and
the Worker's callback invocations must echo it again. Consequence to record:
because the rule is byte-equality (only resources/abilities narrow via
`extends`), `D_worker` **cannot attenuate the caveat map**; that is acceptable
(the binding caveat is metadata, not a constraint) but forecloses worker-specific
restrictions in that map without touching the W1-hardened helper. See §13 for the
matching test obligation.

**F1.8 — caveated deployers (document the practical rule).** Delegation-side
containment applies the same equality rule at *mint* time: if the deployer's own
ability rows carry a **non-SQL** caveat, adding `computeFunctionBinding` breaks
byte-equality and the `D_fn` mint is rejected (`child-caveats-not-subset-of-
parent`). If the deployer's authority carries an *SQL* constrained-statements
caveat, the `(Some, Some)` arm checks only SQL containment and ignores extra keys,
so the binding caveat rides along. Net rule: **the deployer of record should hold
caveat-free (or SQL-caveat-only) data authority.** Space owners — the expected
deployers — always qualify via the root-authority short-circuit
(`invocation.rs:344-362`). This is pre-existing W1 helper behavior, not a compute
defect, but §6.2 states it so deployers are not surprised.

**Why a derived-key *identity* over a caveat-scoped self-delegation.** This is a
distinct question from the D2 binding caveat above. An alternative *identity*
model is to let the routine act *as the deployer* under a new "only usable
inside function CID X" caveat — i.e. the caveat would be the enforcement
boundary. That needs a new runtime invocation-path check ("am I currently
executing inside function CID X?"), which is exactly the kind of trust-boundary
state that is hard to make fail-closed. The derived-key identity needs no such
runtime check: only the execution of `function_cid` can derive the key that
matches `D_fn.delegatee`, so identity enforcement is cryptographic, reusing
`did_principal_matches` and the existing chain walk, and binds data access to
**both** the function identity and the node identity (attestable via
`/attestation`). The D2 caveat then rides *on top of* this as the auditable,
portable record of the binding — it documents the linkage in the event graph;
the derived key is what makes it unforgeable.

### 6.3 Caveat source is the chain, not the facts

Following the same W1 fail-closed lesson the SQL service encodes
(`handle_sql_invoke`, `routes/mod.rs:1192-1246`: the constrained caveat is
derived from the *validated delegation chain*, and invocation facts are only a
fallback), the enforced `ComputeCaveats` (§7) — especially the `functions`
allowlist — MUST be read from the validated chain, not trusted from the
invoker's own invocation facts. An invoker cannot widen or drop the function
allowlist by editing the invocation envelope.

**Invoker-side caveat echo (F1 bites layer (a) too).** The same byte-equality
containment rule means an invoker whose `compute/execute` delegation carries a
non-SQL `ComputeCaveats` map MUST echo that map verbatim on the invocation
capability, or `validate()` rejects the invocation before the handler ever runs
(`invocation.rs:271-289`). The SDK's compute-invoke helper therefore has to copy
the chain caveats onto the invocation — the same pattern the SQL
constrained-statements flow already uses. Land this in the same SDK changeset so
layer-(a) requests under a caveated grant do not fail closed.

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

**Request-variant → ability mapping (NORMATIVE — Codex C1).** The dispatch above
only proves the presented `tinycloud.compute/*` capability follows its delegation
chain (`invocation.rs:218`); it does NOT tie the capability to the *body*. The
handler therefore MUST map each `ComputeRequest` variant to its required ability
and reject a request whose presented capability does not satisfy it (via
`ability_matches`, so an active `compute/*` wildcard covers all): `RoutineDid` and
`Deploy` require `compute/deploy`; `Execute` requires `compute/execute`; `List`
requires `compute/list`. Without this a holder of `compute/execute` (or `list`)
could submit a `Deploy` body. This is exactly why the SQL path carries a separate
request-sensitive authorization check (`require_sql_admin_for_request`,
`routes/mod.rs:1232`); compute mirrors it.

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
    /// Read-only: return the PUBLIC routine DID the node would derive for this
    /// (space, content_cid). No side effects, no secret exposure. This is the
    /// F2 handshake step (§6.2): the client needs it to set D_fn.delegatee
    /// before deploy, and re-running it after a CVM redeploy is the
    /// dstack-stability probe.
    RoutineDid {
        content_cid: String,
    },
    /// Register / upload a new function version. The WASM binary rides as the
    /// request body when large; `wasm_b64` is accepted for small inline
    /// deploys. `grant` carries the deploy-time delegation D_fn (§6.2), which
    /// the handler processes through the standard /delegate path atomically
    /// with the artifact save (§5.1/F4).
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
- **Deploy body.** **MVP (normative) = JSON body + base64 `wasm_b64` + an inline
  encoded `D_fn` only.** Raw-body WASM streaming (the duckdb `import`-style path,
  `routes/mod.rs:1748-1769`) and **pre-submitted grant CIDs** are **DEFERRED /
  non-normative for the MVP** (Codex C7): raw bytes leave no defined channel for
  the deploy metadata + grant, and a pre-submitted CID contradicts atomic grant
  persistence (§5.1/F4). They are listed under the deferred work; the deploy
  handler computes the CID from the received base64 bytes.
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
they do not collide across repeated executions of the same function. This means
"execute the same function twice" is allowed (two distinct outer envelopes, two
distinct routine invocation sets); it is *not* an accidental replay.

**Entry point (precision — Codex C4).** The route-level replay cache guards
`POST /invoke` only (`routes/mod.rs:714`). The mediator's internal routine
invocations are verified AND executed through an **injected internal-invocation
executor backed by `SpaceDatabase::invoke`** (server-composed, `db.rs:620-720`) —
NOT by calling core `process()` alone, which only verifies+persists an invocation
and returns its hash (`invocation.rs:105-118`) and so cannot return KV data. This
executor path never touches the route replay cache (internal invocations use
fresh nonces, so uniqueness is preserved); do not "helpfully" route internal
invocations back through the HTTP path, which would re-trigger the outer replay
cache and CORS/auth guards they neither need nor should re-trigger.

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

#### 9.1.1 Execution manifest / egress journal (F6, wasmtime — NORMATIVE)

Because the wasmtime guest has **no unmediated channel** (no WASI net/fs; every
side effect flows through the `HostMediator`), the mediator MUST **journal every
host call** for the execution, producing an *execution manifest*:

- per host call: `(resource, ability, bytes_in, bytes_out, output_destination)`
  — where `output_destination` is `inline` or the KV path written;
- per execution: the capabilities **granted** (enumerated from the selected
  `D_fn`) vs the capabilities **exercised** (the distinct `(resource, ability)`
  pairs that actually appeared in host calls).

On this backend **the manifest is ground truth**: since no unmediated egress
exists, everything the routine did to space data is in the journal — nothing can
leave except through a logged host call or the returned output. This is genuine
**permission observability**: capabilities that were *granted but never
exercised* are the concrete scope-down signal a deployer uses to tighten `D_fn`
on the next deploy (grant only what the manifest shows the function actually
touches). Contrast this with the Cloudflare backend (§9.2), where the manifest
covers only the *mediated callbacks* and NOT the Worker's unrestricted `fetch` —
there the manifest is a lower bound, not ground truth.

**Storage shape (spec-level decision).** The manifest rides in the
`InvocationOutcome` **metadata**, following the existing outcome-metadata
precedent — `KvMetadata(Option<Metadata>)` is surfaced via the `ObjectHeaders`
responder (`auth_guards.rs:87`, `Metadata` from `tinycloud_core::types`). Compute
attaches the manifest to `ComputeResult` the same way (a `Metadata`-carried
`x-compute-manifest` block, or a `manifest` field on the result JSON for the
inline case), so no new transport is introduced. It **MAY** additionally be
persisted to a KV audit path under the space (e.g.
`audit/compute/<function_cid>/<invocation_cid>`) written under the routine's own
`D_fn` grant — the same KV-output mechanism as §8 option 2, so audit records are
governed by ordinary KV read delegations. Persisting is opt-in via node config
(§11.4); the in-outcome manifest is always returned.

### 9.2 CloudflareWorkerBackend

- **Runs** the function as a Cloudflare Worker. The node acts as the
  orchestrator: it sends the function (or a pre-deployed Worker reference) and
  the input to the Worker, and the Worker returns the output.
- **What is sent:** the WASM/Worker script reference or bytes, the input
  payload, and a **scoped, short-lived credential** (`D_worker`) the Worker uses
  to call back into the node's `/invoke` for the routine's data access.
  `D_worker` is a delegation whose delegatee is the Worker's identity, a child of
  `D_fn` attenuated (in resource/ability only) to the routine's data caps — the
  Worker cannot exceed them because the node validates its callbacks through the
  normal chain check. The private routine key is **not** shipped to the Worker.
  Per F1, `D_worker` and the Worker's callback invocations MUST echo `D_fn`'s
  `computeFunctionBinding` caveat verbatim (the byte-equality containment rule
  applies on both the delegation and invocation sides), so the caveat map cannot
  be attenuated — only resources/abilities narrow.
- **Callback credential mechanics (`D_worker`).** The Worker identity is a
  **fresh ephemeral keypair per execution — never reused** (reuse turns a leaked
  key into a standing capability). **The keypair is generated worker-side**: the
  Worker generates it at start and returns its public key, then the node mints
  `D_worker` for that pubkey — so the private key never transits Cloudflare (one
  extra round-trip, chosen over node-side generation precisely to keep the key
  off the wire). **TTL:** `exp = now + effective_maxDuration + slack`, slack for
  dispatch/queue jitter, e.g. `min(2 × maxDuration, cloudflare.callback_ttl_max)`
  with a config ceiling like `120s`; `D_fn`'s own expiry naturally caps it (a
  child cannot outlive its parent — `delegation.rs:230-270` filters parents by
  the expiry / not-before window). **Revocation:** the node records the
  `D_worker` CID in the execution context and issues a standard revocation on
  completion, timeout, or error. Because `validate()` walks revocations *per
  invocation* with no chain-ok caching (`invocation.rs:180-198`), a mid-flight
  revocation cuts a misbehaving Worker off at its next callback — this is the
  real kill switch; the TTL is only the backstop for a node that crashes before
  revoking. Revoking `D_fn` itself kills every live `D_worker` transitively via
  `first_revoked_ancestor` — the **deployer panic button**, effective even while
  an execution is in flight. Callbacks are ordinary `/invoke` requests, so the
  route replay cache rejects envelope replays; fresh nonces per callback.
- **What is returned:** the function output (JSON or bytes).
- **`verify` = trust-the-deployment.** There is no cryptographic execution proof
  from a stock Cloudflare Worker. The trust model is: you trust Cloudflare's
  runtime to have executed the deployed script faithfully, and you trust the
  node↔Worker transport. This is strictly weaker than the in-node TEE backend
  and MUST be surfaced to callers (a `verification: { mode: "trusted-deployment",
  backend: "cloudflare" }` field on the result).
- **F7 — code identity on CF is a bookkeeping claim, not content-addressed.** On
  wasmtime, code identity is checked at the moment of use (the node hashes the
  bytes it is about to run; the grant follows the hash). On CF the node deploys a
  script once and thereafter trusts that the Worker at route R still corresponds
  to `function_cid` — anyone with Cloudflare account access (**including
  Cloudflare**) can swap the script behind R while `D_worker` is valid, and the
  swapped code inherits the callback credential. So on CF the CID binds the grant
  to *what the node uploaded*, not to *what runs*, and **the Cloudflare account
  credentials join the TCB**. `verification: { mode: "trusted-deployment" }` is
  documented as carrying exactly this meaning.
- **F6 — egress: confidentiality on CF, and the Outbound-Worker mitigation.** The
  wasmtime backend's strongest property is that it has *no exfiltration channel*:
  the guest has no net/fs, only mediated host imports (§9.1), so data the routine
  reads can flow only to (a) the function output or (b) KV paths under `D_fn`'s
  `kv/put`. A **bare** Cloudflare Worker has **unrestricted outbound `fetch`**: a
  malicious or compromised function could ship everything its grant lets it read
  to any endpoint on the internet, and the node could neither prevent nor detect
  it (the input payload additionally transits and rests on Cloudflare infra).
  Without the mitigation below, **anything `D_fn`/`D_worker` permits reading must
  be treated as disclosed to the function author and to Cloudflare.**
- **CF egress mediation (F6, SHOULD).** The CF backend SHOULD deploy routines via
  **Workers for Platforms dispatch namespaces** with an **Outbound Worker**
  interposed on all user-Worker `fetch()`
  (developers.cloudflare.com/cloudflare-for-platforms/workers-for-platforms/configuration/outbound-workers/).
  The Outbound Worker enforces a **default-deny allowlist whose sole default
  entry is the node's callback endpoint**, and returns a **full egress log** in
  the run evidence (folded into the execution manifest of §9.1.1, which on CF is
  a lower bound over mediated callbacks — the Outbound Worker raises it toward
  ground truth for `fetch`). Two facts to record:
  - Enabling an Outbound Worker **disables raw TCP `connect()`** in user Workers
    (closing the non-HTTP egress path). However, **`fetch()` from Durable Object
    or mTLS bindings BYPASS the Outbound Worker** — a known Cloudflare gap. This
    is **closed by construction here**: the node authors the deploy and grants the
    routine **no DO/mTLS bindings**, so the bypass path does not exist for our
    routines.
  - The trust anchor **remains Cloudflare** — they run the interceptor and see
    plaintext. So with the Outbound Worker in place the F6 disclosure rule is
    **softened, not removed**, to: *"disclosed to Cloudflare; the function author
    is confined by the CF-enforced egress policy."* Grant read scopes to CF-backed
    functions on that basis; on the in-node wasmtime backend there is no such
    disclosure. This confidentiality posture — not the resource-limit gap of
    §10.2 — is the single most decision-relevant fact when choosing between
    backends. See also §10.2.

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

### 9.4 Future backends — egress mediation pattern (note only, NOT specced)

For a future **self-hosted container/VM backend** (a middle ground between
in-node wasmtime and the trust-Cloudflare Worker), the egress-mediation pattern
to follow is **iron-proxy** (`github.com/ironsh/iron-proxy`, `iron.sh`): a
default-deny outbound allowlist, a per-request audit log, and **credential
brokering** — the sandbox holds only a short-lived proxy token, and the real
secret is injected at the proxy boundary, never inside the sandbox. This mirrors
our host-mediation philosophy exactly: the routine never holds authority; the
mediator exercises it on the routine's behalf. A container backend fronted by
such a proxy would recover the same **execution-manifest ground-truth property**
that wasmtime has (§9.1.1) — every byte out passes through a logged, policy-gated
boundary — without requiring a full in-process WASM sandbox. This is a
forward-reference only; **no container/VM backend is specified here.**

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
- **Confidentiality / egress — the decisive posture.** Even more important than
  the resource-limit concession above. A **bare** CF Worker has unrestricted
  outbound `fetch`, so the backend cannot constrain egress at all; a read
  allowlist limits *what the routine may read* but not *where that data then
  goes*. With the **Outbound-Worker mitigation** of §9.2/F6 (default-deny
  allowlist, node callback as the sole default entry, no DO/mTLS bindings, egress
  logged into the run evidence), function-author exfiltration is **CF-enforced
  away**, and the residual disclosure **softens to "disclosed to Cloudflare"**
  (they run the interceptor and see plaintext). Absent that mitigation, treat
  everything readable as exfiltrable to the function author too. Either way this
  is strictly weaker than the in-node wasmtime backend, where there is **no**
  disclosure; scope read grants to CF-backed functions accordingly.

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
persist_manifest = false         # §9.1.1: also write the execution manifest to
                                 # a KV audit path (in-outcome manifest is always
                                 # returned regardless)

[storage.compute.cloudflare]     # only when default_backend/allowed = cloudflare
account_id = "…"
callback_ttl_max = "120s"        # §9.2: ceiling on D_worker TTL
dispatch_namespace = "…"         # §9.2/F6: Workers for Platforms namespace
# outbound_worker is deployed by the node; user routines get no DO/mTLS bindings
# credentials via env, never in the toml
```

---

## 12. Resolved Decisions & Open Questions

### 12.1 Resolved (decided by Sam, 2026-07-10)

- **D1 — routine identity: DECIDED = deterministic TEE-derived key from the
  function CID** (§6.2). Chosen for no-secret-at-rest and function+node binding.
  **Carries a deployment risk that MUST be verified empirically:** dstack key
  stability across CVM redeploys is a known open question in this stack (prior
  DID-drift incident in OpenCredentials — see the boxed note in §6.2). If
  derivation proves unstable on the target CVM, the recorded **fallback** is a
  persisted, encrypted per-deploy routine key (a localized `ComputeService`
  change; no wire/auth impact).
- **D2 — binding representation: DECIDED = self-describing CID-binding caveat on
  `D_fn`** (`{ "computeFunctionBinding": { "functionCid": … } }`), NOT an
  internal node-side table (§5.1, §6.2). Rationale: an internal table is
  out-of-band state unverifiable from the event graph; the caveat keeps the
  binding auditable and portable. It composes with D1 — the derived key makes
  the binding unforgeable; the caveat makes it auditable.
- **Deploy authorization tier: DECIDED = capabilities stay specific, no
  `compute/admin` URN for now** (§3). `compute/deploy` is the privileged
  code-mutating ability, analogous to `tinycloud.sql/schema`; standard-tier
  session grants exclude `compute/deploy`. A future `compute/admin` would
  `implies` `compute/deploy` (mirroring `sql/admin ⊃ sql/schema`) only once a
  real admin-only surface (function deletion, backend config) exists.

### 12.2 Still open

- **Cloudflare callback credential lifetime & revocation — PROPOSAL RECORDED
  (§9.2).** No longer fully open: §9.2 now specifies a fresh worker-side
  ephemeral keypair per execution (key never transits), TTL = `maxDuration +
  slack` under a `cloudflare.callback_ttl_max` ceiling (capped by `D_fn`'s
  expiry), per-invocation revocation on completion/timeout/error as the kill
  switch, and `D_fn` revocation as the deployer panic button. Remaining open bit:
  the exact slack multiplier / ceiling default, to tune against real CF dispatch
  jitter.
- **Result cache — DEFER; structural gate criterion recorded.** A
  `(content_cid, input_hash)` cache is only sound when the output depends on
  nothing else. "The function declares itself pure" is the WRONG gate
  (declarations lie). The *structural, checkable* gate is: cacheable **iff**
  `D_fn` grants no read capability (or is absent) **and** the request has no
  `input_refs` — then the WASM had nothing to read but `input`, and wasmtime is
  deterministic for it (enable NaN canonicalization; use **fuel** — not epoch
  deadlines, which are wall-clock-dependent — as the determinism-relevant budget,
  so only *successful* results are cacheable). Anything that reads KV is a
  function of mutable state; a correct key would need the read-set version vector.
  No consumer today → out.
- **Binary inline outputs — DEFER.** The KV output path (§8 option 2) already
  handles binary results, and the `SqlExport`/`DuckDbExport` octet-stream
  responder precedent (`auth_guards.rs:125-133`) makes a later `ComputeBytes`
  variant mechanical. Base64-in-JSON inflation (~33%) under the 413 ceiling is
  tolerable for small blobs; no consumer demands inline binary today. Revisit the
  moment a consumer inlines >1 MB binaries (double-paying base64 + JSON parse).
- **Multi-node execution.** Confirmed OUT of scope here; the escalation path is
  the orchestration layer (Smithers). Flagged so a reviewer does not expect it.
- **ZK verification — deployment realities (FUTURE only; extends §9.3).** Not
  built; recording the realistic shape so the interface holds when it lands:
  - **Where the prover runs.** The prover **cannot run inside a Worker** — the CF
    isolate is capped at ~128 MB, and current Jolt (alpha) needs GPU-class
    hardware. Jolt's Twist/Shout **streaming prover** targets `<2 GB`, which
    would fit **CF Containers** later — so the realistic near-term home is a
    container/VM backend (§9.4), not the Worker.
  - **Two-phase shape.** When it comes: the worker/backend executes fast and the
    output is returned **marked `unverified`**; the prover generates the proof
    **asynchronously**; the node's `verify()` then flips the result to
    `verified`. The `run` → `output`+evidence → `verify` interface (§9) already
    supports this split — no interface change, just an async `verify` that
    resolves later.
  - **Artifact wrinkle.** Jolt proves **RISC-V (RV64IMAC)**, not WASM. So a
    zk-verified function needs a **RISC-V build with its own digest**, pinned in
    the `computeFunctionBinding` caveat **alongside** the WASM CID (the WASM CID
    stays the routine-identity anchor; the RISC-V digest is what the proof is
    about). Both must be recorded at deploy so `verify()` knows which artifact the
    proof attests.
  - **Cheap interim integrity for CF (no ZK).** Deterministic wasmtime (fuel
    budget, NaN canonicalization) + **random spot re-execution on the node** (a
    `k%` audit that re-runs the same input in-node and compares output) catches
    swapped/misbehaving CF code **probabilistically** — a low-cost partial answer
    to F7 available long before ZK.
  - **Scope.** ZK fixes **F7 (integrity)** fully in principle — no trust in the
    executor. It does **NOT** address **F6 (confidentiality)**: a proof that the
    right code ran says nothing about where the code sent the data it read. Say
    so plainly so ZK is not mistaken for an egress control.

---

## 13. Implementation Plan (sketch)

Spec-only doc — no code lands here. When implementation begins, the ordered
steps are:

1. `capabilities.json` reserved entries + `node scripts/gen-capabilities.mjs` +
   drift-guard green.
2. `ComputeService`, `ExecutionBackend` trait, `WasmtimeBackend`, `HostMediator`
   in a new `tinycloud-core/src/compute/` module (feature `compute`).
   Routine-key derivation keyed on **`(space, function_cid)`** (§6.2/F3).
3. `RoutineDid` handshake action (§7.2/F2) — read-only derive-and-return of the
   public `routine_did`; also the dstack-stability probe (§6.2/F1.5).
4. Deploy path: process `D_fn` through the standard `/delegate`
   verification/persistence path **atomically** with the artifact save **and the
   `SqlSizes` update** (one transaction — §5.1/F4, §5/F8); revoke a superseded
   `D_fn` on re-deploy (§5.1).
5. Execute path: re-derive routine key + compare-on-execute tripwire
   (`routine-identity-rotated`, §6.2/F1.5); space-scoped cite-all `D_fn`
   selection (§5.1/F3/F5); backend `run` with the **host mediator echoing
   `D_fn`'s caveat map verbatim** on every internal invocation (§6.2/F1);
   internal invocations enter via core `process()`, not the HTTP route (§8.2);
   output inline/KV.
6. `InvocationOutcome::ComputeResult`/`ComputeList` + Responder arms +
   `handle_compute_invoke` dispatch branch + 501 gate + `/version` feature.
7. Flip registry entries to `active`, add wildcard `implies`, extend
   `canonical_decisions_are_locked`. **SDK: enumerate `compute/execute` +
   `compute/list` in the standard session grant — NEVER `compute/*`** (§3/F9).
8. CloudflareWorkerBackend + callback-delegation (`D_worker`) minting with the
   worker-side ephemeral keypair, TTL, and revocation of §9.2 (echoing the
   binding caveat down the chain, §6.2/F1).
9. (Later) TEE-quote verifier binding `report_data` to execution; ZK-VM backend.

### 13.1 Test obligations (from the fable review)

- **F1 caveat-echo (integration):** a routine host call whose internal
  invocation does NOT echo `D_fn`'s `computeFunctionBinding` caveat is rejected
  with `invocation-caveats-not-subset-of-chain`; the correctly-echoed call
  succeeds. Assert the same on the CF chain (`D_worker` + Worker callback).
- **F1 invoker-side echo:** a `compute/execute` invocation under a
  `ComputeCaveats`-carrying grant that omits the echoed caveat is rejected before
  the handler runs.
- **F3 cross-space isolation:** identical WASM deployed in space A and space B
  yields distinct `routine_did`s; a space-B execution cannot cite space A's
  `D_fn` (both the derivation-path hardening and the selection rule are
  exercised).
- **Space-component hashing (precondition, Codex C8):** the routine-key
  derivation hashes the canonical space string into a fixed-width, delimiter-free
  token; assert that two distinct spaces (including adversarially-chosen names
  with embedded delimiters) can NEVER produce the same derivation input, without
  relying on the global `Name` grammar. (Global `Name` hardening is a separate
  auth task, not tested here.)
- **Execution manifest (F6 wasmtime):** an execution's returned manifest lists
  every host call `(resource, ability, bytes_in/out, destination)` and the
  granted-vs-exercised capability sets; a function that never touches a granted
  capability shows it as granted-but-unexercised (the scope-down signal).
- **F4 atomicity:** a deploy whose `D_fn` fails verification leaves NO artifact
  row and NO `SqlSizes` entry (and vice-versa) — the transaction is all-or-
  nothing.
- **F8 quota:** a deploy increments the space's `store_size` (via `SqlSizes`) and
  a subsequent over-quota deploy 402s.
- **F1.5 rotation:** an execute whose re-derived key ≠ `D_fn.delegatee` fails
  with the distinct `routine-identity-rotated` code, not a generic 403.
