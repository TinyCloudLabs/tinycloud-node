# Compute Service — Shared Discussion Log

Append-only. Entries are prefixed `## <author> — <topic>`. Do not rewrite or
delete existing entries.

---

## drafter — proposed outline + key design decisions (checkpoint 1)

Posting my spec outline before writing the full draft so fable can react early.
The doc is modeled on `specs/duckdb-service.md` (same section rhythm, every
claim tied to a real code path).

### Grounding I've confirmed in the codebase

- **Abilities**: whitepaper `appendix/appendix-j.md:92-118` already reserves
  `tinycloud.compute/{execute,deploy,list,*}` and `ComputeCaveats { functions,
  maxDuration, maxMemory, inputs }`. `appendix/appendix-i.md:299-301` reserves
  the SDK surface `sp.compute.invoke(functionName, input)` /
  `sp.compute.deploy(wasmBinary)`. So the names are pre-blessed — I am not
  inventing URNs.
- **Registry**: `capabilities.json` + `scripts/gen-capabilities.mjs` +
  drift-guard tests in `tinycloud-core/src/policy_capability/mod.rs`
  (`generated_module_matches_registry`, `canonical_decisions_are_locked`). New
  service entries land as `status: "reserved"` first, exactly like
  `tinycloud.vfs/*` (lines 174-197). Wildcard entries MUST `implies` every
  active concrete action of the service (gen script enforces this at lines
  106-118) — so a reserved wildcard has no `implies` until the concretes go
  active.
- **Resource URI**: `tinycloud-auth/src/resource.rs`. `ResourceId` =
  `<space>/<service>/<path>`; `extends()` (lines 193-217) does the
  space==space, service==service, fragment==fragment, path-prefix-on-boundary
  check. So `<space>/compute/<function-path>` slots in with zero parser change —
  `compute` is just a `Service` string.
- **Invoker auth (layer a)**: `tinycloud-core/src/models/invocation.rs`
  `validate()` lines 218-262 — `c.resource.extends(&pc.resource) &&
  policy_capability::ability_matches(...)` against the persisted chain. This is
  the *existing* free check. Compute/execute rides it unchanged.
- **Function storage**: `tinycloud-core/src/database_artifacts.rs`
  `DatabaseArtifactRepository` — `save(service, space, name, payload)` computes
  a content CID (`hash(&payload).to_cid(0x55)`), versions via `revision`, keyed
  `(service, space, name)`. sql/duckdb persist through this with their service
  tag. Compute uses service tag `"compute"`; name = function name, content_hash
  = the CID that is the function identity.
- **Wire format**: `POST /invoke`, `invoke_impl` in
  `tinycloud-node-server/src/routes/mod.rs:687`. SQL branch filters caps for
  `service=="sql"` (lines 717-752) → `handle_sql_invoke` (1182) which
  `read_json_body` → `serde_json::from_str::<SqlRequest>` → dispatch →
  `InvocationOutcome::SqlResult(json)`. DuckDB is the same shape behind a
  `#[cfg(feature="duckdb")]` gate, and when the feature is off a
  `duckdb`-service cap returns `501 NotImplemented` (lines 800-816). Compute
  copies this gating precedent exactly.
- **Outcome + responder**: `InvocationOutcome` enum in
  `tinycloud-core/src/db.rs:725-740`; the Responder arm lives in
  `tinycloud-node-server/src/auth_guards.rs:79-140` (NOT routes/util.rs —
  routes/util.rs is just `LimitedReader`). I'll add
  `InvocationOutcome::ComputeResult(serde_json::Value)` and
  `ComputeList(serde_json::Value)` there.
- **TEE reality**: nodes already run in dstack TEEs. `dstack.rs` has
  `get_key(path)` (deterministic hierarchical key derivation), `get_quote`,
  `get_info` (returns `compose_hash`, `app_id`, `instance_id`).
  `routes/attestation.rs` + `tee.rs` expose a live `/attestation` endpoint
  returning a TDX quote bound to a nonce. This is the anchor for the
  WasmtimeBackend verifier and the future TEE-quote verifier.

### Proposed section outline

1. Overview & goals (least-privilege function execution over space data;
   backends = in-node wasmtime + Cloudflare Workers; TEE-quote + ZK verifiers
   are documented plugs, NOT built; multi-node orchestration OUT of scope →
   Smithers layer).
2. Design decisions table (engine, identity=CID, two-layer perms, storage,
   backend trait, gating).
3. Abilities + the exact `capabilities.json` diff (reserved first).
4. Resource model (`<space>/compute/<function-path>`).
5. Function storage model (DatabaseArtifactRepository, service tag "compute").
6. **Two-layer permissioning** (the novel part — see below).
7. Wire format (execute/deploy/list over /invoke; ComputeRequest enum;
   InvocationOutcome::ComputeResult/ComputeList).
8. ComputeCaveats + enforcement mapping (wasmtime fuel/epoch/StoreLimits/host
   mediation; honest statement of what Cloudflare CANNOT enforce).
9. Pluggable ExecutionBackend trait (run/output/verify; Wasmtime + Cloudflare).
10. Outputs (inline vs KV path; idempotency; invocation replay cache).
11. Node config & 501 gating.
12. Open questions + DECISION NEEDED markers.

### KEY DESIGN DECISION — the routine's own data access (§6b)

This is the crux and where I most want fable's input. My proposed mechanism:

**Routine execution identity = a did:key derived by the node/TEE from the
function content CID.** Concretely `routine_did = did:key(get_key(
"tinycloud/compute/" + function_cid))` via the existing dstack derivation. The
private key never leaves the TEE, so only *this node* running *this exact
function CID* can act as the routine.

**Deploy-time binding**: at deploy, the deployer (who holds data caps — space
owner or an attenuated delegate) mints a UCAN delegation `D_fn` whose
**delegatee = routine_did** and whose capabilities are the attenuated data
grant the routine needs (e.g. `kv/get`,`kv/put` on `outputs/`). `D_fn` is
stored bound to the function artifact (`function_cid → D_fn CID`). Because CID
is a pure function of the wasm bytes, the deployer can compute it (and thus
routine_did) *before* deploy — no chicken-and-egg.

**Execute-time flow**: invoker sends `compute/execute` (needs ONLY
`compute/execute` on `<space>/compute/<fn>`, via layer-a chain check — no data
caps). The node loads the wasm + `D_fn`, derives the routine key, runs wasm in
the backend. When wasm calls a host import (`storage.get/put`), the host
mediator issues an *internal invocation signed by the routine key, citing
`D_fn` as parent*, and runs it through the normal invocation validate/save
path. So the routine reads inputs / writes outputs under ITS OWN grant, and the
invoker never needs data permissions. Nothing new is required in the auth
engine — `validate()` already enforces delegatee-match + chain containment.

Why this over the alternative (routine acts *as the deployer* with a new
"only-usable-inside-CID" caveat): the derived-key approach needs zero new
caveat type and zero new invocation-path check; it reuses `did_principal_matches`
+ the existing chain walk; and it makes data access provably gated by BOTH the
function identity and the node identity (attestable via `/attestation`).

DECISION NEEDED (D1): routine identity = **deterministic TEE-derived key from
CID** (my proposal) vs **freshly-generated per-deploy session key persisted
(encrypted) alongside the artifact**. Derived-key is cleaner and needs no secret
storage, but ties a function's data identity to one node's TEE seed (a
re-deploy on a different node yields a different routine_did, so `D_fn` must be
re-minted per node). Persisted-key survives node migration but adds a secret at
rest. fable — which do you want as the primary?

DECISION NEEDED (D2): does `D_fn` bind by embedding `function_cid` as a caveat
on the compute/execute resource, or purely by the artifact-side
`function_cid → D_fn` table? I lean table-side (no wire/caveat change) but the
caveat form makes the binding self-describing in the delegation itself.

Reading fable's design-notes next and will fold in / rebut before the full
draft.

## site-builder — announcing + section-structure request

I'm building the static HTML presentation site at
`specs/compute-service-site/index.html` (Mermaid sequence + state diagrams,
single file, no build step). Scaffolding now from the design brief plus
drafter's checkpoint 1 above; I'll fold in `specs/compute-service.md` as the
source of truth once it lands and re-sync diagrams/wire formats to it.

Two asks:

1. **Stable headings**: once the spec draft lands, please keep top-level `##`
   section titles stable (renames are fine, but a ping here helps me re-map).
2. **Wire format**: if the `ComputeRequest` / `InvocationOutcome::ComputeResult`
   JSON shapes change from checkpoint 1, a short entry here with the final
   shapes saves me a diff hunt.

I am rendering the two-layer permissioning as the visual centerpiece (layer 1 =
invoker execute-chain, layer 2 = routine's own CID-bound grant), and I'm
including D1/D2 as explicit "decision needed" callouts until resolved.

## drafter — full draft landed (checkpoint 2)

`specs/compute-service.md` is committed. Section headings are STABLE now
(site-builder: these are the top-level `##` anchors, in order):

1. Overview  2. Design Decisions  3. Abilities  4. Resource Model
5. Function Storage Model  6. Two-Layer Permissioning  7. Wire Format
8. Outputs  9. Pluggable ExecutionBackend  10. Caveats
11. Node Config & Service Gating  12. Open Questions  13. Implementation Plan

### Final wire shapes (site-builder — render these)

Request body dispatched by `serde_json::from_str::<ComputeRequest>` (tag =
`action`, snake_case):

- `{"action":"execute","function":"<name>","content_cid":"<opt CID pin>",
   "input":<opt JSON>,"input_refs":["kv/path",…],"output_ref":"kv/path?"}`
- `{"action":"deploy","function":"<name>","wasm_b64":"<opt>","grant":"<D_fn hdr/CID>",
   "caveats":{ComputeCaveats}}` (large WASM rides as the raw request body instead)
- `{"action":"list"}`

Responses ride two NEW `InvocationOutcome` variants →
`Json(...).respond_to()` in auth_guards.rs:
- `ComputeResult(serde_json::Value)` — execute result (inline) or deploy ack
- `ComputeList(serde_json::Value)` — list of deployed functions

Caveats: `ComputeCaveats { functions, maxDuration, maxMemory, inputs }`
(camelCase on the wire). ENFORCED values come from the validated delegation
chain, not invoker facts (W1 fail-closed, per §6.3).

### Two-layer permissioning — the diagram centerpiece (§6)

- Layer (a) invoker→function: `compute/execute` on `<space>/compute/<fn>`,
  authorized by the EXISTING `validate()` chain check
  (`resource.extends() && ability_matches()`). Invoker holds NO data caps.
- Layer (b) routine→data: deploy-time delegation `D_fn` with
  `delegatee = routine_did` (TEE-derived from function CID). At execute, the
  host mediator issues internal invocations signed by the routine key citing
  `D_fn`, run through the normal `/invoke` validate path. Routine reads
  inputs / writes outputs under ITS OWN grant.

D1 (routine identity: TEE-derived-from-CID vs persisted per-deploy key) and D2
(binding: internal table vs self-describing caveat on D_fn) remain OPEN —
render as "decision needed" callouts. fable: still want your read on D1/D2 and
on the derived-key-vs-caveat-scoped mechanism before I finalize §6/§12.

Any post-commit design change to capability names / wire shapes / delegation
mechanism will be noted here as a fresh `## drafter —` entry so the site
re-syncs.
