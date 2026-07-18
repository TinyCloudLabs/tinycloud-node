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

## drafter — decisions applied (checkpoint 3)

Sam resolved the open items; `specs/compute-service.md` is updated and committed.
fable + site-builder: re-sync from this entry (you're both rate-limited).

**D1 — routine identity = deterministic TEE-derived key from the function CID**
(my proposal, now decided). §6.2 gains a boxed DEPLOYMENT RISK note: dstack key
stability across CVM redeploys is a known open question in this stack (prior
DID-drift incident in OpenCredentials); it MUST be verified empirically on the
target CVM before production reliance. Recorded fallback if derivation proves
unstable: a persisted, encrypted per-deploy routine key (localized
`ComputeService` change; NO wire/auth/caveat impact).

**D2 — binding = self-describing caveat on `D_fn`, NOT an internal table.**
The `function_cid → D_fn` link is now a caveat on the deploy-time delegation:
`{ "computeFunctionBinding": { "functionCid": "<function_cid>" } }`. Rationale:
an internal table is out-of-band state unverifiable from the event graph; the
caveat keeps the binding auditable + portable. It COMPOSES with D1 (does not
overlap): the derived key makes the binding unforgeable, the caveat makes it
auditable. Updated in §5.1 and §6.2. NOTE for site-builder: this is a new
delegation-caveat namespace on `D_fn`; it is distinct from the invoker-facing
`ComputeCaveats` (functions/maxDuration/maxMemory/inputs) in §10 — please render
them as two separate things (one on D_fn, one on the execute invocation).

**Deploy tier — capabilities stay specific; NO `compute/admin` URN.**
`compute/deploy` is the privileged code-mutating ability (analogous to
`tinycloud.sql/schema`). Standard-tier session grants EXCLUDE `compute/deploy`
(a browser session may hold execute/list but not deploy). A future
`compute/admin` would `implies` deploy — like `sql/admin ⊃ sql/schema` — only
once a real admin-only surface (function deletion, backend config) exists. Added
to §3. **capabilities.json proposed diff is UNCHANGED** by this — still the same
three specific URNs + wildcard, reserved-first, no admin.

**Wire shapes: UNCHANGED.** `ComputeRequest` (execute/deploy/list),
`InvocationOutcome::ComputeResult`/`ComputeList`, and `ComputeCaveats` are all
exactly as in checkpoint 2. The only new wire artifact is the D_fn binding
caveat above (on the delegation, not the invocation).

**Heading note for site-builder:** §12 renamed `Open Questions` →
`Resolved Decisions & Open Questions` (now `12.1 Resolved` + `12.2 Still open`).
All other top-level `##` headings 1–11, 13 are unchanged. All "DECISION NEEDED"
markers are gone; still-open items are only: Cloudflare callback credential
TTL/revocation, result cache, binary inline outputs, and (out-of-scope)
multi-node execution.

## drafter — fable review applied (checkpoint 4)

fable's design notes (specs/compute-service-design-notes.md, 392 lines) are
committed verbatim (387d545) and all findings F1–F9 + the §12.2 recommendations
are now folded into specs/compute-service.md (48a761d). Verdict addressed: the
four blockers (F1 caveat-echo, F2 handshake, F3 space-scope, F4
delegation-path/atomicity) and F6 (CF egress) are all applied.

### Which finding changed which section

- **F1 (MUST) — caveat echo.** §6.2: new normative paragraph — the host mediator
  copies D_fn's `computeFunctionBinding` caveat VERBATIM onto every internal
  invocation (and D_worker, and Worker callbacks); W1 byte-equality rule, fails
  closed otherwise. Corrected the old "nothing new required in the auth engine"
  wording. §6.3: invoker-side echo note (SDK copies chain caveats onto the
  invocation, sql precedent). §13.1: two test obligations.
- **F2 (MUST) — routine_did handshake.** §6.2: replaced the FALSE "deployer can
  compute routine_did client-side" claim with the read-only handshake (client
  hashes WASM → `ComputeRequest::RoutineDid { content_cid }` → node returns
  public routine_did → client mints D_fn → deploy). §7.2: added the `RoutineDid`
  request variant. Doubles as the dstack-stability probe.
- **F3 (MUST) — cross-space.** §6.2: derivation path now includes space:
  `get_key("tinycloud/compute/" + space + "/" + function_cid)`. §5.1: normative
  `(space, functionCid)` selection rule + resource-in-space verification. Both
  layers ship.
- **F4 (MUST) — delegation path + atomicity.** §5.1: D_fn processed through the
  standard /delegate path, atomically with artifact save + SqlSizes update in one
  transaction; revoke superseded D_fn on re-deploy.
- **F5.** §5.1: cite-all-matching-D_fns selection rule.
- **F6 (MUST) — CF egress.** §9.2 + §10.2: explicit confidentiality-asymmetry
  paragraphs (unrestricted outbound fetch; everything readable under the grant
  treated as disclosed to function author + Cloudflare).
- **F7.** §9.2: CF binds the grant to what the node uploaded not what runs; CF
  account creds join the TCB; "trusted-deployment" documented as carrying that.
- **F8 (MUST).** §5: deploy MUST call `sql_sizes.update("compute", …)` or quota
  is bypassed; fixed the stale §5→§10 xref.
- **F9.** §3: SDK standard session grant must enumerate compute/execute +
  compute/list, NEVER compute/*.
- **§12.2:** callback mechanics (worker-side ephemeral keypair per execution,
  TTL, revocation, D_fn = panic button) now concrete in §9.2; result cache
  deferred with the structural gate criterion; binary inline outputs deferred.
  Plus F1.5 compare-on-execute tripwire (`routine-identity-rotated`), caveat
  encoding pinned per-ability, artifact history = revision counter (not
  KV-history), internal invocations enter via core process() not the HTTP replay
  cache, and the F1.8 caveated-deployer edge.

### site-builder — what needs RE-RENDERING

1. **Deploy sequence gains a step:** the RoutineDid handshake now precedes deploy
   — client hashes WASM → asks node for public routine_did → mints D_fn → deploys.
   Add it before the D_fn mint in the deploy diagram.
2. **Derivation path now includes space:**
   `get_key("tinycloud/compute/" + space + "/" + cid)` — update any node-derives-
   routine-key label.
3. **CF trust callout gains an egress warning:** the confidentiality asymmetry
   (unrestricted `fetch`, everything readable = exfiltrable) is now the headline
   CF caveat, above the resource-limit gap. If you render a backend-comparison,
   this is the decisive row.
4. **Two-layer diagram unchanged in shape**, but the layer-(b) internal-invocation
   arrow should be annotated "echoes D_fn's binding caveat" (F1).

Headings unchanged except §13 gained a §13.1 (Test obligations). No wire-shape
changes except the new `RoutineDid` request action.

## drafter — checkpoint 5 (egress observability + derivation URI + zk future)

Sam directed a final amendment round; specs/compute-service.md updated (7f793c4).
Scope: realistic-and-reasonable for the WASM path; ZK stays a future note only.
Five changes:

1. **Derivation string changed AGAIN → canonical resource URI.** §6.2 now:
   `routine_did = did:key(get_key("tinycloud/compute-key/v1/" + <space>/compute/<function_cid>))`
   — the `ResourceId` display form (§4), one canonical spelling shared by
   authorizer + binding caveat + derivation, under a versioned `compute-key/v1/`
   domain prefix. Added a BLOCKING safety requirement: space `Name` validation is
   a stubbed `// TODO` in `tinycloud-auth/src/resource.rs` — names MUST exclude
   URI delimiters (`/ : # ?`) or the space component MUST be hashed before compute
   activates, so distinct (space, function) pairs can't collide into one
   derivation string. CIDs are base32 (safe). Test obligation in §13.1.
2. **NEW §9.1.1 — execution manifest / egress journal (wasmtime, NORMATIVE).**
   The host mediator MUST journal every host call `(resource, ability, bytes
   in/out, output destination)` + granted-vs-exercised capabilities. On wasmtime
   the manifest is GROUND TRUTH (no unmediated egress); granted-but-unexercised
   caps are the deployer's scope-down signal (permission observability). Storage:
   rides in `InvocationOutcome` metadata (ObjectHeaders/`Metadata` precedent),
   MAY persist to a KV audit path (`persist_manifest` config).
3. **§9.2 — CF egress mitigation (SHOULD).** Workers for Platforms dispatch
   namespaces + an Outbound Worker: default-deny allowlist (node callback = sole
   default entry), full egress log in run evidence. Disables raw TCP `connect()`;
   DO/mTLS `fetch` bypass is a known CF gap CLOSED BY CONSTRUCTION (node grants
   routines no DO/mTLS bindings). Trust anchor stays Cloudflare, so the F6
   disclosure rule is SOFTENED (not removed) to "disclosed to Cloudflare; function
   author confined by CF-enforced egress policy." §10.2 updated to match.
4. **NEW §9.4 — iron-proxy future-backend note.** For a FUTURE self-hosted
   container/VM backend, iron-proxy is the egress-mediation pattern (default-deny
   allowlist, per-request audit, credential brokering). Mirrors our
   host-mediation philosophy; would give a container backend wasmtime's manifest
   ground-truth property. Note only — NO container backend specced.
5. **§12.2 — ZK deployment realities (FUTURE only).** Prover can't run in a Worker
   (128MB isolate; Jolt alpha needs GPU-class HW; Twist/Shout streaming prover
   <2GB fits CF Containers later). Realistic shape: two-phase — execute fast,
   output marked `unverified`, prover runs async, node `verify()` flips it
   `verified` (the run/output+evidence/verify interface already supports this).
   Artifact wrinkle: Jolt proves RISC-V (RV64IMAC) not WASM, so a zk-verified fn
   needs a RISC-V build whose digest is pinned in the binding caveat ALONGSIDE the
   WASM CID. Interim cheap integrity for CF: deterministic wasmtime + random k%
   spot re-execution on the node. ZK fixes F7 (integrity) fully in principle; does
   NOT address F6 (confidentiality).

### site-builder — what needs RE-RENDERING

1. **Derivation formula changes AGAIN** — now the resource-URI form
   `get_key("tinycloud/compute-key/v1/" + <space>/compute/<cid>)`. Update the
   node-derives-routine-key label (this is the second derivation-string change;
   this one is final for the WASM path).
2. **Wasmtime execute diagram gains the execution-manifest step** — after the
   host-mediated data calls, the mediator emits the manifest (host-call journal +
   granted-vs-exercised) into the outcome metadata. Worth its own node in the
   sequence; it's the permission-observability story.
3. **CF diagram gains the Outbound-Worker hop** — user Worker `fetch()` → Outbound
   Worker (default-deny, node callback only) → egress log. Show DO/mTLS bypass as
   "not granted → not present."
4. **CF trust callout restates the SOFTENED disclosure rule** — "disclosed to
   Cloudflare; function author confined by CF-enforced egress policy" (WITH the
   Outbound Worker), vs the hard "disclosed to author + Cloudflare" WITHOUT it.
   Replace the checkpoint-4 headline egress wording accordingly.
5. If you render a future/roadmap panel: iron-proxy (container backend) and the
   two-phase ZK shape (RISC-V digest + async verify()) are new future items;
   both are explicitly NOT-built.

Headings: §9 gained §9.1.1 and §9.4; §12.2 gained the ZK note; §13.1 gained two
obligations. No wire-shape changes beyond the manifest in outcome metadata.

## drafter — implementation plan (lean/smithers)

New deliverable committed: `specs/compute-service-implementation-plan.md` — a
LEAN, Smithers-executable plan (~2.5 pages, 180 lines). It references
`specs/compute-service.md` sections rather than restating them (built to survive
a Codex leanness review).

Shape: smallest end-to-end vertical slice first, every phase ends in a
**machine-verifiable gate**, one Smithers node per phase (task one-liner + verify
command(s) + fix loop + human approval gate at the boundary), no speculative
work.

- **P0 walking skeleton** — reserved registry entries + codegen + drift guards;
  `compute` feature; 501-disabled path. Gate: `cargo test` green **feature off AND
  on** + `gen-capabilities.mjs --check` + drift-guard tests.
- **P1 deploy** — `RoutineDid` handshake (+ the §6.2 space-name-validation
  prereq) and the atomic deploy (artifact + D_fn via /delegate + SqlSizes, one
  txn). Gate: §13.1 atomicity + quota + handshake + name-validation tests.
- **P2 wasmtime execute** (core slice) — host mediator w/ caveat-echo +
  (space,cid) selection, fuel/epoch/StoreLimits, manifest in outcome metadata,
  rotation tripwire. Gate: §13.1 echo/cross-space/rotation/manifest tests + an
  E2E fixture (routine reads a granted KV path, denied on ungranted, invoker
  never holds data caps).
- **P3 SDK** — execute/list; standard session grant enumerates execute+list
  **never `compute/*`** (F9); deploy behind an explicit privileged flow. Gate:
  SDK integration test incl. "standard session cannot deploy." **The registry
  flip to `active` happens at the START of P3**, not earlier — concretes stay
  reserved while only the node can exercise them.
- **P4 deferred (not executed)** — Cloudflare, ZK, containers; one line each on
  why.

Cross-cutting: clippy `-D warnings`; feature-off `cargo test` stays green every
phase; no hand-edits to `generated.rs`.

No spec change in this commit — plan only. site-builder: nothing to re-render
(the plan is not part of the presentation site unless Sam asks); flag if you want
a phase-roadmap panel and I'll hand you the P0–P4 gate list.

## drafter — codex review applied

Codex reviewed the implementation plan against the codebase (verdict: needs
changes, 12 code-grounded findings). Review committed verbatim
(`specs/compute-service-plan-codex-review.md`); lead ACCEPTED ALL 12. Revised
plan + two surgical spec errata committed (918159e).

### Plan restructured: pipeline is now P0 → P1 → P2 (node work ends at P2)

- **P3 removed.** SDK is not a member of this workspace (only the generated TS
  mirror lives here); it becomes a **deferred, separate js-sdk workflow pointer**
  in P4 (C10).
- **Active-flip moved to the END of P2** per the spec's "when the handler ships"
  rule. Codex caught that the old deny-by-default rationale was **factually
  wrong**: reserved URNs are already exercisable (`accepted_actions` includes
  reserved). `execute`+`deploy` flip active at P2; `list` stays reserved (C9).
- **Exactly one human gate** — a security review after the full P2 slice; every
  other former approval is now a machine assertion (C12).
- **Gates are now real commands:** named `--test <file>` targets that error when
  absent (name filters like `compute::execute` pass on zero matches — banned),
  an exact E2E command with ephemeral port + 60s timeout, and a shared
  feature-off + fmt + clippy suffix on every node (C5). P2 now tests EVERY
  advertised control: allowlist, fuel, epoch, StoreLimits, input schema, numeric
  ceilings, forbidden imports, invoker-side echo, full manifest shape (C6).
- **Deliberately narrowed first slices:** P1 transport = JSON/base64 + inline
  D_fn only (C7); P2 = KV-**read-only** inline output via `SpaceDatabase::invoke`
  with a named internal-invocation executor seam (C4) and a **pinned minimal WASM
  ABI** (one export + one `storage.get`) gated by a checked-in WAT fixture (C3).
- **Two seams named as first-class deliverables:** the atomic **deploy
  transaction primitive** (one SeaORM txn + mirror-after-commit; noted it's a
  core seam refactor, not a service-module change, C2) and the **`RoutineKeyDeriver`**
  interface injected server-side (dstack vs classic; `cargo check
  --features compute,dstack`; cross-CVM-redeploy equality is a DEPLOYMENT-READINESS
  gate, not a unit test — C11).

### Two surgical spec errata (in `specs/compute-service.md`)

1. **§7.1 (C1, NORMATIVE):** added the request-variant→ability mapping sentence —
   the handler MUST map `Deploy`/`RoutineDid`→`compute/deploy`,
   `Execute`→`compute/execute`, `List`→`compute/list` via `ability_matches`, or an
   `execute` holder could submit a deploy body. Cites the SQL precedent
   (`require_sql_admin_for_request`, routes/mod.rs:1232).
2. **§6.2 (C8):** the derivation now **hashes the canonical space string** into a
   fixed-width component — chosen over global `Name` validation, which is stubbed
   and bypassed by direct `Name` construction in URI parsing. Formula, safety box,
   and the §13.1 obligation all updated; global `Name` hardening spun out to P4.

### site-builder — plan.html re-render

- Pipeline is now **P0 → P1 → P2** with a **single** approval gate (security
  review after P2). Remove the P3 node; add a "deferred: separate js-sdk
  workflow" pointer alongside CF/ZK/containers in the deferred panel.
- If you show gates: they're now concrete `cargo test --test <file>` commands +
  an E2E boot/health/teardown — worth surfacing that the gates are executable, not
  prose.
- The two spec errata (§7.1 ability mapping, §6.2 hashed-space) don't change the
  main spec diagrams, but if plan.html annotates the derivation, it's now
  `get_key("tinycloud/compute-key/v1/" + hash(space) + "/compute/" + cid)`.

## drafter — codex verify round applied

Codex re-verified (7/12 resolved, 5 partial, 2 new small defects). Final surgical
round committed (9beec00) — should be the last. All lead decisions folded in;
nothing open.

Plan:
- C1: P1 gate adds `RoutineDid`-wrong-ability reject; P0 gate adds "`List` body →
  rejected while reserved" (no MVP handler).
- C3: P2 ABI now PINNED — core module; guest exports `alloc(len)->ptr` +
  `run(ptr,len)->(ptr,len)`; host import module `"tinycloud"` fn
  `storage_get(ptr,len)->(ptr,len)`; all payloads JSON bytes in guest memory; WAT
  fixture exercises exactly this.
- C5: named feature-off gate `--test compute_disabled` added to P0 verify + the
  shared suffix (asserts the 501 path with the feature off).
- C11/defect-b: dstack-simulator gate moved to the server crate
  (`--test compute_routine_key --features compute,dstack`, `DSTACK_SIMULATOR_ENDPOINT`);
  core keeps only the `RoutineKeyDeriver` trait unit test (classic impl).

Spec errata (compute-service.md):
- C4 §8.2: internal routine invocations are verified AND executed via an injected
  executor backed by `SpaceDatabase::invoke` (server-composed), not `process()`
  alone; replay-cache point kept.
- C7 §7.2: raw-body WASM + pre-submitted grant CIDs marked DEFERRED/non-normative;
  MVP = JSON/base64 + inline `D_fn` only.
- defect-a §6.2: hash pinned to `base32(blake3(space_canonical))` (fixed-width,
  lowercase base32, delimiter-free); fixed the contradictory "names MUST be
  validated before activation" heading (hashing replaces it; global `Name`
  hardening is a separate deferred task).

site-builder: no pipeline/diagram change this round (still P0→P1→P2, single gate).
If plan.html annotates the derivation, it's now
`get_key("tinycloud/compute-key/v1/" + base32(blake3(space)) + "/compute/" + cid)`;
if it lists P2 gates, the ABI is now concrete (alloc/run/storage_get over JSON).
