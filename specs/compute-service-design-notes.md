# Compute Service — Design Notes (fable)

**Date:** 2026-07-10
**Author:** fable-compute (design partner / reviewer)
**Reviews:** `specs/compute-service.md` (post-decision draft: D1 = TEE-derived
routine key, D2 = `computeFunctionBinding` caveat, deploy = privileged specific
capability)

These are analysis notes, not a summary. Every claim is checked against the
code paths named inline. Findings are numbered F1–F9 and cross-posted to
`specs/compute-service-discussion.md`.

---

## 1. Is the derived-key + binding-caveat composition sound?

**Verdict: yes, the composition is sound — with two mechanical obligations and
one scoping rule the spec does not yet state.** The division of labor is
correct: the derived key is the *enforcer* (only the node's TEE can derive the
signing key for CID X, so only a genuine execution of X can exercise
`D_fn`), and the caveat is the *auditable record* (the event graph shows which
function each grant is for). Neither can substitute for the other, and neither
weakens the other. The problems are all in the seams.

### 1.1 The enforcement chain, spelled out

For an internal routine invocation to succeed, `validate()`
(`tinycloud-core/src/models/invocation.rs:138-266`) requires ALL of:

1. `did_principal_matches(D_fn.delegatee, invoker)` — only the holder of the
   routine private key passes. Key derivable only inside this node's TEE
   (`dstack::get_key`, `dstack.rs:110-119`) → unforgeable off-node.
2. `c.resource.extends(&pc.resource) && ability_matches(...)` — the routine
   cannot exceed `D_fn`'s resource/ability grant.
3. Revocation walk (`is_revoked` + `first_revoked_ancestor`,
   `invocation.rs:180-198`) — revoking `D_fn` (or the deployer's chain above
   it) kills the function's data access on the next host call. Per-invocation,
   fail-closed.
4. `caveats_contain_child(pc.caveats, c.caveats)` (`invocation.rs:271-289`) —
   see F1. **This is where the D2 caveat becomes load-bearing whether we like
   it or not.**

The caveat plays no *authorization* role node-side under D1 — a key derived
from CID X can never match a `D_fn` whose delegatee was derived from CID Y, so
the binding is already cryptographic. But step 4 means the caveat is not
inert on the wire. Hence:

### 1.2 F1 (MUST-FIX, spec text): the caveat-echo obligation

`caveats_contain_child` in the invocation path has exactly three outcomes for
a non-SQL parent caveat (`invocation.rs:275-289`): pass if the parent caveat
map is empty, pass if `parent.0 == child.0` (byte-equal JSON maps), otherwise
**reject** with `invocation-caveats-not-subset-of-chain`.

Once `D_fn` carries `{"computeFunctionBinding": {...}}`, its ability rows have
a non-empty, non-SQL caveat map. Therefore **every internal invocation the
HostMediator mints MUST echo `D_fn`'s caveat map verbatim on each capability**,
or every `storage.get`/`storage.put`/`sql.query` host call fails closed.

The spec currently says the opposite in spirit — §6.2: "Nothing new is
required in the authorization engine... The only new code is the host
mediator" — which is true only if the mediator's echo duty is specified. It
isn't, anywhere. An implementer who mints caveat-less internal invocations
(the natural reading of §6.2 step 4) ships a service where every function
fails on its first data access.

The echo obligation also **propagates down the Cloudflare chain** (§9.2):

- `D_worker` (routine → worker identity) is a child delegation of `D_fn`. The
  *delegation*-side containment (`delegation.rs:336-364`) applies the same
  equality rule → `D_worker` must echo the binding caveat.
- The Worker's callback invocations cite `D_worker` → they must echo it again.

Required spec change: a short normative paragraph in §6.2 (and a sentence in
§9.2): *"`D_fn`'s caveat map is copied verbatim onto every capability of every
internal invocation (and of `D_worker`, and of Worker callback invocations).
This is required by the W1 containment equality rule for non-SQL caveats;
omitting it fails closed."* Plus a test obligation in §13: an integration test
that a routine host-call with a non-echoed caveat is rejected.

One consequence worth stating honestly: the equality rule means `D_worker`
**cannot attenuate the caveat map** (only resources/abilities can narrow,
via `extends`). That is acceptable — the binding caveat is metadata, not a
constraint you'd want narrowed — but it forecloses ever putting *worker-
specific* restrictions in that map without touching the W1-hardened
containment helper. Fine for now; record it.

### 1.3 F2 (MUST-FIX, spec text): the deployer cannot compute `routine_did`

§6.2: *"the deployer can compute `function_cid` (and therefore `routine_did`,
given the node's derivation convention exposed by the SDK) before deploy."*

The second half is **false**. `get_key("tinycloud/compute/" + cid)` derives
from the node's TEE-internal secret seed. Knowing the derivation *convention*
gives the deployer nothing; the public key is not computable client-side —
otherwise the private key would be too and the scheme would be broken. (This
is also true in classic mode: derivation runs off `keys.rs` secret material.)

There *is* no chicken-and-egg problem — but the fix is a handshake, not
client-side math:

1. Client hashes WASM locally → `function_cid` (CID convention is public).
2. Client asks the node for the routine identity: a small read-only action
   (e.g. `ComputeRequest::RoutineDid { content_cid }`, or a query param on the
   deploy resource). Node derives the keypair, returns the **public**
   `routine_did`. Idempotent, no side effects, no secret exposure.
3. Client mints `D_fn` (delegatee = returned DID, binding caveat, attenuated
   data caps) and submits `deploy(wasm, D_fn)`.

This also gives the dstack-stability tripwire for free (§1.5): the same
"derive and return" operation is the probe you run after a CVM redeploy.

### 1.4 F3 (MUST-FIX, security): cross-space `D_fn` selection

D1 derives the routine key from the CID **only** — the space is not in the
derivation path. So identical WASM bytes deployed in space A and space B share
one `routine_did`. Now consider: both deploys minted valid `D_fn`s (different
spaces, same delegatee, same `functionCid` in the binding caveat). §5.1 says
the execute path "locates the correct `D_fn` for a loaded artifact by matching
that caveat's `functionCid` against the artifact's `content_hash`" — **that
match is ambiguous across spaces.**

If the mediator resolves `D_fn` by `(delegatee == routine_did, caveat
functionCid == cid)` alone, then executing function X *in space B* can cite
space A's `D_fn` — the chain validates (right delegatee, valid chain rooted in
space A's owner) — and the routine reads/writes **space A's data** during a
space-B execution, with the result returned inline to a space-B invoker who
holds nothing on space A. That is a cross-space confused deputy.

Fix (two layers, first is mandatory):

1. **Selection rule (normative):** the mediator MUST resolve `D_fn` scoped to
   the space of the outer `compute/execute` invocation — i.e. the lookup key
   is (space, `functionCid`), and the mediator MUST verify every capability
   resource in the selected `D_fn` lives in that space before citing it.
2. **Hardening (recommended, does not reopen D1):** include the space in the
   derivation path — `get_key("tinycloud/compute/" + space + "/" + cid)` —
   making the routine identity per-(space, function) and cross-space citation
   *cryptographically* impossible rather than policy-blocked. Still
   TEE-derived, still no secret at rest; the only cost is that the "same code,
   two spaces" case needs two `D_fn`s, which D2's per-space minting already
   implies. CID strings are base32 (no `/`), so the path is injection-safe
   either way.

### 1.5 D1's dstack-stability risk: agree, plus a cheap deterministic tripwire

The boxed note in §6.2 (verify `get_key` stability across CVM redeploys
empirically; persisted-key fallback recorded) is the right honesty. Two
additions make the failure mode *diagnosable* instead of mysterious:

- **Persist the expected `routine_did` at deploy time** — it is already
  implied by `D_fn.delegatee`, so no new state is strictly needed, but the
  deploy ack should return it and the SDK should record it.
- **Compare-on-execute:** before running, the node re-derives the key for the
  artifact's CID and compares against `D_fn.delegatee`. On mismatch, fail with
  a *distinct* error code (`routine-identity-rotated`, mapped to 409 or 503 —
  NOT a generic 403) telling the deployer to re-mint `D_fn`. Without this, a
  seed rotation surfaces as `UnauthorizedInvoker` deep inside a host call —
  indistinguishable from a bug.

Re-mint is the recovery path either way; making it cheap (deploy with
identical bytes + new `grant`, no artifact change) should be stated in §5.1.

### 1.6 F4 (MUST-FIX, spec text): `D_fn` must ride the standard delegation path, atomically

§7.2 carries `D_fn` as `grant: Option<String>` ("encoded D_fn delegation
header, or its CID if pre-submitted") — but the spec never says what the
deploy handler *does* with it. It matters: at execute time the chain walk
loads parents from the `delegation` table by CID (`invocation.rs:160-169`), so
`D_fn` must have been processed through the same verification/persistence path
`/delegate` uses (signature check, delegation-side containment vs the
deployer's chain, ability-row persistence with caveats —
`delegation.rs:275-327, 466-476`). Storing it as opaque bytes breaks execute;
skipping validation at deploy defers the failure to first host call.

Also atomicity: artifact save (`DatabaseArtifactRepository::save`) and `D_fn`
processing must succeed or fail together, or you get a deployed function with
no grant (every execution fails) or a live grant for an artifact that never
landed (dormant but untidy). One transaction, stated in §5.1/§13 step 3.

Related hygiene: **re-deploy with new bytes strands the old `D_fn`.** New CID
→ new `routine_did` → old grant is dormant (old bytes are *gone* — see F7 —
so the old key is never derived again), but it remains a live delegation row.
The deploy path SHOULD revoke the superseded `D_fn` (or the spec should tell
deployers to), so the event graph doesn't accumulate live-looking grants to
identities that can no longer act.

### 1.7 F5 (SHOULD-FIX): multiple matching `D_fn`s — selection rule

Even space-scoped (F3), more than one valid `D_fn` can match (re-mints after
rotation, two deployers, a re-grant with wider caps). The spec needs one line:
the mediator cites **all** valid matching `D_fn`s as parents (an invocation's
`parents` is already a Vec; `validate()` authorizes each capability if *any*
parent supports it, `invocation.rs:226-236`) — or, if single-parent is
preferred for auditability, the most-recently-issued valid one. I'd take
cite-all: it is simpler than a tiebreak and degrades gracefully when an older
grant is revoked mid-life.

### 1.8 Known edge (document, don't fix): caveated deployers cannot mint `D_fn`

Delegation-side containment (`delegation.rs:336-364`): if the deployer's own
ability rows carry a **non-SQL** caveat, a child delegation must present a
byte-equal caveat map — so adding `computeFunctionBinding` breaks equality and
the mint is rejected (`child-caveats-not-subset-of-parent`). If the deployer's
authority carries an *SQL* constrained-statements caveat, the `(Some, Some)`
arm checks only SQL containment and ignores extra keys — the binding caveat
rides along. So: SQL-caveated deployers can mint `D_fn`; generically-caveated
deployers cannot. Asymmetric, pre-existing behavior of the W1 helper, not a
compute defect — but §6.2 should state the practical rule: **the deployer of
record should hold caveat-free (or SQL-caveat-only) data authority.** Space
owners — the expected deployers — always qualify (root authority short-circuit,
`invocation.rs:344-362`).

---

## 2. Cloudflare backend — is §9.2/§10.2 honest enough?

§10.2's maxDuration/maxMemory concession is correct and well-put. But the
trust statement has **two omissions that matter more than resource limits**:

### 2.1 F6 (MUST-FIX, honesty): egress — confidentiality is unprotectable on CF

The wasmtime backend's strongest property is *no exfiltration channel*: the
guest has no net/fs, only mediated host imports (§9.1), so data the routine
reads can only flow to (a) the function output, (b) KV paths under `D_fn`'s
`kv/put`. On Cloudflare, the Worker has **unrestricted outbound `fetch`**. A
malicious or compromised function can ship everything its grant lets it read
to any endpoint on the internet, and the node can neither prevent nor detect
it. The input payload additionally transits and rests on Cloudflare infra.

§9.2/§10.2 currently frame the CF gap as "resource caveats are hints" — the
spec MUST also state the confidentiality asymmetry explicitly, something like:
*"the CF backend cannot constrain data egress: anything `D_fn`/`D_worker`
permits reading must be treated as disclosed to the function author and to
Cloudflare. Grant read scopes to CF-backed functions accordingly."* This is
the single most decision-relevant fact for anyone choosing between backends,
and it is absent.

### 2.2 F7 (SHOULD-FIX, honesty): "changing the code voids the grant" does not hold on CF

On wasmtime, code identity is checked at the moment of use: the node hashes
the bytes it is about to run; the grant follows the hash. On CF, the node
deploys a script once and thereafter trusts that the Worker at route R still
corresponds to `function_cid` — a bookkeeping claim, not a content-addressed
one. Anyone with Cloudflare account access (including Cloudflare) can swap the
script behind R while `D_worker` is valid; the swapped code inherits the
callback credential. So on CF, the CID binds the grant to *what the node
uploaded*, not to *what runs*. The CF account credentials join the TCB. One
sentence in §9.2's trust-model paragraph covers it; `verification:
{ mode: "trusted-deployment" }` should be documented as carrying exactly this
meaning.

### 2.3 §12.2 item — callback credential TTL & revocation: concrete proposal

Mechanics first (the spec leaves them implicit): the Worker identity should be
a **fresh ephemeral keypair per execution**. Two options for where it's born:
node-side (node generates, ships the private key in the dispatch request —
key transits CF, acceptable under 2.1's trust model) or worker-side (Worker
generates at start, returns the pubkey, node then mints `D_worker` — one extra
round-trip, key never transits). Either is defensible; pick one and say so.
Never reuse a worker keypair across executions — reuse is what turns a leaked
key into a standing capability.

- **TTL:** `exp = now + effective_maxDuration + slack` where slack covers
  dispatch/queue jitter (propose `min(2 × maxDuration, config ceiling)`, with
  a config ceiling like `cloudflare.callback_ttl_max = 120s`). `D_fn`'s own
  expiry naturally caps it — a child delegation cannot outlive its parent
  (`delegation.rs:230-270` filters parents by expiry, and the not-before/expiry
  window check applies).
- **Revocation:** the node records the `D_worker` CID in the execution context
  and issues a standard revocation when the execution completes, times out, or
  errors. Because `validate()` walks revocations **per invocation**
  (`invocation.rs:180-198`, no chain-ok caching), a mid-flight revocation cuts
  a misbehaving Worker off at its *next* callback — this is the actual
  kill-switch; TTL is the backstop for a node that crashes before revoking.
  Revoking `D_fn` also kills `D_worker` transitively via
  `first_revoked_ancestor` — worth one line in §9.2 as the "deployer panic
  button" that works even while an execution is in flight.
- **Replay:** Worker callbacks are ordinary `/invoke` requests → the route
  replay cache already rejects envelope replays; fresh nonces per callback.

### 2.4 §12.2 item — result cache: defer, and if ever built, gate it structurally

Recommend **defer**, and record the criterion rather than the mechanism:

- A `(content_cid, input_hash)` cache is only sound for executions whose
  output depends on nothing else. "The function declares itself pure" is the
  wrong gate — declarations lie. The *structural* gate is checkable: cacheable
  iff the function's `D_fn` grants **no read capability** (or `D_fn` is absent)
  and the request has no `input_refs` — then the WASM had nothing to read but
  `input`, and wasmtime is deterministic for it (modulo NaN payloads —
  enable wasmtime NaN canonicalization; and use **fuel** as the determinism-
  relevant budget, since epoch-deadline traps are wall-clock-dependent: the
  same input can complete on an idle node and trap on a loaded one, so only
  *successful* results are cacheable even then).
- Anything that reads KV is a function of mutable state; a correct cache key
  would need the version vector of the read set, which the mediator could
  collect — real machinery, no consumer yet. Out.

### 2.5 §12.2 item — binary inline outputs: agree with deferral

The KV output path (§8 option 2) already handles binary results, and the
responder precedent (`SqlExport`/`DuckDbExport` → octet-stream,
`auth_guards.rs:125-133`) makes a later `ComputeBytes` variant mechanical.
Base64-in-JSON inflation (~33%) under the 413 ceiling is tolerable for small
blobs. No consumer demands it today. Defer — and revisit the moment a
consumer inlines >1 MB binaries, because at that point they are double-paying
(base64 + JSON parse) for no reason.

---

## 3. Smaller defects and precision points

- **F8 (spec bug, quota):** §5 claims artifact `size_bytes` "folds into the
  space's `store_size`". Not automatically — `store_size` (`db.rs:446-452`)
  sums block bytes + the **`SqlSizes`** registry, and `SqlSizes` entries are
  written by the *services* (`sql_sizes.update(service, space, name, size)`),
  not by `DatabaseArtifactRepository::save` (which records `size_bytes` on the
  row only). The compute deploy path MUST call the `SqlSizes` update with its
  own service tag or deploys silently bypass quota. Also §5's "see §10" quota
  cross-reference points at Caveats — stale xref.
- **F9 (SDK/registry interaction, deploy tier):** once the compute concretes
  flip to `active`, the codegen validator (`gen-capabilities.mjs:105-118`)
  *forces* `compute/*` to imply **all** active concretes — including
  `deploy`. So §3's "standard-tier session grants exclude `compute/deploy`" is
  only real if the standard session grant also excludes `compute/*`. Note the
  live precedent cuts the other way: `sql/*` and `duckdb/*` ARE in the SDK
  root delegation grant today (per the registry notes, `capabilities.json:69,
  107` → TinyCloudNode.ts ~2272/2279). §3 should say explicitly: **the SDK
  standard session grant must enumerate `compute/execute` + `compute/list`,
  never `compute/*`** — otherwise the sql-wildcard habit silently hands every
  browser session deploy rights.
- **Caveat encoding precision (§5.1/§6.2):** `Caveats` is a
  `BTreeMap<String, serde_json::Value>` and containment compares raw maps.
  Pin the exact shape: which map key carries the binding object (the SQL
  precedent uses positional keys like `"0"`), and that it is attached to
  **every** capability row of `D_fn` (per-ability, not per-delegation —
  `delegation.rs:466-476` persists caveats per ability). Byte-equality in the
  echo rule (F1) makes this non-cosmetic: key drift = fail-closed.
- **Artifact history (§5):** `DatabaseArtifactRepository::save` *replaces* the
  payload in the single `(service, space, name)` row
  (`database_artifacts.rs:100-135`) — `revision` counts, but old bytes are
  unrecoverable. So §7.2's `content_cid` pin protects against a re-deploy
  *race*, not rollback: pinning a superseded CID fails, by design. One
  clarifying sentence in §5 ("versioned = revision counter; prior payloads are
  not retained or executable") prevents a wrong mental model of "KV-like
  history".
- **Replay-cache precision (§8.2):** the route-level replay cache guards
  `POST /invoke` (`routes/mod.rs:714`). Internal routine invocations minted by
  the mediator presumably enter through core (`process()`), not through the
  route — so they never touch that cache at all. §8.2's fresh-nonce statement
  is right in effect; stating the entry point removes an implementer question
  (and keeps someone from "helpfully" routing internal invocations through the
  HTTP path).
- **Invoker-side caveat echo (§6.3/§10):** the F1 equality rule also bites
  layer (a): an invoker whose `compute/execute` delegation carries
  `ComputeCaveats` must echo that caveat map on the invocation capability or
  `validate()` rejects it before the handler ever runs. The SDK invoke helper
  needs to copy chain caveats into the invocation — same as the sql
  constrained-statements flow. Worth a sentence so the SDK work lands in the
  same changeset.

---

## 4. What I checked and did not find problems with

For completeness, load-bearing spec claims I verified against code and confirm:

- §4 resource model: `compute` needs no parser change; `extends()` prefix
  semantics (`resource.rs:193-217`) give single-function vs space-wide grants
  exactly as described.
- §6.1 layer (a) is genuinely free — `validate()` is service-agnostic.
- §3.1 registry mechanics: reserved-first matches the vfs precedent; the
  wildcard-implies-exactly-active rule is real (`gen-capabilities.mjs:105-118`),
  so the "no implies while reserved" note is correct (vfs itself ships no
  wildcard, so compute's reserved wildcard is the first of its kind — the
  validator's exact-match against an empty active set accepts an absent
  `implies`, which is what the note prescribes).
- §6.3's SQL precedent is accurately cited: `handle_sql_invoke` derives the
  enforced caveat from the validated chain (`derive_chain_constrained_caveat`)
  with facts as fallback.
- §7.3 responder location (auth_guards.rs, not routes/util.rs) — correct.
- §10.1 wasmtime mapping (epoch for wall-clock, fuel for CPU, StoreLimits for
  memory, import mediation for reach) is the right toolbox; no notes beyond
  the determinism caveat in §2.4 above.
- §8.2 outer-replay semantics — correct as stated.

**Overall verdict: the architecture is right and the decided D1/D2 compose
soundly. The spec is not implementable as written until F1 (caveat echo), F2
(routine_did handshake), F3 (space-scoped D_fn selection), and F4 (D_fn
through the delegation path, atomically) are folded in; F6 (CF egress honesty)
is a must before anyone points a real grant at the Cloudflare backend.**
