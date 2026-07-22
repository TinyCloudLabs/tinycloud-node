# Spec: The Compute Routine as Encryption-Network Decrypt Receiver (Option B)

**Date:** 2026-07-22
**Status:** Draft
**Depends on:** `specs/compute-service.md` (P2, merged: §5.1 deploy-time binding,
§6.2 two-layer permissioning, §9.1/§9.1.1 WasmtimeBackend + manifest, Appendix A
fixture pattern) and the shipped `tinycloud-core/src/encryption_network/*`
module (network lifecycle, `EncryptionService::decrypt_authorized`).
**Service identifiers:** `tinycloud.compute/*` (existing), `tinycloud.encryption/decrypt`
(existing action, new grantee: a compute routine)

---

## 1. Scope

**Option B, chosen over the alternatives discussed:** a TinyCloud compute
routine (§6.2's derived-key identity) becomes a legitimate **receiver** for
`tinycloud.encryption/decrypt` — i.e. the *routine itself*, not the invoker and
not a client, holds the delegated authority to ask an encryption network to
rewrap a symmetric key to the routine's own key, then unwraps and uses it
in-process to decrypt/re-encrypt a payload. This lets a deployed function
operate on **encrypted space data** (read an `InlineEnvelope`-shaped ciphertext
from KV, decrypt it, transform it, re-encrypt, write it back) without the
routine's data grant ever holding plaintext-equivalent authority outside the
node process, and without the *invoker* of `compute/execute` gaining any
decrypt authority at all (layer (a)/(b) decoupling, §6.1/§6.2, is preserved).

This spec is additive to `compute-service.md`: it adds one new mediated host
import, one new `D_fn` ability row type, one required narrow fix to an existing
core query, and one new core primitive (routine X25519 derivation). It does
**not** change the wire format of `/invoke`, the four existing host imports, or
the encryption-network module's public HTTP routes.

### Non-goals

- No new HTTP endpoint. The decrypt-for-routine flow is entirely internal
  (mediator → core, in-process), triggered by a guest host-import call during
  an existing `compute/execute`.
- No change to `EncryptionService`'s external contract (`decrypt`,
  `decrypt_authorized`, the `/encryption/networks/*` routes) — this spec is a
  new *caller* of the existing `decrypt_authorized`, not a new capability
  inside that module.
- No threshold-backend design. This rides whatever `KeyBackend` is configured
  today (`LocalOneOfOneBackend`); a future threshold backend is orthogonal
  (§9.3-style future plug, not specced here).
- No SDK/deploy-tooling changes. The deployer minting an extra `D_fn` ability
  row for `tinycloud.encryption/decrypt` is a one-line addition to the
  existing deploy flow (COMPUTE-API.md's "Deploy with a real grant" shape);
  wiring that convenience into `@tinycloud/node-sdk` is deferred, non-blocking
  follow-up.

---

## 2. Design Decisions (DECIDED)

**D-ER1 — the routine's decrypt authority rides the SAME `D_fn` as its KV/SQL
grant, as one more ability row.** `D_fn`'s `capabilities` is already a list;
the deployer adds `{ resource: <network-urn>, ability:
"tinycloud.encryption/decrypt" }` alongside the existing `kv/get`, `kv/put`,
`sql/read` rows, all under the same delegation, all carrying the same
`computeFunctionBinding` caveat (§5.1/D2 — caveats attach **per ability row**,
`delegation.rs:466-476`, so this is free). No new delegation type, no second
deploy-time round trip, no new grant-selection code path — `compute_select_d_fns`
(§4 below) already returns the **whole capability list** of every matching
`D_fn`, and the mediator's `find_grant`-style lookup (`compute_exec.rs:311-319`)
already searches by `(ability, resource.extends)` generically over
`Capability`, which is resource-type-agnostic. This is the least-complex-secure
option: reuse cite-all (F5), reuse the caveat echo (F1), reuse chain validate()
— zero new authorization-engine code, exactly the standing §6.2 claim.

**D-ER2 — the routine derives its OWN X25519 keypair from the SAME Ed25519
seed already used for its signing identity, in-process, never exported.**
`RoutineKeyDeriver::derive_routine_seed(space, function_cid) -> [u8; 32]`
(`tinycloud-core/src/compute.rs:295-299`) already produces the seed backing
`routine_jwk_from_seed` (Ed25519, for signing internal invocations) and
`routine_did_from_seed` (the public `routine_did`). This spec adds a THIRD
derivation from the same seed — `routine_x25519_from_seed(seed) ->
(x25519_dalek::StaticSecret, x25519_dalek::PublicKey)` — using the standard
Ed25519-seed→X25519 conversion (SHA-512(seed), take the first 32 bytes,
`StaticSecret::from` applies X25519 clamping). This is the **identical
algorithm** already implemented for client-side use in
`tinycloud-sdk-wasm/src/vault.rs:150-171` (`vault_ed25519_seed_to_x25519`), but
it MUST be a **separate, non-`wasm_bindgen` function living in
`tinycloud-core`**, not a call into the WASM vault: the vault function's
entire purpose is to hand the raw X25519 private scalar back across the
WASM→JS boundary to a browser client, which is exactly the exposure this spec
forbids for a routine's key. The routine's X25519 `StaticSecret` is
constructed inside `HostState` (server crate, §5), used for exactly one ECDH
open per `encryption_decrypt` host call, and dropped (`drop`, matching the
existing `drop(symmetric)` pattern at `service.rs:735`) — it never appears in
a struct field, log, response body, or guest-visible memory.

**D-ER3 — the internal invocation authorizing the routine's decrypt is
audience = node_did (not `space.did()`), with a SHORT expiry (not the far-future
KV/SQL constant).** Two deliberate deviations from the existing
`HostState::mint_internal` (`compute_exec.rs:360-404`), justified below (§5).

**D-ER4 — the EncryptionService boundary never returns the raw symmetric
key.** `decrypt_authorized` (`service.rs:604-760`) already only ever returns a
`wrapped_key` (rewrapped to the caller-supplied `receiver_public_key`,
`service.rs:734`) — the raw `symmetric` value is a local, dropped before the
function returns (`service.rs:735`). This spec's mediator supplies the
routine's own derived X25519 public key as `receiver_public_key`, so the
`EncryptionService` boundary is **unchanged** and still never emits plaintext
key material; the routine-side unwrap (ECDH with the routine's private scalar)
happens entirely after `decrypt_authorized` returns, inside the mediator.

**D-ER5 — the guest, not the host, performs the payload AES-GCM.** The host
import returns the raw 32-byte symmetric key to guest memory (after the
mediator's ECIES unwrap); the guest WASM module runs AES-256-GCM itself to
decrypt `ciphertext`/`aad` it already read via `storage_get`. The host mediator
never touches the payload bytes — it only ever handles the (much smaller)
wrapped/unwrapped *key*. This keeps the host-import surface symmetric with the
existing four (thin, JSON/bytes-in-out, no payload-shaped special-casing) and
keeps "what the host can read" minimal: a host compromise sees keys flow
through it but not (necessarily) which payloads they decrypt, since payload
bytes never cross into host code.

**D-ER6 (REQUIRED CORE FIX, narrow) — `compute_select_d_fns`'s space-scope
check must carve out encryption-network resources.** See §4; this is a real,
load-bearing gap this spec closes with the narrowest correct fix, not a
"nice-to-have."

---

## 3. Deploy-Time Shape

No change to the `Deploy` request variant (`compute-service.md` §7.2) or the
atomic artifact+grant transaction (§5.1/F4). The deployer's `D_fn` simply
includes an additional capability row:

```json
{
  "with": "urn:tinycloud:encryption:<ownerDid>:<name>",
  "can": "tinycloud.encryption/decrypt",
  "nb": [ { "computeFunctionBinding": { "functionCid": "<function_cid>" } } ]
}
```

Everything else about §5.1 applies unchanged: this row rides through the
normal `/delegate` verification/persistence path (F4), the deployer's own
chain must already hold `tinycloud.encryption/decrypt` on that exact network
URN (rooted at the network's `ownerDid` — the deployer must be a network
member/delegate; this spec grants **nothing** new to deployers, it only lets
them re-delegate authority they already hold), and re-deploy hygiene (§5.1)
applies identically (a re-deploy's new `function_cid` makes this row dormant
along with the KV/SQL rows on the same delegation).

**F1.8 interacts identically.** If the deployer's own encryption/decrypt
authority carries a caveat, adding `computeFunctionBinding` to this new row
hits the same byte-equality containment rule as any other ability
(`invocation.rs:271-289`) — deployers should hold caveat-free encryption
authority on the network, same practical rule as §5.1/F1.8 already states for
KV/SQL.

---

## 4. REQUIRED core fix — `compute_select_d_fns` space-scope carve-out

**The gap.** `compute_select_d_fns` (`tinycloud-core/src/db.rs:335-396`)
requires, as its F3 defense-in-depth check:

```rust
let all_in_space = ability_rows
    .iter()
    .all(|row| row.resource.space().map(|s| s == space).unwrap_or(false));
if !all_in_space {
    continue;
}
```

`Resource::space()` (`tinycloud-core/src/types/resource.rs:23-28`) returns
`None` for `Resource::Other` — which is what a `urn:tinycloud:encryption:...`
row IS (`Resource::Other(UriString)`, per `resource.rs:17-20` and the existing
`Resource::extends` NetworkId-comparison arm at `resource.rs:33-48`). Left
unfixed, **adding the D-ER1 ability row to `D_fn` would silently disable
`compute_select_d_fns` for the WHOLE delegation** — `all_in_space` folds over
every row, so one network-URN row makes the entire `D_fn` unselectable, taking
the routine's KV/SQL grants down with it. This is a real regression the P2
code does not anticipate (it predates this spec), not a hypothetical.

**Why this is safe to narrow, not just delete.** The routine's PRIMARY
cross-space boundary is `routine_did` itself — the space is hashed into the
key-derivation path (§6.2/F3: `base32(blake3(space_canonical))`), so
`delegatee.eq(routine_did)` in the same query already scopes every candidate
delegation to one `(space, function_cid)` pair before `all_in_space` ever
runs. The `all_in_space` check is stated as defense-in-depth **on top of**
that primary boundary (`compute-service.md` §5.1: "additionally hardens the
derivation path so this is cryptographically impossible"). A network resource
has no space component **by design** (networks are owned by a DID, not scoped
to a space — `NetworkId::new(owner_did, name)`,
`tinycloud-core/src/encryption_network/network_id.rs:38-56`), so demanding
`row.resource.space() == Some(space)` for it is a category error, not a real
security boundary — no `Resource::Other` row can ever satisfy it, defense-in-
depth or not.

**DECIDED fix.** Narrow the predicate to treat `Resource::TinyCloud` rows
exactly as today, and admit `Resource::Other` rows **only** when their URI
matches the encryption-network URN prefix (not a blanket "any Other resource"
carve-out — that would silently un-scope some future unrelated `Resource::Other`
type too):

```rust
const ENCRYPTION_NETWORK_URN_PREFIX: &str = "urn:tinycloud:encryption:";

let all_in_space = ability_rows.iter().all(|row| match &row.resource {
    Resource::TinyCloud(_) => row.resource.space().map(|s| s == space).unwrap_or(false),
    Resource::Other(uri) => uri.as_str().starts_with(ENCRYPTION_NETWORK_URN_PREFIX),
});
```

The real authorization boundary for the encryption row is unchanged and
enforced elsewhere, twice: (a) the deployer could not have minted this row
unless their own chain already holds `tinycloud.encryption/decrypt` on that
exact network (normal delegation-side containment, unaffected by this fix),
and (b) at execute time the mediator's internal invocation for this row must
still pass the generic `validate()` chain walk (§5 below) AND
`EncryptionService::decrypt_authorized`'s own network/hash/nonce checks. This
fix only restores *selectability* of the `D_fn`; it grants nothing.

`compute_classify_routine_grant` (`db.rs:440-...`) needs **no equivalent
change** — its `has_binding` check only needs ONE ability row (any row) to
carry the `computeFunctionBinding` caveat within the space, and the KV/SQL
rows on the same `D_fn` already satisfy that; the D-ROTATION classification
path is unaffected.

`ENCRYPTION_NETWORK_URN_PREFIX` already exists as a private `const` at
`tinycloud-core/src/types/resource.rs:13` (used by `Resource::extends`'s
`Other, Other` arm) — mark it `pub(crate)` and reuse it from `db.rs` rather
than duplicating the string literal.

---

## 5. Execute-Time Mediator Flow

### 5.1 Host-import ABI addition (5th import)

Extends the §9.1 NORMATIVE host-import surface from four to **five** imports,
all still under module `"tinycloud"`, all still `(i32 ptr, i32 len) -> (i32
ptr, i32 len)` JSON-bytes-on-every-boundary:

```
storage_get, storage_put, storage_del, sql_query, encryption_decrypt
```

**Request (guest → host), JSON:**

```json
{
  "networkId": "urn:tinycloud:encryption:<ownerDid>:<name>",
  "alg": "x25519-aes256gcm/v1",
  "keyVersion": 1,
  "encryptedSymmetricKey": "<base64, from the InlineEnvelope the guest already read via storage_get>",
  "encryptedSymmetricKeyHash": "<hex, ditto>"
}
```

This is intentionally the **minimum guest-supplied subset** of
`DecryptRequestBody` (`protocol.rs:26-46`) — the four fields a guest reading
an `InlineEnvelope` (`types.rs:138-155`, fields `v, networkId, alg, keyVersion,
encryptedSymmetricKey, encryptedSymmetricKeyHash, ciphertext, aad, metadata`)
already has in hand after a normal `storage_get`. The guest does NOT supply
`targetNode` or a `receiverPublicKey` — the host fills both in (target_node =
this node's own DID; receiver_public_key = the routine's freshly-derived
X25519 public key, D-ER2) because neither is guest-controllable data, they are
mediator-owned identity facts, exactly the same reasoning that keeps
`function_cid`/`space` out of the guest-supplied `storage_get`/`storage_put`
request shapes today.

**Response (host → guest), success:**

```json
{ "ok": true, "symmetricKey": "<base64, 32 raw bytes>" }
```

The guest is responsible for AES-256-GCM-decrypting `ciphertext` with this key
and the `aad`/nonce it already has from the envelope (D-ER5); the host import
does not touch payload bytes.

**Response (host → guest), A.4-style denial (no matching grant — NOT
performed, guest does NOT trap, same contract as the four existing imports,
`compute-service.md` Appendix A.4):**

```json
{ "ok": false, "error": { "code": "ability-denied", "ability": "tinycloud.encryption/decrypt", "resource": "urn:tinycloud:encryption:<ownerDid>:<name>" } }
```

**Grant-present-but-failed is FATAL, aborting the whole run** — identical
philosophy to `kv_op`/`sql_op`'s `Err(e) => { self.fatal = Some(...) }` arm
(`compute_exec.rs:604-614`, `798-...`): a `D_fn` grant existed and named this
network, but the request failed for a reason that is not a policy denial
(network not found/revoked/inactive, alg/key-version mismatch, a hash
mismatch between the guest-supplied envelope fields and what the mediator
recomputes, nonce replay, or the chain-authorize step itself failing). These
map to `ComputeExecError::Internal(...)` → 500, exactly like a KV/SQL op that
fails after its grant check passes. Rationale: unlike a missing grant (a
policy fact the guest can legitimately observe and branch on, per A.4), these
are integrity/infrastructure failures — silently continuing execution with a
denial envelope would let a routine paper over e.g. a replay-detected request
as if it were simply unauthorized, which is the wrong signal to make
observable to guest code.

### 5.2 Mediator implementation

New `Import::EncryptionDecrypt` variant alongside the existing four
(`compute_exec.rs:198-203`), dispatched from `HostState::dispatch`
(`compute_exec.rs:420-452`) exactly like `kv_op`/`sql_op` are today, via a new
`HostState::encryption_decrypt_op(&mut self, request: &Value) -> (String,
String, String, bool, Vec<u8>)` following the established
`(resource_str, ability, destination, granted, response_bytes)` return shape
so it journals into the manifest (§6) through the same `self.manifest.record`
call site, no new plumbing.

**Step-by-step (all synchronous via `block_on`, same threading model as
`kv_op`/`sql_op`, §9.1's "Host functions are SYNC" note,
`compute_exec.rs:31-34`):**

1. **Grant lookup.** Build `target = Resource::Other(network_urn)` from the
   guest-supplied `networkId`. Reuse (or trivially generalize)
   `find_grant`'s `(ability_matches, extends)` pattern
   (`compute_exec.rs:311-319`) against `self.grants` for
   `"tinycloud.encryption/decrypt"`. No match → the A.4 denial envelope
   above, `granted: false`, op not performed, guest does not trap.
2. **Derive the routine's X25519 keypair (D-ER2).** The mediator already
   holds the routine's Ed25519 signing material as a `JWK`
   (`HostState.routine_jwk`); this spec additionally threads the raw 32-byte
   seed into `HostState` (via `ExecutionPlan`, alongside the existing
   `routine_jwk` field — the seed is already computed once in
   `handle_compute_invoke`, `routes/mod.rs:2556-2560`, before
   `routine_jwk_from_seed` is called; add a sibling
   `routine_x25519_from_seed(seed)` call there and carry the resulting
   `StaticSecret`/`PublicKey` pair through `ExecutionPlan` the same way
   `routine_jwk` already travels). The private scalar lives only in this
   plan/host-state field for the process lifetime of one execution and is
   never serialized.
3. **Mint the node-audience internal invocation (D-ER3).** A NEW mediator
   method, `HostState::mint_internal_for_node(resource, ability, nota_bene,
   facts, exp_seconds)`, structurally identical to `mint_internal`
   (`compute_exec.rs:360-404`) EXCEPT:
   - `audience`: `self.node_did.parse::<DIDBuf>()` (a new `HostState` field,
     threaded from `ComputeService`/node config the same way `EncryptionService`
     already carries `node_did`) instead of `self.space.did()`. **Why this
     must differ:** `EncryptionService::decrypt_authorized` hard-rejects on
     `invocation.payload().audience != self.node_did` (`service.rs:617-621`,
     `AudienceMismatch`) — the encryption module's own invariant, unrelated to
     and pre-dating compute. The generic chain `validate()`
     (`tinycloud-core/src/models/invocation.rs`) does not itself constrain or
     even read `audience` (confirmed: no `audience` reference anywhere in
     `invocation.rs`), so this per-call override is safe — it only affects a
     check the encryption module performs on top, never the generic engine.
   - `facts`: `Some(vec![serde_json::to_value(DecryptFacts { ty:
     DECRYPT_REQUEST_TYPE, target_node: node_did, network_id, body_hash,
     encrypted_symmetric_key_hash, receiver_public_key_hash, alg, key_version
     })?])` instead of the empty `Vec::new()` KV/SQL use. `body_hash` is
     `canonical_hash(&body_value)` (`encryption_network::canonical::canonical_hash`,
     the SAME canonical-JSON-then-SHA-256 function the encryption module uses
     everywhere else, `canonical.rs:35-43`) over the exact `DecryptRequestBody`
     JSON value built in step 4 — this is the "canonical body/facts" binding:
     the invocation's proof-of-intent (`facts.body_hash`) must equal the hash
     of the body the mediator is about to submit, so the two cannot drift
     (mirrors `native_decrypt_facts`'s lookup, `service.rs:911-914`, and the
     `expected_body_hash` check the service performs, `service.rs:695-700`).
   - `exp_seconds`: `now + 240` (NOT `INTERNAL_INVOCATION_EXP`'s year-2100
     constant). **Why this must differ:** `decrypt_authorized` calls
     `validate_invocation_time` (`service.rs:664`, backed by
     `DEFAULT_INVOCATION_TTL_SECONDS = 300`, `service.rs:42`), which rejects
     when `exp - now > ttl` — a far-future expiry is an automatic reject, not
     merely "generously valid." 240s leaves slack under the 300s ceiling for
     dispatch/queue jitter while remaining a genuinely short-lived credential,
     consistent with the encryption module's own TTL philosophy. `nonce`:
     reuse `self.next_nonce()` unchanged — the mediator's per-call random
     128-bit nonce already satisfies "fresh across executions" (the same
     property the KV/SQL judge finding fixed, `compute_exec.rs:277-289`), and
     `EncryptionService::consume_nonce` (`service.rs:834-856`) independently
     enforces non-replay against its own `encryption_nonce` table keyed by
     `(invoker, nonce)`.
   - `nota_bene` on the single `tinycloud.encryption/decrypt` capability:
     echoed verbatim from the selected grant exactly as `kv_op`/`sql_op` do
     (`echo_nota_bene`, `compute_exec.rs:327-343`) — F1 applies identically;
     this is not a new rule, just applied to a new ability.
4. **Authorize against the chain.** `self.tinycloud.invoke::<BlockStage>(invocation.clone(),
   HashMap::new())` — the SAME call `sql_op`'s step (1) already makes
   (`compute_exec.rs:747-753`) and the SAME call the encryption module's own
   HTTP route makes via `verify_auth` before ever calling `decrypt_authorized`
   (`routes/encryption.rs:159-165, 236-260`) — proves the routine's `D_fn`
   chain genuinely supports this exact `(resource, ability)` pair, persists
   the invocation event, and is what makes "no new authorization-engine code"
   (§6.2's standing claim) hold for this ability too: `Resource::Other`
   capabilities already flow through the identical generic `validate()`/
   `extends()` machinery used for the `/encryption/networks/*` HTTP routes
   today — this is direct, shipped precedent, not a novel code path. Failure
   here → FATAL (§5.1).
5. **Call `EncryptionService::decrypt_authorized` in-process.** No HTTP hop —
   the mediator holds `Arc<EncryptionService>`/`&State<EncryptionService>`
   the same way it already holds `SqlService` (§9.1: "the internal-invocation
   executor needs BOTH `SpaceDatabase::invoke` ... AND `SqlService`", this
   spec adds a third: `EncryptionService`, threaded into `ExecutionPlan`
   exactly like `sql_service` is today, `compute_exec.rs:1030`). Build
   `body_value` as the canonical `DecryptRequestBody` JSON: `ty =
   DECRYPT_REQUEST_TYPE`, `target_node = node_did`, `network_id`, `alg`,
   `key_version`, `encrypted_symmetric_key`/`_hash` (guest-supplied, passed
   through verbatim), `receiver_public_key` = base64 of the routine's derived
   X25519 public key (D-ER2 step 2), `receiver_public_key_hash =
   canonical_hash(Value::String(receiver_public_key))` (matching
   `service.rs:671-672`'s own recomputation, which MUST agree or
   `decrypt_authorized` rejects with `HashMismatch`). Call
   `encryption_service.decrypt_authorized(&network_id, &invocation_info,
   &body_value)` where `invocation_info = InvocationInfo::try_from(invocation)?`
   (the same conversion `AuthHeaderGetter` performs for the HTTP path,
   `util.rs:254-262`). Any `EncryptionServiceError` → FATAL (§5.1), mapped via
   the SAME status-mapping table `map_service_err` already encodes
   (`routes/encryption.rs:262-287`) reused for the eventual `into_status()`
   arm, so a compute-mediated decrypt failure and an HTTP decrypt failure
   report identically-classed errors.
6. **Unwrap the rewrapped key in-process (D-ER4).** `decrypt_authorized`
   returns `VerifiedDecrypt.response.wrapped_key` — base64 of a
   `[32-byte ephemeral X25519 pubkey][AES-256-GCM ciphertext]` envelope
   (`backend.rs:64-77`'s `wrap_to_public_key` format, called at
   `service.rs:734` with the routine's pubkey as `receiver_public_key`).
   The mediator opens it with the **identical arithmetic** `backend.rs`'s
   private `unwrap_with_secret` already implements
   (`backend.rs:79-90`: split the envelope, `StaticSecret::diffie_hellman`
   with the leading 32 bytes as the peer public key, `ColumnEncryption::new(*shared.as_bytes())`,
   `.decrypt(&wrapped[32..])`) — reimplemented inline in the mediator using
   the routine's derived `StaticSecret` (D-ER2) rather than depending on a
   newly-`pub` export from `backend.rs`, since `ColumnEncryption` and
   `x25519_dalek::StaticSecret` are already public core types reachable from
   the server crate; no core visibility change needed for this step (contrast
   §4, which DOES require a core change). The resulting raw symmetric key
   bytes are the host import's success response payload (§5.1); the routine's
   X25519 `StaticSecret` is dropped immediately after this single
   `diffie_hellman` call.
7. **Journal + return.** `bytes_in`/`bytes_out` = the guest-request/host-response
   JSON byte lengths (same convention as the other four imports, §9.1.1);
   `destination = "inline"` (no KV path is written by this import itself —
   any subsequent `storage_put` of re-encrypted output is a separate,
   independently-journaled host call, D-ER5); `granted = true`.

---

## 6. Manifest / Journal Entry

No new field on `ManifestEntry` (`tinycloud-core/src/compute.rs:139-149`) —
`{resource, ability, bytes_in, bytes_out, destination, granted}` already
generalizes. One new row shape:

| field | value |
|---|---|
| `resource` | `urn:tinycloud:encryption:<ownerDid>:<name>` |
| `ability` | `tinycloud.encryption/decrypt` |
| `destination` | `"inline"` |
| `granted` | `true` (success) / `false` (A.4 denial only — a fatal failure never produces a journal row, matching `kv_op`/`sql_op`: `self.fatal` is set and the run aborts before the guest sees a return value at all, so there is nothing to journal past the attempt) |

The granted-vs-exercised scope-down signal (§9.1.1) extends naturally:
`tinycloud.encryption/decrypt` in `D_fn` but never called shows up in
`granted_but_unexercised`, the same deployer-facing tightening signal KV/SQL
abilities already produce.

---

## 7. Error / Denial Contract Summary

| condition | guest-visible? | HTTP status if surfaced | source |
|---|---|---|---|
| no `D_fn` grant for `tinycloud.encryption/decrypt` on this network | yes — `{"ok":false,"error":{"code":"ability-denied",...}}`, op not performed, no trap | n/a (200 w/ envelope in `run` result) | A.4 pattern, §5.1 step 1 |
| chain `validate()` rejects the internal invocation (grant present but chain-invalid — should not normally happen if step 1 passed, but the two checks are independent layers) | no — FATAL | 500 | §5.2 step 4 |
| `EncryptionServiceError::{NetworkNotFound,NetworkRevoked,NetworkNotActive,AlgKeyVersionMismatch,HashMismatch,NonceReplay,Expired,NotYetValid,AudienceMismatch,TargetNodeMismatch,NetworkMismatch,WrongInvocationType,Unauthorized,SignatureInvalid}` | no — FATAL | per `map_service_err` (`routes/encryption.rs:262-287`) — mostly 401/409/400, never silently swallowed | §5.2 step 5 |
| `EncryptionServiceError::{Db,Backend,Signing}` (infra) | no — FATAL | 500 | §5.2 step 5 |
| malformed guest request JSON | yes — `{"ok":false,"error":{"code":"bad-request",...}}` | n/a | matches existing `dispatch`'s malformed-request handling, `compute_exec.rs:422-433` |

---

## 8. Threat-Model Invariants

1. **No authority inheritance from the external invoker.** Holding
   `tinycloud.compute/execute` on the function resource grants nothing toward
   `tinycloud.encryption/decrypt` — layer (a)/(b) decoupling (§6.1/§6.2) is
   unchanged; the invoker never needs, and never gains, network membership.
   This is structurally guaranteed the same way it already is for KV/SQL: the
   internal invocation is signed by the ROUTINE key, never the invoker's.
2. **No payload plaintext, and no raw symmetric key, ever crosses the
   `EncryptionService` boundary.** Unchanged from the shipped module
   (`service.rs:731-735`); this spec is a new *caller*, not a new *exposure*.
3. **The routine's X25519 private scalar never leaves core/TEE mediation.**
   It is derived fresh per execution inside `HostState` (server crate,
   in-process, inside the same `spawn_blocking` the WASM guest runs in — the
   TEE boundary, when running under dstack, already encloses this), used for
   exactly one `diffie_hellman` call, and dropped. It is never: returned to
   the guest, included in a response body, logged, or persisted. Contrast the
   client-side `vault_ed25519_seed_to_x25519` (D-ER2) which deliberately
   *does* export the scalar — that function is architecturally the wrong tool
   for this job and MUST NOT be reused here.
4. **The raw AES-256 symmetric key DOES cross into guest memory** (D-ER5) —
   this is an accepted, scoped exposure: the guest already held (or could
   derive) everything needed to request this key via its `D_fn` grant, and
   holding the payload symmetric key is exactly what "decrypt this payload"
   means. What must NOT cross into guest memory is the routine's X25519
   private scalar (invariant 3) — that key protects the *transport* of the
   symmetric key from `EncryptionService` to the routine, not the payload
   itself, and reusing it (or exposing it) would let anything with guest-code
   execution impersonate the routine to the encryption network indefinitely,
   not just for one payload.
5. **Replay/TTL is enforced twice, independently.** The mediator's fresh
   random nonce + short expiry (D-ER3) is one layer; `EncryptionService`'s own
   `consume_nonce`/`validate_invocation_time` (`service.rs:664, 706-711`) is a
   second, independent layer the mediator does not and cannot bypass — a
   compute-mediated decrypt gets no weaker replay protection than the direct
   HTTP path.
6. **Space isolation is preserved.** §4's core fix narrows, it does not
   remove, the space-scope defense-in-depth; the primary boundary
   (space-hashed `routine_did`) is untouched. A routine in space A still
   cannot cite space B's `D_fn` for anything, encryption included.
7. **Network membership is the deployer's, delegated, not manufactured.** A
   `D_fn` row for `tinycloud.encryption/decrypt` can only be minted by a
   deployer whose own chain already holds that authority (normal delegation
   containment); this spec adds no privilege-escalation path onto encryption
   networks the space owner/deployer wasn't already a member of.

---

## 9. Test Gates (named, narrow)

**Unit (`tinycloud-core`):**
- `routine_x25519_from_seed` determinism: same seed → same keypair, byte-exact,
  across repeated calls (mirrors the existing `routine-key-determinism` test
  pattern at `compute.rs:506`).
- `routine_x25519_from_seed` produces a DIFFERENT keypair per distinct
  `(space, function_cid)` (mirrors `routine-key-per-function`, `compute.rs:527`).
- `compute_select_d_fns` carve-out: a `D_fn` with one `Resource::Other`
  encryption-network row (matching the URN prefix) and one in-space
  `Resource::TinyCloud` row is SELECTED (regression test for the exact bug
  §4 fixes); a `D_fn` with a `Resource::Other` row whose URI does NOT match
  the prefix is REJECTED (proves the carve-out is prefix-scoped, not a
  blanket bypass); a `D_fn` with an out-of-space `Resource::TinyCloud` row is
  still REJECTED unchanged (regression guard on the untouched arm).

**Integration (`tinycloud-node-server`, new `tests/compute_encryption.rs`,
naming mirrors `compute_execute.rs`/`compute_e2e.rs`):**
- End-to-end fixture, same structure as Appendix A: create a one-of-one
  encryption network owned by the space owner; deploy a WAT fixture whose
  `D_fn` grants `kv/get` on `in/`, `kv/put` on `out/`, and
  `tinycloud.encryption/decrypt` on the network; seed `in/x` with an
  `InlineEnvelope` (wrapped to the network's public key, per
  `wrap_to_public_key`) over a known plaintext; `run` reads it via
  `storage_get`, calls `encryption_decrypt`, AES-GCM-decrypts in-guest,
  writes the recovered plaintext to `out/y` via `storage_put`. Assert: the
  final KV value equals the original plaintext; the manifest contains the
  `tinycloud.encryption/decrypt` call with `granted: true`; a SECOND fixture
  run with the network row omitted from `D_fn` gets the A.4 denial envelope
  (op not performed, no trap); a THIRD run against a REVOKED network
  produces a FATAL 500 (not a silent denial) — proving §7's two-tier
  contract.
- Regression: an existing `compute_execute.rs`/`compute_e2e.rs` fixture with
  KV+SQL-only `D_fn` (no encryption row) still selects and executes
  correctly post-§4 fix — proves the carve-out didn't change behavior for
  the unmodified path.

**Live E2E (gated, real dstack CVM, mirrors the existing
`compute_fixture`/E2E harness conventions and the `dstack-stability probe`
already required by §6.2):**
- Full round trip against a live encryption-network node instance: deploy →
  seed encrypted KV value → execute → assert decrypted output, run TWICE
  across the process to confirm the routine's re-derived X25519 keypair is
  stable (same underlying seed-stability assumption §6.2 already flags as
  "VERIFY EMPIRICALLY" for the Ed25519 identity — this reuses that same
  empirical check, now also covering the X25519 derivation since it's a
  deterministic function of the same seed).

---

## 10. Deferred / Non-Normative

- SDK convenience for minting the `tinycloud.encryption/decrypt` `D_fn` row
  at deploy time (a one-line addition to the existing deploy-grant builder in
  `@tinycloud/node-sdk`, per `COMPUTE-API.md`'s "Deploy with a real grant"
  shape) — follow-up, not blocking this node-side contract.
- Re-encrypt-on-write (a routine writing a NEW `InlineEnvelope` back to KV via
  `storage_put`) needs no new host import — the guest already has
  `storage_put` and can construct the envelope JSON itself once it holds a
  symmetric key (from a fresh network wrap-to-public-key call the routine
  would need `kv/put`-equivalent... actually network **encrypt** authority,
  which the module deliberately does not expose node-side, "clients encrypt
  to the network public key locally" per `encryption_network/mod.rs:4-5`).
  Re-encryption by a routine using a NEW network-derived key is therefore
  OUT OF SCOPE for this spec's MVP — only decrypt-of-existing-envelope is
  specced. A routine MAY re-encrypt with a symmetric key it generates itself
  (ordinary AES-256-GCM, no network involvement) and store the wrap
  out-of-band; that is unconstrained by this spec either way.
- Optional KV-audit persistence of the decrypt manifest entry — same
  MAY/config-gated status as the general manifest persistence hook (§9.1.1),
  not wired in this stage.
- Threshold `KeyBackend` — orthogonal, unblocked by this spec (the mediator
  only ever calls the existing `EncryptionService::decrypt_authorized`
  trait-object boundary, agnostic to backend).
