# Spec: The Compute Routine as Encryption-Network Decrypt Receiver (Option B)

**Date:** 2026-07-22
**Status:** Draft (round 6 — Sol fixes: pinned the missing `wrappedKey`
base64-decode step before `unwrap_with_secret`, added its regression test,
trimmed rationale prose to target length; normative content unchanged)
**Depends on:** `specs/compute-service.md` (P2, merged: §5.1 deploy-time binding,
§6.2 two-layer permissioning, §9.1/§9.1.1 WasmtimeBackend + manifest, Appendix A
fixture pattern) and the shipped `tinycloud-core/src/encryption_network/*`
module (network lifecycle, `EncryptionService::decrypt_authorized`).
**Service identifiers:** `tinycloud.compute/*` (existing), `tinycloud.encryption/decrypt`
(existing action, new grantee: a compute routine)

---

## 1. Scope

**Option B:** a TinyCloud compute routine (§6.2's derived-key identity)
becomes a legitimate **receiver** for `tinycloud.encryption/decrypt` — the
routine itself, not the invoker and not a client, holds delegated authority to
ask an encryption network to rewrap a symmetric key to the routine's own key,
then unwraps and uses it in-process to decrypt/re-encrypt a payload. A
deployed function can read an `InlineEnvelope`-shaped ciphertext from KV,
decrypt, transform, re-encrypt, and write it back, without the routine's
grant ever holding plaintext-equivalent authority outside the node process,
and without the *invoker* of `compute/execute` gaining any decrypt authority
(layer (a)/(b) decoupling, §6.1/§6.2, preserved).

Additive to `compute-service.md`: one new mediated host import, one new
`D_fn` ability row type, four REQUIRED core fixes (§4). Does **not** change
`/invoke`'s wire format, the four existing host imports, or the
encryption-network module's public HTTP routes/types
(`DecryptRequestBody`/`DecryptFacts` keep their existing fields).

### Non-goals

- No new HTTP endpoint — entirely internal (mediator → core, in-process),
  triggered by a guest host-import call during `compute/execute`.
- No change to `EncryptionService`'s external behavior (`decrypt`,
  `decrypt_authorized`, `/encryption/networks/*`) — new *caller*, not a new
  capability inside that module.
- No threshold-backend design; rides whatever `KeyBackend` is configured
  today (`LocalOneOfOneBackend`).
- No SDK/deploy-tooling changes for minting the extra `D_fn` row — deferred,
  non-blocking.
- No new host import for randomness — the re-encryption nonce comes from the
  `encryption_decrypt` import's own response (§6).

---

## 2. Design Decisions (DECIDED)

Rationale for each item lives in `specs/compute-encrypted-routine-rationale.md`
(non-normative); this section pins only the DECIDED facts.

- **D-ER1 — the routine's decrypt authority rides the SAME `D_fn` as its
  KV/SQL grant, as one more ability row.** The deployer adds
  `{ resource: <network-urn>, ability: "tinycloud.encryption/decrypt" }`
  alongside the existing `kv/get`, `kv/put`, `sql/read` rows under the same
  delegation, carrying the same `computeFunctionBinding` caveat (caveats
  attach per ability row, `delegation.rs:466-476`). No new delegation type.

- **D-ER2 — the routine derives its own X25519 keypair from the same Ed25519
  seed already used for its signing identity, once per execution, retained
  for the run's lifetime.** `RoutineKeyDeriver::derive_routine_seed`
  (`tinycloud-core/src/compute.rs:295-299`) already produces the seed backing
  `routine_jwk_from_seed`/`routine_did_from_seed`. This spec adds
  `routine_x25519_from_seed(seed) -> RoutineX25519Keypair` in
  `tinycloud-core` (non-`wasm_bindgen`), using the same Ed25519-seed→X25519
  conversion already implemented client-side in
  `tinycloud-sdk-wasm/src/vault.rs` (`vault_ed25519_seed_to_x25519`:
  SHA-512(seed), first 32 bytes, `StaticSecret::from`). `RoutineX25519Keypair`
  is a `pub type` alias for `(x25519_dalek::StaticSecret,
  x25519_dalek::PublicKey)` re-exported from
  `tinycloud_core::encryption_network::backend` (§4.4) so node-server never
  names the crate. Derived once per execution into a `HostState` field
  (`routine_x25519`), reused across calls, dropped with `HostState` at the end
  of `run_blocking` — never returned to the guest, logged, or persisted.
  `x25519_dalek::StaticSecret` (`static_secrets` feature,
  `tinycloud-core/Cargo.toml:44`) keeps the crate's default `zeroize` feature
  active, so `StaticSecret` derives `ZeroizeOnDrop` — the scalar zeroes
  automatically on drop, no extra code needed.

- **D-ER3 — the internal invocation authorizing the routine's decrypt uses
  audience = node_did (not `space.did()`), sourced from
  `EncryptionService::node_did()` (`service.rs:144`), with a SHORT expiry
  (`now + 240`, under `DEFAULT_INVOCATION_TTL_SECONDS = 300`).** Two
  deviations from `HostState::mint_internal` (`compute_exec.rs:360-404`):
  audience and expiry. `nonce` reuses `self.next_nonce()` unchanged;
  `consume_nonce` (`service.rs:834-856`) independently enforces non-replay.
  `nota_bene` is echoed verbatim from the selected grant exactly as
  `kv_op`/`sql_op` do (`echo_nota_bene`, `compute_exec.rs:327-343`).

- **D-ER4 — the `EncryptionService` boundary never returns the raw symmetric
  key.** `decrypt_authorized` (`service.rs:604-760`) already only ever
  returns a `wrapped_key` (rewrapped to the caller-supplied
  `receiver_public_key`, `service.rs:734`) — the raw `symmetric` value is
  local and dropped before return (`service.rs:735`). This spec supplies the
  routine's derived X25519 public key as `receiver_public_key`; the boundary
  is unchanged. The routine-side unwrap happens entirely after
  `decrypt_authorized` returns, inside the mediator, via the reused core
  helper (§4.4).

- **D-ER5 — the guest, not the host, performs the payload AES-256-GCM
  decrypt AND re-encrypt (§6 pins byte layout, AAD binding, nonce sourcing).**
  The host import returns the raw 32-byte symmetric key to guest memory; the
  guest WASM module runs AES-256-GCM itself. The host mediator never touches
  payload bytes — only the wrapped/unwrapped key and the non-secret AAD bytes
  plus their hash. Re-encryption of the SAME payload using the SAME
  already-unwrapped key is in scope; minting a brand-new symmetric key and
  wrapping it to the network's public key is out of scope (§11).

- **D-ER6 (REQUIRED CORE FIX) — `compute_select_d_fns`'s space-scope check
  must carve out encryption-network resources.** See §4.1.

- **D-ER7 (REQUIRED CORE FIX) — `dispatch` must latch on `self.fatal` and
  short-circuit every subsequent host call.** See §4.2.

- **D-ER8 (REQUIRED CORE FIX) — `EncryptionService` must be `Clone` so an
  owned instance can be threaded into `ExecutionPlan`/`HostState`, without
  duplicating the node's Ed25519 signing key on every compute execution.**
  `node_keypair` moves from `Option<Keypair>` to `Option<Arc<Keypair>>` so
  `#[derive(Clone)]` only bumps a refcount. See §4.3.

- **D-ER9 (REQUIRED CORE FIX) — the mediator reuses `tinycloud-core`'s
  existing crypto/encoding primitives; it implements none of its own.** Three
  functions move from module-private to `pub` (logic unchanged, visibility
  only): `backend::unwrap_with_secret` (`backend.rs:87`),
  `service::encode_base64`/`service::decode_base64` (`service.rs:1011-1017`,
  the `STANDARD` — RFC 4648, padded, non-URL-safe — engine). `backend.rs`
  additionally re-exports `x25519_dalek::{PublicKey, StaticSecret}` and
  `pub type RoutineX25519Keypair = (StaticSecret, PublicKey)`. Net effect: no
  new `Cargo.toml` dependency anywhere for this spec. See §4.4.

---

## 3. Deploy-Time Shape

No change to the `Deploy` request variant or the atomic artifact+grant
transaction (§5.1/F4). The `D_fn` simply includes an additional capability
row:

```json
{
  "with": "urn:tinycloud:encryption:<ownerDid>:<name>",
  "can": "tinycloud.encryption/decrypt",
  "nb": [ { "computeFunctionBinding": { "functionCid": "<function_cid>" } } ]
}
```

Rides the normal `/delegate` verification/persistence path (F4); the
deployer's own chain must already hold `tinycloud.encryption/decrypt` on that
exact network URN (grants **nothing** new to deployers, only lets them
re-delegate authority they already hold). Re-deploy hygiene (§5.1) applies
identically (a new `function_cid` makes this row dormant along with KV/SQL
rows on the same delegation). F1.8 interacts identically — a caveated row
must byte-equal-contain `computeFunctionBinding` (`invocation.rs:271-289`).

---

## 4. REQUIRED Core Fixes

Each fix's "why this gap exists / why narrow-not-delete" reasoning is in
`specs/compute-encrypted-routine-rationale.md`; this section pins the
DECIDED fix.

### 4.1 `compute_select_d_fns` space-scope carve-out

**The gap.** `compute_select_d_fns` (`tinycloud-core/src/db.rs:335-396`)
requires every ability row's `resource.space()` to equal the target space.
`Resource::space()` (`resource.rs:23-28`) returns `None` for
`Resource::Other` — what a `urn:tinycloud:encryption:...` row IS. Unfixed,
adding the D-ER1 row would silently disable selection for the WHOLE
delegation. Predates this spec.

**DECIDED fix.** Treat `Resource::TinyCloud` rows as today; admit
`Resource::Other` rows **only** when their URI parses as a well-formed
`NetworkId` — not merely a reserved-prefix match:

```rust
let all_in_space = ability_rows.iter().all(|row| match &row.resource {
    Resource::TinyCloud(_) => row.resource.space().map(|s| s == space).unwrap_or(false),
    Resource::Other(uri) => uri.as_str().parse::<NetworkId>().is_ok(),
});
```

Mirrors `Resource::extends`'s own `Other, Other` arm (`resource.rs:33-48`) —
fails closed on a malformed `Resource::Other` row (whole delegation
unselectable), not silently admitted. Needs only
`use crate::encryption_network::NetworkId;` in `db.rs` (module is
unconditionally public, `lib.rs:8`). Grants nothing new — enforced twice
elsewhere: the deployer's own chain already held the ability, and at execute
time the mediator's internal invocation still passes `validate()` (§5.2 step
4) AND `decrypt_authorized`'s own checks. `compute_classify_routine_grant`
(`db.rs:440`) needs no equivalent change — its `has_binding` check is
already satisfied by the KV/SQL rows.

### 4.2 `dispatch` fail-stop latch

**The gap.** `dispatch` (`compute_exec.rs:420-452`) always calls
`self.manifest.record(...)` and returns response bytes to the guest,
regardless of whether the op set `self.fatal`; `host_import`
(`compute_exec.rs:1273-1338`) never traps on it — the only check happens in
`run_blocking`, AFTER `run()` fully returns (`compute_exec.rs:1177-1179`).

**DECIDED fix.** Latch at the top of `dispatch`, before any request parsing:

```rust
fn dispatch(&mut self, import: Import, req: &[u8]) -> Vec<u8> {
    if self.fatal.is_some() {
        return serde_json::to_vec(&json!({
            "ok": false, "error": { "code": "aborted" }
        }))
        .expect("aborted envelope serializes");
    }
    // ... unchanged from here
}
```

The ORIGINAL triggering call is unaffected — still runs to completion, still
journaled (`granted: false`, §7), still returns its own
`{"ok":false,"error":{"code":"internal"}}`; `run_blocking`'s post-`run()`
check still raises `ComputeExecError::Internal` → 500 (§8). Every call AFTER
that point is rejected before any grant lookup or core call — a
Wasmtime-host-fn latch (no trap, no unwind). Rollback of prior mutations is
out of scope (§9 invariant 8) — pre-existing per-call commit behavior.

### 4.3 `EncryptionService: Clone`

**The gap.** `ExecutionPlan`/`HostState` must own `'static` data — moved into
`tokio::task::spawn_blocking`. `EncryptionService`
(`encryption_network/service.rs:97-103`) does not implement `Clone` today.

**DECIDED fix.** Wrap `node_keypair` in `Arc` before deriving `Clone`:

```rust
pub struct EncryptionService {
    db: DatabaseConnection,
    node_did: String,
    node_keypair: Option<Arc<Keypair>>,   // was Option<Keypair>
    backend: Arc<dyn KeyBackend>,
    invocation_ttl_seconds: i64,
}
```

`new_with_node_keypair` (`service.rs:129-140`) wraps once at construction
(`node_keypair: Some(Arc::new(node_keypair))`); the one existing read site
(`service.rs:772`) needs no change (`&Arc<Keypair>` derefs via `Deref`).
Every field is now cheap to clone. No `.manage()` call changes — the route
handler building `ExecutionPlan` takes a new `&State<EncryptionService>`
parameter and passes `encryption_service.inner().clone()` into the plan,
alongside `sql_service` (same pattern `compute-service.md` §9.1 describes
for `SqlService`).

### 4.4 Reused core primitives, zero new node-server dependencies

**The gap.** A naive mediator would need `x25519_dalek::StaticSecret` as a
`HostState` field type and reimplement `backend.rs`'s private
`unwrap_with_secret` inline — neither `x25519-dalek` nor `aes-gcm` is
re-exported from `tinycloud-core`'s public API, and
`tinycloud-node-server/Cargo.toml` has neither as a direct dependency.

**DECIDED fix — reuse, don't duplicate:**
1. `tinycloud-core/src/encryption_network/backend.rs`: change
   `fn unwrap_with_secret` (line 87) to `pub fn`. No logic change. Add
   `pub use x25519_dalek::{PublicKey, StaticSecret};` and
   `pub type RoutineX25519Keypair = (StaticSecret, PublicKey);`; add
   `unwrap_with_secret, RoutineX25519Keypair` to `mod.rs:18`'s `pub use`.
2. `tinycloud-core/src/encryption_network/service.rs`: change
   `fn encode_base64`/`fn decode_base64` (lines 1011-1017) to `pub fn`. No
   logic change (still the `STANDARD` engine, `service.rs:11`). Add both to
   the module's `pub use service::{...}` list.
3. `tinycloud-core/src/compute.rs`: add
   `pub fn routine_x25519_from_seed(seed: &[u8; 32]) -> RoutineX25519Keypair`
   (D-ER2), built from the SHA-512-then-`StaticSecret::from` conversion
   already in `vault_ed25519_seed_to_x25519`.
4. `tinycloud-node-server`: the mediator (§5.2) calls
   `tinycloud_core::encryption_network::backend::unwrap_with_secret(&secret, &wrapped_key_bytes)`
   directly and `tinycloud_core::encryption_network::service::{encode_base64, decode_base64}`
   for every base64 field on this boundary — `aad`, `receiverPublicKey`,
   `wrappedKey` (decoded from `VerifiedDecrypt.response.wrapped_key` before
   the `unwrap_with_secret` call, §5.2 step 6 — this decode is REQUIRED, not
   optional: `unwrap_with_secret` takes `&[u8]`, `wrapped_key` is a base64
   `String`), `symmetricKey`, `reencryptNonce`. The re-encrypt nonce (§6) is
   12 bytes from `rand::rngs::OsRng`/`RngCore::fill_bytes` — `rand = "0.8"` is
   already a `tinycloud-node-server` dependency (`Cargo.toml:43`).

Result: **no `Cargo.toml` dependency edit anywhere for this spec.**
`x25519_dalek::StaticSecret`/`PublicKey` reach `tinycloud-node-server` only
through `RoutineX25519Keypair`; the unwrap arithmetic and the base64 encoding
convention each have exactly one implementation, in `tinycloud-core`.

---

## 5. Execute-Time Mediator Flow

### 5.1 Host-import ABI addition (5th import)

Extends the §9.1 NORMATIVE host-import surface from four to **five**
imports, all under module `"tinycloud"`, all `(i32 ptr, i32 len) -> (i32 ptr,
i32 len)` JSON-bytes-on-every-boundary:

```
storage_get, storage_put, storage_del, sql_query, encryption_decrypt
```

**Request (guest → host), JSON:**

```json
{
  "networkId": "urn:tinycloud:encryption:<ownerDid>:<name>",
  "alg": "x25519-aes256gcm/v1",
  "keyVersion": 1,
  "encryptedSymmetricKey": "<base64 STANDARD, from the InlineEnvelope>",
  "encryptedSymmetricKeyHash": "<hex>",
  "aad": "<base64 STANDARD (canonical, padded — decoded via core's decode_base64), the raw InlineEnvelope.aad bytes the guest already holds; FATAL on invalid/non-canonical base64, §5.2 step 3a>",
  "aadHash": "<hex, guest's own canonical_hash(base64(aad)) — a request self-consistency check only; the mediator always signs its OWN recomputed hash, never this field, §5.2/§9 invariant 9>"
}
```

Minimum guest-supplied subset of `DecryptRequestBody` (`protocol.rs:26-46`)
plus the AAD fields — everything a guest reading an `InlineEnvelope`
(`types.rs:138-155`) already has after a `storage_get`. The guest does NOT
supply `targetNode` or `receiverPublicKey` — the host fills both in
(`target_node` = this node's own DID; `receiver_public_key` = the routine's
derived X25519 public key, D-ER2) — neither is guest-controllable.

**Response (host → guest), success — canonical encoding pinned:**

```json
{ "ok": true, "symmetricKey": "<base64 STANDARD, padded, EXACTLY 32 raw bytes>", "reencryptNonce": "<base64 STANDARD, padded, 12 fresh random bytes, single-use>" }
```

Both fields encoded with core's `encode_base64` (`service.rs:1011`, the
`STANDARD` engine), the SAME helper used for every other encoded field on
this boundary (D-ER9/§4.4) — exactly one encoder for these bytes; the guest
MUST decode with the same standard, padded alphabet. The mediator rejects
(FATAL, §8) any unwrapped key not exactly 32 bytes BEFORE this envelope is
constructed (§5.2 step 6) — a `symmetricKey` field never reaches guest
memory otherwise. The guest is responsible for AES-256-GCM-decrypting
`ciphertext` with this key and the `aad`/nonce it already has (§6); the host
import never touches payload bytes.

**Response (host → guest), A.4-style denial (no matching grant — NOT
performed, guest does not trap, same contract as the four existing imports):**

```json
{ "ok": false, "error": { "code": "ability-denied", "ability": "tinycloud.encryption/decrypt", "resource": "urn:tinycloud:encryption:<ownerDid>:<name>" } }
```

**Grant-present-but-failed is FATAL** — identical philosophy to
`kv_op`/`sql_op`'s `Err(e) => { self.fatal = Some(...) }` arm
(`compute_exec.rs:604-614`): a `D_fn` grant existed and named this network,
but the request failed for a non-policy reason (network not
found/revoked/inactive, alg/key-version mismatch, hash mismatch, nonce
replay, chain-authorize failure, or the mediator's post-unwrap 32-byte check
failing). These map uniformly to `ComputeExecError::Internal` → HTTP 500
(§8). The FIRST such failure IS journaled (`granted: false`, §7) and DOES
return its own `{"ok":false,"error":{"code":"internal"}}` envelope. Every
host call after that point, of any import, is rejected with
`{"ok":false,"error":{"code":"aborted"}}` (§4.2/D-ER7) — no work, not
journaled.

### 5.2 Mediator implementation

New `Import::EncryptionDecrypt` variant alongside the existing four
(`compute_exec.rs:198-203`), dispatched from `HostState::dispatch` (now with
the §4.2 latch at its top) exactly like `kv_op`/`sql_op`, via a new
`HostState::encryption_decrypt_op(&mut self, request: &Value) ->
(String, String, String, bool, Vec<u8>)` following the established
`(resource_str, ability, destination, granted, response_bytes)` shape.

**Step-by-step (synchronous via `block_on`, same threading model as
`kv_op`/`sql_op`):**

1. **Grant lookup.** Build `target = Resource::Other(network_urn)`. Reuse
   `find_grant`'s `(ability_matches, extends)` pattern
   (`compute_exec.rs:311-319`) for `"tinycloud.encryption/decrypt"`. No match
   → the A.4 denial envelope, `granted: false`, op not performed.
2. **Derive the routine's X25519 keypair once (D-ER2).** At `ExecutionPlan`
   build time (`routes/mod.rs`, alongside the existing
   `routine_jwk_from_seed(seed)` call), add a sibling
   `routine_x25519_from_seed(seed)` call and carry `RoutineX25519Keypair`
   into `HostState.routine_x25519`. Reused for every `encryption_decrypt`
   call in the execution; dropped with `HostState`.
3. **Validate `aad`, bind its hash, mint the node-audience internal
   invocation (D-ER3), clone `InvocationInfo` before it moves.**
   - **3a — AAD binding.** Decode `request.aad` with core's `decode_base64`
     (`service.rs:1011-1017`); decode failure → FATAL
     (`self.fatal = Some("aad is not valid base64")`) before touching
     `aadHash`. Compute `computed_aad_hash =
     canonical_hash(&Value::String(request.aad.clone()))` on the
     now-validated string — same convention
     `encryptedSymmetricKeyHash`/`receiverPublicKeyHash` already use
     (`service.rs:671-672, 683-684`). Guest-declared `aadHash` mismatching
     `computed_aad_hash` → FATAL (`self.fatal = Some("aadHash does not match
     recomputed hash of aad")`) — a request self-consistency check only (§9
     invariant 9); the value that gets signed is always
     `computed_aad_hash`, never the guest-declared field. Not a new
     exposure — `InlineEnvelope.aad` is already readable via `kv/get`.
   - **3b — build `body_value` and mint.** Construct the complete
     `DecryptRequestBody` (`protocol.rs:26-46`; `serde` rejects a partial
     struct, `service.rs:440-444`):
     ```rust
     let receiver_public_key = encode_base64(routine_x25519_public.as_bytes()); // step 2's derived PublicKey
     let body = DecryptRequestBody {
         ty: DECRYPT_REQUEST_TYPE.to_string(),
         target_node: self.encryption_service.node_did().to_string(),   // mediator-owned, never guest-supplied
         network_id: network_id.clone(),
         alg: request.alg.clone(),
         key_version: request.key_version,
         encrypted_symmetric_key: request.encrypted_symmetric_key.clone(),
         encrypted_symmetric_key_hash: request.encrypted_symmetric_key_hash.clone(),
         receiver_public_key: receiver_public_key.clone(),
         receiver_public_key_hash: canonical_hash(&Value::String(receiver_public_key)),
     };
     ```
     Serialize to a `serde_json::Value`, insert a top-level `"aadHash"` key
     holding `computed_aad_hash`. `body_hash = canonical_hash(&body_value)`
     (covers `aadHash` too). `facts = Some(vec![DecryptFacts { ty,
     target_node, network_id, body_hash, encrypted_symmetric_key_hash,
     receiver_public_key_hash, alg, key_version }])` — unchanged shape;
     `serde_json::from_value::<DecryptRequestBody>` (`service.rs:610`)
     silently ignores the extra `aadHash` key, and `expected_body_hash`
     (`service.rs:695`) hashes the raw `Value` passed in, so no changes are
     needed to `DecryptRequestBody`/`DecryptFacts`/`decrypt_authorized`. Mint
     via a new `HostState::mint_internal_for_node(resource, ability,
     nota_bene, facts, exp_seconds)`, structurally identical to
     `mint_internal` (`compute_exec.rs:360-404`) except `audience =
     self.encryption_service.node_did().parse::<DIDBuf>()` and
     `exp_seconds = now + 240` (D-ER3).
   - **3c — clone `InvocationInfo` before it moves.** `Invocation =
     SerializedEvent<InvocationInfo>` derives only `Debug`, not `Clone`
     (`events/mod.rs:17-18`), so it moves into `.invoke()` exactly once;
     `InvocationInfo` derives `Clone` (`util.rs:232-238`). `let
     invocation_info: InvocationInfo = invocation.0.clone();` (one `.0` hop,
     not the two-hop `i.0.0.clone()` at `routes/mod.rs:192-193`), then move
     `invocation` into step 4's `invoke()`.
4. **Authorize against the chain.** `self.tinycloud.invoke::<BlockStage>(invocation,
   HashMap::new())` — the same call `sql_op` makes (`compute_exec.rs:747-753`)
   and the same call the encryption module's own HTTP route makes via
   `verify_auth` (`routes/encryption.rs:159-165, 236-260`) — `Resource::Other`
   already flows through the identical `validate()`/`extends()` machinery.
   Failure → FATAL (§8).
5. **Call `EncryptionService::decrypt_authorized` in-process.** No HTTP hop —
   the mediator holds an owned `EncryptionService` clone (§4.3):
   `self.encryption_service.decrypt_authorized(&network_id, &invocation_info,
   &body_value)`. Any `EncryptionServiceError` → FATAL (§8) → uniform 500
   (deliberately not `map_service_err`'s finer classification — §8).
6. **Unwrap the rewrapped key in-process (D-ER4), then validate its
   length.** `decrypt_authorized` returns
   `VerifiedDecrypt.response.wrapped_key: String` — base64 (via
   `encode_base64`, `service.rs:584,744`) of `[32-byte ephemeral X25519
   pubkey][AES-256-GCM ciphertext]` (`backend.rs:64-77`'s
   `wrap_to_public_key` format). REQUIRED decode step before unwrap:
   `let wrapped_key_bytes = decode_base64(&verified.response.wrapped_key)`
   (§4.4) — `unwrap_with_secret` takes `&[u8]` (`backend.rs:87`), never a
   base64 string. Decode failure → FATAL (`self.fatal = Some("wrappedKey is
   not valid base64")`), same envelope as §8's internal-error row, before
   calling `unwrap_with_secret`. On decode success, call
   `tinycloud_core::encryption_network::backend::unwrap_with_secret(&secret,
   &wrapped_key_bytes)` (§4.4) — the SAME implementation `backend.rs`'s own
   tests exercise. **NEW check (closes a real gap, §6):** if the resulting
   plaintext is not exactly 32 bytes, FATAL (`self.fatal = Some("unwrapped
   symmetric key has unexpected length: expected 32, got N")`) — a
   `symmetricKey` field is never emitted otherwise. Realistic, not
   theoretical: `InlineEnvelope.encryptedSymmetricKey` is client-authored,
   so `wrap_to_public_key`'s `plaintext` can be any length; `decrypt_authorized`
   is payload-key-shape-agnostic, so the mediator is the correct, narrowest
   enforcement point. The routine's `StaticSecret` is not dropped here — it
   survives for subsequent calls (D-ER2).
7. **Generate the re-encrypt nonce (§6).** 12 bytes from
   `rand::rngs::OsRng`/`RngCore::fill_bytes` (§4.4 — no `aes-gcm` dependency
   needed), encoded via core's `encode_base64` into the response as
   `reencryptNonce` alongside `symmetricKey`.
8. **Journal + return.** `bytes_in`/`bytes_out` = request/response JSON byte
   lengths (same convention as the other four imports); `destination =
   "inline"`; `granted = true`.

---

## 6. Payload Crypto Contract

Supporting detail (why the byte layout only shares conventions with
`ColumnEncryption`, why AAD binding is scoped rather than end-to-end) is in
`specs/compute-encrypted-routine-rationale.md`.

**Ciphertext byte layout.** `InlineEnvelope.ciphertext` (`types.rs:150`) uses
the identical wire framing `ColumnEncryption::encrypt` already uses
(`encryption.rs:43-54`): `0x01 || nonce(12 bytes) || AES-256-GCM(ciphertext ‖
16-byte tag)`. The guest uses `aes_gcm::aead::Aead::{encrypt,decrypt}`
`Payload { msg, aad }` directly (same AAD pattern as `XChaCha20Poly1305` in
`key_provider.rs:549-587`, with `Aes256Gcm`), supplying `InlineEnvelope.aad`
(`types.rs:152`) as associated data: `ciphertext[0]` is the version byte
(MUST be `0x01`), `ciphertext[1..13]` is the nonce, `ciphertext[13..]` is
`msg` (AEAD ciphertext + tag).

**AAD binding.** The mediator decodes and validates the guest's declared
`aad` (§5.2 step 3a — FATAL on invalid/non-canonical base64) and binds its
own recomputed hash of it into the routine's signed `facts.body_hash` — a
scoped self-consistency-plus-provenance guarantee (§9 invariant 9), not
independent verification of the guest's separate in-WASM AEAD call.

**Fresh-nonce source for re-encryption.** No entropy source inside the
Wasmtime sandbox, and no general-purpose `random_bytes` import (§1). The
`encryption_decrypt` success response (§5.2 step 7) returns
`reencryptNonce` — 12 fresh, host-generated random bytes — for one new
ciphertext. The guest MUST NOT reuse `reencryptNonce` across more than one
AES-GCM call (nonce reuse under a fixed key is catastrophic for GCM); a
routine needing to re-encrypt more than once calls `encryption_decrypt`
again for a fresh nonce.

**Re-encrypted envelope shape.** The guest writes back (`storage_put`) a new
`InlineEnvelope` with `v`/`networkId`/`alg`/`keyVersion`/`encryptedSymmetricKey`/
`encryptedSymmetricKeyHash` unchanged (D-ER5 — no new symmetric key minted)
and `ciphertext = 0x01 || reencryptNonce || AES-256-GCM(new_plaintext, aad)`;
`aad` MAY be reused unchanged or updated by the guest (the node never reads
it).

---

## 7. Manifest / Journal Entry

No new field on `ManifestEntry` (`compute.rs:139-149`) —
`{resource, ability, bytes_in, bytes_out, destination, granted}` already
generalizes. One new row shape: `resource =
urn:tinycloud:encryption:<ownerDid>:<name>`, `ability =
tinycloud.encryption/decrypt`, `destination = "inline"`, `granted = true`
(success) or `false` (the A.4 denial AND the one triggering fatal failure —
`dispatch`, `compute_exec.rs:442-451`, unconditionally journals after any
op's return, including the branch that sets `self.fatal`; only calls made
AFTER `self.fatal` is already set are never journaled, §4.2's latch). The
granted-vs-exercised scope-down signal (§9.1.1) extends naturally:
`tinycloud.encryption/decrypt` in `D_fn` but never called shows up in
`granted_but_unexercised`, same as KV/SQL.

---

## 8. Error / Denial Contract Summary

Two things visible here: **(a) the host-call return** — the JSON `dispatch`
hands back into guest memory for THIS `encryption_decrypt` call, always
present — and **(b) the external HTTP response** — what `compute/execute`'s
HTTP caller sees once `run()` returns, driven by `run_blocking`'s
post-`run()` `self.fatal` check (`compute_exec.rs:1177-1179`). A FATAL
condition's host-call return is always guest-visible (no call ever traps
mid-execution); never visible externally is the SPECIFIC error reason — the
outside caller only ever sees a uniform 500.

| condition | host-call return (this call) | external HTTP response | source |
|---|---|---|---|
| no `D_fn` grant for this network | `{"ok":false,"error":{"code":"ability-denied",...}}`, op not performed, no trap | n/a — 200 w/ this envelope in `run`'s result | A.4, §5.2 step 1 |
| `aad` not valid canonical STANDARD base64 | `{"ok":false,"error":{"code":"internal"}}` (FATAL, `granted: false`) | 500 | §5.2 step 3a (earliest fatal trigger) |
| guest `aadHash` mismatches mediator's `computed_aad_hash` | `{"ok":false,"error":{"code":"internal"}}` (FATAL) | 500 | §5.2 step 3a |
| chain `validate()` rejects the internal invocation | `{"ok":false,"error":{"code":"internal"}}` (FATAL) | 500 | §5.2 step 4 |
| any `EncryptionServiceError` (not-found/revoked/not-active, alg/key-version mismatch, hash mismatch, nonce replay, expiry, audience/target-node mismatch, wrong type, unauthorized, bad signature, infra) | `{"ok":false,"error":{"code":"internal"}}` (FATAL) | **500, uniformly** — deliberately not `map_service_err`'s finer 401/404/409/400 classes; `HostState.fatal: Option<String>` is untyped exactly like the existing `kv_op`/`sql_op` fatal path. Uniform 500 leaks no more than the direct HTTP path's classes already do. | §5.2 step 5 |
| `wrappedKey` is not valid base64 | `{"ok":false,"error":{"code":"internal"}}` (FATAL) — no `symmetricKey` field ever emitted | 500 | §5.2 step 6 |
| unwrapped key is not exactly 32 bytes | `{"ok":false,"error":{"code":"internal"}}` (FATAL) — no `symmetricKey` field ever emitted | 500 | §5.2 step 6 |
| malformed guest request JSON | `{"ok":false,"error":{"code":"bad-request",...}}` — not fatal, op not performed | n/a | existing `dispatch` malformed-request handling |
| any host call (any import) after `self.fatal` is set | `{"ok":false,"error":{"code":"aborted"}}`, op not performed, NOT journaled | n/a for this call — original FATAL row drives the 500 | §4.2 |

---

## 9. Threat-Model Invariants

Supporting detail for invariant 5 is in
`specs/compute-encrypted-routine-rationale.md`.

1. **No authority inheritance from the external invoker.** Holding
   `tinycloud.compute/execute` grants nothing toward
   `tinycloud.encryption/decrypt` — the internal invocation is signed by the
   ROUTINE key, never the invoker's.
2. **No payload plaintext, and no raw symmetric key, ever crosses the
   `EncryptionService` boundary** (`service.rs:731-735`, unchanged).
3. **The routine's X25519 private scalar never leaves core/TEE mediation.**
   Derived once per execution inside `HostState`, reused across calls (D-ER2),
   dropped with `HostState`. Never returned to the guest, logged, or
   persisted.
4. **The raw AES-256 symmetric key DOES cross into guest memory** (D-ER5) —
   an accepted, scoped exposure: holding the payload key is exactly what
   "decrypt this payload" means. What must not cross is the X25519 scalar
   (invariant 3).
5. **Nonce-replay, duplicate-invocation, and TTL are three different
   controls.** Nonce-replay's only gate is
   `EncryptionService::consume_nonce` (`service.rs:834-856`, DB-backed, keyed
   on `(invoker, nonce)`). TTL is checked twice against two DIFFERENT
   objects: the generic chain-walk enforces the delegation's own expiry;
   `validate_invocation_time` separately enforces the invocation's own short
   D-ER3 expiry.
6. **Space isolation is preserved.** §4.1 narrows, not removes, the
   space-scope defense-in-depth; the primary boundary (space-hashed
   `routine_did`) is untouched.
7. **Network membership is the deployer's, delegated, not manufactured.** A
   `D_fn` row for this ability can only be minted by a deployer whose own
   chain already holds that authority.
8. **A grant-present failure fail-stops the run; no guest code runs past it
   un-mediated.** §4.2's latch rejects every host call after the first fatal
   failure, regardless of import, before any grant lookup, mint, or core
   call. Mutations from calls that succeeded BEFORE the fatal point are NOT
   rolled back — compute's pre-existing per-call commit model, unchanged.
9. **The `aad` value declared to the host is bound by the mediator's own
   computation** — scoped self-consistency plus provenance, not independent
   verification of the guest's later AEAD call. `computed_aad_hash` (never
   the guest-declared `aadHash`) is the sole value signed into
   `facts.body_hash`. `EncryptionService` itself never sees raw `aad` — it
   only re-verifies `facts.body_hash` equality (`service.rs:695-700`),
   unchanged (D-ER4 boundary unchanged).
10. **`reencryptNonce` reuse is a guest-code correctness bug, not a boundary
    this spec's mediator polices** (§6). Breaks the guest's own AES-GCM
    security but crosses no authority boundary this spec is responsible for.

---

## 10. Test Gates (named, exact)

**Unit — `cargo test -p tinycloud-core --features compute <name>`:**
- `routine_x25519_from_seed_is_deterministic` (`compute.rs`) — same seed → same `RoutineX25519Keypair` bytes.
- `routine_x25519_from_seed_differs_by_function_cid` — mirrors `classic_routine_key_deriver_differs_by_function_cid` (`compute.rs:523-532`).
- `routine_x25519_from_seed_matches_vault_conversion` — known-answer seed matches `vault_ed25519_seed_to_x25519`'s scalar/public-key bytes.
- `unwrap_with_secret_is_now_public_and_reused` (`backend.rs`) — reachable as `pub`; `wrap_to_public_key` → `unwrap_with_secret` round trip recovers plaintext (§4.4 regression).
- `encode_decode_base64_round_trip_is_canonical` (`service.rs`) — `decode_base64(encode_base64(bytes))` round trips for 0/1/12/32-byte inputs; a URL-safe or unpadded variant is REJECTED (§4.4 regression).
- `compute_select_d_fns_admits_encryption_row_alongside_in_space_kv_row` (`db.rs`) — one well-formed `Resource::Other` network row + one in-space `Resource::TinyCloud` row IS selected (§4.1).
- `compute_select_d_fns_rejects_other_resource_outside_prefix` — `Resource::Other` row outside `ENCRYPTION_NETWORK_PREFIX` → `D_fn` UNSELECTED.
- `compute_select_d_fns_rejects_malformed_network_id_inside_prefix` — malformed-`NetworkId` rows inside the reserved prefix (missing owner DID/name/separator, forbidden `/`) all UNSELECTED — fails closed like `Resource::extends`'s `Other, Other` arm.
- `compute_select_d_fns_still_rejects_out_of_space_tinycloud_row` — out-of-space `Resource::TinyCloud` row still rejected (untouched-arm regression).

**Integration — `tinycloud-node-server`, new `tests/compute_encryption.rs`
(register `[[test]] name = "compute_encryption" path = "tests/compute_encryption.rs"
required-features = ["compute"]`, mirroring the existing `compute_execute`/
`compute_e2e` entries). Run via `cargo test -p tinycloud-node --features
compute --test compute_encryption <fn_name>`.**

*Tier E1 — key-mediation only, WAT fixture (no in-guest crypto; guest calls
`encryption_decrypt` and returns the raw JSON response as its `run()` result):*
- `encryption_decrypt_returns_32_byte_key_and_reencrypt_nonce` — `symmetricKey` decodes to exactly 32 bytes, `reencryptNonce` to exactly 12; re-encoding reproduces the original string byte-for-byte; manifest `granted: true`.
- `encryption_decrypt_decodes_wrapped_key_before_unwrap` — a real `decrypt_authorized` response (`DecryptResponse.wrapped_key: String`, not a stubbed byte buffer) is `decode_base64`'d then `unwrap_with_secret`'d, recovering the 32-byte key — proves §5.2 step 6's decode runs against the actual encoded type.
- `encryption_decrypt_rejects_non_32_byte_unwrapped_key` — `encryptedSymmetricKey` wraps a deliberately 16-byte plaintext via real `wrap_to_public_key`; fatal 500, `granted: false`, no `symmetricKey` field, chained `storage_put` returns `aborted` and is not journaled.
- `encryption_decrypt_denied_without_grant` — network row omitted from `D_fn`; A.4 `ability-denied`, op not performed, `granted: false`.
- `encryption_decrypt_against_revoked_network_is_fatal_500` — network `Revoked`; HTTP 500, proving the two-tier contract.
- `encryption_decrypt_wrong_network_id_is_denied` — `D_fn` grants network A, guest requests network B; A.4 denial.
- `encryption_decrypt_expired_dfn_still_returns_403_before_any_execution` — encryption row present but delegation expired; same pre-existing 403 + `"routine-grant-expired"` as `expired_grant_reports_grant_expired_not_rotated` (`tests/compute_execute.rs:829-889`); no WAT guest runs.
- `encryption_decrypt_invalid_base64_aad_is_rejected_before_hashing` — illegal alphabet/padding/URL-safe-char cases; `self.fatal = Some("aad is not valid base64")` before `aadHash` inspection or any mint; 500, `granted: false`, no `storage_put`.
- `encryption_decrypt_mismatched_aad_hash_is_rejected_before_mint` — valid base64 `aad`, wrong `aadHash`; rejected at step 3a before mint/invoke; 500, `granted: false`.
- `encryption_decrypt_consistent_aad_hash_binds_into_signed_body_hash` — matching `aad`/`aadHash`; succeeds end-to-end and `facts.body_hash`'s preimage carries the mediator's own recomputed `computed_aad_hash`, never the guest-declared field verbatim.
- `encryption_decrypt_repeated_call_reuses_same_derived_secret` — two calls in one execution against the same network both succeed and unwrap correctly (proxy for reused `StaticSecret`).
- `encryption_decrypt_replayed_nonce_is_rejected_by_consume_nonce` (invariant 5) — replay a consumed `(invoker, nonce)` pair; `EncryptionServiceError::NonceReplay` specifically, `granted: false`.
- `host_call_after_fatal_is_aborted_and_not_journaled` (D-ER7/§4.2) — `encryption_decrypt` against a revoked network, then a `storage_put`; first call journaled `granted: false`, second returns `aborted`, absent from manifest, storage unchanged, HTTP 500 for the original failure.
- `encryption_decrypt_oversized_request_rejected_cleanly` — mirrors `bogus_host_call_length_rejected_cleanly`; the existing `max_message_bytes` ceiling (`compute_exec.rs:1286-1292`) applies to the new import.

*Tier E2 — full crypto round trip, real `wasm32-unknown-unknown` guest (new
fixture crate at `tests/fixtures/compute-guests/encrypted_counter/`, own
`[workspace]` table, pinned `aes-gcm = "0.10"`, `edition = "2021"`, `[lib]
crate-type = ["cdylib"]`; built via `cargo build --manifest-path
tinycloud-node-server/tests/fixtures/compute-guests/encrypted_counter/Cargo.toml
--release --target wasm32-unknown-unknown`, copied to
`tests/fixtures/compute/encrypted_counter.wasm`):*
- `encrypted_counter_round_trip_via_real_wasm_guest` — `InlineEnvelope` wraps a little-endian `u32` counter, `aad = b"counter-v1"`; guest `storage_get`s, calls `encryption_decrypt`, AES-256-GCM-decrypts (§6), increments, re-encrypts with the SAME key + `reencryptNonce` + `aad`, `storage_put`s. Re-reading and independently decrypting recovers `counter + 1`; manifest shows `tinycloud.encryption/decrypt` `granted: true`.
- `encrypted_counter_regression_kv_sql_only_dfn_still_works` — an existing KV+SQL-only `D_fn` still selects/executes post-§4.1 fix, using unmodified `probe_get.wat`/`probe_put.wat`.
- `invoker_cannot_directly_call_encryption_decrypt_route` — an actor holding only `tinycloud.compute/execute` calls `POST /encryption/networks/<id>/decrypt` directly with their own key; `Unauthorized`/401, proving invariant 1.

**Live E2E (gated, `#[ignore]`, real dstack CVM + a live encryption network,
run via `cargo test -p tinycloud-node --features compute,dstack --test
compute_encryption -- --ignored encrypted_counter_live_dstack_round_trip`):**
- `encrypted_counter_live_dstack_round_trip` — the E2 flow against a live node, run TWICE across separate process invocations to confirm the routine's re-derived X25519 keypair is stable (same seed-stability assumption `compute-service.md` §6.2 flags "VERIFY EMPIRICALLY" for Ed25519, reused for X25519).

---

## 11. Deferred / Non-Normative

- SDK convenience for minting the `tinycloud.encryption/decrypt` `D_fn` row
  at deploy time — follow-up, not blocking this node-side contract.
- Wrapping a BRAND NEW symmetric key to the network's public key (vs.
  re-encrypting with the same already-authorized key, in scope per §6/D-ER5)
  is out of scope for this MVP — "network encrypt" authority, which the
  module deliberately does not expose node-side. A routine MAY re-encrypt
  with a key it generates itself and store the wrap out-of-band,
  unconstrained by this spec.
- A dedicated `random_bytes` host import — deferred; the
  single-nonce-per-`encryption_decrypt`-call shape covers the MVP.
- Optional KV-audit persistence of the decrypt manifest entry — same
  MAY/config-gated status as general manifest persistence (§9.1.1).
- Threshold `KeyBackend` — orthogonal, unblocked (the mediator only ever
  calls the existing `decrypt_authorized` trait-object boundary).
- A typed `HostState.fatal` (carrying an HTTP status/error class instead of a
  `String`) that would let this spec preserve `map_service_err`'s finer HTTP
  classification through the mediator (§8) — real, out-of-scope design work;
  uniform 500 is the accepted MVP simplification.
