# Spec: The Compute Routine as Encryption-Network Decrypt Receiver (Option B)

**Date:** 2026-07-22
**Status:** Draft (revised — Sol round 3: round-2 `needs_fixes` findings
addressed — detached AAD binding, non-compiling invocation-ownership flow,
unpinned x25519-dalek/aes-gcm/encrypted-counter dependencies, deep-cloned
signing key, and contradictory expired-grant/fail-stop tests)
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
import, one new `D_fn` ability row type, and three narrow REQUIRED core fixes
(§4): a query carve-out, a `dispatch`-level fail-stop latch, and an
`EncryptionService` ownership change. It does **not** change the wire format of
`/invoke`, the four existing host imports, or the encryption-network module's
public HTTP routes or Rust types (`DecryptRequestBody`/`DecryptFacts` keep
their existing fields — see §6 for how AAD binding is achieved without
touching them).

### Non-goals

- No new HTTP endpoint. The decrypt-for-routine flow is entirely internal
  (mediator → core, in-process), triggered by a guest host-import call during
  an existing `compute/execute`.
- No change to `EncryptionService`'s external behavior (`decrypt`,
  `decrypt_authorized`, the `/encryption/networks/*` routes) — this spec is a
  new *caller* of the existing `decrypt_authorized`, not a new capability
  inside that module. (`EncryptionService` itself gains a `#[derive(Clone)]`,
  §4.3 — a pure ownership change with zero behavioral effect.)
- No threshold-backend design. This rides whatever `KeyBackend` is configured
  today (`LocalOneOfOneBackend`); a future threshold backend is orthogonal.
- No SDK/deploy-tooling changes. The deployer minting an extra `D_fn` ability
  row for `tinycloud.encryption/decrypt` is a one-line addition to the
  existing deploy flow; wiring that convenience into `@tinycloud/node-sdk` is
  deferred, non-blocking follow-up.
- No new host import for randomness. Re-encryption's fresh nonce comes from
  the `encryption_decrypt` import's own response (§6), not a general-purpose
  `random_bytes` import.

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
(§4.1 below) already returns the **whole capability list** of every matching
`D_fn`, and the mediator's `find_grant`-style lookup (`compute_exec.rs:311-319`)
already searches by `(ability, resource.extends)` generically over
`Capability`, which is resource-type-agnostic. This is the least-complex-secure
option: reuse cite-all (F5), reuse the caveat echo (F1), reuse chain validate()
— zero new authorization-engine code, exactly the standing §6.2 claim.

**D-ER2 — the routine derives its OWN X25519 keypair from the SAME Ed25519
seed already used for its signing identity, ONCE per execution, retained (not
re-derived) for the lifetime of the run.** `RoutineKeyDeriver::derive_routine_seed(space,
function_cid) -> [u8; 32]` (`tinycloud-core/src/compute.rs:295-299`) already
produces the seed backing `routine_jwk_from_seed` (Ed25519, for signing
internal invocations) and `routine_did_from_seed`. This spec adds a THIRD
derivation from the same seed — `routine_x25519_from_seed(seed) ->
(x25519_dalek::StaticSecret, x25519_dalek::PublicKey)` — using the SAME
Ed25519-seed→X25519 conversion already implemented client-side in
`tinycloud-sdk-wasm/src/vault.rs:150-171` (`vault_ed25519_seed_to_x25519`:
SHA-512(seed), take the first 32 bytes, feed to `StaticSecret::from`). It MUST
be a separate, non-`wasm_bindgen` function living in `tinycloud-core`, not a
call into the WASM vault — the vault function's entire purpose is to hand the
raw X25519 private scalar back across the WASM→JS boundary to a browser
client, which is exactly the exposure this spec forbids for a routine's key.

*Correction (clamping):* `x25519_dalek::StaticSecret::from([u8; 32])` (crate
version `2.0`, `static_secrets` feature, `tinycloud-core/Cargo.toml:44`) stores
the supplied bytes as given; RFC 7748 clamping is applied internally by the
crate when the secret is *used* — computing the public key
(`PublicKey::from(&secret)`) or a Diffie-Hellman (`secret.diffie_hellman(&peer)`)
— not at construction. An earlier draft of this spec incorrectly said
`StaticSecret::from` performs the clamping; corrected here. This does not
change any derivation OUTPUT (the same seed still yields the same effective
scalar every time it's used), only the prose.

*Lifecycle (corrected):* the earlier draft was self-contradictory — it said
the scalar "never appears in a struct field" while also storing it in
`ExecutionPlan`/`HostState` for the run, and said it was dropped after ONE
`diffie_hellman` call even though the host-import ABI (§5.1) permits the guest
to call `encryption_decrypt` MULTIPLE times per execution. DECIDED: derive the
`StaticSecret`/`PublicKey` pair ONCE, store it in a genuine `HostState`
field (`routine_x25519: (x25519_dalek::StaticSecret, x25519_dalek::PublicKey)`
— owning it across `block_on` calls requires this; "never in a struct field"
was aspirational, not achievable), reuse it for EVERY `encryption_decrypt`
host call in the same execution (no re-derivation per call), and let it drop
with `HostState` at the end of `run_blocking`, the same point `routine_jwk`
already goes out of scope. It is never: returned to the guest, included in a
response body, logged, cloned into a second field, or persisted.
`x25519_dalek::StaticSecret` (crate `2.0`, no `zeroize` feature enabled) does
not zero its memory on drop; this spec does not add that — the same posture
already accepted for `routine_jwk`'s Ed25519 material and the credentials
`HostState` already carries.

**D-ER3 — the internal invocation authorizing the routine's decrypt is
audience = node_did (not `space.did()`), sourced from the routine's own
`EncryptionService::node_did()` accessor (`service.rs:144`, available once
§4.3 threads an owned `EncryptionService` into `HostState` — no separate
`HostState.node_did` field needed), with a SHORT expiry (not the far-future
KV/SQL constant).** Two deliberate deviations from the existing
`HostState::mint_internal` (`compute_exec.rs:360-404`):
- **Audience:** `EncryptionService::decrypt_authorized` hard-rejects on
  `invocation.payload().audience != self.node_did` (`service.rs:617-621`,
  `AudienceMismatch`) — the encryption module's own invariant, unrelated to
  and pre-dating compute. The generic chain `validate()`
  (`tinycloud-core/src/models/invocation.rs`) does not itself constrain or
  even read `audience` (no `audience` reference anywhere in `invocation.rs`),
  so this per-call override only affects a check the encryption module
  performs on top, never the generic engine.
- **Expiry:** `decrypt_authorized` calls `validate_invocation_time`
  (`service.rs:664`, backed by `DEFAULT_INVOCATION_TTL_SECONDS = 300`,
  `service.rs:42`), which rejects when `exp - now > ttl` — a far-future expiry
  is an automatic reject. `now + 240` leaves slack under the 300s ceiling for
  dispatch/queue jitter while remaining genuinely short-lived. `nonce`: reuse
  `self.next_nonce()` unchanged — the mediator's per-call random 128-bit nonce
  already satisfies "fresh across executions," and `EncryptionService::consume_nonce`
  (`service.rs:834-856`) independently enforces non-replay against its own
  `encryption_nonce` table keyed by `(invoker, nonce)`.
- `nota_bene` on the single `tinycloud.encryption/decrypt` capability: echoed
  verbatim from the selected grant exactly as `kv_op`/`sql_op` do
  (`echo_nota_bene`, `compute_exec.rs:327-343`) — F1 applies identically.

**D-ER4 — the EncryptionService boundary never returns the raw symmetric
key.** `decrypt_authorized` (`service.rs:604-760`) already only ever returns a
`wrapped_key` (rewrapped to the caller-supplied `receiver_public_key`,
`service.rs:734`) — the raw `symmetric` value is a local, dropped before the
function returns (`service.rs:735`). This spec's mediator supplies the
routine's own derived X25519 public key as `receiver_public_key`, so the
`EncryptionService` boundary is **unchanged** and still never emits plaintext
key material; the routine-side unwrap (ECDH with the routine's private scalar)
happens entirely after `decrypt_authorized` returns, inside the mediator.

**D-ER5 — the guest, not the host, performs the payload AES-256-GCM decrypt
AND re-encrypt (§6 pins the exact byte layout, AAD binding, and nonce
sourcing).** The host import returns the raw 32-byte symmetric key to guest
memory (after the mediator's ECIES unwrap and its own exact-length check,
§4.2/§5.2 step 6); the guest WASM module runs AES-256-GCM itself. The host
mediator never touches the payload bytes — it only ever handles the (much
smaller) wrapped/unwrapped *key* and the (non-secret, already
storage-readable) AAD bytes plus their hash (§6, §5.2 step 3a — needed to
bind the guest's real AAD into the routine's signed intent, corrected in this
revision to actually be verifiable). This keeps the
host-import surface symmetric with the existing four (thin, JSON/bytes-in-out)
and keeps "what the host can read" minimal. Re-encryption of the SAME payload
using the SAME already-unwrapped symmetric key is IN SCOPE (§6, needed for the
encrypted-counter gate, §10); generating a BRAND NEW symmetric key and
wrapping it to the network's public key remains OUT OF SCOPE (§11) — a
distinct "network encrypt" authority this module does not expose node-side.

**D-ER6 (REQUIRED CORE FIX, narrow) — `compute_select_d_fns`'s space-scope
check must carve out encryption-network resources.** See §4.1.

**D-ER7 (REQUIRED CORE FIX, narrow) — `dispatch` must latch on `self.fatal`
and short-circuit every subsequent host call.** See §4.2. This closes a real
gap that predates this spec (it already exists for `kv_op`/`sql_op`); this
spec's `encryption_decrypt` import would otherwise inherit it, and the E0
threat model explicitly requires a fail-stop guarantee.

**D-ER8 (REQUIRED CORE FIX, narrow) — `EncryptionService` must be `Clone` so
an owned instance can be threaded into `ExecutionPlan`/`HostState`, WITHOUT
duplicating the node's Ed25519 signing key material on every compute
execution.** `node_keypair` moves from `Option<Keypair>` to
`Option<Arc<Keypair>>` so `#[derive(Clone)]` only bumps a refcount for that
field instead of deep-copying the private scalar. See §4.3.

**D-ER9 (REQUIRED CORE FIX, narrow) — `tinycloud-node-server` needs direct,
`compute`-gated dependencies on `x25519-dalek` and `aes-gcm`.** Neither crate
is re-exported from `tinycloud-core`'s public API, so naming
`x25519_dalek::StaticSecret` as a `HostState` field type or reimplementing
the unwrap arithmetic inline in the mediator does not compile without both
crates listed directly in `tinycloud-node-server/Cargo.toml`. See §4.4.

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

## 4. REQUIRED Core Fixes

### 4.1 `compute_select_d_fns` space-scope carve-out

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
row IS (`Resource::Other(UriString)`, `resource.rs:17-20`). Left unfixed,
**adding the D-ER1 ability row to `D_fn` would silently disable
`compute_select_d_fns` for the WHOLE delegation** — `all_in_space` folds over
every row, so one network-URN row makes the entire `D_fn` unselectable,
taking the routine's KV/SQL grants down with it. This predates this spec, not
a hypothetical.

**Why this is safe to narrow, not just delete.** The routine's PRIMARY
cross-space boundary is `routine_did` itself — the space is hashed into the
key-derivation path, so `delegatee.eq(routine_did)` in the same query already
scopes every candidate delegation to one `(space, function_cid)` pair before
`all_in_space` ever runs. A network resource has no space component **by
design** (networks are owned by a DID, not scoped to a space —
`NetworkId::new(owner_did, name)`,
`tinycloud-core/src/encryption_network/network_id.rs:38-56`), so demanding
`row.resource.space() == Some(space)` for it is a category error, not a real
security boundary.

**DECIDED fix.** Narrow the predicate to treat `Resource::TinyCloud` rows
exactly as today, and admit `Resource::Other` rows **only** when their URI
matches the encryption-network URN prefix:

```rust
let all_in_space = ability_rows.iter().all(|row| match &row.resource {
    Resource::TinyCloud(_) => row.resource.space().map(|s| s == space).unwrap_or(false),
    Resource::Other(uri) => uri.as_str().starts_with(ENCRYPTION_NETWORK_PREFIX),
});
```

*Correction (constant name/visibility):* the constant already exists as
`ENCRYPTION_NETWORK_PREFIX` (**not** `ENCRYPTION_NETWORK_URN_PREFIX`, an
earlier draft's typo/invention) at `tinycloud-core/src/types/resource.rs:13`,
and is **module-private** (no `pub` qualifier at all — not `pub(crate)`),
already used by `Resource::extends`'s `Other, Other` arm (`resource.rs:33-48`,
the two `starts_with(ENCRYPTION_NETWORK_PREFIX)` checks around lines 41-42).
Mark it `pub(crate)` (a strictly widening, non-breaking visibility change) so
`db.rs` can reuse it, rather than duplicating the string literal or inventing
a second constant.

The real authorization boundary for the encryption row is unchanged and
enforced elsewhere, twice: (a) the deployer could not have minted this row
unless their own chain already holds `tinycloud.encryption/decrypt` on that
exact network, and (b) at execute time the mediator's internal invocation for
this row must still pass the generic `validate()` chain walk (§5.2 step 4)
AND `EncryptionService::decrypt_authorized`'s own checks. This fix only
restores *selectability* of the `D_fn`; it grants nothing.

`compute_classify_routine_grant` (`db.rs:440-...`) needs **no equivalent
change** — its `has_binding` check only needs ONE ability row (any row) to
carry the `computeFunctionBinding` caveat within the space, and the KV/SQL
rows on the same `D_fn` already satisfy that.

### 4.2 `dispatch` fail-stop latch (fixes the false FATAL claim)

**The gap.** The current mediator's fatal path is NOT fail-stop, contrary to
an earlier draft's claim. `dispatch` (`compute_exec.rs:420-452`) always calls
`self.manifest.record(...)` and returns `response` bytes to the guest,
regardless of whether the op set `self.fatal`. `host_import`
(`compute_exec.rs:1273-1338`) writes those bytes into guest memory and
returns `(out_ptr, len)` normally — it never traps on `self.fatal`. The ONLY
place `self.fatal` is checked is `run_blocking`, AFTER `run()` has fully
returned (`compute_exec.rs:1177-1179`). Between a `kv_op`/`sql_op` call
setting `self.fatal` (e.g. `compute_exec.rs:608`) and `run()` returning, an
adversarial or buggy guest can freely ignore the `{"ok":false,...}` envelope
and keep making further host calls — `storage_put`, `sql_query`, and (after
this spec) `encryption_decrypt` all still execute normally, since `dispatch`
performs no fatal check before running its op. Already-performed mutations
from calls before the fatal point are not, and will not be, rolled back
(there is no cross-call transaction; each call commits independently via
`invoke_with_options`).

**DECIDED fix.** Latch at the top of `dispatch`, before any request parsing:

```rust
fn dispatch(&mut self, import: Import, req: &[u8]) -> Vec<u8> {
    // REQUIRED CORE FIX (D-ER7): once self.fatal is set by ANY earlier call
    // in this execution, every subsequent host call — of any import, not
    // just the one that failed — is a guaranteed no-op: not performed, not
    // journaled (dispatch returns before reaching self.manifest.record). A
    // guest that ignores the failing call's envelope and keeps calling
    // storage_put/sql_query/encryption_decrypt cannot cause any further
    // core mutation after the fatal point.
    if self.fatal.is_some() {
        return serde_json::to_vec(&json!({
            "ok": false, "error": { "code": "aborted" }
        }))
        .expect("aborted envelope serializes");
    }
    let bytes_in = req.len() as u64;
    // ... unchanged from here
}
```

The ORIGINAL triggering call is unaffected by this fix — it still runs to
completion, still gets journaled (`granted: false`, see §7), and still
returns its own `{"ok":false,"error":{"code":"internal"}}` envelope exactly
as today; `run_blocking`'s post-`run()` check (`compute_exec.rs:1177-1179`)
still raises `ComputeExecError::Internal`, surfacing as 500 (§8) once the
guest's `run()` call returns. What's new is that every call AFTER that point
is rejected before any grant lookup or core call — this is a Wasmtime-host-fn
latch (no trap, no unwind through FFI — consistent with `compute-service.md`'s
NORMATIVE "host functions never trap on a mediated denial or internal error"
constraint), not a Wasmtime `Trap`. Rollback of prior mutations is explicitly
OUT OF SCOPE (§9 invariant 8) — this is pre-existing, documented behavior for
`kv_op`/`sql_op` today, unchanged by this spec.

### 4.3 `EncryptionService: Clone` (ownership fix, key-hygiene corrected)

**The gap.** `ExecutionPlan`/`HostState` must own `'static` data — it's moved
into `tokio::task::spawn_blocking` (`compute_exec.rs:1052`). `SqlService` is
threaded in today exactly this way because it already `#[derive(Clone)]`s
(`tinycloud-core/src/sql/service.rs:22-23`) and Rocket manages a bare (not
`Arc`-wrapped) instance; the route handler calls `.inner().clone()`
(`compute_exec.rs:1030`/`1091` pattern). `EncryptionService`
(`tinycloud-core/src/encryption_network/service.rs:97-103`) does not
implement `Clone` today and is managed as a bare `State<EncryptionService>`
(`routes/encryption.rs:50` etc., `.manage(encryption_service)` at
`lib.rs:408`) — it cannot be threaded into `ExecutionPlan` as-is.

*Correction (key hygiene — round-2 gap).* An earlier draft proposed a bare
`#[derive(Clone)]` on `EncryptionService` as-is, reasoning every field was
"already `Clone`." That premise is true — `node_keypair: Option<Keypair>`
(`libp2p::identity::Keypair`, re-exported at `tinycloud-core/src/keys.rs:10-13`)
IS `Clone` — but its `Clone` impl is a DEEP copy, not a refcount bump:
`libp2p-identity` 0.2.13 (the version this workspace pins, `Cargo.lock`,
`ed25519` feature only) defines `Keypair` as `#[derive(Debug, Clone)] struct
Keypair { keypair: KeyPairInner }` wrapping `enum KeyPairInner {
Ed25519(ed25519::Keypair), .. }`, and `ed25519::Keypair` itself is
`#[derive(Clone)] struct Keypair(ed25519_dalek::SigningKey)` — cloning it
copies the raw private scalar byte-for-byte into a fresh allocation. A bare
`#[derive(Clone)]` on `EncryptionService` would therefore duplicate the
node's private signing key on EVERY compute execution that reaches this code
path (once per `spawn_blocking` call, §9.1) — a real key-hygiene regression,
not the "pure ownership change" an earlier draft claimed. Corrected here.

**DECIDED fix.** Wrap `node_keypair` in `Arc` BEFORE deriving `Clone`, so the
derive only ever bumps a refcount for that field:

```rust
pub struct EncryptionService {
    db: DatabaseConnection,
    node_did: String,
    node_keypair: Option<Arc<Keypair>>,   // was Option<Keypair>
    backend: Arc<dyn KeyBackend>,
    invocation_ttl_seconds: i64,
}
```

Two call sites change, both narrow: `new_with_node_keypair`
(`service.rs:129-140`) wraps its owned `Keypair` parameter once, at
construction — `node_keypair: Some(Arc::new(node_keypair))`; the single
existing read site (`service.rs:772`, `if let Some(keypair) = &self.node_keypair`)
needs NO change — `&Arc<Keypair>` derefs to `&Keypair` for whatever call
follows via `Deref` coercion. Every field is now cheap to clone: `db`
(sea-orm's connection type is internally `Arc`-backed), `node_did: String`
(small, bounded), `node_keypair: Option<Arc<Keypair>>` (refcount bump),
`backend: Arc<dyn KeyBackend>` (refcount bump), `invocation_ttl_seconds: i64`
(`Copy`). No Rocket `.manage()` call changes — `EncryptionService` becomes
cloneable exactly the way `SqlService` already is, the SAME pattern
`compute-service.md` §9.1 describes ("the internal-invocation executor needs
BOTH `SpaceDatabase::invoke` ... AND `SqlService`" — this spec adds a third,
`EncryptionService`, threaded identically). The route handler that builds
`ExecutionPlan` (`routes/mod.rs`, near the `compute_select_d_fns` call site)
takes a new `&State<EncryptionService>` parameter and passes
`encryption_service.inner().clone()` into the plan, alongside `sql_service`.

### 4.4 Node-server crypto dependencies (REQUIRED CORE FIX, closes an incomplete dependency claim)

**The gap.** §5.1/§5.2 store an `x25519_dalek::StaticSecret`/`PublicKey` pair
directly in a `HostState` field and reimplement `backend.rs`'s private
`unwrap_with_secret` (`tinycloud-core/src/encryption_network/backend.rs:87`)
inline in the mediator. Neither `x25519-dalek` nor `aes-gcm` is re-exported
from `tinycloud-core`'s public API — `backend.rs:10`'s `use
x25519_dalek::{PublicKey, StaticSecret}` and `encryption.rs:9`'s `use
aes_gcm::{..}` are both PRIVATE `use`s, and `tinycloud-core/src/lib.rs` has no
`pub use` for either crate — and `tinycloud-node-server/Cargo.toml` (crate
`tinycloud-node`) has NEITHER crate as a direct dependency today (its own
crypto deps are `chacha20poly1305`, `scrypt`, `subtle`, `sha2`, `rsa`, `rand`
— a different AEAD, no X25519). Naming `x25519_dalek::StaticSecret` as a
field type, or calling `Aes256Gcm::new_from_slice`/`Aead::decrypt` inline in
`compute_exec.rs`, does not compile without the crate itself listed as a
dependency of `tinycloud-node-server` — a Cargo dependency-graph requirement,
independent of any core visibility change. (`ColumnEncryption`, by contrast,
IS already public — `tinycloud-core/src/lib.rs:32` — and already used from
node-server today, `webhook_dispatcher.rs:8`/`routes/hooks.rs:29`; no fix is
needed there. The gap is specific to the two raw crypto crates.)

**DECIDED fix.** Add both as direct, `compute`-gated dependencies of
`tinycloud-node-server/Cargo.toml`, pinned to the SAME versions
`tinycloud-core/Cargo.toml:42,44` already uses:

```toml
[dependencies]
x25519-dalek = { version = "2.0", features = ["static_secrets"], optional = true }
aes-gcm = { version = "0.10", optional = true }
```

and extend the existing `compute` feature (`Cargo.toml:118`) from `compute =
["tinycloud-core/compute", "dep:wasmtime"]` to `compute =
["tinycloud-core/compute", "dep:wasmtime", "dep:x25519-dalek", "dep:aes-gcm"]`
— both crates only ever compile into a `--features compute` build, matching
how `wasmtime` itself is already gated. There is no root
`[workspace.dependencies]` entry for either crate (confirmed: `Cargo.toml:24-45`
lists neither) — each crate pins its own version independently, matching the
existing convention (`tinycloud-core` and `tinycloud-sdk-wasm` already do
this for the same two crates today).

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
  "encryptedSymmetricKeyHash": "<hex, ditto>",
  "aad": "<base64, the RAW InlineEnvelope.aad bytes the guest already holds from storage_get — NOT secret, see §6>",
  "aadHash": "<hex, the guest's own canonical_hash(base64(aad)) declaration — RECOMPUTED from `aad` and verified by the mediator before use, never trusted as-supplied; see §5.2 step 3a/§6>"
}
```

This is the **minimum guest-supplied subset** of `DecryptRequestBody`
(`protocol.rs:26-46`) plus two AAD-related fields (`aad`, `aadHash`) —
everything a guest reading an `InlineEnvelope` (`types.rs:138-155`) already
has in hand after a normal `storage_get` (the raw `aad` bytes), plus a hash
it computes locally over those same bytes as a self-consistency declaration
the mediator independently verifies (§5.2 step 3a, §6). The guest does NOT supply `targetNode` or a `receiverPublicKey` — the
host fills both in (target_node = this node's own DID, via
`EncryptionService::node_did()`; receiver_public_key = the routine's derived
X25519 public key, D-ER2) — neither is guest-controllable data, they are
mediator-owned identity facts.

**Response (host → guest), success:**

```json
{ "ok": true, "symmetricKey": "<base64, EXACTLY 32 raw bytes>", "reencryptNonce": "<base64, 12 fresh random bytes, single-use — §6>" }
```

The mediator rejects (FATAL, §8) any unwrapped key that is not exactly 32
bytes BEFORE this envelope is ever constructed (§5.2 step 6) — a
`symmetricKey` field never reaches guest memory unless it is exactly 32 raw
bytes. The guest is responsible for AES-256-GCM-decrypting `ciphertext` with
this key and the `aad`/nonce it already has from the envelope (§6); the host
import does not touch payload bytes.

**Response (host → guest), A.4-style denial (no matching grant — NOT
performed, guest does NOT trap, same contract as the four existing imports,
`compute-service.md` Appendix A.4):**

```json
{ "ok": false, "error": { "code": "ability-denied", "ability": "tinycloud.encryption/decrypt", "resource": "urn:tinycloud:encryption:<ownerDid>:<name>" } }
```

**Grant-present-but-failed is FATAL** — identical philosophy to
`kv_op`/`sql_op`'s `Err(e) => { self.fatal = Some(...) }` arm
(`compute_exec.rs:604-614`): a `D_fn` grant existed and named this network,
but the request failed for a reason that is not a policy denial (network not
found/revoked/inactive, alg/key-version mismatch, a hash mismatch, nonce
replay, the chain-authorize step failing, or the mediator's own post-unwrap
32-byte check failing, §5.2 step 6). These map uniformly to
`ComputeExecError::Internal(...)` → HTTP 500 (§8) once `run()` returns. The
FIRST such failure IS journaled (granted: false, §7) and DOES return its own
`{"ok":false,"error":{"code":"internal"}}` envelope to the guest — the guest
is not trapped mid-call. What changed in this revision (§4.2/D-ER7): EVERY
host call the guest makes AFTER that point, of any import, is rejected
immediately with `{"ok":false,"error":{"code":"aborted"}}`, performs no work,
and is not journaled — closing the gap where a guest could ignore the first
failure and keep mutating state.

### 5.2 Mediator implementation

New `Import::EncryptionDecrypt` variant alongside the existing four
(`compute_exec.rs:198-203`), dispatched from `HostState::dispatch`
(`compute_exec.rs:420-452`, now with the §4.2 latch at its top) exactly like
`kv_op`/`sql_op` are today, via a new `HostState::encryption_decrypt_op(&mut
self, request: &Value) -> (String, String, String, bool, Vec<u8>)` following
the established `(resource_str, ability, destination, granted,
response_bytes)` return shape so it journals into the manifest (§7) through
the same `self.manifest.record` call site, no new plumbing.

**Step-by-step (all synchronous via `block_on`, same threading model as
`kv_op`/`sql_op`, §9.1's "Host functions are SYNC" note):**

1. **Grant lookup.** Build `target = Resource::Other(network_urn)` from the
   guest-supplied `networkId`. Reuse (or trivially generalize) `find_grant`'s
   `(ability_matches, extends)` pattern (`compute_exec.rs:311-319`) against
   `self.grants` for `"tinycloud.encryption/decrypt"`. No match → the A.4
   denial envelope above, `granted: false`, op not performed, guest does not
   trap.
2. **Derive the routine's X25519 keypair once (D-ER2).** At `ExecutionPlan`
   build time (`routes/mod.rs`, alongside the existing
   `routine_jwk_from_seed(seed)` call at `routes/mod.rs:2563-2564`), add a
   sibling `routine_x25519_from_seed(seed)` call and carry the resulting
   `(StaticSecret, PublicKey)` pair through `ExecutionPlan` into
   `HostState.routine_x25519` the same way `routine_jwk` already travels. The
   mediator reuses this SAME pair for every `encryption_decrypt` call in the
   execution (no re-derivation per call); it is dropped when `HostState` is
   dropped at the end of `run_blocking`.
3. **Recompute+verify `aadHash`, mint the node-audience internal invocation
   (D-ER3), and clone `InvocationInfo` before the invocation moves (fixes two
   round-2 gaps: a detached AAD hash and a non-compiling ownership flow).**
   - **3a — AAD binding (closes the gap).** The mediator now receives the RAW
     `aad` bytes (§5.1), not just a guest-declared hash. Compute
     `computed_aad_hash = canonical_hash(&Value::String(request.aad.clone()))`
     — the SAME `canonical_hash`-of-base64-string convention
     `encryptedSymmetricKeyHash`/`receiverPublicKeyHash` already use
     (`service.rs:671-672, 683-684`). If `computed_aad_hash !=
     request.aad_hash`, FATAL immediately (`self.fatal = Some("aadHash does
     not match recomputed hash of aad")`) and return the standard FATAL
     envelope here — no invocation is minted or signed for this failure; it
     journals `granted: false` the same way every other pre-mint fatal does
     (§7). This closes a round-2 gap: an earlier draft let the guest declare
     `aadHash` with no raw bytes for the mediator to check it against, so a
     guest could sign one hash while using a DIFFERENT `aad` locally for its
     own AES-GCM call, and the mismatch was undetectable. After this fix, the
     value that ends up in the routine's SIGNED `facts.body_hash` is always
     one the mediator derived itself from bytes it directly received in this
     same call. (§6 explains why seeing `aad` server-side is not a new
     exposure — it is not secret payload data.)
   - **3b — build `body_value` and mint.** Construct `DecryptRequestBody`
     (network_id, alg, key_version, encrypted_symmetric_key/_hash passed
     through verbatim from the guest request, receiver_public_key = base64 of
     the routine's X25519 public key from step 2, receiver_public_key_hash =
     `canonical_hash(Value::String(receiver_public_key))`), serialize it to a
     `serde_json::Value`, then insert an EXTRA top-level `"aadHash"` key onto
     that `Value` holding `computed_aad_hash` from 3a — NEVER the raw
     guest-declared value (they are equal by construction once 3a has
     passed, but the mediator always writes its OWN computed value, as a
     matter of provenance hygiene). Compute `body_hash =
     canonical_hash(&body_value)` (this now covers `aadHash` too, since
     `canonical_hash` hashes the raw `Value`, extra key included). `facts =
     Some(vec![serde_json::to_value(DecryptFacts { ty: DECRYPT_REQUEST_TYPE,
     target_node: node_did, network_id, body_hash, encrypted_symmetric_key_hash,
     receiver_public_key_hash, alg, key_version })?])` — the standard core
     `DecryptFacts` shape, unchanged, still binds body/receiver/network/key-version;
     `aadHash`'s binding lives in `body_hash` transitively (§6). Mint via a
     NEW mediator method, `HostState::mint_internal_for_node(resource,
     ability, nota_bene, facts, exp_seconds)`, structurally identical to
     `mint_internal` (`compute_exec.rs:360-404`) EXCEPT `audience =
     self.encryption_service.node_did().parse::<DIDBuf>()` (D-ER3) and
     `exp_seconds = now + 240` (D-ER3), returning an owned `Invocation` (`=
     SerializedEvent<InvocationInfo>`) exactly as `mint_internal` does today
     (`compute_exec.rs:404`).
   - **3c — clone `InvocationInfo` before the invocation moves (ownership
     fix; corrects a non-compiling earlier draft).** `SerializedEvent<T>`
     (`tinycloud-core/src/events/mod.rs:17-18`, and `Invocation =
     SerializedEvent<InvocationInfo>`) derives only `Debug`, NOT `Clone` — the
     invocation can be moved into `.invoke()` exactly once. `InvocationInfo`
     itself (the `.0` field, `util.rs:232-238`) DOES derive `Clone`. The
     established principle — clone the `InvocationInfo` out before the
     `SerializedEvent` wrapping it is consumed — is proven at two existing
     call sites, `routes/mod.rs:192-193` and `:1472-1475`, each written as
     `let invocation_info = i.0 .0.clone();` because THERE `i:
     AuthHeaderGetter<InvocationInfo>` adds a Rocket-request-guard wrapper
     layer on top (`i.0: SerializedEvent<InvocationInfo>`, `i.0.0:
     InvocationInfo` — two `.0` hops). `mint_internal_for_node` (step 3b)
     returns a bare `Invocation` (`= SerializedEvent<InvocationInfo>`) with
     no such wrapper — ONE `.0` hop reaches `InvocationInfo` directly. So the
     correct expression here is `let invocation_info: InvocationInfo =
     invocation.0.clone();` (single `.0`, not the two-hop `.0 .0` those two
     HTTP-route call sites use for their differently-wrapped type) FIRST,
     THEN move the original `invocation` into step 4's `invoke()` call.
     *Correction:* an earlier draft called `invocation.clone()` directly
     (not available — `SerializedEvent` is not `Clone`) and separately
     proposed `InvocationInfo::try_from(invocation)` (not the right shape
     either — the actual `impl TryFrom<TinyCloudInvocation> for
     InvocationInfo`, `util.rs:255-264`, takes the INNER signed-token type,
     not the outer `SerializedEvent` wrapper `mint_internal_for_node`
     returns; not applicable here). Both are corrected to the
     clone-the-inner-`InvocationInfo`-then-move idiom already proven
     elsewhere in this codebase, adjusted for the one fewer wrapper layer.
4. **Authorize against the chain.** `self.tinycloud.invoke::<BlockStage>(invocation,
   HashMap::new())` — moving the ORIGINAL invocation from step 3c (there is
   only one owned copy, no clone) — the SAME call `sql_op`'s step (1) already
   makes (`compute_exec.rs:747-753`) and the SAME call the encryption
   module's own HTTP route makes via `verify_auth` before ever calling
   `decrypt_authorized` (`routes/encryption.rs:159-165, 236-260`) —
   `Resource::Other` capabilities already flow through the identical generic
   `validate()`/`extends()` machinery used for the `/encryption/networks/*`
   HTTP routes today. Failure here → FATAL (§8).
5. **Call `EncryptionService::decrypt_authorized` in-process.** No HTTP hop —
   the mediator holds an owned `EncryptionService` clone (§4.3). Call
   `self.encryption_service.decrypt_authorized(&network_id, &invocation_info,
   &body_value)` using the `invocation_info` cloned in step 3c and the SAME
   `body_value` (with the mediator-computed `aadHash`) built in step 3b. Any
   `EncryptionServiceError` → FATAL (§8) → uniform 500 (this spec deliberately
   does NOT reuse `map_service_err`'s (`routes/encryption.rs:262-287`) finer
   per-variant HTTP classification — see §8's rationale).
6. **Unwrap the rewrapped key in-process (D-ER4), then validate its length.**
   `decrypt_authorized` returns `VerifiedDecrypt.response.wrapped_key` — base64
   of a `[32-byte ephemeral X25519 pubkey][AES-256-GCM ciphertext]` envelope
   (`backend.rs:64-77`'s `wrap_to_public_key` format). The mediator opens it
   with the identical arithmetic `backend.rs`'s private `unwrap_with_secret`
   already implements (`backend.rs:79-90`), reimplemented inline in the
   mediator using the routine's derived `StaticSecret` (step 2) — no core
   visibility change needed (`ColumnEncryption` and `x25519_dalek::StaticSecret`
   are already public core types reachable from the server crate). **NEW
   check (closes a real gap, §6):** if the resulting plaintext is not
   EXACTLY 32 bytes, set `self.fatal = Some("unwrapped symmetric key has
   unexpected length: expected 32, got N")` and return the standard FATAL
   `{"ok":false,"error":{"code":"internal"}}` envelope — a `symmetricKey`
   field is never emitted to the guest otherwise. (This is realistic, not
   theoretical: `InlineEnvelope.encryptedSymmetricKey` is client-authored,
   client-controlled data — `wrap_to_public_key`'s `plaintext` parameter can
   be any length, so a buggy or adversarial client can wrap a non-32-byte
   value; `decrypt_authorized` itself has no reason to validate the
   plaintext's length, since the module is payload-key-shape-agnostic in
   general — this spec's mediator is the correct, narrowest place to enforce
   the exact shape ITS OWN guest-facing contract requires.) On success, the
   routine's X25519 `StaticSecret` is NOT dropped here (step 2, D-ER2 — it
   survives for subsequent calls in the same execution).
7. **Generate the re-encrypt nonce (§6).** `Aes256Gcm::generate_nonce(&mut
   OsRng)` (`aes_gcm::aead::OsRng`, the SAME primitive `ColumnEncryption::encrypt`
   already uses at `tinycloud-core/src/encryption.rs:44`) — 12 fresh random
   bytes, base64-encoded into the response as `reencryptNonce` alongside
   `symmetricKey`.
8. **Journal + return.** `bytes_in`/`bytes_out` = the guest-request/host-response
   JSON byte lengths (same convention as the other four imports);
   `destination = "inline"`; `granted = true`.

---

## 6. Payload Crypto Contract

**Ciphertext byte layout.** `InlineEnvelope.ciphertext` (`types.rs:150`) uses
the IDENTICAL wire framing `ColumnEncryption::encrypt`'s own output already
uses (`tinycloud-core/src/encryption.rs:43-54`): `0x01 || nonce(12 bytes) ||
AES-256-GCM(ciphertext ‖ 16-byte tag)`. `ColumnEncryption` never supplies
non-empty associated data (it calls the `Aead::encrypt(&nonce, plaintext)`
convenience method, implicit `aad = &[]`); this spec's guest instead uses the
underlying `aes_gcm::aead::Aead::{encrypt,decrypt}` `Payload { msg, aad }` API
directly (SAME `aes-gcm` crate version `tinycloud-core`/`tinycloud-sdk-wasm`
already pin — `"0.10"` — though this guest crate carries its own
self-pinned dependency, §10 Tier E2; SAME associated-data pattern already
used for `XChaCha20Poly1305` in
`tinycloud-node-server/src/node_control/key_provider.rs:549-587`, just with
`Aes256Gcm`), supplying `InlineEnvelope.aad` (`types.rs:152`) as the
associated data. Concretely: `ciphertext[0]` is the version byte (MUST be
`0x01`), `ciphertext[1..13]` is the nonce, `ciphertext[13..]` is the `msg`
argument to `Payload` (AEAD ciphertext + appended tag), and `InlineEnvelope.aad`
is the `aad` argument. *Correction (ColumnEncryption interoperability):* an
earlier draft claimed this layout is "a strict superset of `ColumnEncryption`'s
framing ... decodable by both." That is only true in the trivial `aad == []`
case: `ColumnEncryption::encrypt`/`decrypt` hard-code `aad = &[]` via the
`Aead::{encrypt,decrypt}` CONVENIENCE methods (previous paragraph) — they are
not parameterized by AAD at all. Whenever a guest supplies non-empty `aad`
(the intended case for this spec, below), `ColumnEncryption::decrypt` CANNOT
open that ciphertext (AES-GCM authentication fails against the wrong, empty,
AAD). `ColumnEncryption` is never actually used to decrypt an `InlineEnvelope`
at runtime in this spec; the two types only SHARE the same
version/nonce/tag byte convention for layout consistency, not a promise of
cross-decodability — nothing in this spec relies on `ColumnEncryption`
decoding a guest-produced envelope.

**AAD binding into the routine's signed intent, without touching core
types.** The guest sends the RAW `aad` bytes (base64, §5.1) alongside its own
`aadHash = canonical_hash(&Value::String(base64_standard_encode(&envelope.aad)))`
declaration — the SAME convention `encryptedSymmetricKeyHash`/
`receiverPublicKeyHash` already use (`canonical_hash` of the base64-encoded
STRING, not `hash_hex` of raw bytes — `service.rs:671-672`, `683-684`). The
mediator INDEPENDENTLY recomputes this same hash from the `aad` bytes it
received and REJECTS, fatally, before minting any invocation, if the two
disagree (§5.2 step 3a) — this closes a round-2 gap: an earlier draft let the
guest declare `aadHash` with no raw bytes for the mediator to check it
against, so a guest could sign one hash while using a DIFFERENT `aad` locally
for its own AES-GCM call, and the mismatch was undetectable; the named
tamper test (§10) could not actually establish any property about the
mediator. Only the mediator's OWN recomputed value is ever written into
`body_value`'s extra top-level `"aadHash"` key (§5.2 step 3b), BEFORE
computing `canonical_hash(body_value)` for the signed invocation's
`facts.body_hash` AND before passing that SAME `Value` into
`decrypt_authorized(..., &body_value)` (§5.2 step 5). This works with **zero
changes** to `DecryptRequestBody`/`DecryptFacts`/`decrypt_authorized` because:
(1) `serde_json::from_value::<DecryptRequestBody>(body_value.clone())`
(`service.rs:610`) silently ignores unknown JSON keys — `DecryptRequestBody`
has no `#[serde(deny_unknown_fields)]`; and (2) `expected_body_hash =
canonical_hash(body_value)` (`service.rs:695`) hashes the RAW `Value` the
caller passed in, not a re-serialization of the typed struct, so the extra
key participates in the hash. Net effect: `aadHash` is now cryptographically
bound to bytes the mediator itself observed in THIS call, and that binding is
verified server-side (§5.2 step 3a) BEFORE it ever reaches a signed
invocation — closing the detached-binding gap. Seeing raw `aad` bytes
server-side is NOT a new exposure: `InlineEnvelope.aad` is associated
(non-secret) metadata stored in-clear alongside the ciphertext, already fully
readable by anything with the routine's existing `kv/get` grant (including,
trivially, the node's own storage backend) — this spec does not extend host
visibility into payload PLAINTEXT or the symmetric KEY (D-ER4/D-ER5,
invariant 2 unchanged), only into a field that was never secret to begin
with. `EncryptionService` itself still never validates `aad`/`aadHash`
against anything beyond the existing `facts.body_hash` equality check
(`service.rs:695-700`, `HashMismatch("bodyHash")` on any tamper AFTER the
mediator has minted) — this only guards signature integrity in transit, not
the 3a gate itself, which is a mediator-side, pre-mint check; this is
intentional (D-ER4 boundary unchanged).

**Fresh-nonce source for re-encryption.** The guest has no entropy source of
its own inside the Wasmtime sandbox, and this spec does not add a
general-purpose `random_bytes` import (§1 non-goals). Instead, the
`encryption_decrypt` SUCCESS response (§5.1/§5.2 step 7) returns
`reencryptNonce` — 12 fresh, host-generated random bytes — for the guest's
OPTIONAL, SINGLE use constructing ONE new ciphertext. **The guest MUST NOT
reuse `reencryptNonce` for more than one AES-GCM encryption call** (nonce
reuse under a fixed key is catastrophic for GCM). This is a guest-code
correctness obligation the host does not and cannot enforce (it has no
visibility into how the guest's own linked `aes-gcm` crate is called); a
routine needing to re-encrypt more than once per execution simply calls
`encryption_decrypt` again — cheap, in-process, no new HTTP hop — to obtain a
second fresh nonce.

**Re-encrypted envelope shape.** The guest writes back (`storage_put`) a NEW
`InlineEnvelope` with `v`/`networkId`/`alg`/`keyVersion`/`encryptedSymmetricKey`/
`encryptedSymmetricKeyHash` UNCHANGED (this spec does not mint a new
symmetric key — D-ER5) and `ciphertext = 0x01 || reencryptNonce || AES-256-GCM(new_plaintext,
aad)`; `aad` MAY be reused unchanged or updated by the guest (unconstrained,
consistent with "the node never reads it").

---

## 7. Manifest / Journal Entry

No new field on `ManifestEntry` (`tinycloud-core/src/compute.rs:139-149`) —
`{resource, ability, bytes_in, bytes_out, destination, granted}` already
generalizes. One new row shape:

| field | value |
|---|---|
| `resource` | `urn:tinycloud:encryption:<ownerDid>:<name>` |
| `ability` | `tinycloud.encryption/decrypt` |
| `destination` | `"inline"` |
| `granted` | `true` (success) / `false` — for BOTH the A.4 denial AND the ONE triggering fatal failure. *Correction:* an earlier draft claimed "a fatal failure never produces a journal row." That is false — `dispatch` (`compute_exec.rs:442-451`) unconditionally calls `self.manifest.record(...)` after ANY op's return, including the branch that sets `self.fatal` (see `kv_op`'s existing fatal arm, `compute_exec.rs:604-614`, which still returns a `(resource_str, ability_canon, ..., false, resp)` tuple that gets journaled). What is NEVER journaled is any call made AFTER `self.fatal` is already set (§4.2's latch returns before `dispatch` reaches `self.manifest.record` at all). |

The granted-vs-exercised scope-down signal (§9.1.1) extends naturally:
`tinycloud.encryption/decrypt` in `D_fn` but never called shows up in
`granted_but_unexercised`, the same deployer-facing tightening signal KV/SQL
abilities already produce.

---

## 8. Error / Denial Contract Summary

| condition | guest-visible? | HTTP status if surfaced | source |
|---|---|---|---|
| no `D_fn` grant for `tinycloud.encryption/decrypt` on this network | yes — `{"ok":false,"error":{"code":"ability-denied",...}}`, op not performed, no trap | n/a (200 w/ envelope in `run` result) | A.4 pattern, §5.2 step 1 |
| guest-declared `aadHash` does not match the mediator's recomputed hash of guest-supplied `aad` | no — FATAL, journaled | 500 | §5.2 step 3a (occurs BEFORE any invocation is minted or signed — earliest of all fatal triggers) |
| chain `validate()` rejects the internal invocation | no — FATAL, journaled | 500 | §5.2 step 4 |
| ANY `EncryptionServiceError` variant (network not-found/revoked/not-active, alg/key-version mismatch, hash mismatch, nonce replay, expired/not-yet-valid, audience/target-node/network mismatch, wrong invocation type, unauthorized, signature invalid, or infra `Db`/`Backend`/`Signing`) | no — FATAL, journaled | **500, uniformly.** This spec deliberately does NOT reuse `map_service_err`'s (`routes/encryption.rs:262-287`) finer per-variant classification (401/404/409/400/...). That function is `fn`-private and, more fundamentally, `HostState.fatal: Option<String>` (`compute_exec.rs:273`) is untyped exactly like the existing `kv_op`/`sql_op` fatal path (`compute_exec.rs:608, 733`) — preserving `EncryptionServiceError`'s distinct HTTP classes through the mediator would require making `HostState.fatal` carry a typed error/status, a real design change out of scope here. Uniform 500 is least-complex-secure: it doesn't weaken anything (500 is already what `kv_op`/`sql_op` return for every non-A.4 failure today) and leaks no MORE information through the compute path than the direct HTTP path's 401/404/409 classes already leak (if anything, less — conservative, not a regression). | §5.2 step 5 |
| mediator's own post-unwrap check: rewrapped key does not decode to exactly 32 bytes (§6) | no — FATAL, journaled | 500 | §5.2 step 6 |
| malformed guest request JSON | yes — `{"ok":false,"error":{"code":"bad-request",...}}` | n/a | matches existing `dispatch`'s malformed-request handling, `compute_exec.rs:422-433` |
| ANY host call (any import) made after `self.fatal` is already set (§4.2) | yes — `{"ok":false,"error":{"code":"aborted"}}`, op not performed, NOT journaled | n/a (200 w/ envelope; the ORIGINAL triggering failure is what surfaces as 500 once `run()` returns) | §4.2 |

---

## 9. Threat-Model Invariants

1. **No authority inheritance from the external invoker.** Holding
   `tinycloud.compute/execute` on the function resource grants nothing toward
   `tinycloud.encryption/decrypt` — layer (a)/(b) decoupling (§6.1/§6.2) is
   unchanged; the invoker never needs, and never gains, network membership.
   The internal invocation is signed by the ROUTINE key, never the invoker's.
2. **No payload plaintext, and no raw symmetric key, ever crosses the
   `EncryptionService` boundary.** Unchanged from the shipped module
   (`service.rs:731-735`); this spec is a new *caller*, not a new *exposure*.
3. **The routine's X25519 private scalar never leaves core/TEE mediation.**
   Derived once per execution inside `HostState` (server crate, in-process,
   inside the same `spawn_blocking` the WASM guest runs in), reused across
   however many `encryption_decrypt` calls occur in that execution (D-ER2),
   and dropped with `HostState`. Never: returned to the guest, included in a
   response body, logged, cloned into a second field, or persisted. Contrast
   the client-side `vault_ed25519_seed_to_x25519` (D-ER2), which
   deliberately *does* export the scalar — architecturally the wrong tool for
   this job, MUST NOT be reused here.
4. **The raw AES-256 symmetric key DOES cross into guest memory** (D-ER5) —
   an accepted, scoped exposure: the guest already held (or could derive)
   everything needed to request this key via its `D_fn` grant, and holding
   the payload symmetric key is exactly what "decrypt this payload" means.
   What must NOT cross into guest memory is the routine's X25519 private
   scalar (invariant 3).
5. **Replay/TTL is enforced twice, independently.** The mediator's fresh
   random nonce + short expiry (D-ER3) is one layer; `EncryptionService`'s
   own `consume_nonce`/`validate_invocation_time` (`service.rs:664, 706-711`)
   is a second, independent layer the mediator does not and cannot bypass.
6. **Space isolation is preserved.** §4.1's core fix narrows, it does not
   remove, the space-scope defense-in-depth; the primary boundary
   (space-hashed `routine_did`) is untouched.
7. **Network membership is the deployer's, delegated, not manufactured.** A
   `D_fn` row for `tinycloud.encryption/decrypt` can only be minted by a
   deployer whose own chain already holds that authority.
8. **A grant-present failure fail-stops the run; no guest code runs past it
   un-mediated.** §4.2's `dispatch`-level latch guarantees every host call
   after the FIRST fatal failure in an execution — regardless of import — is
   rejected before any grant lookup, internal-invocation mint, or core call
   happens. Mutations from calls that succeeded BEFORE the fatal point are
   NOT rolled back — this is compute's pre-existing per-call commit model
   (each `kv_op`/`sql_op`/`encryption_decrypt` call that reaches a core
   `invoke_with_options` commits independently and immediately; there is no
   cross-call transaction to roll back), unchanged by this spec.
9. **`aadHash` is bound into the routine's signed intent, and IS
   independently verified — by the mediator, not by `EncryptionService`.**
   (§6, §5.2 step 3a) The mediator recomputes `aadHash` from the RAW `aad`
   bytes it receives in the same call and rejects, fatally, before minting
   any invocation, if the guest's declared `aadHash` disagrees — this closes
   a round-2 gap where an undetectable guest-declared hash could diverge from
   the guest's own later AES-GCM call. `EncryptionService` itself still never
   independently checks `aad`/`aadHash` against anything (it has no way to —
   it never sees raw `aad`; it only re-verifies `facts.body_hash` equality
   against whatever `body_value` the mediator submitted, `service.rs:695-700`)
   — this is intentional (D-ER4 boundary unchanged). A compromised or buggy
   routine could still supply a locally-used AAD that diverges from BOTH the
   real `InlineEnvelope.aad` on disk AND its own signed `aadHash`, if it lies
   consistently across both fields it controls — that only self-sabotages the
   routine's own later AES-GCM decrypt (a wrong AAD fails AEAD
   authentication) or produces a signed intent that doesn't match the actual
   stored envelope; it never grants access to a key or payload the routine
   wasn't already authorized for via D-ER1's grant, and never crosses an
   authority boundary.
10. **`reencryptNonce` reuse is a guest-code correctness bug, not a boundary
    this spec's mediator polices.** (§6) The host issues a fresh nonce per
    `encryption_decrypt` call; a guest that reuses one nonce across multiple
    ciphertexts breaks its OWN AES-GCM security but does not cross any
    authority boundary this spec is responsible for.

---

## 10. Test Gates (named, exact)

**Unit — `cargo test -p tinycloud-core --features compute <name>`:**
- `routine_x25519_from_seed_is_deterministic` (`tinycloud-core/src/compute.rs`)
  — same seed → same `(StaticSecret, PublicKey)` bytes, across repeated
  calls, mirroring `classic_routine_key_deriver_is_deterministic`
  (`compute.rs:502-521`).
- `routine_x25519_from_seed_differs_by_function_cid` — mirrors
  `classic_routine_key_deriver_differs_by_function_cid` (`compute.rs:523-532`).
- `routine_x25519_from_seed_matches_vault_conversion` — a fixed known-answer
  seed produces the SAME private-scalar and public-key bytes as
  `vault_ed25519_seed_to_x25519` (`tinycloud-sdk-wasm/src/vault.rs:150-171`)
  for that seed — proves the two implementations use the identical
  conversion, not just "similar."
- `compute_select_d_fns_admits_encryption_row_alongside_in_space_kv_row` (`tinycloud-core/src/db.rs`)
  — a `D_fn` with one `Resource::Other` encryption-network row (URN-prefix
  match) and one in-space `Resource::TinyCloud` row IS selected (regression
  test for the §4.1 bug).
- `compute_select_d_fns_rejects_other_resource_outside_prefix` — a
  `Resource::Other` row whose URI does NOT match `ENCRYPTION_NETWORK_PREFIX`
  makes the `D_fn` UNSELECTED (proves the carve-out is prefix-scoped, not a
  blanket bypass).
- `compute_select_d_fns_still_rejects_out_of_space_tinycloud_row` — an
  out-of-space `Resource::TinyCloud` row is still REJECTED unchanged
  (regression guard on the untouched arm).

**Integration — `tinycloud-node-server`, new `tests/compute_encryption.rs`
(register `[[test]] name = "compute_encryption" path = "tests/compute_encryption.rs"
required-features = ["compute"]` in `Cargo.toml`, mirroring the existing
`compute_execute`/`compute_e2e` entries at lines 150-167). Run via `cargo test
-p tinycloud-node --features compute --test compute_encryption <fn_name>`.**

*Tier E1 — key-mediation only, WAT fixture (no in-guest crypto; mirrors the
existing `probe_get.wat`/`echo_get.wat` fixture style — the guest calls
`encryption_decrypt` and returns the raw JSON response as its `run()` result,
so the test asserts on the mediator's output directly):*
- `encryption_decrypt_returns_32_byte_key_and_reencrypt_nonce` — one-of-one
  network, `D_fn` grants the network row, seed an `InlineEnvelope`; asserts
  `symmetricKey` decodes to exactly 32 bytes and `reencryptNonce` decodes to
  exactly 12 bytes; manifest row has `granted: true`.
- `encryption_decrypt_denied_without_grant` — network row omitted from
  `D_fn`; asserts the A.4 `ability-denied` envelope, op not performed, no
  trap, `granted: false` journaled.
- `encryption_decrypt_against_revoked_network_is_fatal_500` — network in
  `Revoked` state; asserts the compute-execute HTTP response is 500 (not a
  silent denial), proving §8's two-tier contract.
- `encryption_decrypt_wrong_network_id_is_denied` — `D_fn` grants network A,
  guest requests network B; A.4 denial, cross-network isolation proven.
- `encryption_decrypt_expired_dfn_still_returns_403_before_any_execution` —
  NOT a WAT-fixture/guest-execution test (unlike the other Tier E1 bullets
  above and below): per §4.1's carve-out, the `D_fn`'s delegation-level
  expiry check happens entirely at the ROUTE level, in
  `compute_classify_routine_grant` (`tinycloud-core/src/db.rs:493-498`, the
  `identity_expired` branch) BEFORE `compute_select_d_fns` returns anything
  and BEFORE any wasmtime `Module`/`Store`/`Linker` setup
  (`routes/mod.rs:2572-2603`) — no guest ever runs, so there is no manifest
  and nothing to journal. *Correction:* an earlier draft named this test
  `..._is_fatal_500` and described an A.4-style in-run denial; both were
  wrong — the existing, ALREADY-SHIPPED behavior
  (`ComputeExecError::RoutineGrantExpired`, `compute_exec.rs:141-145`)
  returns HTTP **403** (not 500), pre-run, exactly as the existing KV-only
  regression test `expired_grant_reports_grant_expired_not_rotated`
  (`tinycloud-node-server/tests/compute_execute.rs:829-889`) already proves
  for a `D_fn` with no encryption row. This spec's version is a pure
  REGRESSION check, not new behavior: deploy a `D_fn` whose ability list
  includes BOTH a KV row AND the new `tinycloud.encryption/decrypt` row (§3),
  expire the delegation exactly as the existing test does, and assert the
  SAME 403 + `"routine-grant-expired"` body — proving the encryption row's
  presence doesn't change this pre-existing, route-level classification. No
  WAT guest fixture is exercised.
- `encryption_decrypt_mismatched_aad_hash_is_rejected_before_mint` —
  construct the guest request with `aad` (raw bytes, §5.1) and a
  DELIBERATELY WRONG `aadHash` that does not equal
  `canonical_hash(base64(aad))`; assert the mediator rejects at §5.2 step 3a
  BEFORE any internal invocation is minted or signed (no
  `mint_internal_for_node` call, no `invoke()` call), the compute-execute
  HTTP response is 500 (fatal, §8), the manifest row for this call has
  `granted: false`, and no `storage_put` occurs. *Correction:* an earlier
  draft named this test `..._fails_signature_and_leaves_storage_unchanged`
  and asserted only a LATER guest-side AEAD failure (invariant 9's weaker
  self-sabotage fallback), because the prior request shape gave the mediator
  no raw `aad` to check the guest's `aadHash` against. §5.2 step 3a now
  makes this a real mediator-side rejection, not merely a guest-side
  AEAD-authentication failure.
- `encryption_decrypt_consistent_aad_hash_binds_into_signed_body_hash` — the
  guest sends `aad`/`aadHash` that DO match; assert the call succeeds
  end-to-end AND that the value inside the internal invocation's
  `facts.body_hash` preimage is the mediator's OWN recomputed
  `computed_aad_hash` (constructed test-side by re-running `canonical_hash`
  over the SAME `body_value` shape and comparing), not merely a value read
  back verbatim from the guest request — proving §5.2 step 3b's
  provenance-hygiene requirement.
- `encryption_decrypt_repeated_call_reuses_same_derived_secret` — TWO
  `encryption_decrypt` calls in one execution against the same network both
  succeed and both unwrap correctly (proxy for "same `StaticSecret` reused,"
  since the raw scalar is never observable directly — D-ER2's repeated-call
  test).
- `host_call_after_fatal_is_aborted_and_not_journaled` (D-ER7/§4.2) — a
  fixture with a `D_fn` grant that NAMES a real (matching) encryption-network
  resource whose network is seeded in `Revoked` state — the SAME
  deterministic trigger as `encryption_decrypt_against_revoked_network_is_fatal_500`
  above (grant-present, so NOT an A.4 denial; an
  `EncryptionServiceError::NetworkNotActive`-class failure → FATAL per §8).
  The guest's FIRST call is this `encryption_decrypt` against the revoked
  network; its SECOND call, in the SAME `run()`, is a `storage_put` to an
  in-space, otherwise-authorized KV path. Assert: the first call is
  journaled with `granted: false`; the second call returns
  `{"ok":false,"error":{"code":"aborted"}}`, is NOT present in the manifest
  at all, the underlying storage value is UNCHANGED after the run (the
  `storage_put` never reached `invoke_with_options`), and the run still
  surfaces as HTTP 500 for the ORIGINAL (first) failure. *Correction:* an
  earlier draft proposed triggering the first fatal via "`kv/put` to an
  unauthorized-mid-run path via a store error" — no such deterministic,
  grant-present KV fatal exists as a ready-made fixture today (the only
  unauthorized-KV path, `compute_exec.rs:493-498`, is a clean, NON-fatal A.4
  denial); this spec's OWN `encryption_decrypt`-against-a-revoked-network
  trigger is reused here instead, since it IS a real, deterministic,
  grant-present fatal requiring nothing beyond what Tier E1 already sets up.
- `encryption_decrypt_oversized_request_rejected_cleanly` — mirrors
  `bogus_host_call_length_rejected_cleanly` (`compute_execute.rs:1555-...`,
  new fixture `encryption_decrypt_oversized_request.wat`), proving the
  existing `max_message_bytes` guest-memory ceiling (`compute_exec.rs:1286-1292`)
  applies to the new import too.

*Tier E2 — full crypto round trip, real `wasm32-unknown-unknown` guest (NEW
guest crate at `tinycloud-node-server/tests/fixtures/compute-guests/encrypted_counter/`).
*Correction (pinning, closes a round-2 gap):* this crate is NOT a member of
the root workspace (`Cargo.toml:4-14`'s `members` list is explicit, not a
glob, and does not include it) and there is no root
`[workspace.dependencies]` entry for `aes-gcm` (confirmed: `Cargo.toml:24-45`)
— "depending on the workspace's `aes-gcm` crate" in an earlier draft was
imprecise on both counts. Its `Cargo.toml` MUST carry its own empty
`[workspace]` table (the standard fix for an out-of-tree fixture crate nested
inside a workspace member's directory — without it, `cargo` walks up to the
ROOT `Cargo.toml`'s `[workspace]` and fails with "current package believes it
is in a workspace when it is not," since this path is not in `members`),
plus its own direct, self-pinned dependency `aes-gcm = "0.10"` (matching, but
not sourced from, the version `tinycloud-core`/`tinycloud-sdk-wasm`
independently pin), `edition = "2021"`, and `[lib] crate-type = ["cdylib"]`
for the `wasm32-unknown-unknown` build target. Built via `cargo build
--manifest-path tinycloud-node-server/tests/fixtures/compute-guests/encrypted_counter/Cargo.toml
--release --target wasm32-unknown-unknown`, output copied to
`tests/fixtures/compute/encrypted_counter.wasm`, loaded via the existing
`load_fixture` helper — no changes needed there since it just reads raw
bytes):*
- `encrypted_counter_round_trip_via_real_wasm_guest` — seed an `InlineEnvelope`
  wrapping a little-endian `u32` counter, `aad = b"counter-v1"`; execute the
  guest, which: `storage_get`s the envelope, calls `encryption_decrypt`,
  AES-256-GCM-decrypts `ciphertext` using `symmetricKey`+`aad` (§6 layout),
  increments the counter, AES-256-GCM-re-encrypts using the SAME key +
  `reencryptNonce` + `aad`, `storage_put`s the new envelope. Assert: the
  `run()` result reports success; re-reading and independently decrypting
  (test-side, same layout) the stored envelope recovers `counter + 1`; the
  manifest contains `tinycloud.encryption/decrypt` with `granted: true`.
- `encrypted_counter_regression_kv_sql_only_dfn_still_works` — an existing
  KV+SQL-only `D_fn` (no encryption row) still selects and executes
  correctly post-§4.1 fix, using the EXISTING `probe_get.wat`/`probe_put.wat`
  fixtures unmodified — proves the carve-out didn't change behavior for the
  unmodified path.
- `invoker_cannot_directly_call_encryption_decrypt_route` — an actor holding
  ONLY `tinycloud.compute/execute` (no encryption-network delegation of
  their own) calls `POST /encryption/networks/<id>/decrypt` directly using
  their OWN key (not the routine's); asserts `Unauthorized`/401, proving
  invariant 1 (zero authority inheritance from the external invoker).

**Live E2E (gated, `#[ignore]`, real dstack CVM + a live encryption network —
NEW gate, run via `cargo test -p tinycloud-node --features compute,dstack
--test compute_encryption -- --ignored encrypted_counter_live_dstack_round_trip`):**
- `encrypted_counter_live_dstack_round_trip` — the E2 flow above against a
  live node instance, run TWICE across separate process invocations to
  confirm the routine's re-derived X25519 keypair is stable (the same
  seed-stability assumption `compute-service.md` §6.2 already flags as
  "VERIFY EMPIRICALLY" for the Ed25519 identity — this reuses that same
  empirical check for the X25519 derivation, since it's a deterministic
  function of the same seed).

---

## 11. Deferred / Non-Normative

- SDK convenience for minting the `tinycloud.encryption/decrypt` `D_fn` row
  at deploy time — follow-up, not blocking this node-side contract.
- **Wrapping a BRAND NEW symmetric key to the network's public key** (as
  opposed to re-encrypting with the SAME already-authorized key, which IS
  in-scope per §6/D-ER5) remains OUT OF SCOPE for this spec's MVP — that is
  "network encrypt" authority, which the module deliberately does not expose
  node-side ("clients encrypt to the network public key locally" per
  `encryption_network/mod.rs:4-5`). A routine MAY re-encrypt with a symmetric
  key it generates itself (ordinary AES-256-GCM, no network involvement) and
  store the wrap out-of-band; unconstrained by this spec either way.
- A dedicated `random_bytes` host import (§1, §6) — deferred; the
  single-nonce-per-`encryption_decrypt`-call shape covers the MVP's
  re-encrypt-what-you-just-decrypted use case without it.
- Optional KV-audit persistence of the decrypt manifest entry — same
  MAY/config-gated status as the general manifest persistence hook (§9.1.1),
  not wired in this stage.
- Threshold `KeyBackend` — orthogonal, unblocked by this spec (the mediator
  only ever calls the existing `EncryptionService::decrypt_authorized`
  trait-object boundary, agnostic to backend).
- A typed `HostState.fatal` (carrying an HTTP status/error class instead of
  a `String`) that would let this spec preserve `map_service_err`'s finer
  HTTP-status classification through the mediator (§8) — real, out-of-scope
  design work; uniform 500 is the accepted MVP simplification.
