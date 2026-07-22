# Rationale Appendix: Compute Routine as Encryption-Network Decrypt Receiver

Non-normative. Supporting "why" for the DECIDED facts pinned in
`specs/compute-encrypted-routine.md`. If this appendix and the main spec ever
disagree, the main spec is authoritative.

## D-ER1 — one `D_fn`, one more ability row

No new delegation type, no second deploy-time round trip:
`compute_select_d_fns` (§4.1) already returns the whole capability list of a
matching `D_fn`, and the mediator's `find_grant`-style lookup
(`compute_exec.rs:311-319`) already searches by `(ability, resource.extends)`
generically over `Capability`. Zero new authorization-engine code.

## D-ER2 — routine X25519 derivation

The vault function `vault_ed25519_seed_to_x25519`
(`tinycloud-sdk-wasm/src/vault.rs`) exists to hand the raw scalar across a
WASM→JS boundary to a browser client — exactly the exposure this spec
forbids for a routine's key. That's why the equivalent derivation
(`routine_x25519_from_seed`) lives in `tinycloud-core` (non-`wasm_bindgen`)
instead of being reused from the SDK directly. Contrast is drawn again in §9
invariant 3.

## D-ER3 — audience/expiry deviations

Two deliberate deviations from `HostState::mint_internal`
(`compute_exec.rs:360-404`):
- **Audience:** `decrypt_authorized` hard-rejects on
  `invocation.payload().audience != self.node_did` (`service.rs:617-621`,
  `AudienceMismatch`) — a check the encryption module performs on top of the
  generic chain `validate()`, which does not itself read `audience`.
- **Expiry:** `decrypt_authorized` calls `validate_invocation_time`
  (`service.rs:664`, `DEFAULT_INVOCATION_TTL_SECONDS = 300`, `service.rs:42`),
  rejecting `exp - now > ttl`. `now + 240` leaves slack under the 300s
  ceiling while staying short-lived.

## D-ER9 — dependency-avoidance rationale

A naive mediator implementation would need `x25519_dalek::StaticSecret` as a
`HostState` field type and would reimplement `backend.rs`'s private
`unwrap_with_secret` inline — but neither `x25519-dalek` nor `aes-gcm` is
re-exported from `tinycloud-core`'s public API, and
`tinycloud-node-server/Cargo.toml` has neither as a direct dependency.
Naming the type or reimplementing the arithmetic would not compile without
adding both crates directly to `tinycloud-node-server` — and doing so would
create a second, independently-versioned crypto/encoding surface. Avoiding a
second `base64` crate also avoids the version skew that would otherwise
exist between `tinycloud-node-server/Cargo.toml:27`'s direct
`base64 = "0.13"` and `tinycloud-core`'s workspace `base64 = "0.22"`. This is
the least-complex-secure option: one authoritative unwrap implementation,
one authoritative base64 encoding convention, zero parallel crypto/encoding
code in the mediator.

## §4.1 — why narrow, not delete, the space-scope check

The routine's primary cross-space boundary is `routine_did` itself — the
space is hashed into the key-derivation path, so `delegatee.eq(routine_did)`
already scopes every candidate delegation to one `(space, function_cid)`
pair before `all_in_space` runs. A network resource has no space component
by design (`NetworkId::new(owner_did, name)`, `network_id.rs:38-56`), so
demanding `resource.space() == Some(space)` for it is a category error. The
fix mirrors `Resource::extends`'s own `Other, Other` arm
(`resource.rs:33-48`), which fails closed the moment either side is a
malformed reserved-prefix value rather than falling back to a raw prefix
comparison. The real authorization boundary is unchanged, enforced twice
elsewhere: (a) the deployer could not have minted this row without their own
chain already holding `tinycloud.encryption/decrypt` on that network, and
(b) at execute time the mediator's internal invocation for this row still
passes the generic `validate()` chain walk (§5.2 step 4) AND
`EncryptionService::decrypt_authorized`'s own checks. This fix only restores
selectability; it grants nothing.

## §4.2 — why a latch, and why not roll back

Between a `kv_op`/`sql_op` call setting `self.fatal` and `run()` returning, a
guest could otherwise keep making further host calls — `storage_put`,
`sql_query`, and (after this spec) `encryption_decrypt` would all still
execute, since `dispatch` performs no fatal check first. The ORIGINAL
triggering call is unaffected by the fix — it still runs to completion,
still gets journaled, still returns its own error envelope; what's new is
that every call AFTER that point is rejected before any grant lookup or core
call — a Wasmtime-host-fn latch (no trap, no unwind), consistent with
`compute-service.md`'s "host functions never trap on a mediated denial or
internal error" constraint. Rollback of prior mutations is out of scope (§9
invariant 8) — pre-existing per-call commit behavior, unchanged by this
spec.

## §4.3 — key-hygiene note on `EncryptionService: Clone`

A bare `#[derive(Clone)]` would be wrong: `node_keypair: Option<Keypair>`
(`libp2p::identity::Keypair`) IS `Clone`, but that clone is a DEEP copy of
the private scalar (`libp2p-identity` 0.2.13's `Keypair` wraps
`ed25519_dalek::SigningKey`, itself `#[derive(Clone)]`) — a bare derive
would duplicate the node's private signing key on every compute execution.
Wrapping in `Arc` first makes every field cheap to clone (`db` is
sea-orm/`Arc`-backed, `backend: Arc<dyn KeyBackend>` a refcount bump,
`invocation_ttl_seconds: Copy`).

## §6 — payload crypto contract, supporting detail

`InlineEnvelope.ciphertext` (`types.rs:150`) shares only the
version/nonce/tag byte conventions of `ColumnEncryption::encrypt`
(`encryption.rs:43-54`) for consistency — `ColumnEncryption` always uses
`aad = &[]` and cannot open a non-empty-AAD ciphertext, so nothing in this
spec relies on it decoding a guest-produced envelope. The AAD-binding
mediator check is a scoped self-consistency-plus-provenance guarantee, not
independent verification of what the guest's later, separate in-WASM AEAD
call actually uses — the mediator has no visibility into that call. A
compromised or buggy routine can still supply a locally-used AAD that
diverges from both the on-disk `InlineEnvelope.aad` and the value it
declared to the host; that only self-sabotages the routine's own AES-GCM
call (wrong AAD fails authentication) or produces a signed intent mismatched
with the actual envelope — it never grants access to a key or payload the
routine wasn't already authorized for via D-ER1, and never crosses an
authority boundary.

## §9 invariant 5 — replay/TTL control separation, supporting detail

The HTTP-layer `InvocationReplayCache` (`invocation_replay.rs`) does not
cover this path at all — it only guards the `/invoke` Rocket route; the
mediator's internal invocation is minted and consumed entirely in-process.
Test gate `encryption_decrypt_replayed_nonce_is_rejected_by_consume_nonce`
asserts rejection specifically via `EncryptionServiceError::NonceReplay`.

## Rejected alternative: typed `HostState.fatal`

A typed `HostState.fatal` (carrying an HTTP status/error class instead of a
`String`) would let this spec preserve `map_service_err`'s finer HTTP
classification through the mediator (§8). Real, out-of-scope design work —
`HostState.fatal: Option<String>` is untyped exactly like the existing
`kv_op`/`sql_op` fatal path; preserving per-variant classes would require a
genuine typed-error change across that shared path. Uniform 500 leaks no
more than the direct HTTP path's classes already do (arguably less); this is
the accepted MVP simplification, revisited only if a caller needs finer
error discrimination.
