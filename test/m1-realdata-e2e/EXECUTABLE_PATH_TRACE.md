# M1-G-05a executable-path trace

This is the constructibility checkpoint for the deterministic, in-process
cross-layer proof. Citations to policy-engine are to git revision
`ba318116365171f3be19de4e3efa1a5eafd842d2`; node citations are to this
worktree's clean base `2ad3cef`. The harness will use only conformance rows
whose vendored `reachability` is `mounted-runtime`.

## Startup and ordering

1. Start a Rocket node in-process with the W5 Figment overlay. `tinycloud::app`
   initializes the database and managed `SqlService`. There is no production
   route for initial space creation: as in the W5 recipe, the harness inserts
   exactly one `space` row and creates its block directory as a setup-only
   storage precondition. It immediately observes one space row and zero
   delegation/ability rows, so this direct setup mutation is explicitly outside
   the authority-chain claim. The harness then seeds Listen-shaped SQL through
   `SqlService` and KV bytes through an owner-signed native invocation before
   any holder read (`tinycloud-node-server/src/lib.rs`,
   `tinycloud-node-server/src/routes/mod.rs`, and
   `tinycloud-core/src/sql/service.rs`). No socket is bound.
2. Compose and sign Policy and PolicyStatus objects, verify each with
   `policy_core::verify_signed_object_value`, and insert only the verified
   variants into `PolicySpaceState`. This mirrors the production startup load
   loop in `crates/policy-engine-http/src/lib.rs::PolicyEngineService::load_objects`
   (verification followed by `insert_policy` / `insert_policy_status`). Runtime
   authority is startup state except for the explicit in-process status-update
   denial below.
3. Construct `PolicyRuntime` with `policy_evidence_vc::VcEvidenceVerifier` keyed
   by the trusted public key in the vendored launch-profile fixture and a
   `GrantIssuer` that signs a real node UCAN delegation. The runtime is ready
   only after node seeding and verified authority loading.
4. Call `issue_challenge`, sign a holder presentation containing the
   vendored SD-JWT, and call `resolve` (`crates/policy-runtime/src/lib.rs`). The
   issuer's returned `PortableDelegation.encoded` is the signed node UCAN.
5. Import that exact encoding through Rocket's local `/delegate` route. The
   route calls `TinyCloud::delegate`, which reaches
   `tinycloud_core::models::delegation::{verify,validate,save}`; no delegation or
   ability row is inserted by the harness. Only after the route returns its CID
   do holder-signed `/invoke` calls execute named SQL and KV reads.

## Acceptance observations

| Required behavior | Production hop | Observation produced by the harness |
| --- | --- | --- |
| Space storage precondition (not authority evidence) | No production initial-space route exists; W5 provisions `space::ActiveModel` plus the block directory before native service use | The setup insert produces exactly one space row while delegation and ability tables remain empty. Authority provenance is observed separately only after `/delegate`. |
| Real launch-profile resolve | `PolicyRuntime::resolve` -> `verify_evidence` -> `policy_evidence_vc::VcEvidenceVerifier::verify` -> `GrantIssuer::issue` | The resolve returns a delegation whose holder, policy, capabilities, validity, and encoded UCAN are compared with the presentation and policy used by that call. |
| Delegation import provenance | local `/delegate` -> `TinyCloud::delegate` -> delegation `verify`/`validate`/`save` | Delegation and ability tables are empty before import; the returned import CID is then observed in the created delegation row and its abilities. The test never writes either table. |
| Named Listen SQL reads | local `/invoke` -> chain validation in `models/invocation.rs` -> `routes::enforce_constrained_profile` -> `SqlService::execute` | Named statements return the exact rows/bytes seeded earlier; disallowed name, fixed-param override, raw query, raw execute/write, batch, and export requests report their native `sql-*` outcomes from the dispatched response. |
| KV read and containment | local `/invoke` -> invocation chain validation -> native KV dispatch | Authorized `kv/get` returns exactly the seeded bytes. An unauthorized KV ability reports `Unauthorized Action`, and a before/after read proves it returned no protected bytes. |
| Expired delegation | `/delegate` -> `models/delegation.rs::verify` -> UCAN `validate_time` | A genuinely signed expired node delegation is refused by the import operation; no expired authority row is manufactured. |
| Issuance read-back | successful `resolve` inserts `IssuanceRecord`; `PolicySpaceState::issuance` reads it | Every field is compared to this resolve's policy, subject, holder, resource/delegation id, evidence id, issued/expires times, and `RevocationMode::RefreshOnly`; observed TTL must be positive and at most 300 seconds. (`refresh_only` is the pinned API's `revocation` enum field, not a separate boolean.) |
| Expired credential | fresh challenge + resolve -> VC verifier over vendored `expired.json` | The returned runtime error's nested mounted-runtime code is `evidence-credential-invalid`. |
| Untrusted issuer | fresh challenge + resolve -> VC verifier over vendored `untrusted-issuer-did.json` | The returned runtime error's nested mounted-runtime code is `evidence-issuer-untrusted`. |
| Nonce replay | successful resolve then a second `resolve` with the consumed nonce | Second operation returns `challenge-nonce-consumed`. |
| Audience mismatch | fresh challenge + holder-signed presentation with a different audience -> presentation validation | Resolve returns nested code `presentation-audience-mismatch`. |
| Revoked PolicyStatus | `PolicySpaceState::insert_policy_status` with a higher sequence and revoked disposition, then a fresh resolve | The next resolve returns `policy-inactive`. This is only the deterministic in-process status-update contract. |
| Compromised signer | `EnrollmentStatusTracker::apply_status` applies a revoked status and then a higher active status before a fresh resolve | The attempted recovery operation returns `enrollment-revoked-irreversible`; the subsequent resolve remains denied. |

## Unsupported or intentionally absent hops

- Importing policy-engine's `tc-pdel-v0` envelope directly into tinycloud-node
  is unsupported: node `/delegate` accepts UCAN/CACAO authorization material,
  while that envelope is a policy-engine wire record. The harness therefore
  implements the pinned `GrantIssuer` seam with a real UCAN signer and places
  those same issued bytes in `PortableDelegation.encoded`; it does not translate
  or mutate node state afterward.
- Initial node space provisioning has no production route in this pinned node.
  The direct `space` row insertion and block-directory creation are disclosed
  setup-only preconditions copied from W5, not authority evidence. The test
  proves they create no delegation or ability rows before the real `/delegate`
  import.
- There is no shared correlation identifier with m1-g-05b live issuance. This
  crate makes no claim about that live issuance or production readiness.
- `canonicalization-mismatch` and `evidence-freshness-expired` have no allowed
  deterministic mounted-runtime hop for this ticket and are not manufactured.
- Direct delegation/ability insertion, mocked evidence acceptance, subprocesses,
  sockets, manifest-existence behavior, and canned response evidence have no
  acceptance path and are prohibited.
