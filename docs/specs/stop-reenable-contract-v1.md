# Stop and re-enable renewal: proposed control contract v1

Status: DOC-ONLY PROPOSAL, revised for Bobbie323fd442 (six required changes), for delta review then Naomi freeze. Not approved wire vocabulary. Requested by Naomi3411713e. No runtime or frozen-fixture changes are authorized by this document.

The current node runtime slice ships **renew + existing revoke/status only**. Stop/re-enable are deferred to the next slice. Existing #545/#546 Renew leases grant only `tinycloud.delegation/renew`; this proposal does not modify those bytes, CIDs, capabilities or the stamp format. `design.md` R5 is target behavior for that later slice, not a claim that stop is currently exposed. Never substitute revoke when a caller asks to stop: revoking the lease invalidates renewal-added time and falls back to the original signed expiry; revoking the original ends its access/descendants. Stop preserves admitted stamps. This proposal adds no “stop and end now” mode.

## Recommended route, actions and target

Recommend ONE new thin endpoint in the **existing delegation-control route family**, `POST /delegation/renewal/state`, using the strict owner-control validation template in `tinycloud-core/src/encryption_network/delete_auth.rs:301–356`: explicit audience, proofless principal, one capability, lifetime, nonce and unknown-caveat rejection. Existing `/delegation/status` supplies only route-family/exact-CID precedent; its signature/time-only verifier is NOT a sufficient auth template (it lacks audience/replay checks). This endpoint does not exist today. Reuse control authorization/replay/transaction code; do not route these owner operations through generic data `/invoke`, and do not overload `/revoke` with a stop mode.

| Desired transition | Exact proposed ability | Exact signed resource |
|---|---|---|
| active → stopped | `tinycloud.delegation/stop-renewal` | `urn:cid:<canonical LEASE CID>` |
| stopped → active | `tinycloud.delegation/enable-renewal` | `urn:cid:<canonical LEASE CID>` |

`enable` means D13 re-enable of a lease previously stopped through this contract. Registration always starts an owner-authorized renewable lease at `state=active, generation=1`; there is no registered-stopped initial mode in v1. Turning renewal on later for an originally nonrenewing grant requires explicit owner-signed lease registration while that original is live, then active/gen1. It never creates/extends a lease or changes its holder, period or abilities. The target is the **lease**, not the original, so multiple historical leases cannot be confused. New lease authorization/registration remains separate. The server resolves the lease's original from stored signed artifacts; no client-supplied original/holder/scope is trusted.

Alternative considered: two `/invoke` action handlers on the original CID. Rejected for this slice: expands the generic invocation path and leaves lease selection ambiguous. Existing control-family route + exact lease target is the narrowest extension. Final route/action strings and the numeric caveat below are one-way contract choices for Naomi to freeze after review.

## Lease cardinality and initial state — recommended freeze

Require **at most ONE unrevoked, unexpired lease per (canonical original CID, renewer identity epoch)**. A stopped lease counts against this limit. Enforce at registration under the SAME original-CID advisory lock: a repeated registration of the identical lease is idempotent and never resets state/generation; a different live lease conflicts. Do not create lease B to bypass stopped lease A. This closes the multi-lease stop bypass rather than silently stopping just one of two active leases. Different historical expired/revoked leases remain auditable and cannot be re-enabled. A new separately authorized lease must still pass original-live/D15 checks after revoked/expired stamps are excluded.

If the preceding runtime admits multiple live leases, this cardinality must be enforced/reconciled before the stop endpoint is advertised: return owner-only409 `ambiguous_renewal_lease` for an ambiguous original, never choose one silently or auto-revoke another. Existing affected rows need explicit owner resolution; this doc authorizes no migration or new user flow. Alternative for Naomi: define stop as original-wide across all leases. Recommendation is the ≤1 rule; no all-lease implicit mutation.

Initial state is **active/gen1** only after explicit owner-authorized registration. Nonrenewing grants have no lease row. D13 re-enable mutates an existing live stopped row, never re-registers to reset its generation.

## Owner authentication and signed request

`Authorization` is the existing verifiable signed invocation format accepted by the node (including compact Ed25519 UCAN where applicable), with normal signature, audience, nbf/expiry and replay validation. No new signature scheme. The issuer must resolve to the **original delegation's delegator**, using canonical principal matching (`ControlAction::party_may_act` issuing-side rule). “Owner” here means that authenticated issuer, not arbitrary space owner, current holder or renewer. Under the original-CID lock ALSO require the verified issuer equals the lease’s OWN signed issuer, defending against a misregistered lease. In v1 require direct issuer authorization and `prf: []`; no delegated stop/enable management, space/network fallback, cookie-only authorization or unsigned profile metadata.

For stop/enable: exactly one resource, one ability, and a caveat LIST of exactly ONE object with exactly ONE key (`expectedGeneration`). Check the raw signed shape before normalization: reject `[{},{}]`, `[{"expectedGeneration":1},{}]`, `[{}]`, objects with extra keys or collapsed/array-index keys (`"0"`, `"1"`). Read uses a distinct explicitly empty caveat profile below. Mutation example:

```json
{
  "urn:cid:<lease CID>": {
    "tinycloud.delegation/stop-renewal": [ { "expectedGeneration": 1 } ]
  }
}
```

For enable, use the enable ability and current expected generation. `expectedGeneration` is a nonnegative integer representable exactly in JSON (≤2^53−1); reject floats, negative/overflow values and unknown caveat keys. The control parser MUST validate this signed caveat; it must not drop it as a generic unknown restriction. Lease generation cannot wrap.

Body (strict keys and types):

```json
{"version":1,"leaseCid":"<canonical lease CID>","expectedGeneration":1}
```

Signed exact resource must equal `urn:cid:` + body lease CID, and signed expected generation must equal body generation. The CAS operand is ALWAYS taken from that SIGNED caveat, never the body; body generation is only an equality check. The action is derived ONLY from the single signed ability, never a body `state`, query, HTTP method override or generic resource interpretation. The body is not a separate signature envelope: all mutable selection is bound by those signed checks. Body version must be exactly1; future versions cannot be interpreted as v1. Reject URI paths, fragments, queries, wildcards, Space/Network resources, duplicate/multiple abilities and a target whose CID is not the stored canonical lease CID. This route requires canonical CID strings, not alias guessing.

Require invocation audience = current stable node DID; node time only, fresh nonce and current invocation lifetime ceiling (the existing compact profile is ≤60s). No grace or timestamp-only replay protection. Replay identity is **(canonical authenticated invoker, nonce)** through `invoker_nonce_reservation`, NEVER invocation content_hash (re-signing/changing exp must not reuse a nonce). Insert that reservation atomically with the successful state mutation; the state-read route also reserves its nonce in its protected transaction. Repeated successful nonce is refused; recovery reads status rather than performing a second state change. Unknown/transient transaction outcome must not be labelled success.

A Renew lease is NEVER a management proof. The renewer DID remains barred from generic `/delegate` and `/invoke`, and cannot call this owner control route either. The holder cannot stop/re-enable merely because it holds the original grant. An owner changing a setting requires a newly signed explicit request; nothing automatically re-enables after a stop.

## Conditional mutation and D13/D18 semantics

Use the SAME `pg_advisory_xact_lock` keyed by canonical original CID as renew/registration; SQLite uses its reserved write transaction. Begin one write transaction; acquire the canonical-original lock before authoritative reads. Never rely on in-process locks or mix a separate `FOR UPDATE` synchronization regime.

Under that lock re-read canonical original/lease, verified original delegator, lease chain + revocations, original/ancestor current effective ends, current renewer identity epoch, lease end, current state and generation. Check original delegator AND lease signed issuer before producing any lease existence/state-specific response; the owner must still be authorized at commit. Not-found and not-owner have the SAME403 code/message, with no state/generation/leaseEnd details. No404/409 detail is returned to a non-owner. Reject revoked original/ancestor/lease, identity mismatch, an expired lease, or a lapsed original. State changes cannot restore expired or revoked authority (D15/D18).

- **Stop:** conditional `UPDATE ... SET state='stopped', generation=generation+1 WHERE original=$O AND lease=$L AND state='active' AND generation=$expected`. Exactly one row or409. It creates NO stamp, changes NO signed artifact/end/period, and does NOT mark anything revoked. Admitted stamps continue to their previously admitted end under lease, ancestor, revocation and identity constraints.
- **Enable/re-enable:** only the original delegator can conditionally change `stopped → active`, same generation increment, while the original is effectively LIVE and the lease/chain unrevoked, lease end future, epoch current. It writes NO stamp, moves NO end, and continues the existing lease-CID-rooted stamp chain. A revoked lease never returns. A new signed lease is a separate operation; this control cannot silently create a successor or extend90d to1y.
- **Same-state requests:** return409 `renewal_state_conflict`, not a mutation or new stamp. Clients may query status to see the actual state; no hidden retry with a new generation. Nonce and CAS conflicts cannot increment generation twice.

Lease generation is mutation/CAS history only, NOT a use-time equality predicate. Stop/re-enable increments must never invalidate old stamps. Renewer **identity epoch** is separate and remains a use-time validity check. Explicit revocation or true node identity change still invalidates affected stamps. Revocation joins are authoritative at use; even if a competing revoke commits after a successful enable, the state cannot override that revoke.

Commit state update and invocation-replay insertion in the SAME transaction. Rollback both on failure. Audit rows use existing Status read authorization (issuer/delegatee as applicable, or space owner), not extra data access. No new reader may see another holder's lease history. A successful receipt reports only confirmed state:

```json
{"version":1,"originalCid":"<original>","leaseCid":"<lease>","state":"stopped","generation":2,"leaseEnd":"<signed UTC expiry>"}
```

Enable returns active/generation3 for the example sequence. The owner-authorized state read defined below supplies the CAS generation (the current `/delegation/status` response DOES NOT contain it). It must distinguish stopped/active and signed lease end; no success response promises an additional renewal period. If the older node lacks this endpoint, SDK returns unsupported, with no fallback to revoke or silent local-only preference.

## Owner-authorized lease-state read (required for CAS recovery)

Use the SAME proposed `POST /delegation/renewal/state` endpoint, with exactly one signed `tinycloud.delegation/status` capability on `urn:cid:<canonical LEASE CID>`, `prf: []`, and exactly one EMPTY caveat object `[{}]`. Do not accept a generation caveat/extra keys on this read. Body is exactly `{"version":1,"leaseCid":"<canonical lease CID>"}`. This read profile is distinct from mutation’s mandatory one-key caveat; the decoder must not infer operation from normalized empty objects.

Same strict signature/audience/lifetime/nonce and ORIGINAL-delegator == LEASE-issuer checks apply. A generic `/delegation/status` grant or lease recipient’s existing Status rights DO NOT bypass this endpoint’s owner-only rule. No renewer/holder/delegated proof may fetch state here. In a transaction, resolve authority before returning existence/state and reserve `(invoker, nonce)`; same403 for unknown lease and wrong owner. Do not return cached generation. Authorized result:

```json
{"version":1,"originalCid":"<original>","leaseCid":"<lease>","state":"stopped","generation":2,"leaseEnd":"<signed UTC expiry>"}
```

`state`, `generation`, `leaseEnd` are required and current. A successful stop/enable receipt contains the same fields, including leaseEnd, after its confirmed commit. Owner reads may inspect stopped/revoked/expired lease history without mutating it. Existing status/revocation APIs supply revocation/expiry reasons where needed; no additional flags or fabricated state change are introduced by this read. Owner can safely learn generation before signing a new CAS. Unknown transaction outcome → state read with a NEW nonce; never reuse successful mutation nonce or blindly retry a mutation with a guessed generation.

## Error contract (proposed v1)

Responses contain `{version:1,code:<static code>,message:<static safe message>}`; owner text is reviewed separately before implementation. Do not echo request tokens, raw node errors, URLs or signed artifacts. All refusal cases leave state/stamps unchanged; unauthenticated callers do not receive grant details.

| HTTP | Code | Condition |
|---|---|---|
|400|`invalid_request`|Bad CID/schema/version, multiple actions/resources, unknown caveat, invalid integer or malformed nonce.|
|401|`auth_required`|Missing/bad signature, expired/not-yet-valid invocation or wrong node audience.|
|403|`unauthorized_control`|Not-found OR not-owner (same static message/no details); signer must match BOTH original delegator and signed lease issuer. Also renewer/holder/proof/wrong binding/wildcard/Space/Network refusal.|
|409|`renewal_state_conflict`|OWNER-ONLY: wrong state, stale generation, overflow or conditional update not exactly one row.|
|409|`ambiguous_renewal_lease`|OWNER-ONLY: multiple unexpired/unrevoked leases for the original/epoch; no partial stop or automatic resolution.|
|409|`invocation_replay`|Successful nonce already committed; never treat it as a new state change.|
|409|`grant_expired`|Original or any required ancestor no longer effectively live.|
|409|`lease_expired`|Lease reached its signed end; re-enable cannot extend it.|
|409|`grant_revoked` / `lease_revoked`|Original/ancestor or lease chain revoked; status-only outcome, no resurrection.|
|409|`renewer_identity_changed`|Lease belongs to another renewer identity epoch.|
|503|`renewal_state_unavailable`|Database/revocation/registry lookup/commit outcome unavailable; fail closed, do not turn it into404/403 or automatic re-request.|

## Synthetic signed vectors (doc-only; not yet node conformance evidence)

Use #546 fixture `bd2f95ca`'s public synthetic owner seed `11`×32, owner DID `did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S`, original CID `bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4`, lease CID `bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq`, node DID `did:key:z6MkpXveUyjpCDe6P83rNYqAZmoTc9qopJ6GBuRQRotz3zF7`. These are PUBLIC TEST DATA, never live keys.

Known-answer authorizations below were computed locally with existing SDK `signCompactUcanAuthorization` and independently checked by the Ed25519 verifier. Signed bytes are ASCII `<base64url(JCS header)>.<base64url(JCS claims)>`, existing UCAN0.10.0/EdDSA profile; no new signing format or stamp signature domain is introduced. They are proposals to freeze, not executed against a stop endpoint (none exists). All three use nbf1701000000/exp1701000060, fct[{}], no proofs; verifier clock1701000001. Fixture lease signed end1731536000, original signed end1702592000. Preload original/lease/chain as valid, epoch1, and existing first stamp from #546. Tests after original signed expiry must use effective expiry, not discard it locally.

### V1: stop active generation1 → stopped generation2

Request body:

```json
{"version":1,"leaseCid":"bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq","expectedGeneration":1}
```

Signed claims:

```json
{
  "att": {
    "urn:cid:bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq": {
      "tinycloud.delegation/stop-renewal": [
        {
          "expectedGeneration": 1
        }
      ]
    }
  },
  "aud": "did:key:z6MkpXveUyjpCDe6P83rNYqAZmoTc9qopJ6GBuRQRotz3zF7",
  "exp": 1701000060,
  "fct": [
    {}
  ],
  "iss": "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S#z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S",
  "nbf": 1701000000,
  "nnc": "urn:uuid:00000000-0000-4000-8000-000000000001",
  "prf": []
}
```

Authorization (one literal line):

```text
eyJhbGciOiJFZERTQSIsImp3ayI6eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiMEVxeU1uUXJ0S3M2RTJpOVJoWGs1dEFpU3JjYUFXdXZoU0NqTXNsM2h6YyJ9LCJ0eXAiOiJKV1QiLCJ1Y3YiOiIwLjEwLjAifQ.eyJhdHQiOnsidXJuOmNpZDpiYWZrcjRpZ25oM2lvd2E1Z3lzZ2VndHVvc2E2MnBka3c2bXB2cmhzcjN1bWpleTV4MnpvNGZ2amdxcSI6eyJ0aW55Y2xvdWQuZGVsZWdhdGlvbi9zdG9wLXJlbmV3YWwiOlt7ImV4cGVjdGVkR2VuZXJhdGlvbiI6MX1dfX0sImF1ZCI6ImRpZDprZXk6ejZNa3BYdmVVeWpwQ0RlNlA4M3JOWXFBWm1vVGM5cW9wSjZHQnVSUVJvdHozekY3IiwiZXhwIjoxNzAxMDAwMDYwLCJmY3QiOlt7fV0sImlzcyI6ImRpZDprZXk6ejZNa3RVTHVkVHRBc0FoUmVnWVBpWjY2MzFSVjN2aXYxMnFkNEdRRjh6MXhCMjJTI3o2TWt0VUx1ZFR0QXNBaFJlZ1lQaVo2NjMxUlYzdml2MTJxZDRHUUY4ejF4QjIyUyIsIm5iZiI6MTcwMTAwMDAwMCwibm5jIjoidXJuOnV1aWQ6MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAxIiwicHJmIjpbXX0.a7ep_-r1c0emPJJO0p1zQBu9ZGDAbTL1VU_P3GVINGQlwXwIQDkcFm1MWYHGUKGk6qPwGxVEu75FQlGdF5VYDQ
```

Detached signature hex: `6bb7a9ffeaf57347a63c924ed29d73401bbd6460c06d32f5554fcfdc6548346425c17c0840391c166d4c5981c650a1a4eaa3f01b1544bbbe4542519d1795580d`. Signing-input SHA-256: `314cf79709ef6bc8f75da4186e0bc69660e4492c848db949294f0dc99ce5e3ce`.

### V2: enable stopped generation2 → active generation3

Request body:

```json
{"version":1,"leaseCid":"bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq","expectedGeneration":2}
```

Signed claims:

```json
{
  "att": {
    "urn:cid:bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq": {
      "tinycloud.delegation/enable-renewal": [
        {
          "expectedGeneration": 2
        }
      ]
    }
  },
  "aud": "did:key:z6MkpXveUyjpCDe6P83rNYqAZmoTc9qopJ6GBuRQRotz3zF7",
  "exp": 1701000060,
  "fct": [
    {}
  ],
  "iss": "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S#z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S",
  "nbf": 1701000000,
  "nnc": "urn:uuid:00000000-0000-4000-8000-000000000002",
  "prf": []
}
```

Authorization (one literal line):

```text
eyJhbGciOiJFZERTQSIsImp3ayI6eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiMEVxeU1uUXJ0S3M2RTJpOVJoWGs1dEFpU3JjYUFXdXZoU0NqTXNsM2h6YyJ9LCJ0eXAiOiJKV1QiLCJ1Y3YiOiIwLjEwLjAifQ.eyJhdHQiOnsidXJuOmNpZDpiYWZrcjRpZ25oM2lvd2E1Z3lzZ2VndHVvc2E2MnBka3c2bXB2cmhzcjN1bWpleTV4MnpvNGZ2amdxcSI6eyJ0aW55Y2xvdWQuZGVsZWdhdGlvbi9lbmFibGUtcmVuZXdhbCI6W3siZXhwZWN0ZWRHZW5lcmF0aW9uIjoyfV19fSwiYXVkIjoiZGlkOmtleTp6Nk1rcFh2ZVV5anBDRGU2UDgzck5ZcUFabW9UYzlxb3BKNkdCdVJRUm90ejN6RjciLCJleHAiOjE3MDEwMDAwNjAsImZjdCI6W3t9XSwiaXNzIjoiZGlkOmtleTp6Nk1rdFVMdWRUdEFzQWhSZWdZUGlaNjYzMVJWM3ZpdjEycWQ0R1FGOHoxeEIyMlMjejZNa3RVTHVkVHRBc0FoUmVnWVBpWjY2MzFSVjN2aXYxMnFkNEdRRjh6MXhCMjJTIiwibmJmIjoxNzAxMDAwMDAwLCJubmMiOiJ1cm46dXVpZDowMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJwcmYiOltdfQ.RJwsIMaEuh9yMRyKvMhHj06BFANolxxan0a1qLEHAcLEXXTnxtXicyEiNgTp-AAS6m8Q4sX_kTN4rEDl2k1-Dg
```

Detached signature hex: `449c2c20c684ba1f72311c8abcc8478f4e81140368971c5a9f46b5a8b10701c2c45d74e7c6d5e27321223604e9f80012ea6f10e2c5ff913378ac40e5da4d7e0e`. Signing-input SHA-256: `acb42ead8923fd435747920f806c7a5cb0b9b81b17c0a4c055a968cbb9654be7`.

### V3-read: learn the current CAS generation

The existing node `/delegation/status` shape is insufficient. The third signed sample below binds an owner-only state read to the SAME actual lease CID. It uses an independent nonce; afterV1 it must return state=stopped, generation2 and signed leaseEnd, without changing stamps/state.

Body:

```json
{"version":1,"leaseCid":"bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq"}
```

Claims:

```json
{
  "att": {
    "urn:cid:bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq": {
      "tinycloud.delegation/status": [
        {}
      ]
    }
  },
  "aud": "did:key:z6MkpXveUyjpCDe6P83rNYqAZmoTc9qopJ6GBuRQRotz3zF7",
  "exp": 1701000060,
  "fct": [
    {}
  ],
  "iss": "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S#z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S",
  "nbf": 1701000000,
  "nnc": "urn:uuid:00000000-0000-4000-8000-000000000003",
  "prf": []
}
```

Authorization:

```text
eyJhbGciOiJFZERTQSIsImp3ayI6eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiMEVxeU1uUXJ0S3M2RTJpOVJoWGs1dEFpU3JjYUFXdXZoU0NqTXNsM2h6YyJ9LCJ0eXAiOiJKV1QiLCJ1Y3YiOiIwLjEwLjAifQ.eyJhdHQiOnsidXJuOmNpZDpiYWZrcjRpZ25oM2lvd2E1Z3lzZ2VndHVvc2E2MnBka3c2bXB2cmhzcjN1bWpleTV4MnpvNGZ2amdxcSI6eyJ0aW55Y2xvdWQuZGVsZWdhdGlvbi9zdGF0dXMiOlt7fV19fSwiYXVkIjoiZGlkOmtleTp6Nk1rcFh2ZVV5anBDRGU2UDgzck5ZcUFabW9UYzlxb3BKNkdCdVJRUm90ejN6RjciLCJleHAiOjE3MDEwMDAwNjAsImZjdCI6W3t9XSwiaXNzIjoiZGlkOmtleTp6Nk1rdFVMdWRUdEFzQWhSZWdZUGlaNjYzMVJWM3ZpdjEycWQ0R1FGOHoxeEIyMlMjejZNa3RVTHVkVHRBc0FoUmVnWVBpWjY2MzFSVjN2aXYxMnFkNEdRRjh6MXhCMjJTIiwibmJmIjoxNzAxMDAwMDAwLCJubmMiOiJ1cm46dXVpZDowMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDMiLCJwcmYiOltdfQ.hzLmQd4IObMUOwNXAfKTWnxhfeZ1KM2-ekzW7tyU6ruoPdyftqhjjz3QDblzgjzv8-LD-OkXJmXJI0ceH-b8AQ
```

Signature hex: `8732e641de0839b3143b035701f2935a7c617de67528cdbe7a4cd6eedc94eabba83ddc9fb6a8638f3dd00db973823ceff3e2c3f8e9172665c923471e1fe6fc01`; signing-input SHA-256: `d55df0c5258a6d3a96c112d635faf03db8675864bf991b5d16efa4ab5dc8caa3`.

### Required conformance and race vectors

Each mutation below is independently re-signed where stated, so authorization checks—not just bad-signature detection—must fail. Keep positive controls. New fixture/test code is for the FOLLOWING slice only, after freeze.

| Vector | Input/state | Expected result |
|---|---|---|
|V1|Above owner stop, active/gen1, live/unrevoked/current epoch|200 stopped/gen2; no stamp or end changed.|
|V2|Above owner enable afterV1, stopped/gen2, same live lease|200 active/gen3; no stamp/end changed; same stamp chain.|
|V3|Use #546's gen1 stamp after stop/gen2 and after enable/gen3|Still valid until admitted end, unless original/lease/ancestor revoked or epoch changed.|
|V4|Body generation2 with V1 signed generation1 unchanged|403; no mutation/replay insertion.|
|V5|Fresh owner signature/gen1 after successfulV1 state/gen2|409 generation/state conflict; no second increment.|
|V6|V1 exact token reused after success|409 replay; no second increment.|
|V7|Holder seed22×32 signs otherwise valid stop/enable|403; holder is not original delegator.|
|V8|Derived renewer key signs same; or uses Renew lease as proof|403; renewal right is not management right.|
|V9|Owner signs stop resource naming ORIGINAL CID instead of LEASE CID, body unchanged|403 target mismatch.|
|V10|Re-sign wildcard, Space/Network target, extra resource/ability/caveat, or add proof|400/403 according to error table; never broaden via space-owner branch.|
|V11|Clock equals original's EFFECTIVE end, even lease still live|409 grant_expired; enable never revives.|
|V12|Stopped lease but revoked original, ancestor or lease chain|409 revoked; no re-enable/stamp. A fresh lease requires separate authorization.|
|V13|Clock equals lease end; or true node identity changes|409 lease_expired/renewer_identity_changed; no extension.|
|V14|Signature bit flips, audience changed, expired invocation, nbf in future|401; no state changes.|
|V15|Corrupt/unavailable registry or unknown commit outcome|503; no success claim, no automatic revoke fallback.|
|V16|Two processes: same generation, two valid stop nonces|Exactly one commit/gen increment; loser409.|
|V17|Two processes: stop ∥ renew (both use same canonical-original lock)|Renew-before-stop admitted stamp survives; stop-before-renew rejects issuance. No new stamp after winning stop.|
|V18|Enable ∥ revoke original/lease/ancestor|Even if enable receipt wins first, authoritative use-time join rejects all revoked access. Never treat enable as undoing revoke.|
|V19|Stop → enable ∥ a renew that READ STATE BEFORE acquiring the lock (renew signs NO generation)|Renew must re-read lease state/generation after the shared lock. A stopped winner rejects issue; active current state permits only re-evaluated issuance. Existing admitted old stamp remains valid.|
|V20|Restart client after stop/enable, cached expiry claims access|Re-fetch node status/effective expiry; cache is display hint only.|

Additional required vectors: owner-only read returns exact current `{state,generation,leaseEnd}`; unknown lease and known foreign lease return identical403 shape/no state; a deliberately misregistered lease whose issuer differs from the original rejects both read/mutation; duplicate live lease registration conflicts including while first is stopped; re-registering same lease cannot reset state/generation; unknown caveat-array shape/multiple entries/floats reject; same invoker+nonce with newly signed exp/body still409; read nonce cannot be reused as mutation; initial registered state active/gen1 and no registered-stopped mode.

Pin real server success/refusal and multi-process outcomes in implementation tests, not only signed-request fixtures. Verify frozen #545/#546 fixtures remain byte-identical. D13 opt-in-after-stop is explicit owner authorization on a still-live unrevoked lease; no hidden settings-page flow or new approval prompt is imposed by this protocol.

## Review/freeze boundaries

Bobbie: verify direct owner authority vs proof delegation, signed generation/body binding, lease-target choice, nonce/atomic mutation, use-time lease revocation join, stop≠revoke, re-enable races, existing signature-suite support and error classification. Naomi: freeze action strings, route/resource, caveat/receipt AND owner-state-read schemas, ≤1-live-lease cardinality, initial active/gen1 and signed vectors after that review. No generic `ControlAction::Revoke/Status` permission is widened; those routes keep their behavior. No published docs/UI wording or production operation is authorized by this internal proposal.

Primary local references: node d63d4c44 `tinycloud-core/src/encryption_network/delete_auth.rs:301–356` strict owner-control validator template (borrow checks, not key-admin-specific facts); `tinycloud-node-server/src/routes/mod.rs:630` route-family/exact-CID precedent ONLY, not sufficient authentication; `tinycloud-core/src/models/revocation.rs:375-392` ControlAction/party rules and `:480-521` direct-CID vs broader authorization; canonical `design.md` R1–R7; merged expiry spec D13/D15/D18; frozen real lease/stamp #546 bd2f95ca. Actual R5 runtime code is explicitly deferred.
