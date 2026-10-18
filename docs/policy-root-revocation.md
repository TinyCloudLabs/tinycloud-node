# Revoking a Policy/v3 root (TC-1423)

A policy has two roots, the policy root and the enforcement root. Both are
signed by the policy owner (`ownerDid`), which may be an agent or session key
of the space owner. There are two ways to revoke a root, both `POST /revoke`.

## Generic route (SIWE or UCAN)

The root is an ordinary delegation in the graph, so the core revocation rules
apply. These principals may revoke it:

- the root's signer (its delegator, `ownerDid`);
- the owner of a space that the root's abilities touch, for example the
  wallet (did:pkh, over SIWE) that owns the content space of an agent-signed
  root;
- the holder of a revoke control that one of them granted. A
  `<space>/delegation` control covers the root's kv rows. The root's
  `encryption/decrypt` row needs a control that names that exact encryption
  network (typed control scope), so a space-only control gets 403 on a
  decrypt-bearing root.

Recipients, session holders, other agents of the same owner, and unrelated
principals get 403. The revocation applies on every later use:

- admitted sessions' reads, and reads by their re-shared children, get `403
  root-revoked`;
- the decrypt route authorizes the session chain before the policy checks, so
  a decrypt gets the core `401 delegation-ancestor-revoked`;
- challenge and mint are refused.

A policy session grants only kv and decrypt, so it can't mint a hook ticket
(`401 Unauthorized Action`). There is then no hook stream to close, and the
300-second bound for open streams after a JSON-route revocation doesn't apply
to policy roots.

## JSON route (`RootRevocation/v1`)

Only the root's own signer may use it, or the enforcer for the enforcement
root. The signature is Ed25519. Any other issuer, including the space owner,
gets `403 root-revocation-issuer-invalid`.

## Client rule

- The root's own signer (or the enforcer, for the enforcement root) uses the
  JSON route.
- Every other revoker uses the generic route on the root CID: the owner's
  wallet over SIWE, or a control holder citing its control.

## Confirming a revocation

Confirm on the CID you revoked, with `POST /delegation/status`, or with the
owner listing where the node offers it.

After a generic revocation of a root, `GET /policy/v3/status/<root>` returns
`state: revoked` over the last signed checkpoint, whose own `state` stays
`active`. Clients that require the two to match (the released SDK) report an
error, so this route is not a confirmation. Renewal (`POST
/policy/v3/status`) returns `409 root-revoked`.

After a JSON-route revocation, both `state` values are `revoked`.

The released SDK parser also rejects a checkpoint whose `freshUntil` is more
than 300 seconds after `checkedAt`. The node sets `freshUntil` to the root's
expiry, so the parser may reject a root that lives longer than 5 minutes even
while it is active (TC-1450).
