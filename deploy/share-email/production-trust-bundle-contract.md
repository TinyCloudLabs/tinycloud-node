# Production share-email trust-bundle contract

This is the durable hand-off contract for the reviewed public trust bundle. It
contains no private key material. Share owns the reviewed JSON artifact after
Share#102; TinyCloud Node consumes exactly one copy and refuses to start the
share-email capability if its fields do not meet this contract.

## Required fields

The JSON version is `tinycloud.share-email-trust-bundle/v1`. Its production
origins are exact strings:

- `shareOrigin` and `returnOrigin`: `https://share.tinycloud.xyz`
- `registryOrigin`: `https://registry.tinycloud.xyz`
- `credentialsOrigin`: `https://witness.credentials.org`
- `emailOrigin`: `https://witness.credentials.org`

`emailOrigin` is the independently checked generic invitation-delivery
audience, currently co-located with credential issuance at
`https://witness.credentials.org`. It is not a route served by Node and must
match the origin receiving `POST /v1/credential-invitations`.
Node exposes Policy/v3 admission/control and ordinary `/delegate` and `/invoke`
data-plane routes only; it does not expose `/share` routes or proxy delivery.

For addressed delivery, Share sends `POST /policy/v3/deliveries/authorize` a
body of `shareUrl`, `recipientEmail`, `documentName`, `jti`, `expiresAt` and
`requestBodyDigest`. `shareUrl` is the short link
`<returnOrigin>/s/<id>#v=4&k=<key>&c=<cid>`: the id names a record in the links
API, the key is the AES-256-GCM key of the record's sealed envelope and `c` is
the CID of the sealed bytes. The key stays in the link's fragment. Node reads
the record for `<id>` from `share_email.links_origin` (default
`https://api.tinycloud.xyz`; `https://host[:port]` only, checked when the
configuration loads; `share_email.links_origin_allow_private = true` permits a
host on a private network for a self-hosted links API), checks that the
record's header is signed by the policy owner's key, that the sealed bytes
match both `bodyCid` and `c`, that the record expires no later than the share,
and that the decrypted canonical envelope, exact recipient and delivery
authorization all agree. Node never writes the link or its key to a log, an
error response or a stored row.

Before the fetch, each request passes a per-invoker token bucket (burst 5,
`share_email.links_fetch_per_invoker_per_minute`, default 20) and a node-wide
cap on fetches in any 60 seconds (`share_email.links_fetch_global_per_minute`,
default 90, at most 110: the links API allows 120 reads a minute per client
address). A request over either limit is answered `429 delivery-rate-limited`
with `Retry-After` before anything is fetched; only requests that reach the
fetch count against the limits.

Each links API read is signed with the node identity key (`TinyCloud-Read-Auth`).
An operator reads the node's DID from `GET /info`, field `nodeId`, and lists it
in the API's `links.readSigners`. A read signed by a DID that is not listed is
served as an ordinary unauthenticated read, at the lower unauthenticated rate;
the node's handling of the response is the same.

The node identity must be internally exact, not merely a canonical DID:

- `nodeAudience` is `did:web:<nodeOrigin host>`;
- `nodeInvitationKid` is
  `<nodeAudience>#invitation-key-<nodeKeyVersion>` and the version is positive;
- `nodeInvitationPublicKey` exactly equals the public descriptor derived by the
  production Node `TINYCLOUD_KEYS_SECRET`; and
- `nodeEnabled` is `true`.

The issuer identity is exact: `issuerDid` is
`did:web:issuer.credentials.org`, `issuerVct` is
`opencredentials.email/v1`, `issuerKid` belongs to that DID, its key version is
positive, its public key is canonical, and `issuerEnabled` is `true`.

The separately owner-signed authority material must bind every Policy/v3
`enforcerDid` to the same Node `nodeAudience`; the enforcer binding signature
is checked against that Node's derived attestation key at registration. This
keeps the concrete enforcer identity coupled to the concrete Node identity
without copying a deployment-specific DID into source control.

## Delivery and release hand-off

Share serializes the reviewed JSON compactly and base64-encodes it without
line wrapping. Before a Node release, the release owner places that exact value
in the GitHub secret `PROD_TINYCLOUD_SHARE_TRUST_BUNDLE_BASE64`. The deploy
workflow passes it as `SHARE_TRUST_BUNDLE_BASE64`; the Node runtime consumes it
as `TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_BASE64`. A mounted deployment instead
sets `TINYCLOUD_SHARE_EMAIL_TRUST_BUNDLE` to the reviewed JSON file and uses
`trust_bundle_path`.

Do not set both sources. Do not create a substitute `api.share.tinycloud.xyz`
or `email.tinycloud.xyz` audience: Node rejects it in non-fixture builds.
Share must emit the generic OpenCredentials origin before it removes or
rotates its legacy bundle. Node validates this contract before
advertising share-email readiness, so a missing, malformed, mismatched, or
fixture bundle fails closed.
