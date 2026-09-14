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
- `emailOrigin`: `https://email.tinycloud.xyz`

`emailOrigin` is the delivery-receipt audience, not a route served by Node.
Node exposes Policy/v3 admission/control and ordinary `/delegate` and `/invoke`
data-plane routes only; it does not expose `/share` routes or proxy delivery.

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
audience: Node rejects it in non-fixture builds. Share must update its
downstream bundle producer to emit `https://email.tinycloud.xyz` before it
removes or rotates its legacy bundle. Node validates this contract before
advertising share-email readiness, so a missing, malformed, mismatched, or
fixture bundle fails closed.
