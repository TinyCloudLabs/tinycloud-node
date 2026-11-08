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
fetch count against the limits. The per-invoker limit is kept for each invoker;
the node-wide limit is shared by all invokers.

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

## Issuer-key rotation with a bounded overlap

The existing single-key bundle remains valid. To rotate the issuer while
preserving verification of credentials already in flight, keep the current
issuer in `issuerDid`, `issuerKid`, `issuerPublicKey` and
`issuerKeyVersion`, then add:

- `nextIssuer`: one `CredentialIssuerConfig` for the same
  `did:web:issuer.credentials.org`, with a distinct `kid` and public key,
  `alg: "EdDSA"`, the existing email VCT and both existing email profiles;
- `issuerNotAfter`: a UTC RFC 3339 timestamp ending the current key's trust.

The next key's `notBefore` must be no later than `issuerNotAfter`. The node
accepts either pinned key before the end time and refuses the old key at or
after it. The end time is mandatory; an unbounded same-DID overlap, a duplicate
key or `kid`, an invalid timestamp, or an already-expired end makes startup
and `--validate-config` fail closed.

### Verify a new issuer key

Do not add a key copied only from a DID document, HTTPS response, or `GetKey`
response. Obtain from Phala the exact witness application ID and key domain,
the complete dstack `GetKey` result including its `signature_chain`, and the
KMS root SPKI from `DstackKms.kmsInfo().k256Pubkey`. Authenticate that root
independently against Phala's attestation or signed publication; do not trust a
root fetched only from the same unauthenticated endpoint as `GetKey`. Verify
the app-key claim over the raw returned public key and its application
ID/domain, then verify the KMS signature over that claim using the
independently authenticated root. Verify that the resulting 32-byte Ed25519
public key is the witness DID document's
`did:web:issuer.credentials.org` verification method, obtained through a
Phala-attested or RA-TLS-verified channel. Record the evidence and verifier
output with the rotation change. If Phala cannot provide the app ID/domain,
complete chain, or independent root authentication, stop; do not pin the key.

### Seal, deploy, and remove the overlap

1. Review the public key and bundle diff. Keep the current issuer fields
   unchanged; add the verified next issuer and a fixed UTC `issuerNotAfter`
   chosen with enough time for every consumer to receive the new key. The
   overlap must be operationally bounded, not extended by default.
2. Compactly serialize the exact JSON and base64-encode it without line
   wrapping. Put that exact value in
   `PROD_TINYCLOUD_SHARE_TRUST_BUNDLE_BASE64` through the normal secret-change
   process. Never put the bundle value in a PR, workflow log, or chat. Run
   `--validate-config` and the issuer-verification tests against the reviewed
   artifact before release.
3. The Share producer, browser verifier, and any other bundle consumer must
   be updated to accept `nextIssuer` and the bounded overlap before this
   bundle is activated. Their current single-key strict parsers reject these
   fields; this Node change alone is not an end-to-end rotation.
4. Before `issuerNotAfter`, publish a second reviewed bundle that promotes the
   next key into the top-level `issuerKid`, `issuerPublicKey`, and
   `issuerKeyVersion` fields, and removes `nextIssuer` and `issuerNotAfter`.
   Update every consumer to the same single-key bundle, verify configuration
   and credential checks, then allow the old key's deadline to pass. Do not
   leave an expired overlap in the bundle: it intentionally prevents startup.

If the node's own `GetKey("tinycloud/keys/primary")` output changes, derive
`nodeInvitationPublicKey` from that production key using the existing node
key-provider procedure; do not generate or substitute a key. Set
`nodeKeyVersion` to the version associated with that public key and set
`nodeInvitationKid` to
`<nodeAudience>#invitation-key-<nodeKeyVersion>`. Recheck `nodeAudience`,
`nodeEnabled`, and the enforcer DID binding in the separately signed authority
material. The issuer-key overlap itself does not change the node invitation
key or node key version.
