# TinyCloud Node share-email deployment

This deployment consumes Share contract commit
`36f6c4303eca3bee917692c77237c264b4dfa342` and manifest digest
`pl8-1Rpx_DYCBjOpK3hRrLfrSVDINNFssZDfFw6BMTs`. A different digest or an
ancestor-only pin is a release failure.

tinycloud.toml.example is the checked-in, non-secret configuration shape for
an enabled exact-email node. Copy it out of the repository, fill in the
operator-delivered paths and mount it with TINYCLOUD_CONFIG_FILE. The single
mounted trust-bundle path is the only production source for the public trust
tuple; missing or inconsistent legacy field overrides fail closed. Never put a
private key, database password, claim, credential, or token in the file.

## Delivering the trust bundle (TC-397)

The trust document has two interchangeable delivery forms, and exactly one may
be configured — setting both is a startup error, because two sources for one
document is the divergence the shared bundle exists to prevent.

- `trust_bundle_path` / `TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_PATH` — a
  read-only mounted file. Use this wherever a host filesystem exists.
- `trust_bundle_base64` / `TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_BASE64` — the
  same bytes, base64-encoded, inline in the environment.

The inline form exists because the dstack/Phala target admits nothing else.
The release image's runtime stage is `FROM scratch`, so there is no shell and
no `base64` binary — the decode-to-tmpfs entrypoint `share-api`'s compose file
uses cannot be reproduced here — and a Phala deployment uploads only a compose
file, so there is no host path to bind-mount a bundle from. An opaque
environment variable is the one channel that reaches the container. It is
base64 rather than raw JSON because Figment's `Env` provider interprets brace-
and bracket-delimited values as structured data; a base64 token passes through
Figment, YAML and dstack's sealed environment storage byte-for-byte.

Produce it from the reviewed document without a trailing newline or line
wrapping:

```sh
SHARE_TRUST_BUNDLE_BASE64="$(base64 < trust-bundle.production.json | tr -d '\n')"
```

`share-api` reads the same document from a variable of the same name and in the
same encoding, so a single sealed value can feed both services and cannot drift
between them.

### `emailOrigin`

The document carries an `emailOrigin` field that Share's schema requires (it
feeds the CSP `connect-src` without which the browser blocks the send). The
node validates it — canonical HTTPS origin, no path, query, fragment, port or
credentials, and covered by the production placeholder scan — but does not
consume it, exactly like `shareOrigin` and `registryOrigin`. It is optional on
this side so that adding it did not become a breaking change to an unchanged
document version; the requirement is enforced by Share, its only consumer.
Unknown fields are still rejected.

The staging compose file consumes that mounted config and has no development
or test fallback. It requires an immutable image reference, a PostgreSQL URL,
the CA bundle, issuer and invitation public keys, the signed authority bundle,
and the node key source. The node then refuses startup when any of these are
partial or inconsistent:

- `allowed_origins` is exactly `https://share.tinycloud.xyz`; wildcard CORS is
  never accepted for the share routes.
- issuer DID, `opencredentials.email/v1`, issuer `kid`, key version, and
  public key form one pinned trust tuple.
- invitation `kid` and public key match the node signer derived from
  `TINYCLOUD_KEYS_SECRET`.
- the authority bundle contains cryptographically verified policy and
  enforcement material, enrollment, two fresh status observations, and a
  current runtime attestation.
- PostgreSQL uses `sslmode=verify-full` and the configured CA bundle exists.
- the database transaction and all signed evidence pass the startup readiness
  probe before `/info` advertises `share-email-claim`.

The mounted fixture uses the same production composition and derives its node
signer from the configured key secret. Its generated authority artifacts are
test data only and are never accepted by this deployment template.
