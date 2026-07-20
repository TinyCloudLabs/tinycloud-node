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
