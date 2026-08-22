# TinyCloud Policy/v3 delivery trust

This directory documents the node-side trust configuration used by native
sharing. The node stores and serves the owner's content, registers Policy/v3,
authorizes recipient invocations, and signs a narrowly scoped email-delivery
receipt. It does not upload share blobs or delegate content authority to an
email service.

`tinycloud.toml.example` is a non-secret configuration shape. Supply exactly
one copy of the reviewed trust bundle either as a read-only file through
`trust_bundle_path` or as base64 through `trust_bundle_base64`. Configuring
both is a startup error. Private keys, database passwords, credentials, and
delivery tokens do not belong in this file.

The trust bundle must bind these production origins:

- `shareOrigin`: `https://share.tinycloud.xyz`
- `registryOrigin`: `https://registry.tinycloud.xyz` (node discovery only)
- `emailOrigin`: `https://api.share.tinycloud.xyz`
- the exact owner-node origin and node/enforcer identities

`emailOrigin` is required and becomes the audience of the short-lived,
single-use delivery authorization. The node validates the requested recipient,
share URL, label, issuer, audience, expiry, and JTI against the registered
delegation before it signs. `api.share` can then send that exact invitation;
it cannot mint policy, read content, proxy an invocation, or receive a bearer
fragment.

The production node still fails closed on inconsistent origins, keys,
attestation, authority material, or PostgreSQL TLS configuration. The mounted
fixture uses the same validation with test-only authority artifacts.
