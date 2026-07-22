# TinyCloud exact-email claim v1 — frozen Wave 0 contract

This directory is the language-neutral contract. Consumers load and verify
`test/vectors/email-claim-v1/manifest.json` before using any fixture. The
fixture set is test-only; its private keys MUST never be used in production.

## Canonical bytes

All protocol messages use RFC 8785 JCS UTF-8. v1 JSON numbers are integers
only; the implementation rejects fractional, non-finite, unsafe integers,
`-0`, undefined/functions/symbols,
non-plain objects, and lone UTF-16 surrogates. Object keys are sorted by UTF-16
code unit. Binary is strict unpadded base64url. Every signed artifact,
including the shipped envelope, signs exactly
`UTF8(domains[artifact]) || UTF8(JCS(message))`. The envelope domain is
normative and is not optional or a future compatibility patch.

The shipped envelope body is the strict object:

```json
{"version":1,"shareId":"…","delegation":"…","authorizationTarget":{"kind":"policy","policyCid":"…","policyBytes":"…"},"target":{"origin":"https://…","nodeAudience":"did:web:…","spaceId":"…","resource":{"kind":"exact","path":"…"}},"display":{},"expiry":"…"}
```

The signed target is a discriminated union. A policy target always contains
`kind`, `policyCid`, and `policyBytes`; policy bytes are canonical bytes of a
policy descriptor that contains neither `policyCid` nor `shareCid`. The CID is
computed independently as CIDv1/raw/SHA-256 over those exact bytes and the
bytes are embedded in the target. The share CID is computed over the complete
shipping sealed blob (`version || nonce || ciphertext`) using the same
CIDv1/raw/SHA-256 rule; fixture blobs are deterministic test blobs.

## Email and sources

The protocol accepts only an ASCII addr-spec. The local part is RFC 5322
`dot-atom-text` using `atext` and is preserved byte-for-byte; only the domain
is ASCII-lowercased. Leading, trailing, repeated, or interior whitespace,
quoted/commented locals, Unicode, multiple `@`, and invalid LDH/A-label DNS
labels are rejected. Limits are byte limits, not JavaScript character counts.
`documentName` is a non-empty printable string capped at 200 UTF-8 bytes; a
string with fewer than 200 JavaScript code units can still be rejected when it
contains multi-byte characters.

`contentSource` is a strict KV or named-SQL union. SQL v1 arguments are a flat
object with at most 32 properties; every value is a safe JSON integer and
negative zero is rejected. Their JCS UTF-8 bytes are separately digested and
bounded to 4096 bytes. Raw SQL transport is never part of this contract. Both
source and source digest are carried byte-for-byte by every signed artifact.

The email credential uses the OpenCredentials SD-JWT profile: claims carry
`_sd_alg: "sha-256"`, and the sole email object disclosure decodes exactly to
`[salt, "email", canonicalEmail]`. Fixture salts are deterministic and the
disclosure digest is SHA-256 over the encoded disclosure string. The issuer
compact JWT uses the library profile (`alg: "EdDSA"`); the test-only salt and
keys are not production material.

`shareUrl` is exactly `https://share.tinycloud.xyz/s/<share-CID>#k=<32-byte
base64url>`. The parser rejects HTTP, userinfo, ports, alternate hosts or
paths, query strings, duplicate fragment keys, unknown keys, percent-encoding,
and non-canonical base64url. Scanner fragments additionally carry exactly one
32-byte `k`, one 16-byte `i`, and one 32-byte `c`; scanning is read-only.

The node authority tuple is frozen as `https://node.example` ↔
`did:web:node.example`. An enrollment is accepted only when enabled, on the
authority's active key version, and with the matching key ID/public key.
Rotation uses a strictly higher version; retired or disabled versions reject
both new proof verification and enrollment. Issuer trust is likewise an exact
issuer-DID, VCT, and enabled Ed25519 public-key tuple.

## Authority-material profile

The v1 authority seam is a strict, sender-signed wrapper containing exact
Node #117 parent artifacts, with registry domain
`xyz.tinycloud.share/authority-material-bundle/v1\0`.
Its preimage is exactly `UTF8(domains.authorityMaterial) ||
UTF8(JCS(bundle))`; the artifact wrapper records the JCS, message digest,
signed-byte digest, signature digest, Ed25519 `kid`, and signature. The
The wrapper freezes `policyOwnerDid` and `senderDid` as an authenticated,
distinct relationship: the policy owner signs the exact Node parent bytes,
while the invitation sender signs the Share authorization and wrapper. The
handle (`amh_kv_001` or `amh_sql_001`) is an authenticated lookup handle,
never authority and never a substitute for the bundle.

The bundle maps the existing Share `policyCid` and `delegationCid` to exact
canonical bytes and CIDv1/raw/BLAKE3-256 CIDs for #117 `PolicyAuthority` and
`PolicyEnforcement`. Share CIDs, Share delegation CIDs, PolicyAuthority CIDs,
and PolicyEnforcement CIDs remain separate identifier domains. Each parent has
a separately signed status observation with a monotonic sequence,
checkedAt/freshUntil bounded to 300 seconds, and irreversible revocation. A
separately signed runtime attestation binds target origin/audience, enforcer
DID/key/version, local signer, measurement/digest, expiry, and enrollment
digest. Every frozen authorization, holder binding,
policy challenge/presentation/session, and read invocation carries
`delegationCid`, `authorityMaterialHandle`, and `authorityMaterialDigest`.

Every positive scenario supplies an explicit `evaluationTime` and
`clockSkewSeconds`. Credential `iat`/`nbf`/`exp` are checked against those
values, and `exp` is also exactly the share expiry. The credential must have
the sole `/email` disclosure and the complete four-field `tinycloud_share`
scope; all signed re-bindings are checked against the same holder, node,
source, share, and policy values.

## API and state coverage

`schemas.json` and `authority-material.schema.json` cover every invitation-create, resend, claim-challenge,
claim-redeem, policy-challenge, policy-session, and read request, success, and
failure surface from product spec §§6 and 9. `claimRedeemRequest` is a
discriminated `oneOf`: `magic` carries a 32-byte claim secret and `otp` carries
exactly six decimal digits. Policy challenge/session response wrappers carry a
strict node proof bound to their signed challenge/session artifact; claim
challenge responses retain both `contentSource` and `contentSourceDigest`.
Capability descriptors are
validated against their strict schema and route allowlists. `negative.json` is
executable: every applicable row drives a native schema/CID/JCS/DID/signature/
reference validator or a re-signed mutation in each consumer. Rows contain
concrete deterministic mutation/input data; symbolic scenario references are
forbidden. JavaScript executes cryptographic/schema mutations, strict
TypeScript independently executes the serialized mutation semantics, and Rust
independently executes the same serialized mutations and equations. Unknown
row IDs fail all three consumers. `states.json` is executed as a transactional
model covering resend/provider acceptance/crash recovery, pending encrypted
issuance-seed retry, and atomic issuance resolution. Before the single success
event there is no durable result; that event persists the credential/result,
marks the invitation `CONSUMED`, and deletes the seed together. The terminal
error event likewise persists the terminal result, marks the invitation
`CONSUMED`, and deletes the seed atomically. Provider acceptance is confined to
delivery; issuance recovery models credential generation and durable credential
persistence separately. The model also covers cleanup refusal, OTP, JTI, nonce,
redemption idempotency, and scanner GET boundaries. `states.json` contains a
serialized `operationProgram`; every operation carries pre/post durable rows
and explicit `transaction`, `crash`, `retry`, or `reject` operations. JavaScript
interprets that program to execute premature resend invalidation, provider
failure/recovery, atomic success/failure rollback, cleanup refusal, twenty
same-redemption contenders with one issuance, different-redemption rejection,
OTP wrong-vs-invalid-magic isolation, nonce/JTI replay, and a valid scanner GET
with no mutation. The redaction window is 900 seconds from durable completion
only.

The envelope domain is `xyz.tinycloud.share/envelope/v1\0`. The checked-in
shipping envelope package signs and verifies the envelope body with that
domain-separated input. This fixture suite and the package tests therefore
share one normative preimage. A consumer MUST reject a bare-JCS envelope
signature; there is no bare-JCS compatibility mode, migration exception, or
runtime flag that can enable one.

Run the complete contract suite with:

```sh
node test/vectors/email-claim-v1/build.mjs
node test/vectors/email-claim-v1/validate.mjs
tsc --noEmit --target ES2022 --module ESNext --moduleResolution bundler --strict --skipLibCheck test/vectors/email-claim-v1/loader.ts
bun test/vectors/email-claim-v1/loader.ts
cargo fmt --check --manifest-path test/vectors/email-claim-v1/rust/Cargo.toml
cargo clippy --offline --manifest-path test/vectors/email-claim-v1/rust/Cargo.toml -- -D warnings
cargo test --offline --manifest-path test/vectors/email-claim-v1/rust/Cargo.toml
cargo run --offline --manifest-path test/vectors/email-claim-v1/rust/Cargo.toml
```

The Rust verifier independently checks fixture bytes, signatures, SD-JWT
disclosure shape/digests, cross-artifact equations, native negative mutations,
and state invariants. It does not claim to execute JavaScript schema callbacks;
each language validates the serialized contract with its own native checks.
