# Primitive vector checker

Independent TypeScript computation for `../v1/primitives.json`, using
`@noble/curves` 2.4.0 and Bun 1.4.4. All scalar inputs are public test values.

```sh
bun install --frozen-lockfile && bun run check
```

`check` runs the Bun tests, TypeScript checking, and the real vector CLI. The
existing `threshold` CI job invokes this command. To check another JSON file:

```sh
bun run vectors /absolute/path/to/primitives.json
```

The CLI reports each computed record and exits nonzero on a schema, byte,
equation, or expected-error disagreement. Its default path is relative to the
CLI module, not the calling directory.

## Computations

- H1 and Pedersen h use the specified RFC 9380 custom DSTs.
- SHA-256 XMD computes H2/H4 and H3 with modulus r, count 1, and L=48.
- Both reduced pairing values use twelve 48-byte big-endian coefficients in
  SPEC §3.2 tower order.
- FullIdent recomputes the ciphertext from explicit sigma, derives the key from
  the public master scalar, and unwraps the encoded tuple.
- Context, identity, request and share layouts are decoded and re-encoded.
  Shares carry both digests in the amended 259-byte layout. Signing preimages
  include the matching request digest explicitly.
- Each share is checked against its scalar/public share and both pairing
  equations. All three 2-of-3 subsets derive the master-derived key and unwrap
  the FullIdent tuple. The recorded aggregate uses the two lowest indices.
- Negative records execute their decoder, verifier or unwrap operation and
  compare the computed typed error, including member attribution.

The share randomizers are not explicit fixture inputs. The checker treats
c1/c2 as public group inputs, verifies their common-randomizer equation, and
recomputes c3 from the scalar share and transport scalar. It does not recreate
the producer RNG from the seed metadata.

`schema.ts` implements the supplied JSON-only handoff shape, including the
current named record set, field widths, literal metadata and additional-field
rules. That shape is a vector-format contract, not a general test-count policy.
Expected cryptographic output bytes are not part of the schema.

The Pedersen derivation message is the SPEC literal `706564657273656e2d68`
(`pedersen-h`). Hashing uses compiled SPEC DSTs, and pairing inputs are checked
against independently constructed points. `constants.test.ts` runs real-CLI
rejection cases for alternate labels with matching points, all five DSTs,
row-local DST copies, both pairing inputs, the identity prefix and the three
S0.1 tagged-hash domains, using in-memory documents.

`protocol.test.ts` uses independently chosen identities, scalar shares,
transport keys and randomizers. It covers point/scalar encodings, request
bindings, both share equations, duplicate members, binding precedence,
zero-randomness aggregates, and FullIdent tuple/identity errors.
`vectors.test.ts` perturbs expected bytes, replaces negative inputs with valid
ones, and runs the real CLI against committed and throwaway JSON inputs.
Tests create private tool homes using `mktemp -d -p /var/tmp`, record the exact
created path, set the homes before writing, and remove that exact directory.

## Provenance

This checker was written in a separate implementation session from SPEC,
public JSON vectors, and the JSON-only schema/byte-layout handoff. No Rust
source, Rust tests, Rust diffs or Rust implementation traces were opened.
Dependency implementation files were not opened or used as design inputs.

| Consulted source | Use |
| --- | --- |
| TinyCloud approved design/plan and `../../SPEC.md` §§3.1–3.6, S0.1 appendix | Equations, DSTs, encodings, error ordering and RequestDigest amendment |
| `../v1/primitives.json` and JSON-only schema/byte-layout handoff | Public inputs, expected bytes and current record format |
| [RFC 9380 §§5.2–5.3.1](https://www.rfc-editor.org/rfc/rfc9380#section-5.2) | Scalar-field reduction and SHA-256 XMD algorithm |
| [noble-curves 2.4.0 API documentation](https://github.com/paulmillr/noble-curves/blob/2.4.0/README.md) | Group operations, hash-to-curve, pairings and field API |
| npm registry version metadata | Version, integrity and license declarations |

## Dependencies

`bun.lock` freezes package versions and integrity digests. Runtime dependencies
are `@noble/curves` 2.4.0 and its `@noble/hashes` 2.4.0 dependency, both MIT.
Development dependencies are TypeScript 5.9.3 (Apache-2.0), `@types/bun` 1.3.1,
`bun-types` 1.3.1, `@types/node` 26.6.6, `undici-types` 8.9.0,
`@types/react` 19.3.0 and `csstype` 3.2.3 (all MIT). License declarations were
read from the npm registry metadata for those exact versions.

Details: TC-2219

## Certificate-core checker portion

The default `bun run vectors` now checks both module-relative inputs:
`../v1/primitives.json` and `../v1/cert-core.json`. An explicit path checks
only that document:

```sh
bun run vectors /absolute/path/to/cert-core.json
```

The existing frozen-install / `bun run check` entry runs all test files,
typechecking and both real CLI paths. No dependency versions changed.

`cert-schema.ts` defines the current named certificate document shape.
`certificates.ts` computes canonical certificate and ceremony encodings,
tagged hashes, Ed25519 signatures, public-share commitment evaluations,
lineage, authenticated closed rounds, readiness/activation and fault verdicts.
`cert-vectors.ts` executes the operations and compares every declared output
or computed error. Format metadata, tags, bounds and role constants come from
compiled definitions, not fixture metadata.

All 17 explicit synthetic-DID seed/public-key mappings are independently
checked with noble Ed25519. These labels form a test signing-key directory;
the checker does not resolve production DIDs. Certificates require the
external owner/network anchor, owner signature, canonical member directory,
commitments and pinned lineage. The checker evaluates public shares from the
input commitments rather than using expected public shares.

Reference lookup indexes only independently recomputed hashes of input
bodies. It returns certificates and ceremonies only after verification.
Expected-output digests are comparison values, never reference authority.
Unresolved, ambiguous and unanchored references are rejected. Record order
does not establish trust.

### Fixture-only omitted-anchor conventions

For `stale-ceremony-predecessor`, `inputs.pinned_predecessor` selects the
independently verified certificate and its external anchor. The body's
encoded current digest does not select a predecessor; it must equal that
explicit pin. The declared stale current value is therefore checked against
the pin, not used as a fallback.

For `genuine-old-response-after-rekey`, the inline certificate is
canonical-decoded to locate its previous digest. That digest must resolve to
an independently verified predecessor. The checker inherits only that
predecessor's rooted external anchor, verifies the inline successor's owner,
network, lineage and signature, then uses its verified current context.
The candidate body's owner/network do not establish an anchor.

These are disclosed cross-record conventions for this fixture, not production
trust or freshness defaults. No trusted-log freshness input is invented.
`certificate-anchors.test.ts` exercises both conventions and the absence of
candidate-owner or first-record fallbacks.

### Round, activation and fault boundaries

Closed-round checking authenticates each exact member envelope under its
signed cohort and directory without fallback, preserves raw payloads and
owner order, verifies the closure, and computes its recursive transcript hash.
The owner relay is trusted; this is not consensus or a freshness mechanism.
Opaque inner payloads are retained, not interpreted as DKG phase outcomes.

Activation checks every receipt signature, including surplus receipts, before
counting, receipt hashing or sorting. Receipts encode as
`01 || index:u16be || lp(signature)` and hash under READY. Their 32-byte hashes
sort in binary lexicographic order. Readiness and activation signatures remain
signed claims, not proofs of possession or durable installation.

Fault checking first requires a verified certificate, matching amended
request/share bindings and the member signature. Only then do the two share
equations determine `Fault(member)` versus `NotAFault(ValidShare)`. Context,
helper or signature failures do not attribute an equation fault.

### Chosen single-byte CLI probes

Each probe uses an in-memory clone and the real CLI through `/dev/stdin`;
the producer file is not rewritten. Offsets below are zero-based decoded
field-byte offsets; each substitution is checked to change exactly one byte.
Offsets are decimal; byte values and XOR masks in the table are hexadecimal.

| Record | Field / byte basis | Changed decision |
| --- | --- | --- |
| genesis-2of3 | outputs.digest[31] XOR 01 | Computed digest comparison |
| reshare-3of4 | outputs.digest[31] XOR 01 | Computed digest comparison |
| rekey-2of3 | outputs.digest[31] XOR 01 | Computed digest comparison |
| ceremony-epoch-0 | outputs.digest[31] XOR 01 | Computed authorization comparison |
| ceremony-epoch-1 | outputs.digest[31] XOR 01 | Computed authorization comparison |
| ceremony-epoch-2 | outputs.digest[31] XOR 01 | Computed authorization comparison |
| closed-round-1 | outputs.transcript_hash[31] XOR 01 | Computed recursive hash comparison |
| activate-all-2of3 | inputs.receipts[0].receipt_hash[31] XOR 01 | Computed receipt hash comparison |
| duplicate-member-did | inputs.body[143], 31 to 32 | Decoder succeeds instead of declared error |
| trailing-certificate-byte | error UTF-8[0] XOR 01 | Schema-only error-label probe |
| stale-ceremony-predecessor | inputs.body[0] XOR 01 | Actual error becomes InvalidEncoding |
| signed-valid-share | outputs.signing_preimage[31] XOR 01 | Computed signing hash comparison |
| signed-bad-share | outputs.signing_preimage[31] XOR 01 | Computed signing hash comparison |
| genuine-old-response-after-rekey | inputs.owner_signature[0] XOR 01 | NotAFault reason becomes InvalidSignature |
| activation-under-quorum | inputs.receipts[0].signature[0] XOR 01 | InvalidReadiness before counting |
| activation-zero-budget | budget encoded u16be[1] XOR 01 | Budget becomes 1; activation succeeds |
| activation-budget-overflow | inputs.candidate[31] XOR 01 | UnresolvedReference before budget evaluation |
| activation-duplicate-member | inputs.candidate[31] XOR 01 | UnresolvedReference before duplicate evaluation |

The trailing-byte row also has a separate valid-body substitution proving its
actual expected-error comparison. Overflow and duplicate rows additionally
substitute a valid budget and unique receipts, respectively, proving semantic
success disagrees with their declared errors. Their one-byte reference probes
are not direct repairs of the budget or duplicated signature. No arbitrary
bit-flip assertion is made.

Independent behavior tests also cover external anchors, canonical boundaries,
lineage, cohort selection, signature-before-quorum ordering and fault-check
precedence. Constant-substitution tests cover all eight tags, fixed format
metadata and alternate-domain matching signatures/outputs.

### Certificate portion provenance and scope

This portion uses the immutable certificate JSON, the approved Rust-free
byte-layout inventory and its two clarified cross-reference conventions,
existing independently written checker utilities, and the
[noble-curves 2.4.0 API README](https://github.com/paulmillr/noble-curves/blob/2.4.0/README.md).
No Rust source/tests/diffs, dependency implementation or other threshold
implementation was consulted.

This is certificate-core checking only. DKG/resharing execution and transcript
outcome recomputation, and full S0.5 completion, remain outside this portion.
Producer API execution is distinct from this independent checker execution.

Details: TC-2223
