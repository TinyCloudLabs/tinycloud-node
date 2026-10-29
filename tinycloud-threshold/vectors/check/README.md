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
