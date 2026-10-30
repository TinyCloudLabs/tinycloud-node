# Independent vector and transcript checker

Independent TypeScript computation for `../v1/primitives.json`,
`../v1/dkg-genesis.json` and `../v1/reshare.json`, using `@noble/curves` 2.4.0
and Bun 1.4.4. All scalar inputs are public test values.

```sh
bun install --frozen-lockfile && bun run check
```

`check` runs the Bun tests, TypeScript checking, and the real vector CLI over
all three committed documents. The existing `threshold` CI job invokes this
command. To check one JSON file (primitive, DKG or redistribution; the kind is
read from its `spec_sections`):

```sh
bun run vectors /absolute/path/to/document.json
```

The CLI reports each computed record and exits nonzero on a schema, byte,
equation, or expected-error disagreement. Its default paths are relative to the
CLI module, not the calling directory.

## Transcript verification (S0.5)

`dkg.ts` (`dkgVerifyTranscript`) and `reshare.ts` (`reshareVerifyTranscript`)
recompute a whole genesis DKG or reshare/refresh outcome from the raw signed
records, using `ceremony.ts` for the S0.2 layer. Check order:

1. Byte-length sum of every closure body/signature and member envelope/signature
   above 4194304 → `LimitExceeded`, before any decoding or signature.
2. Ceremony statement: decode (`InvalidEncoding`), owner/network against the
   anchor, owner signature, kind and generation rules; genesis `n < 2t−1` →
   `UnsupportedFaultBudget`.
3. Redistribution only: the current certificate (decode, anchor, owner
   signature, evaluated public shares), then ceremony/certificate binding
   (`ContextMismatch`), successor epoch/re-key and refresh shape.
4. Each present record k as closed round k from the start link H0: closure
   ceremony/round/previous hash, owner closure signature, each envelope
   (decode, ceremony/round, signer in its signed cohort, strict RFC 8032
   signature), then the ordered-list commitment.
5. The S0.3/S0.4 classification rules (missing, conflicting, malformed), QUAL
   or D, R4–R6 extraction and reconstruction, then the output identity checks.
   An abort (`InsufficientQualified`, `InsufficientRecovery`) must be the last
   record; missing or additional records are `InvalidRound`.

Per SPEC "Verifier conformance", outcomes (accept/reject, QUAL or D, mpk,
commitments, public shares, excluded dealers) are normative; error codes and
their precedence are informative. Conditions SPEC describes without naming an
error use the defaults in `DEFAULT_ERROR` (`ceremony.ts`), ruled by Naomi on
2026-10-30.

`testkit.ts` builds signed transcripts from the published fixture seeds in
`../v1/cert-core.json`, with payload encoders written separately from the
decoders; expected outputs are computed in the scalar domain. `dkg.test.ts` and
`reshare.test.ts` cover every disqualification/exclusion reason and its
precedence, extraction and reconstruction, identity rejections, caps, entry
checks and strict signatures. `probes.ts` and `transcript-corruption.test.ts`
flip one byte in each field class of every committed record and pin the
checker-order reason codes (informative); re-signed flips reach the rule-level
outcome.
`transcript-vectors.test.ts` perturbs expected outputs and runs the real CLI.

The checker does not open sealed dealings (it holds no recipient keys); a
sealed dealing is decoded by layout, and a ciphertext shorter than the 16-byte
AEAD tag makes that R1 malformed (SPEC S0.3 appendix).
`s02.test.ts` runs the `../v1/cert-core.json` certificate, ceremony and
closed-round records through the same S0.2 layer and covers the §3.9
decoded-certificate rules.

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
| `../../SPEC.md` §§3.0, 3.7–3.12, S0.2, S0.3 and S0.4 appendices; plan r2 §§3.0–3.11, §5, §6 | Ceremony, certificate, envelope, closure and transcript layouts; DKG and redistribution rules (TC-2223) |
| `../v1/primitives.json`, `../v1/dkg-genesis.json`, `../v1/reshare.json`, `../v1/cert-core.json` seeds | Public inputs, expected bytes and fixture signing seeds |
| [RFC 9380 §§5.2–5.3.1](https://www.rfc-editor.org/rfc/rfc9380#section-5.2) | Scalar-field reduction and SHA-256 XMD algorithm |
| [RFC 8032 §5.1](https://www.rfc-editor.org/rfc/rfc8032#section-5.1) | Ed25519 encodings for the strict-verification tests |
| [noble-curves 2.4.0 API documentation](https://github.com/paulmillr/noble-curves/blob/2.4.0/README.md) | Group operations, hash-to-curve, pairings, field API and Ed25519 `zip215: false` |
| npm registry version metadata | Version, integrity and license declarations |

## Dependencies

`bun.lock` freezes package versions and integrity digests. Runtime dependencies
are `@noble/curves` 2.4.0 and its `@noble/hashes` 2.4.0 dependency, both MIT.
Development dependencies are TypeScript 5.9.3 (Apache-2.0), `@types/bun` 1.3.1,
`bun-types` 1.3.1, `@types/node` 26.6.6, `undici-types` 8.9.0,
`@types/react` 19.3.0 and `csstype` 3.2.3 (all MIT). License declarations were
read from the npm registry metadata for those exact versions.

Details: TC-2219, TC-2223
