# Independent vector and transcript checker

Independent TypeScript computation for `../v1/primitives.json`,
`../v1/dkg-genesis.json`, `../v1/reshare.json`, `../v1/dkg-rekey.json` and
`../v1/chain.json` (and the certificate-core document `../v1/cert-core.json`),
using `@noble/curves` 2.4.0 and Bun 1.4.4. All scalar inputs are public test
values.

```sh
bun install --frozen-lockfile && bun run check
```

`check` runs the Bun tests, TypeScript checking, and the real vector CLI over
all six committed documents. The existing `threshold` CI job invokes this
command. To check one JSON file (primitive, certificate, DKG, re-key,
redistribution or chain; the transcript kind is read from its `spec_sections`):

```sh
bun run vectors /absolute/path/to/document.json
```

The CLI reports each computed record and exits nonzero on a schema, byte,
equation, or expected-error disagreement. Its default paths are relative to the
CLI module, not the calling directory.

## Transcript verification (S0.5)

`dkg.ts` (`dkgVerifyTranscript`) and `reshare.ts` (`reshareVerifyTranscript`)
recompute a whole genesis (or re-key) DKG or reshare/refresh outcome from the raw signed
records, using `ceremony.ts` for the S0.2 layer. Check order:

1. Byte-length sum of every closure body/signature and member envelope/signature
   above 4194304 → `LimitExceeded`, before any decoding or signature.
2. Ceremony statement: decode (`InvalidEncoding`), owner/network against the
   anchor, owner signature, kind and generation rules; a genesis shape other
   than `n >= 2t−1` or exactly 3-of-4 → `UnsupportedFaultBudget`.
3. Redistribution only: the current certificate (decode, anchor, owner
   signature, evaluated public shares), then ceremony/certificate binding
   (`InvalidCeremony`), successor epoch/re-key and refresh shape.
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

## Re-key and chain (S0.5)

A re-key is the S0.3 DKG under an owner-authorized ceremony of kind 4 pinned to the
current certificate. `dkgVerifyTranscript(anchor, statement, records, verify, pinned?)`
is the one DKG entry point: without `pinned` the ceremony must be a genesis, with the
pinned current certificate it must be a re-key, and every other kind, or either kind at
the other call shape, is `InvalidCeremony`. `authorizeRekey` (`dkg.ts`) checks the owner
signature and anchor, kind 4, the pinned certificate (decode, anchor, owner signature,
evaluated public shares), the statement's current digest equal to the pinned digest, the
checked successor `epoch` and `rekey`, and then the §3.0 genesis budget for the *new*
threshold (`UnsupportedFaultBudget`), all before any record is read. Rounds, cohorts
(recipients only; a cohort-2 envelope does not resolve and is refused), H0 label, QUAL,
R4–R6 and output are the unchanged genesis code. An output whose master key equals the
pinned one is refused (SPEC names no code; `DEFAULT_ERROR.rekeyMpk`, informative).

`chain.ts` (`verifyChainStep`, `chainOrder`, `verifyChain`) takes one `chain_step` case
and in this order: sums transcript bytes (`LimitExceeded`); requires a genesis to name no
predecessor and every other kind to name one; recomputes the ceremony outcome through the
DKG (genesis, re-key) or redistribution (reshare, refresh) verifier against the pinned
`previous_certificate`; verifies the candidate certificate (decode, anchor, owner
signature); checks S0.2 lineage by ceremony kind against the pinned predecessor
(`checkLineage`: reshare/refresh keep mpk, `rekey` and `genesis_t`; re-key changes mpk,
names the old mpk, adds one to `rekey` and sets `genesis_t = t`; every successor has the
pinned digest and epoch + 1); rebuilds the canonical body from the recomputed outcome and
the pinned predecessor and requires it byte-for-byte; then verifies every readiness
receipt (strict signature over the READY preimage, no duplicates or non-members) before
counting, the all-holders quorum (`NotEnoughReady` below `n`), and the activation (exact
sorted-receipt-hash preimage, owner signature). `chainOrder` requires the first case to
pin nothing and case k to pin exactly case k−1's certificate (body and signature).
`chain-vectors.ts` holds the chain document schema; only after all of that does it
compare its own kind, epoch, `rekey`, `genesis_t`, threshold, members, mpk, commitments,
public shares, transcript hash, certificate digest, activation and ceremony outcome with
the declared `outputs`, which are never inputs to a decision. Chain error codes that
SPEC does not name (`certificateOutcome`, `lineage`, `chainOrder`) are informative
defaults in `DEFAULT_ERROR`.

`transcript-common.ts` holds the schema pieces and helpers shared by every
transcript-style document; `transcripts.ts` dispatches `dkg`, `rekey`, `reshare` and
`chain` (the chain marker `S0.5 chain appendix` decides before `S0.5 re-key appendix`).

### Adversarial coverage (all built in `testkit.ts` / `chain-kit.ts`, never by editing JSON alone)

`chain-kit.ts` builds whole generations (ceremony, certificate, receipts, activation) in
the scalar domain. A variant re-signs only the record it changes and regenerates the
records that depend on it, so one rule is violated at a time; a control test shows the
harness is clean. `rekey.test.ts` runs the DKG variants through `dkgVerifyTranscript`;
`chain.test.ts` runs the chain variants through `verifyChainStep` / `verifyChain`.

| Finding | Cases (file) |
| --- | --- |
| F1 fault budget | Re-key shapes 2-of-2, 3-of-3, 4-of-4, 4-of-5, 4-of-6, 5-of-8 → `UnsupportedFaultBudget` before any dealing, with and without honest records; 3-of-4, 2-of-3 (and 2-of-4, 3-of-5, 4-of-7, 5-of-9) pass the entry check; budget independent of the old threshold; 3-of-5 with two corrupt members (bad R4 and silence, or silence after R1) reconstructs the genuine mpk; the same shapes refused inside a chain step (`rekey.test.ts`, `chain.test.ts`) |
| F2 selective extraction | Dealer 3 passes member 1's Feldman check only; upheld R5 forces R6, dealer stays in QUAL, genuine contribution recovered; missing R5 barrier, missing R6, extra R6, `InsufficientRecovery`; a chain re-key with the R5 barrier dropped (`rekey.test.ts`, `chain.test.ts`) |
| F3 ceremony-scoped recipient keys | Altered HPKE key or swapped directory DIDs → new digest, edited statement fails the owner signature, re-signed statement leaves every closed round naming the old digest (`InvalidRound`, checked round by round); altered index not canonical; two ceremonies differing only in a recipient key never verify under each other; messages resolve only in this ceremony's directory, never from the old certificate (`rekey.test.ts`) |
| F4 authorization before dealing | Stale, absent, foreign current digest; unchanged, skipped, regressed and u64-maximum `rekey`/`epoch`; kinds 1/2/3 (also with a successor's fields) and 4 at the wrong entry point; genesis statement as re-key and the reverse; redistribution statement at the DKG verifier and re-key at the reshare verifier; changed recipients or threshold versus the signed statement; cohort-2 envelope; master key kept; genesis/re-key transcripts under each other's ceremony and the redistribution H0 label (`rekey.test.ts`) |
| F5 trust anchor | Fully replaced, correctly self-signed previous or candidate certificate for another owner or network (every chain step); foreign ceremony pinned to a foreign certificate; candidate signed by a non-owner key; a chain step pinning a replaced predecessor; pinned certificate for another owner/network/key in the DKG (`chain.test.ts`, `rekey.test.ts`) |
| F6 context binding | Re-key certificate keeping the old mpk (with and without previous mpk), wrong previous mpk, `rekey` unchanged/skipped/zero, `genesis_t` not reset, new mpk differing from the ceremony output; reshare/refresh certificate changing mpk, `rekey`, `genesis_t` or dressed as a re-key; skipped/repeated epoch, wrong or absent previous digest; transcript hash, commitments, mpk, `n` differing from the recomputed outcome, certificate of another ceremony on the same predecessor, a changed dealing; receipts for the previous candidate, for another transcript, key or index; activation over another receipt set, candidate or key; fewer than `n` receipts (including `t′` alone), duplicates, non-members; skipped, repeated, reordered, branched and front-truncated chains; `checkLineage` applied to decoded candidates on its own (`chain.test.ts`) |

`probes.ts` and `transcript-corruption.test.ts` flip one byte in each field class of every
committed record of `../v1/dkg-rekey.json` as for the genesis and redistribution
documents. `chain-probes.ts` and `rekey-chain-vectors.test.ts` flip one byte in the
ceremony, every closure, first and last message of every round, the candidate and
previous certificates, every receipt and the activation of every `chain.json` case (each
must be rejected, with several distinct reasons), perturb every declared output, and run
the real CLI on edited committed documents for each record class (exit code 1 and the
failing case name on stderr).

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
source, Rust tests, Rust diffs or Rust implementation traces were opened. The
re-key and chain extension was written from SPEC §§3.0, 3.7–3.9, 3.12 and the
S0.2–S0.5 appendices and the public `../v1/dkg-rekey.json` and `../v1/chain.json`
only; the expected outputs of those documents are comparison values and were
never fed to a decision.
Dependency implementation files were not opened or used as design inputs.

| Consulted source | Use |
| --- | --- |
| TinyCloud approved design/plan and `../../SPEC.md` §§3.1–3.6, S0.1 appendix | Equations, DSTs, encodings, error ordering and RequestDigest amendment |
| `../../SPEC.md` §§3.0, 3.7–3.12, S0.2, S0.3, S0.4 and S0.5 appendices; plan r2 §§3.0–3.11, §5, §6 | Ceremony, certificate, envelope, closure and transcript layouts; DKG, re-key, redistribution and chain rules (TC-2223) |
| `../v1/primitives.json`, `../v1/dkg-genesis.json`, `../v1/reshare.json`, `../v1/dkg-rekey.json`, `../v1/chain.json`, `../v1/cert-core.json` seeds | Public inputs, expected bytes and fixture signing seeds |
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
