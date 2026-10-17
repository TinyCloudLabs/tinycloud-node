# At-rest key escrow (TC-887)

Nothing in the node binary uses these two crates yet.

- `tinycloud-at-rest-escrow` (a node workspace member) holds the escrow format:
  - the 2-of-3 split of the at-rest root key (ARK);
  - shares sealed to age recipients;
  - the bundle and its fingerprint;
  - the canary;
  - the verification record;
  - the recovery wire format.
- `tinycloud-at-rest-cli` is the `tinycloud-at-rest` tool that holders and operators run.
  - It is a Cargo workspace of its own, with its own `Cargo.lock`.
  - Its DCAP verifier and HTTP stack never enter the node's dependency graph or feature set.

Build the tool from the release tag you are verifying:

```sh
cargo build --release --locked --manifest-path tinycloud-at-rest-cli/Cargo.toml
# tinycloud-at-rest-cli/target/release/tinycloud-at-rest
```

## Formats

`lp(x)` is `u32 BE length ‖ x`. Digests are SHA-256, written in lowercase hex.

- **Share.**
  - The ARK is split with Shamir over GF(256) (`vsss-rs` 5.4.0): threshold 2 of 3, and share `i` has x-coordinate `i`.
  - The sealed plaintext is `"TCS1" ‖ ark_id(16) ‖ generation u32 BE ‖ i ‖ share(33)`, 58 bytes.
- **Recipients.** Each share is age-encrypted (`age` 0.12.1, ASCII armor) to one holder. The recipient type can be:
  - `age1yubikey1…` (`piv-p256` stanza). This is what released age-plugin-yubikey (0.5.x) prints and decrypts. The stanza is produced exactly as the plugin's own `wrap_file_key`, so the TEE needs no plugin.
  - `age1tag1…` (`p256tag` stanza). This is native age 1.3 tagged P-256. The released age-plugin-yubikey 0.5.1 **cannot** decrypt it, so every command warns when a holder uses one.
  - `age1…` X25519. These are software keys, refused unless software recipients are explicitly allowed (`--allow-software` on the CLI; tests and self-hosted nodes only). Every command prints a warning while that is in effect.
  - A recipient format proves which kind of key decrypts, **not** where the private key lives. That a P-256 key was generated on a YubiKey is established in the escrow ceremony.
- **Commitment.** `SHA-256(lp("tinycloud/at-rest/escrow-share-commit/v1") ‖ ark_id ‖ generation ‖ i ‖ lp(share))`.
- **Canary.**
  - `canary = HKDF-SHA256(ikm = ARK, salt = ark_id, info = lp("tinycloud/at-rest/escrow-canary/v1") ‖ generation)`.
  - `canary_fp = SHA-256(lp("tinycloud/at-rest/escrow-canary-fp/v1") ‖ ark_id ‖ generation ‖ lp(canary))`.
- **Bundle.** JSON with `version`, `ark_id`, `generation`, `threshold`, `canary_fp`, and `shares[{index, holder, recipient, commitment, ciphertext}]`. Unknown fields are rejected.
- **EFP (escrow fingerprint).** `SHA-256(lp("tinycloud/at-rest/escrow-bundle/v1") ‖ version ‖ ark_id ‖ generation ‖ threshold ‖ canary_fp ‖ n ‖ for each share: i ‖ lp(holder) ‖ lp(recipient) ‖ commitment ‖ SHA-256(ciphertext))`.
- **Verification record.**
  - It is JSON naming the EFP, all three indices and all three pairs, with an HMAC-SHA256 under `HKDF(ARK, salt = ark_id, info = lp("tinycloud/at-rest/escrow-record/v1"))`.
  - Only the ARK holder (the TEE) can make or check the MAC. `record-efp` checks only the public fields and says so.
- **Recovery binding.**
  - The binding string is `xyz.tinycloud.at-rest/recovery-key/v1\0:<recovery recipient>:<efp>:<nonce>`, where `\0` is two characters.
  - A TDX quote's REPORTDATA must be `SHA-256(binding) ‖ 32 zero bytes`.

## Commands

Every command that reads a bundle:
- refuses software holders unless `--allow-software` is given;
- accepts `--expect-efp E` (case-insensitive) and refuses a bundle with any other EFP.

Bundles, records and the node's recovery response carry a `version`, which is checked before any other field. A newer format is reported as "version N; this tool reads version 1".

Exit codes:
- `0`: OK.
- `1`: REFUSED. A check failed: don't release a share and don't pin a value.
- `2`: usage error.
- `3`: ERROR. A file, stdin or the PCCS couldn't be read.

| Command | Reads | Prints |
|---|---|---|
| `recipients --holder NAME=RECIPIENT` ×3 | — | `[at_rest.escrow]` TOML and the compose env line |
| `self-test --recipient R [--out DIR]` | — | a throwaway escrow whose share 1 is sealed to `R` by the TEE's own code (ceremony step 0) |
| `nonce` | — | 32 random bytes, base64url |
| `inspect --bundle B` | bundle | EFP, ark_id, generation, canary_fp, each holder's recipient kind |
| `extract-share --bundle B --holder H` | bundle | holder H's armored age file |
| `check-share --bundle B` | decrypted share on **stdin** | which share it is; refuses on a commitment mismatch (e.g. a share from an earlier split) |
| `verify-compose --app-compose A --trust T` | the deployment's `app-compose.json` | OK if it hashes to `compose_hash` and its compose YAML passes the strict check below; also lists the other app-compose settings to review |
| `verify-node --bundle B --recovery R --nonce N --trust T [--collateral C \| --pccs-url U]` | node's recovery response | OK (with node state and shares held) or REFUSED |
| `share-wrap` (same flags) | decrypted share on **stdin** | after `verify-node` passes: the share sealed to the node's recovery key |
| `record-efp --bundle B --record V` | record | `TINYCLOUD_AT_REST__ESCROW__VERIFIED_FP=<efp>`, marked NOT AUTHENTICATED: the record's MAC is checked only in the TEE |

A decrypted share only ever arrives on stdin (`age -d -i <identity> share.age | tinycloud-at-rest …`). It never goes on argv or to a file.

### What `verify-node` and `share-wrap` check before releasing a share

All of these must hold, or the command prints `REFUSED: …` and exits 1:

1. The node answered as an attested TEE: `mode` is `dstack` and a quote is present.
2. The node's `efp`, `ark_id` and `generation` equal the holder's own bundle.
3. The node's binding is exactly the one recomputed from the recovery recipient, that EFP, and the holder's nonce (at least 22 characters). A response made for any other nonce is stale.
4. The quote passes Intel DCAP verification with `dcap-qvl` 0.7.0: signature, PCK chain, CRLs, TCB info and QE identity. Collateral comes from the PCCS (Phala's by default; Intel PCS also works) with a 60 s timeout, or from `--collateral`, and is checked at the current time.
5. The TCB status is one fixed class:
   - `UpToDate` passes.
   - `SWHardeningNeeded`, `ConfigurationNeeded` and `ConfigurationAndSWHardeningNeeded` pass only if the policy lists them and pins every advisory ID the TCB level carries.
   - `OutOfDate*`, `TDRelaunchAdvised*`, `Revoked` and unknown statuses never pass.
   - On a pass, the status, the advisory IDs and the collateral dates are printed.
6. The TD debug bit is clear.
7. MRTD and RTMR0-2 equal the trust policy.
8. The dstack event log replays to the quoted RTMR3:
   - each `boot-mr-done` and `system-ready` marker appears once, in that order;
   - exactly one `app-id` and one `compose-hash` event appear, each before `boot-mr-done`, and each equals the trust policy;
   - v2 events must carry their canonical preimage.
9. The quoted REPORTDATA is `SHA-256(binding) ‖ 0³²`.

Not pinned: `key-provider`, `instance-id`, `os-image-hash`, XFAM, MRCONFIGID, MROWNER and MROWNERCONFIG. RTMR0-2 and the compose hash cover what the per-boot, in-memory recovery key depends on.

`compose_hash` pins container images only if `app-compose.json` references every image by digest. `verify-compose` parses the compose YAML with a real parser and accepts only a small subset:
- exactly one document;
- no anchors, aliases, merge keys, tags or duplicate keys;
- a `services` mapping, and no `include`;
- every service has a string `image` of the form `<name>[:tag]@sha256:<64 lowercase hex>`, with no `build` or `extends`.

Anything else is refused. Run it when building the trust policy.

A PCCS can't forge collateral, which is Intel-signed. A malicious PCCS can, however, serve older collateral that is still valid (TCB info is valid for about 30 days), which could hide a TCB recovery for that long. Use Intel PCS when that matters.

Trust policy (`--trust`), from a source independent of the node being checked:

```json
{
  "app_id": "<40 hex>",
  "compose_hash": "<64 hex: SHA-256 of app-compose.json>",
  "mrtd": "<96 hex>",
  "rtmr0": "<96 hex>",
  "rtmr1": "<96 hex>",
  "rtmr2": "<96 hex>",
  "allowed_tcb_status": ["UpToDate"],
  "allowed_advisories": []
}
```
