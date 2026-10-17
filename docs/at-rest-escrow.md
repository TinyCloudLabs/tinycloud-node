# At-rest key escrow (TC-887)

The node provisions and escrows at-rest keys only when `at_rest` is configured (below). The default config does nothing: no key reads, no rows.

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

`compose_hash` pins container images only if `app-compose.json` references every image by digest. `verify-compose` reads it with a real parser (`tinycloud_at_rest_escrow::compose`, shared with the node) and accepts only a small subset:
- `runner` is `docker-compose`;
- the compose text is newlines and printable ASCII only, because YAML parsers disagree on Unicode line breaks such as U+2028;
- exactly one document;
- no anchors, aliases, merge keys, tags or duplicate keys;
- a `services` mapping, and no `include`;
- every service has a string `image` of the form `<name>[:tag]@sha256:<64 lowercase hex>`, with no `build` or `extends`;
- `TINYCLOUD_AT_REST__ESCROW__RECIPIENTS` and `TINYCLOUD_AT_REST__ESCROW__VERIFIED_FP`, if set, are literal values: no `$` interpolation and no pass-through from the runtime environment.

Anything else is refused. `verify-compose` prints the escrow values the compose sets and every other app-compose setting in full (scripts included). All untrusted text is escaped, so control characters and terminal escapes show up as `\u{…}`. Run it when building the trust policy.

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

## Node configuration and endpoints

```toml
[at_rest]
mode = "off"            # off | encrypt | strict
escrow_none = false     # self-hosted Static-root nodes only (refused in a TEE)

[at_rest.escrow]
recipients = [ { holder = "sam", recipient = "age1yubikey1…" }, … ]   # exactly 3
verified_fp = "<efp>"   # after the ceremony (record-efp)
allow_software = false  # X25519 holders; tests and self-host only, refused in a TEE
allow_resplit_before_verify = false  # before the ceremony only: corrected holders get a fresh root key
```

The same settings as compose env: `TINYCLOUD_AT_REST__MODE`, `TINYCLOUD_AT_REST__ESCROW_NONE`, `TINYCLOUD_AT_REST__ESCROW__RECIPIENTS=[{holder="…",recipient="…"},…]`, `TINYCLOUD_AT_REST__ESCROW__VERIFIED_FP`, `TINYCLOUD_AT_REST__ESCROW__ALLOW_SOFTWARE`, `TINYCLOUD_AT_REST__ESCROW__ALLOW_RESPLIT_BEFORE_VERIFY`.

- **Recipients set, `mode = "off"`:**
  - at boot the node creates the ARK (sealed under its root) and the escrow bundle;
  - it keeps a copy of the sealed key, the bundle, the ceremony record and each space's wrapped data key in the block store (`_tc/at-rest/` in S3, `{datadir}/at-rest/_tc/at-rest/` on disk). Data-key objects are named by a keyed hash, not the space;
  - in this mode a copy that can't be written is logged and the boot goes on (nothing depends on it yet). With `encrypt` or `strict`, every boot-time copy must be written: a block store that refuses the write stops the boot;
  - nothing is encrypted.
- **`encrypt` and `strict` are refused at boot in this build.** Block storage has no seal path yet, so the node won't claim to encrypt while it writes plaintext; `/info` never shows `encrypting: true`. Storage turns the capability on when the seal path lands (TC-887 S3). From then on, `encrypt` or `strict` refuses to start unless the recipients equal the bundle's, `verified_fp` equals its EFP, and the stored ceremony record verifies under the key inside the TEE. A Static-root node with no recipients may use `escrow_none = true` instead, which acknowledges that no escrow exists.
- **In a TEE, the escrow recipients and `verified_fp` must be literal values in the measured compose.** With any at-rest config, the node reads its `app-compose.json` from the guest agent (`/Info`, `tcb_info.app_compose`), checks it against `compose_hash`, and refuses to boot unless `TINYCLOUD_AT_REST__ESCROW__RECIPIENTS` and `TINYCLOUD_AT_REST__ESCROW__VERIFIED_FP` are set there as literals (no `${…}`, no pass-through) equal to the effective config. Values from the encrypted environment, a file or anywhere else are refused. If the app-compose can't be read or parsed, the node refuses to boot. The `/Info` shape must be confirmed on a live CVM before the escrow ceremony.
- **The escrow bundle is made or changed only at boot, never by a request.** Every endpoint below only reads it.
  - If the configured recipients differ from the active bundle's, the node refuses to boot: it never re-splits on its own. Changing a holder after the ceremony needs an explicit re-escrow (a follow-up, with the rotation tooling in TC-1345).
  - **Fixing a wrong holder before the ceremony:** set `allow_resplit_before_verify = true` together with the corrected recipients. The node then **replaces the root key**: it makes a fresh ARK, splits it for the corrected holders, and retires the old ARK and its bundle. Shares of the old bundle become worthless: any two of them rebuild only the retired key, which never protected anything and is never loaded again (a W-authenticated retirement marker in the block store drops it even from a database restored to before the fix). The node does this only if no fingerprint is pinned, no ceremony record exists, and no data key was ever made, checking both the database and the block store. If any of those fails, it still refuses to boot. Remove the flag after the fix.
  - With `verified_fp` set, the node uses only the pinned bundle, restoring it from the block store if the database lost it, and refuses to boot if that bundle is not for the configured recipients and the newest key.
- **If the node's root can no longer unseal the key** (new app id or KMS), it boots **locked**:
  - `/info` shows `at_rest.state = "locked"` and encryption is unavailable;
  - two holders recover it through the endpoints below, which needs `verified_fp` to be pinned;
  - the node then re-seals the key under its new root, with no restart and no data rewrite.

| Endpoint | Answer |
|---|---|
| `GET /at-rest/status` | `mode`, `state`, `encrypting`, `efp`, `generation`, `verified` |
| `GET /at-rest/escrow` | the active escrow bundle (or, on a locked node, the pinned one) |
| `GET /at-rest/escrow/record` | the ceremony record, only if its MAC verifies under the live key |
| `GET /at-rest/recovery?nonce=N` | `RecoveryInfo`: this boot's recovery recipient, bound with `N` and the EFP into a TDX quote (`mode = "classic"` with no quote outside a TEE) |
| `POST /at-rest/recovery/shares` | body: one share age-sealed to the recovery recipient (≤ 4 KiB). Answers `held` (with `shares_held`), `verified` (all three shares rebuilt the key), or `unlocked` (locked node recovered), with the gate result |

The share endpoint:
- is rate limited per IP. Until TC-1357, the client IP comes from a proxy header trusted from any peer, so per-client limits are best effort; the per-boot budget below doesn't depend on them;
- checks every share against the bundle's commitments before it takes one of three slots;
- counts only shares that authenticate (decrypt and match a commitment) against the node's per-boot share budget, so junk can't starve genuine holders. Rejected shares are limited per client (5, then one a minute);
- never logs share bytes or ciphertexts.

Shares live in memory for the current boot only.

A keyring failure answers `503` when a retry may help (`store_unavailable`, `mirror_unavailable`, `locked`, `conflict: …`, `dek_unavailable: …`) and `500` when an operator must act (`inconsistent: …`, `escrow_pinned`, `escrow_holders_changed`, `escrow: …`). The reason never contains key material or backend detail; the server log has the rest.

**Recovery is per node.** Each boot has its own recovery key, so a share wrapped for one node is rejected by another. With several nodes on one database:
- recover one node, by its own address (not through a load balancer);
- then restart the others; a locked node doesn't pick up another node's recovery until it restarts;
- every node on one database must use the same root. A node under another root boots locked, and recovering it re-seals the rows under its root, which locks the others out at their next restart.

Production runs one node per database. Multi-node recovery is a known limitation.

### Key continuity

- **Database restored to an earlier point.** At boot the node takes back a key generation or chain from the block-store copy only once it authenticates: the newest under this node's root, each older one by its chain. During recovery, the recovered key authenticates them. Anything else in the copy (forged, junk, a gap, an oversized object) is skipped with a warning and never stored, so objects planted in the bucket can neither lock the node nor stop it booting while the database is healthy. A block store that refuses the node's own writes is different: with `encrypt` or `strict` it stops the boot (see above).
- **Data keys after a restore.** A space's data key missing from the database is restored from its copy only if its wrap authenticates for that space. A copy that exists but doesn't authenticate is never ignored and never overwritten: it may be the genuine key under a generation the node hasn't loaded (for example after a failed read at boot). That space answers `503 dek_unavailable` until the generation loads or an operator removes the object; no new key is made over it.
  - **Runbook, `dek_unavailable` that doesn't clear:** first restart once the block store reads cleanly; a genuine key under an unloaded generation then authenticates and comes back. If the error stays, the server log names the space's data-key object as not authenticating under any loaded generation. Check no newer key generation exists anywhere (database backups, other nodes); only then delete that object under `_tc/at-rest/` and the space gets a new key on its next write. Deleting a genuine key makes everything sealed under it unreadable.
- **No key is ever made over existing material.** The node creates a new root key only when the database has no key, escrow or data-key rows and the block store has nothing under `_tc/at-rest/`. A store or mirror error stops the boot instead, and so does an empty database whose block-store copy holds nothing usable.
- **Escrow and ceremony record after a restore.** A bundle or record the database lost is restored from the block store at boot, so a restore doesn't force a new ceremony: the pinned bundle (the pin authenticates it), or, unpinned, a bundle whose mirrored ceremony record verifies under the key. A record is restored only if its MAC verifies under the key.
- **Generations.** Each older generation is sealed under the next one's key (its chain), so escrowing the newest generation recovers all of them. At boot under the same root, a missing or broken chain is rebuilt and logged. During recovery under a new root it can't be rebuilt, and the shares are refused with the reason. The newest generation never keeps a chain: a stale one is cleared at boot.
- The key tables' migration `down` refuses while they hold rows.
