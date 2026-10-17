# At-rest key escrow (TC-887)

Two workspace crates, both unused by the node binary so far:

- `tinycloud-at-rest-escrow`: the escrow format. It splits the at-rest root key (ARK) 2-of-3 and seals the shares to age recipients. It also builds the bundle and its fingerprint, the canary, the verification record, and the recovery wire format.
- `tinycloud-at-rest-cli`: the `tinycloud-at-rest` tool that holders and operators run.

Build the tool from the release tag you are verifying:

```sh
cargo build --release -p tinycloud-at-rest-cli   # target/release/tinycloud-at-rest
```

## Formats

`lp(x)` is `u32 BE length ‖ x`. All digests are SHA-256 and written as lowercase hex.

- **Share.** The ARK is split with Shamir over GF(256) (`vsss-rs` 5.4.0), threshold 2 of 3. Share `i` has x-coordinate `i`. The sealed plaintext is `"TCS1" ‖ ark_id(16) ‖ generation u32 BE ‖ i ‖ share(33)`, 58 bytes in all.
- **Recipients.** Each share is age-encrypted (`age` 0.12.1, ASCII armor) to one holder.
  - `age1tag1…`: a P-256 hardware key. Use the `age1tag1` form that `age-plugin-yubikey` prints. age encrypts to it natively, and decryption needs the plugin and the key.
  - `age1…` X25519: software keys only. The CLI warns when one is used.
  - `age1yubikey1…` is refused, because encrypting to it needs the plugin.
- **Commitment.** `SHA-256(lp("tinycloud/at-rest/escrow-share-commit/v1") ‖ ark_id ‖ generation ‖ i ‖ lp(share))`.
- **Canary.**
  - `canary = HKDF-SHA256(ikm = ARK, salt = ark_id, info = lp("tinycloud/at-rest/escrow-canary/v1") ‖ generation)`.
  - `canary_fp = SHA-256(lp("tinycloud/at-rest/escrow-canary-fp/v1") ‖ ark_id ‖ generation ‖ lp(canary))`.
- **Bundle.** JSON with `version`, `ark_id`, `generation`, `threshold`, `canary_fp`, and `shares[{index, holder, recipient, commitment, ciphertext}]`. Unknown fields are rejected.
- **EFP (escrow fingerprint).** `SHA-256(lp("tinycloud/at-rest/escrow-bundle/v1") ‖ version ‖ ark_id ‖ generation ‖ threshold ‖ canary_fp ‖ n ‖ for each share: i ‖ lp(holder) ‖ lp(recipient) ‖ commitment ‖ SHA-256(ciphertext))`.
- **Verification record.** JSON that names the EFP, all three indices and all three pairs. It carries an HMAC-SHA256 under `HKDF(ARK, salt = ark_id, info = lp("tinycloud/at-rest/escrow-record/v1"))`, so only the ARK holder can make or check one.
- **Recovery binding.** `xyz.tinycloud.at-rest/recovery-key/v1\0:<recovery recipient>:<efp>:<nonce>`. The `\0` here is two characters. A TDX quote's REPORTDATA must be `SHA-256(binding) ‖ 32 zero bytes`.

## Commands

| Command | Reads | Prints |
|---|---|---|
| `recipients --holder NAME=RECIPIENT` ×3 | — | `[at_rest.escrow]` TOML and the compose env line |
| `nonce` | — | 32 random bytes, base64url |
| `inspect --bundle B [--expect-efp E]` | bundle | EFP, ark_id, generation, canary_fp, holders |
| `extract-share --bundle B --holder H` | bundle | holder H's armored age file |
| `check-share --bundle B` | decrypted share on **stdin** | which share it is; refuses on a commitment mismatch |
| `verify-node --bundle B --recovery R --nonce N --trust T [--collateral C \| --pccs-url U]` | node's recovery response | OK or REFUSED |
| `share-wrap` (same flags) | decrypted share on **stdin** | after `verify-node` passes: the share sealed to the node's recovery key |
| `verify-record --bundle B --record V` | record | `TINYCLOUD_AT_REST__ESCROW__VERIFIED_FP=<efp>` |

A decrypted share only ever arrives on stdin (`age -d -i <identity> share.age | tinycloud-at-rest …`). It never goes on argv or to a file.

### What `verify-node` and `share-wrap` check before releasing a share

All of these must hold, or the command prints `REFUSED: …` and exits 1:

1. The node's `efp`, `ark_id` and `generation` equal the holder's own bundle.
2. The node's binding is exactly the one recomputed from the recovery recipient, that EFP, and the holder's nonce. The nonce must be at least 22 characters. A response made for any other nonce is stale.
3. The quote passes Intel DCAP verification with `dcap-qvl` 0.7.0. That covers the signature, the PCK chain, the CRLs, the TCB info and the QE identity. Collateral comes from the PCCS (Phala's by default) or from `--collateral`, checked at the current time.
4. The TCB status is in the trust policy's `allowed_tcb_status` (default `["UpToDate"]`), and the TD debug bit is clear.
5. MRTD and RTMR0-2 equal the trust policy.
6. The dstack event log replays to the quoted RTMR3. Its single `app-id` and `compose-hash` events come before `boot-mr-done` and equal the trust policy.
7. The quoted REPORTDATA is `SHA-256(binding) ‖ 0³²`.

Trust policy (`--trust`), from a source independent of the node being checked:

```json
{
  "app_id": "<40 hex>",
  "compose_hash": "<64 hex: SHA-256 of app-compose.json>",
  "mrtd": "<96 hex>",
  "rtmr0": "<96 hex>",
  "rtmr1": "<96 hex>",
  "rtmr2": "<96 hex>",
  "allowed_tcb_status": ["UpToDate"]
}
```
