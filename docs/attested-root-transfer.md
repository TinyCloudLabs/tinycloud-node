# Attested root transfer

The workspace contains an offline Rust attestation verifier and a one-shot,
operator-shuttled root transfer. These tools do not connect to a database, change
CVM configuration, restart services, or perform a deployment.

Use the export program only on a disposable **replica**, never the primary.
This document does not authorize creating or changing any CVM. Obtain the
required operator approval and security review before using real key material.
Do not copy production environment files or database credentials into an export
container. No DNS or ingress is required.

## Required Phala confirmations

Record these independently before preparing the public transfer policy:

1. A replica of the source app receives the same `GetKey("tinycloud/keys/primary")`
   bytes as the source app, including after replica boot.
2. The replica can run the reviewed export compose under that same app ID with a
   different compose hash. If not, **stop**; running the exporter on the primary
   is not an alternative in this procedure.
3. The destination uses a separately identified KMS root. Obtain the exact,
   nonempty **KMS ID encoded in the destination's measured `key-provider` event**,
   with provider name `kms`. In dstack `43f69f41`, this is hex-encoded DER
   SubjectPublicKeyInfo from the KMS certificate (`dstack-util/src/system_setup.rs`).
   Confirm this encoding for the destination's exact dstack version. A dashboard
   label, URL, provider name, certificate fingerprint, or app ID is not this ID.
4. The destination's measured provider ID distinguishes KMS root generations.
   If a root changes while its measured ID stays the same, an ID comparison
   cannot prove which root supplied the key; do not use the tool on that basis.
5. Obtain the reviewed destination app ID, allowed compose hashes, and trusted
   Phala OS measurements (MRTD and RTMR0–2). Source these independently of the
   untrusted destination document.
6. Obtain current Intel collateral for the destination quote. The verifier
   authenticates collateral and checks validity at the current verifier time;
   an archived collateral snapshot is for historical tests only.

No destination KMS ID or replica capability is supplied by this repository.
These are external prerequisites, not values to infer from a quote or default.
An empty/`none` provider is not a migration destination.

## Build and replica procedure

Build from the reviewed PR head, using a private execution home. Keep Rust's
toolchain and dependency caches separate from application state:

```sh
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export HOME="$(mktemp -d)"
export TC_HOME="$(mktemp -d)"
cargo build --locked --release -p tinycloud-attestation -p tinycloud-root-transfer
cargo test --locked -p tinycloud-attestation -p tinycloud-root-transfer
```

Package the built tools into the reviewed replica/import image. Do not run them
on the workstation against a real guest-agent socket. Commands below assume the
already-approved replica and destination exist; they do not create or modify
them.

Prepare `policy.json` independently, with these fields:

| Field | Required value |
|---|---|
| `app_id` | Destination app ID, hex bytes |
| `compose_hashes` | Nonempty array of reviewed compose SHA-256 hex hashes |
| `kms_id` | New KMS certificate SubjectPublicKeyInfo DER, hex bytes |
| `mrtd` | Reviewed OS MRTD, 48-byte hex |
| `rtmr0`, `rtmr1`, `rtmr2` | Reviewed OS measurements, each 48-byte hex |

`config.json` contains `{"policy": <the policy object>, "expected_old_did":
<the independently pinned source did:key>}`. The policy is trusted configuration,
not a template populated from the destination's response.

1. **Destination only:** give `prepare` the current Intel collateral JSON in
   `dcap-qvl::QuoteCollateralV3` format (binary fields are hex strings, not JS
   integer arrays). The tool derives the stable import key
   from the destination root and requests a bound quote:

   ```sh
   tinycloud-root-import prepare --socket /var/run/dstack.sock \
     --policy policy.json --collateral collateral.json --output target.json
   ```

   Preparation does not authenticate the quote. The exporter authenticates it
   before releasing any ciphertext.
2. Shuttle only `target.json` to the source **replica**. Supply the reviewed
   `config.json` as part of the export compose's measured configuration. Run the
   exporter as the only service, without DB/S3 credentials or ingress:

   ```sh
   tinycloud-root-export --socket /var/run/dstack.sock \
     --config config.json --target target.json --output sealed.json
   ```

   Without `--output`, only the sealed JSON is written to stdout. A DID or quote
   mismatch exits with an error and no sealed output. Output files are created
   exclusively; existing files are not overwritten.
3. Shuttle `sealed.json` to the destination. Keep the exact original
   `target.json`, because the ciphertext authenticates its quote hash. A
   validation-only run opens the root in memory, verifies the expected old DID,
   and immediately drops it:

   ```sh
   tinycloud-root-import verify-only --socket /var/run/dstack.sock \
     --config config.json --target target.json --sealed sealed.json
   ```

4. In the destination re-encryption process, call
   `tinycloud_root_transfer::import_for_job` with the same inputs and the actual
   job closure. `LegacyRoot::derive_key(context)` returns a zeroizing derived key;
   the root has no raw-byte, serialization, clone, or debug interface. The job
   must not persist or log derived keys. `verify-only` does not run that job.

All paths passed as arguments contain public policy, attestations, or sealed
ciphertext, not plaintext roots. Never put the root in an environment variable,
CLI argument, temporary file, or log.

## Protocol

The import private key is X25519 from
`Blake3(destination_root || "tinycloud/root-import/v1")`. REPORTDATA is
`SHA256("tinycloud/root-import/v1\\0" || public_key || decoded_app_id)` followed
by 32 zero bytes.

The verifier authenticates the Intel DCAP chain and collateral at the caller's
current time, requires `UpToDate` TCB status, rejects debug TDs, checks the pinned
MRTD/RTMR0–2, and replays all runtime RTMR3 events. App/compose events precede
`boot-mr-done`; the unique `key-provider` event lies after that marker and before
`system-ready`. Its JSON must identify `name = "kms"` and the pinned KMS SPKI.

HPKE uses RFC 9180 base mode, X25519/HKDF-SHA256/AES-256-GCM, and
`info = "tinycloud/root-export/v1"`. AAD is
`"tinycloud/root-export/aad/v1\\0"` followed by each of the old DID UTF-8 bytes,
decoded destination app ID, and SHA-256 of the decoded quote, individually
prefixed with its length as a big-endian `u32`. `transcript_hash = SHA256(AAD)`.
The complete source root is transferred; roots longer than 32 bytes are not
truncated.

## OpenKey reuse

Use the native `tinycloud-attestation` CLI from TypeScript as a subprocess.
Pass a JSON object on stdin with fields `bundle`, `policy`, and
`expected_report_data` (exactly 64 bytes encoded as hex). `bundle` contains
`quote` (hex), `event_log` (event array), and `collateral` (Intel collateral).
Check both its exit status and JSON stdout: exit 0 returns `{"ok":true}`;
rejection returns exit 2 and `{"ok":false,"error":...}`. The CLI uses its own
wall clock and accepts no timestamp override.

This is a CLI integration, not a WASM verifier. The Rust crate exposes the same
verification function for native consumers. OpenKey must compute its own
domain-separated expected REPORTDATA; it must not reuse the node import binding.

## Evidence and limits

The recorded dstack TDX quote and Intel collateral originate in
`registry/packages/location-registry/scripts/fixtures/dstack-tdx-quote.json`.
They provide a historical cryptographic quote-chain and RTMR3 replay check.
Their REPORTDATA is not an import-key binding, and their measured key provider
is `{"name":"none","id":""}`. They are **not** a valid destination transfer
quote. KMS policy positives and the root-transfer roundtrip use explicitly
synthetic inputs; they do not demonstrate a transfer between real CVMs.

The actual new-KMS event encoding and a real destination quote binding an import
key must be confirmed in an approved lab before use. No live CVM or production
data is required for the checked-in offline tests.

Local verification uses
`cargo test --locked -p tinycloud-attestation -p tinycloud-root-transfer`
(31 tests), scoped `cargo clippy ... --all-targets -- -D warnings`, and scoped
`cargo fmt --check`. The crypto tests include the recorded Intel chain, damaged
quote/collateral rejection, RFC 9180 sender and receiver known answers, and a
synthetic 80-byte root roundtrip.

A standalone mock Unix guest-agent run also exercises the built binaries:
`prepare` publishes a synthetic bound document; export rejects a wrong source
DID and a signature-invalid quote without a sealed output file or stdout;
the verifier CLI returns structured rejection; import rejects the invalid quote
before connecting to its guest socket. This is fail-closed CLI evidence, not a
successful real-CVM migration. The throwaway smoke driver is not shipped.

The serving node's normal root and identity are not changed by these tools.
Import exposes an in-memory job boundary; the re-encryption job must consume the
old root there. Import validation is not a completed database migration, does not
persist the old root, and cannot resume a job after process exit without a new
import.
