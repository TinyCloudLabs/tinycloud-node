# TC-3554: fetching a historical dstack KMS root epoch inside the TEE

How a CVM obtains its app keys for a *historical* KMS root epoch (epoch 0 here, the
root used before Phala's 2026-11-20 KMS move), checks them, and derives the legacy v0
`GetKey` value from them. tinycloud-node implements this in
`tinycloud-node-server/src/dstack_kms.rs`. OpenKey mirrors the same protocol and checks
in TypeScript. Both sides follow this document; if the code and this document disagree,
treat it as a bug.

There are two transports, selected by configuration. At most one is configured; neither
falls back to the other at runtime. The node needs one only until the fetched root is
sealed in its database (see [Sealed root](#sealed-root-root_wrap)).

- **A, key-recovery sidecar (1.26.14's compose; with `root_wrap`, only for the sealing
  boot).** Phala's `dstack-key-recovery` 0.6.5
  runs as a sidecar, talks to the KMS with its own attestation and the launch ticket,
  and serves the derived key and its signature chain on a unix socket. The sidecar does
  not check the KMS root signature and pins no root, so every check below still runs in
  the consumer.
- **B, direct KMS (kept as a fallback).** The consumer runs its own RA-TLS client
  against the KMS. It cannot send a launch ticket; a KMS policy that requires one
  refuses it.

The fetched app root is the root Phala declared exposed on 2026-11-06. Use it only as a
migration bridge. The protocol never falls back to the current epoch: any failure stops
startup.

## Pinned inputs

All of these are public. They go in the compose `environment:` as plaintext, so the
compose hash attests them.

| Input | Node config (`TINYCLOUD_KEYS__LEGACY__*`; OpenKey uses `OPENKEY_LEGACY_*`) | Format |
|---|---|---|
| Sidecar socket (transport A) | `KEY_RECOVERY_SOCKET` | absolute path of the sidecar's unix socket |
| KMS origin (transport B) | `KMS_URL` | `https://host[:port]`, no path |
| KMS RPC CA (transport B) | `KMS_CA_CERT` | base64 (standard, padded) of the CA certificate's DER |
| Root epoch | `ROOT_EPOCH` | u32, `0` for the pre-move root |
| KMS root k256 key for that epoch | `KMS_ROOT_PUBKEY` | hex, 33-byte SEC1 compressed secp256k1 |
| App id | `APP_ID` | hex, 20 bytes |
| Expected legacy identity | `EXPECTED_DID` | the `did:key` derived from the fetched root (node only; OpenKey uses a canary unseal instead) |

Set `KEY_RECOVERY_SOCKET`, or both `KMS_URL` and `KMS_CA_CERT`, or (node, once the root
is sealed) neither; any other combination refuses startup before any call.

The node selects this source with `TINYCLOUD_KEYS__TYPE=DstackKmsEpoch`. Independently
of the key source, `TINYCLOUD_KEYS__EXPECTED_NODE_DID` pins the DID the node may serve
and publish. A mismatch refuses startup before anything but `root_wrap` is written to
the database, and the control plane refuses to report a different identity.

## Sealed root (`root_wrap`)

The node fetches the historical root once and keeps it sealed in its own database, so
later boots depend neither on the transport nor on the KMS still serving that epoch.

- **Table.** `root_wrap(id SMALLINT PRIMARY KEY CHECK (id = 1), wrapped BLOB/BYTEA NOT
  NULL, node_did TEXT NOT NULL, kms_root_epoch INTEGER NOT NULL, created_at)`: at most one
  row.
- **Wrap key.** `K_wrap` = agent `GetKey("tinycloud/keys/primary-wrap")`, from the
  current KMS root. It never becomes the identity.
- **Seal.** AES-256-GCM, `wrapped = nonce(12, random) || ciphertext || tag(16)`,
  `AAD = "tinycloud/root-wrap/v1" || APP_ID(20 raw bytes) || EXPECTED_DID(UTF-8)`.
  Keys and plaintext are zeroized after use.

Boot, before any migration, `renewal_identity` write or other database write:

1. Parse the pins (no call). Connect the database, `CREATE TABLE IF NOT EXISTS
   root_wrap`, read the row.
2. **Row absent.** No transport configured: refuse. Otherwise fetch and verify the root
   as below (every check, steps 1-10), seal it, `INSERT … ON CONFLICT DO NOTHING`, and
   re-read the row, so that concurrent first boots agree on one blob. Logs
   `sealed the node root into root_wrap`.
3. **Open.** The row's `node_did` must equal `EXPECTED_DID` and its `kms_root_epoch`
   `ROOT_EPOCH`. Unseal under `K_wrap` and the AAD, and check the root's node DID equals
   `EXPECTED_DID`. A row present never triggers a fetch, even with a transport
   configured. Logs `opened identity root from root_wrap` (`event = "root_wrap_opened"`).
4. `TINYCLOUD_KEYS__EXPECTED_NODE_DID`, then migrations and the rest of startup.

Any failure refuses startup; the node never falls back to fetching again or to the
current root.

### Release order

With a `root_wrap` release, in this order:

1. **Seal boot**, on the sidecar compose. The node fetches epoch 0, seals it into
   `root_wrap`, then reads the row back and opens it in the same boot before it serves,
   which is the path every later boot takes. A node that serves its expected DID after
   this boot has sealed and opened the blob.
2. **Check the row** on a database read: exactly one `root_wrap` row, `node_did` equal to
   `EXPECTED_DID`, `kms_root_epoch` 0, `created_at` after the seal boot. Never select
   `wrapped`. Keep an operator-only export of the row (see Recovery).
3. **Then** the sidecar-free compose. Serving the same DID on it proves the node opens
   from the blob with no transport.

A separate restart on the sidecar compose is not needed, and on production it cannot be
observed: the `seal` and `opened identity root from root_wrap` lines are INFO and are not
shipped.

### Recovery: the blob no longer opens

`K_wrap` comes from the current KMS root. If that root changes again, the blob stops
opening and startup refuses. A rollback to an older `root_wrap` release does not help:
with a row present, every such release opens from the blob and refuses the same way.
Recovery is an operator action, in this order:

1. **Export** the `root_wrap` row (all columns, `wrapped` as hex) to operator-only
   storage and record its sha256, checked against a second read. It is ciphertext, so it
   is safe to keep; never put it in an issue or a repository.
2. **Delete** the row (one transaction, exactly `id = 1` and the exported hash).
3. **Boot once on the sidecar compose.** Once the production compose is sidecar-free,
   that takes a release that restores the sidecar compose and its reviewed N0 template.
   The node fetches epoch 0 and seals a new row with the same DID.
4. If that boot refuses because epoch 0 cannot be fetched, **re-insert the exported row
   byte-exact**. The database is then as it was before step 2.

The delete is reversible only while the export exists: never delete without it. If the
KMS no longer serves epoch 0, the exported row is the only remaining copy of the root,
sealed under a key the node can no longer derive. Open question: how long Phala keeps
root epoch 0 retrievable.

## Protocol

The guest agent is the dstack socket (`/var/run/dstack.sock`, v0 API). Bytes fields in
KMS and sidecar JSON are hex strings; accept an optional `0x` prefix.

1. **App id.** Agent `GET /Info`. Its `app_id` must equal `APP_ID`, compared as
   case-insensitive hex without `0x`. Both transports.

### Transport A: key-recovery sidecar

The sidecar runs `serve --no-addr --socket <KEY_RECOVERY_SOCKET>` (no TCP listener) on a
volume shared only with the consumer, with read-only file mounts of
`/dstack/.host-shared/.appkeys.json` and `.sys-config.json` (never the whole directory,
which holds the decrypted env).

A1. **Request.** Over the unix socket send
    `GET /v0/key?path=<urlencoded path>&root_epoch=ROOT_EPOCH&app_epoch=0`, `purpose`
    unset (empty). The node's path is `tinycloud/keys/primary`. Always send
    `app_epoch=0`: without it the KMS answers with the app's *current* app epoch. Any
    non-2xx answer means the sidecar or the KMS refused: stop, and never retry against
    another epoch.
A2. **Response.** `{api, key, public_key, signature_chain, root_epoch, app_epoch}`
    (key-recovery `main.rs` `KeyResult::to_json`). `api` must be `"v0"`. `key` is the
    32-byte v0 `GetKey(path)` value of step 10 itself, computed by the sidecar from the
    app root, which never leaves the sidecar.
A3. **Epoch check (a)** as in step 8, on the response's `root_epoch` and `app_epoch`.
A4. **Key and chain.** `public_key` must equal the SEC1-compressed public key of `key`.
    `signature_chain` must have exactly 2 links, each 65 bytes `r || s || v`:
    - Link 0 is the app key's recoverable signature over
      `keccak256(purpose || ":" || hex(public_key))`, lowercase hex, purpose empty.
      Recover `app_pub` (SEC1-compressed) from it with recovery id `v`.
    - Link 1 is the KMS `k256_signature`. Apply the issuance check (b) of step 9 to it
      with that recovered `app_pub`.

    The chain proves that the pinned epoch root issued an app key to this app and that
    this app key vouched for `public_key`. It does not prove the path or the derivation;
    only the identity check proves those, so it is mandatory.
A5. **Identity check (c)** of step 10 on `key` directly: node DID = `EXPECTED_DID`
    (OpenKey: canary unseal).

### Transport B: direct KMS

KMS calls are prpc JSON: `POST {KMS_URL}/prpc/{Method}?json` with a JSON body.

2. **KMS TLS.** Every KMS connection is TLS 1.2/1.3. The only trust anchor is
   `KMS_CA_CERT` (no system roots), with normal hostname verification against the
   `KMS_URL` host. After the handshake, two checks apply to the server's leaf
   certificate:
   - It must be issued *directly* by `KMS_CA_CERT`: its issuer is the CA's subject,
     and its signature verifies under the CA's key. The KMS CA also signs per-app CAs
     (kms `main_service.rs:847-861`, usage `app:ca`), so a longer chain could be
     minted by an app.
   - It must carry extension `1.3.6.1.4.1.62397.1.4` whose value is the DER OCTET
     STRING `kms:rpc`. The CA also signs app certificates, so the CA alone does not
     prove you are talking to the KMS.
3. **Temp CA.** Without a client certificate, `POST /prpc/GetTempCaCert?json`, body
   `{}`. The response is `{temp_ca_cert, temp_ca_key, ca_cert}` (PEM strings). The
   temp CA key is public by design; the KMS shares it with every caller.
4. **Key and report data.** Generate a fresh ECDSA P-256 key. Let `spki` be its
   SubjectPublicKeyInfo DER. Set
   `report_data = SHA-512("ratls-cert:" || spki)`, which is 64 bytes.
5. **Quote.** Agent `POST /GetQuote`, body `{"report_data": hex(report_data)}`. The
   response is `{quote: hex, event_log: string, report_data: hex, vm_config: string}`.
   The quote's REPORTDATA (TDX v4 quote, byte offset 568, 64 bytes) must equal
   `report_data`.
6. **RA-TLS client certificate.** An X.509 v3 certificate with:
   - subject `CN=RA-TLS TEMP Cert`;
   - the P-256 public key;
   - key usage `digitalSignature`;
   - two non-critical extensions, each value a DER OCTET STRING:
     - `1.3.6.1.4.1.62397.1.1`: the raw quote bytes;
     - `1.3.6.1.4.1.62397.1.2`: the agent's `event_log` string as UTF-8 bytes,
       verbatim and uncompressed.

   Sign it with the temp CA key, so the issuer is the temp CA.

   This is dstack's legacy RA-TLS encoding. Both the 0.5.x and the 0.6.x KMS parse it
   (`ra_tls::attestation::from_ext_getter`: quote plus event log when there is no
   `…1.8` attestation extension). Older KMSes pin the temp CA at the TLS layer, so the
   certificate must chain to it. Newer ones accept any attested certificate and verify
   the quote's binding to the certificate key.
7. **GetAppKey.** On a TLS connection that presents `[client cert, temp CA cert]` and
   verifies the server as in step 2, send `POST /prpc/GetAppKey?json`, body
   `{"api_version": 1, "vm_config": <vm_config from step 5>, "root_epoch": ROOT_EPOCH, "app_epoch": 0, "launch_ticket": ""}`.
   Always send `app_epoch: 0`; unset selects the app's current app epoch. Any non-2xx
   answer means the KMS refused: stop, and never retry against another epoch.
8. **Epoch check (a).** The response must contain `root_epoch` equal to `ROOT_EPOCH`
   and `app_epoch` equal to `0`. The signature format in step 9 is the app-epoch-0
   format. An absent field is a refusal: dstack's prpc JSON emits every scalar,
   zeros included. In the KMS proto (`kms_rpc.proto:65,68` @350a0a73) both are plain
   `uint32`, and the prpc-build 0.6.1 `enable_serde_extension` (`prost.rs:475-478`)
   only adds `#[derive(Serialize)]` and `#[serde(default)]`. It has no
   `skip_serializing_if`. The JSON reply is `serde_json::to_vec(&response)`
   (`server.rs:268`).
9. **Issuance check (b).** Decode `k256_key` (32 bytes) and `k256_signature` (65 bytes,
   `r || s || v`).
   - Let `app_pub` be the SEC1-compressed (33-byte) public key of `k256_key`.
   - Require `0 < r < n` and `0 < s <= n/2` (low-S), where `n` is the secp256k1 order.
   - Let `digest = keccak256("dstack-kms-issued:" || app_id(20 raw bytes) || app_pub)`.
     This is Ethereum Keccak, not SHA3.
   - The ECDSA signature `(r, s)` over the prehashed `digest` must verify under
     `KMS_ROOT_PUBKEY`. Ignore `v`.
10. **Derivation and identity check (c).** The legacy v0 `GetKey(path)` value is
    `HKDF-SHA256(salt = "RATLS", ikm = k256_key, info = path, L = 32)`.
    - Node: the root is `GetKey("tinycloud/keys/primary")`, and its node DID must equal
      `EXPECTED_DID`.
    - OpenKey: `legacyKey(path) = SHA-256(GetKey(path))`, an AES-256-GCM key; a sealed
      record is `base64(iv12 || tag16 || ct)`, no AAD. The path is
      `openkey/key/<sealingContext>`, or `openkey/user/<userId>/keys` when the context
      is NULL. Then a canary unseal of one known record.
11. **Hygiene.** Discard every other response field at once: disk, env and sealed-env
    keys, the CA cert, the client key and the temp CA key. Never log, persist or serve
    the app root or anything derived from it, apart from the public DID.

## Test vectors

Computed with the `scripts/key-escrow/decode_bundle.py` helpers (@0c759eba) and pinned
in `dstack_kms::tests`:

- `keccak256("")` = `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`
- `k256_key` = `01` repeated 32 times
- `app_id` = `35` repeated 20 times
- `app_pub` = `031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f`
- `keccak256("dstack-kms-issued:" || app_id || app_pub)` =
  `b5e4fd2ef63b05285fe79190ddfb3e40efba1eef5a507bf4aed05da771847721`
- `GetKey("tinycloud/keys/primary")` =
  `bbeb1e02123fe7cfab8471656ab89eff4d0b517fabdd457aa624942d1d5e0b02`
- node DID of that root = `did:key:z6Mki14g4VZeY9fra5wUt8m5DmYkmAfWDtUKecu65Kd1uWU9`
- transport A, for that `GetKey` value as `key`: `public_key` =
  `0324658ea9452d044b7e5a70c79b352bb73968365b45bed193df98f6dde67a65e3`, and the digest
  link 0 signs, `keccak256(":" || hex(public_key))` =
  `aafcab4c272e0db55aac89ee9d441edb18b2a0a3742794205dcd013d08d25c98`

## Failure modes, all fail-closed

| Condition | Result |
|---|---|
| Agent unreachable or app id mismatch | startup refused |
| Two transports configured, or a partial KMS transport | startup refused before any call |
| No `root_wrap` row and no transport | startup refused, nothing written but the empty table |
| `root_wrap` row for another DID or epoch, tampered, or sealed under another key or AAD | startup refused, no fetch, no fallback |
| Unsealed root's DID ≠ `EXPECTED_DID` | startup refused before any other database write |
| Sidecar unreachable or answers non-2xx | startup refused, no fallback |
| Sidecar `api` ≠ `v0`, `public_key` ≠ pub(`key`), chain not 2 × 65 bytes | startup refused |
| KMS TLS fails, server leaf not `kms:rpc` | startup refused |
| KMS answers non-2xx (not authorized for the epoch, unknown app, bad attestation) | startup refused, no fallback |
| `root_epoch` absent or different; `app_epoch` absent or ≠ 0 | startup refused |
| Signature malformed, high-S, or not by `KMS_ROOT_PUBKEY` (transport A: for the app key link 0 recovers) | startup refused |
| Derived DID ≠ `EXPECTED_DID` | startup refused, nothing sealed |
| Served DID ≠ `TINYCLOUD_KEYS__EXPECTED_NODE_DID` (any key source) | startup refused before any database write other than `root_wrap` |
