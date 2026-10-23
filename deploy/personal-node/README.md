# Run a personal TinyCloud node

This ordinary-server profile runs a single node with local SQLite, local blocks, and Caddy HTTPS. It pins the published **1.22.0** node image by immutable digest in [`compose.yaml`](compose.yaml): the multi-platform index pushed by the `docker.yml` run for the `v1.22.0` tag. Caddy **2.10.2** is pinned by its multi-platform image digest there too. The previous published image, 1.20.6, is used only to rehearse an upgrade and restore-based rollback. Pin by digest; do not use a mutable tag such as `latest`.

This is **not** a TEE: the VPS operator and its host can access the filesystem and key. No hardware attestation, dstack KMS isolation, or cross-host account migration is claimed. This guide does not configure registry discovery or hosted-to-owned-node replication (TC-1280/TC-1283). TLS authenticates your domain but does not attest the machine.

## Preflight

- Own an ordinary Linux VPS with Docker Engine and Compose v2, `bash`, `curl`, `jq`, `openssl`, `tar`, `sudo`, Node.js 22 and npm. Clone this repository at the revision carrying the guide. Check that ports 80/443 are free, the domain A/AAAA record points to the VPS, and incoming 80/443 are allowed for Caddy certificate issuance and HTTPS. Do not expose the node's unauthenticated metrics port 8001, Docker socket, or its plain HTTP port 8000.
- Store node data on a persistent local filesystem with available disk for both the live data and a full backup. `node.sh init` sets only that dedicated data directory to UID/GID 1000, the non-root image user. Confirm host backups and access controls before admitting users.
- Choose a unique `NODE_HOME` path for this installation. Keep its `node.env` (node identity root) and your owner-held Ethereum private key separate, private and recoverable. Never put either in git, CI logs, or a public volume. Back up the node identity independently of the data. Preserve the original root through upgrades: changing it changes node identity and can make encrypted/sealed state unreadable.
- There is **no** hosted billing/quota URL in this profile. The ordinary node still depends on its chosen wallet/signing client and, for public HTTPS, DNS and the CA. Review the EGPL-1.5 license and host hardening for your deployment.

All commands below use the same [`node.sh`](node.sh) operations invoked by [the CI rehearsal](ci.sh). Run them from the repository root. No production credentials or hosted services are used by CI.

## Provision and launch

```bash
npm ci --prefix test/probe
export NODE_HOME="$HOME/personal-tinycloud"
bash deploy/personal-node/node.sh init node.example.com
bash deploy/personal-node/node.sh check-missing-key
bash deploy/personal-node/node.sh start
bash deploy/personal-node/node.sh check-version 1.22.0
```

Replace `node.example.com` with the domain you own. `init` writes a unique 48-byte random Static root to a `0600` private `node.env`; it is never echoed. The profile mounts a keyless TOML over the config bundled in the image. The 1.22.0 image's own default configuration contains no key; the 1.20.6 image used in the upgrade rehearsal embeds a sample key, which the mount masks. With the mount, both images **fail** if the installation root is absent. CI also starts the bare 1.22.0 image with no mount, key or environment and requires the same failure (`check-bare-image-missing-key`); the bare 1.20.6 image still embeds the sample key and is never run bare. `check-missing-key` must run before `start`; it requires the node's exact `Missing secret` diagnostic and rejects unrelated failures without printing their logs. Caddy obtains and renews a public certificate; do not bypass its trust verification.

The 1.20.6 and 1.22.0 config loaders accept both the legacy single-underscore nesting (`TINYCLOUD_KEYS_TYPE`, `TINYCLOUD_STORAGE_DATADIR`) and canonical double-underscore nesting (`TINYCLOUD_KEYS__TYPE`, `TINYCLOUD_STORAGE__DATADIR`). They merge canonical values last when both are set. This profile uses the canonical form; the existing dstack Compose retains its working single-underscore key-type setting.

To prove owner-held EOA operations, place your own wallet's 32-byte hexadecimal private key (without `0x`) in a separate `0600` file outside `NODE_HOME`, then run:

```bash
bash deploy/personal-node/node.sh seed /secure/path/owner.key
bash deploy/personal-node/node.sh restart
bash deploy/personal-node/node.sh verify /secure/path/owner.key
```

The pinned `@tinycloud/node-sdk` signs in, hosts an owned space, writes and reads a KV object and a SQL row. The `verify` operation checks their exact values and the node's public identity after restart. Do not put a key on the command line; only its file path is passed. Your wallet key is **not** included in the node backup and must be retained separately.

## Offline backup and fresh restore

Stop writes before backup. `backup` stops the node, archives the entire `/data` tree while SQLite and SQL actors are closed, encrypts `node.env` as a separate artifact, then restarts the node. The data archive itself is **not encrypted**; protect it as sensitive data or encrypt it using your backup system. The passphrase file is not included in either artifact. Retain both the backup and passphrase in independent secure locations. Test recovery regularly.

```bash
# Generate a strong private passphrase file outside the node and backup tree.
export BACKUP_PASSPHRASE_FILE=/secure/path/node-backup-passphrase
umask 077
openssl rand -base64 48 > "$BACKUP_PASSPHRASE_FILE"
bash deploy/personal-node/node.sh backup /secure/path/node-backup-2026-10-16 "$BACKUP_PASSPHRASE_FILE"

# On the destination, copy the encrypted backup, passphrase and owner wallet
# by independent secure channels. Stop the old node, repoint DNS to the new
# host, then start the restored node after Caddy can obtain its certificate.
export NODE_HOME="$HOME/personal-tinycloud-restored"
bash deploy/personal-node/node.sh restore /secure/path/node-backup-2026-10-16 "$BACKUP_PASSPHRASE_FILE"
bash deploy/personal-node/node.sh start
bash deploy/personal-node/node.sh check-version 1.22.0
bash deploy/personal-node/node.sh verify /secure/path/owner.key
```

Use a fresh host/directory, not two live nodes serving the same identity and domain at once. Stop the old node before DNS cutover; wait for the new host's Caddy certificate, then verify before admitting clients. If verification fails, stop the destination and revert DNS to the old host. `verify` compares the public node DID saved before backup and the signed KV/SQL data; a different root fails rather than silently rotating. The backup is a full offline snapshot, **not** continuous replication. TLS ACME state is not in the backup, and a restore needs a reachable domain and valid certificate again.

## Upgrade and rollback rehearsal

CI executes [`ci.sh`](ci.sh) on a clean runner: a fresh 1.22.0 installation with missing-key denial, an unrelated-failure negative control, the bare 1.22.0 image's missing-key failure, signed data and restart; then 1.20.6 → 1.22.0, with data checks before and after restart, fresh-volume restores, and rollback by restoring the **pre-upgrade** snapshot into another fresh instance on 1.20.6. An in-place downgrade of a migrated database is not supported. A normal new installation starts directly on 1.22.0; do not install 1.20.6 except to rehearse this upgrade.

```bash
# Run only on a disposable isolated runner with permission to create Docker
# containers. This is exactly the end-to-end job used by GitHub Actions.
bash deploy/personal-node/ci.sh
```

### What 1.22.0 changes for an upgrade from 1.20.6

- **Database migrations.** The upgrade applies seven migrations that 1.20.6 does not ship: `m20261014_000000_delegation_cid_alias`, `m20261015_000000_delegation_cursor_index`, `m20261017_000000_epoch_order_space_index` and `m20261018_000000_epoch_head` (1.21.0), `m20261020_000000_current_kv_key_c_index` (1.21.3, an index on PostgreSQL), `m20261021_000000_sql_store_manifest` (1.21.8, two empty tables) and `m20261022_000000_encryption_network_key` (1.21.9, a table and a nullable column, not yet used). 1.22.0 itself adds none. An older image refuses to start against a database that has recorded a migration it does not ship.
- **Rollback needs the restore.** Because of those migrations, rolling back from 1.22.0 means restoring the pre-upgrade backup into a fresh instance of the 1.20.6 image, as `ci.sh` does for its last instance. Take and verify that backup before the upgrade; data written after it is not in it.
- **Named keys and delegated SQL caveats are disabled.** `[global.encryption_network] named_keys_v1` and `[global.sql] delegated_caveats_enforced` default to off, and this profile does not set them. With them off, named-key routes are not mounted, a `tinycloud.sql/*` delegation carrying `tables`, `columns` or `readOnly` caveats is refused as an unsupported caveat, and `/version` does not list `encryption-named-keys-v1` or `sql-delegated-caveats-v1`. `check-version` asserts that neither feature is listed. Enabling either is outside this guide and is not exercised by CI.

### A later upgrade

Take and verify an offline backup as above, stop the node, change the pinned image only to a reviewed released digest, start and verify identity and signed data. If verification fails, stop the candidate and restore that pre-upgrade backup to a fresh instance of the previous image; never blindly start the older binary against migrated data. Moving the pin to a later release also means updating the previous/current pair in [`node.sh`](node.sh) and [`ci.sh`](ci.sh) and running the published-image CI job for that pair.

For a Caddy update, choose a reviewed release and resolve its published multi-platform index digest (for example, from the [Docker Hub tag metadata](https://hub.docker.com/v2/repositories/library/caddy/tags/2.10.2)). Replace only the `caddy@sha256:…` reference in `compose.yaml`, run the published-image CI job and verify HTTPS certificate issuance and renewal on a staging domain before upgrading a live proxy. Retain the Caddy `/data` and `/config` volumes; do not switch to a mutable tag.

The [personal-node workflow](../../.github/workflows/personal-node.yml) is the acceptance evidence only when its `published-images` job is green; its `dstack-profile` and `dstack-config-source` jobs cover the separate dstack Compose profile and the shipped key configuration. Record the successful run URL and exact image versions/digests in TC-1282; no CI result here authorizes a production deployment or a stronger sovereignty claim.
