# Run a personal TinyCloud node

This ordinary-server profile runs a single node with local SQLite, local blocks, and Caddy HTTPS. It tracks the version TinyCloud itself runs in production: **1.20.6**, pinned by immutable image digest in [`compose.yaml`](compose.yaml). The prior published ordinary image 1.20.5 is used only to rehearse an upgrade and restore-based rollback. Do not use `latest` or 1.20.7: the latter was rolled back in production (TC-1176). New node-image changes remain unavailable to this published-image guide until a separately approved release ships.

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
bash deploy/personal-node/node.sh check-version 1.20.6
```

Replace `node.example.com` with the domain you own. `init` writes a unique 48-byte random Static root to a `0600` private `node.env`; it is never echoed. The profile mounts a keyless TOML over the bundled image config, so even the older 1.20.6 image **fails** if the installation root is absent. `check-missing-key` must run before `start`; it probes the unprovisioned path without printing keys. Caddy obtains and renews a public certificate; do not bypass its trust verification.

The 1.20.6 config loader accepts both the legacy single-underscore nesting (`TINYCLOUD_KEYS_TYPE`, `TINYCLOUD_STORAGE_DATADIR`) and canonical double-underscore nesting (`TINYCLOUD_KEYS__TYPE`, `TINYCLOUD_STORAGE__DATADIR`). It merges canonical values last when both are set. This profile uses the canonical form; the existing dstack Compose retains its working single-underscore key-type setting.

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
bash deploy/personal-node/node.sh check-version 1.20.6
bash deploy/personal-node/node.sh verify /secure/path/owner.key
```

Use a fresh host/directory, not two live nodes serving the same identity and domain at once. Stop the old node before DNS cutover; wait for the new host's Caddy certificate, then verify before admitting clients. If verification fails, stop the destination and revert DNS to the old host. `verify` compares the public node DID saved before backup and the signed KV/SQL data; a different root fails rather than silently rotating. The backup is a full offline snapshot, **not** continuous replication. TLS ACME state is not in the backup, and a restore needs a reachable domain and valid certificate again.

## Upgrade and rollback rehearsal

CI executes [`ci.sh`](ci.sh) on a clean runner: 1.20.5 → 1.20.6, with data checks before and after restart, fresh-volume restores, and rollback by restoring the **pre-upgrade** snapshot into another fresh instance on 1.20.5. An in-place downgrade of a migrated database is not supported. A normal new installation starts directly on 1.20.6; do not downgrade it merely to rehearse.

```bash
# Run only on a disposable isolated runner with permission to create Docker
# containers. This is exactly the end-to-end job used by GitHub Actions.
bash deploy/personal-node/ci.sh
```

Before a future upgrade, take and verify an offline backup as above, stop the node, change the pinned image only to a reviewed released digest, start and verify identity and signed data. If verification fails, stop the candidate and restore that pre-upgrade backup to a fresh instance of the previous image; never blindly start the older binary against migrated data. The next-release upgrade step **requires the next approved production node release** and a new published-image CI run. TC-1176 prohibits promotion of that release until Sam separately clears the hold. Changes to the shipped default key in TC-1200 likewise require that next image; the mounted keyless profile is the safe 1.20.6 workaround, not proof that its bare image fails closed.

The [personal-node workflow](../../.github/workflows/personal-node.yml) is the acceptance evidence only when its published-image job is green. Record the successful run URL and exact image versions/digests in TC-1282; no CI result here authorizes a production deployment or a stronger sovereignty claim.
