# TC-75: Node Control Plane v1

Status: Draft

Scope: TC-58 Stage A

Consumers: TC-76 CLI layer, TC-77 KeyProvider, TC-78 control API

## 0. Goals

This spec defines the local control plane for `tinycloud-node` and the JSON
contract the CLI and desktop app will rely on.

It deliberately does not change the public Rocket API yet. The public server
continues to serve the existing TinyCloud protocol routes on Rocket 0.5 while
the local control plane is added beside it.

## 1. Transport Decision

### Decision

Use loopback HTTP plus a token file, with a separate control listener.

The control listener MUST bind only to loopback (`127.0.0.1` or `::1`). It
MUST authenticate every request with `Authorization: Bearer <token>`, where the
token is stored in a local file with mode `0600`.

### Why this option

| Option | Verdict | Why |
|---|---|---|
| Loopback HTTP + token file | Chosen | Cross-platform, easy for the CLI and desktop app, and keeps the local control surface simple. |
| Unix domain socket | Rejected for v1 | Better file-system ACL story on Unix, but it is not the best fit for the current desktop + service-manager target and it complicates discovery. |
| Add control routes to the Rocket app | Rejected for v1 | It couples the public API and local control plane, expands the Rocket surface area, and makes future migration harder. |

### Rocket 0.5 reality check

Rocket 0.5 expects TCP/IP listeners. Its own 0.5 release notes call out Unix
domain sockets as a next-major-release item, not a first-class v0.5 feature.
That means a UDS-based control plane would need extra plumbing that Rocket does
not give us today.

### Why a separate axum listener

axum is a better fit for the local control listener than adding the control
surface to Rocket:

- `axum::serve` runs a service on a supplied listener and is intentionally
  minimal.
- The control plane is small, JSON-only, and local-only.
- A separate axum listener keeps the public Rocket API stable while giving us a
  clean place to evolve the node control contract.

### Runtime files

The control listener writes a small runtime file under the node data directory:

- `dataPath/runtime/control.json`
- `dataPath/runtime/control.token`

`control.json` is the discovery file for the CLI. It is local-only and contains
the current loopback host/port, pid, and token path. `control.token` is the
auth token file and MUST have mode `0600`.

## 2. Control API v1

### Common rules

- Base path: `/v1`
- All JSON uses lowerCamelCase field names.
- Every successful response includes `contractVersion`.
- The token is sent as `Authorization: Bearer <token>`.
- The control listener never exposes secrets. Private keys, passphrases, and
  raw env-var secrets never appear in responses.

### Compatibility model

There are two independent version checks:

- Public API protocol: the existing public `/version.protocol` value. SDK
  compatibility remains an exact match.
- Control contract: the v1 semver string exposed here as `contractVersion`.

Rules:

1. Control clients are compatible when the major version matches and the server
   is on the same or newer minor/patch release.
2. Clients MUST ignore unknown fields.
3. A major-version mismatch is a hard incompatibility for mutating commands.
4. The public SDK protocol and the control contract are independent. A node can
   be compatible on one axis and incompatible on the other.

### Error shape

Non-2xx responses use a JSON error body:

```json
{
  "contractVersion": "1.0.0",
  "error": {
    "code": "invalid_token",
    "message": "missing or invalid bearer token",
    "details": {}
  }
}
```

`details` is optional. The exact code set is implementation-defined, but the
shape is stable.

### 2.1 `GET /v1/version`

Purpose: report the control contract version, node binary version, and public
protocol version.

Response:

```json
{
  "contractVersion": "1.0.0",
  "appVersion": "1.4.2",
  "publicProtocolVersion": 1,
  "identityReady": true,
  "keyBackend": "macos-keychain",
  "nodeDid": "did:key:z6Mk..."
}
```

Fields:

- `contractVersion`: control contract semver string.
- `appVersion`: `CARGO_PKG_VERSION` for the running binary.
- `publicProtocolVersion`: the existing public protocol integer.
- `identityReady`: whether the KeyProvider can sign with the node identity.
- `keyBackend`: `macos-keychain` or `encrypted-file`.
- `nodeDid`: the node DID when identity is ready, otherwise `null`.

### 2.2 `GET /v1/status`

Purpose: report the live runtime view of the node process.

Response:

```json
{
  "contractVersion": "1.0.0",
  "state": "running",
  "version": "1.4.2",
  "configPath": "/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml",
  "dataPath": "/Users/me/Library/Application Support/TinyCloud Node/",
  "logMode": "file",
  "keyBackend": "macos-keychain",
  "identityReady": true,
  "nodeDid": "did:key:z6Mk..."
}
```

Fields:

- `state`: `starting`, `running`, `stopping`, or `error`.
- `version`: node binary version.
- `configPath`: absolute path to the base config file in use.
- `dataPath`: absolute path to the node data root in use.
- `logMode`: `file`, `journald`, or `stdout`.
- `keyBackend`: identity KeyProvider kind.
- `identityReady`: whether the node can sign internally.
- `nodeDid`: public DID for the node identity, or `null` if not yet generated.

### 2.3 `GET /v1/identity`

Purpose: expose public identity material only.

Response:

```json
{
  "contractVersion": "1.0.0",
  "identityReady": true,
  "keyBackend": "macos-keychain",
  "nodeDid": "did:key:z6Mk..."
}
```

This endpoint MUST never expose the private key or any recovery material.

### 2.4 `GET /v1/config`

Purpose: return the effective node config, with secrets redacted.

Response:

```json
{
  "contractVersion": "1.0.0",
  "baseConfigPath": "/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml",
  "overlayPath": "/Users/me/Library/Application Support/TinyCloud Node/runtime/config.override.toml",
  "config": {
    "cors": true,
    "storage": {
      "datadir": "/Users/me/Library/Application Support/TinyCloud Node/",
      "database": "sqlite:/Users/me/Library/Application Support/TinyCloud Node/caps.db",
      "limit": "10 MiB"
    },
    "publicSpaces": {
      "rateLimitPerMinute": 60,
      "rateLimitBurst": 10,
      "storageLimit": "10 MiB"
    },
    "hooks": {
      "maxTicketTtlSeconds": 300,
      "maxScopesPerTicket": 32,
      "maxActiveSseStreams": 100,
      "sseBroadcastCapacity": 1024,
      "maxWebhookSubscriptionsPerSpace": 5,
      "webhookTimeoutSeconds": 10,
      "webhookMaxAttempts": 5
    },
    "keys": {
      "backend": "macos-keychain"
    }
  }
}
```

Rules:

- The `config` object is the effective merged config.
- Any secret-bearing value is omitted, not masked with fake data.
- The `keys` object only exposes the backend kind.

### 2.5 `PATCH /v1/config`

Purpose: persist a safe config overlay.

Request body:

```json
{
  "cors": false,
  "storage": {
    "limit": "20 MiB"
  },
  "publicSpaces": {
    "rateLimitPerMinute": 120
  }
}
```

Patch rules:

- Request format is JSON Merge Patch over the `config` object.
- The request MUST be rejected if it contains any field outside the whitelist
  below.
- The patch is persisted to the runtime overlay file, not to the base config
  file.
- Patchable fields are only the safe operational fields:
  - `cors`
  - `storage.limit`
  - `publicSpaces.rateLimitPerMinute`
  - `publicSpaces.rateLimitBurst`
  - `publicSpaces.storageLimit`
  - `hooks.maxTicketTtlSeconds`
  - `hooks.maxScopesPerTicket`
  - `hooks.maxActiveSseStreams`
  - `hooks.sseBroadcastCapacity`
  - `hooks.maxWebhookSubscriptionsPerSpace`
  - `hooks.webhookTimeoutSeconds`
  - `hooks.webhookMaxAttempts`

Response:

```json
{
  "contractVersion": "1.0.0",
  "restartRequired": false,
  "appliedPaths": [
    "cors",
    "storage.limit"
  ],
  "config": {
    "cors": false
  }
}
```

The response MAY include the full redacted config, but it MUST at least include
`appliedPaths`, `restartRequired`, and the current effective config snapshot.

### 2.6 `GET /v1/logs/tail`

Purpose: return the newest node logs in structured JSON.

Query params:

- `lines`: optional integer, default `200`, max `2000`.
- `since`: optional RFC3339 timestamp.

Response:

```json
{
  "contractVersion": "1.0.0",
  "source": "file",
  "cursor": "2026-07-02T12:34:56Z#000120",
  "entries": [
    {
      "timestamp": "2026-07-02T12:34:56Z",
      "level": "INFO",
      "target": "tinycloud::node",
      "message": "node started"
    }
  ]
}
```

Fields:

- `source`: `file`, `journald`, or `stdout`.
- `cursor`: opaque tail cursor for incremental fetching.
- `entries`: ordered oldest-to-newest within the returned slice.

## 3. CLI Contract

### 3.1 `tinycloud serve --config <path>`

Starts the public Rocket server and the local control listener.

Rules:

- `--config <path>` selects the base config file.
- If `--config` is omitted, the current dev behavior of using `./tinycloud.toml`
  remains supported for backward compatibility.
- The node writes the runtime control files under `dataPath/runtime/`.
- The public API remains on Rocket 0.5.
- The control listener is separate and local-only.

### 3.2 `tinycloud node service install|start|stop|restart|status --json|uninstall`

This is the host integration layer.

Manager selection:

- macOS: `launchd-user` by default. `homebrew-launchagent` is used when the
  install is managed by Homebrew services.
- Linux user: `systemd-user`.
- Linux system: `systemd-system`.

Command behavior:

- `install` writes the service definition and enables it.
- `start` launches the node.
- `stop` stops the node.
- `restart` stops and starts the node.
- `status` reports the merged service status object.
- `uninstall` disables and removes the service definition and runtime control
  files.

`status --json` MUST emit the exact schema in section 3.3.

### 3.3 Exact `service status --json` output shape

```json
{
  "contractVersion": "1.0.0",
  "platform": "macos",
  "manager": "launchd-user",
  "state": "running",
  "pid": 12345,
  "enabledAtLogin": true,
  "version": "1.4.2",
  "configPath": "/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml",
  "dataPath": "/Users/me/Library/Application Support/TinyCloud Node/",
  "logMode": "file",
  "keyBackend": "macos-keychain",
  "identityReady": true,
  "nodeDid": "did:key:z6Mk..."
}
```

Field contract:

- `platform`: `macos` or `linux`.
- `manager`: `homebrew-launchagent`, `launchd-user`, `systemd-user`, or
  `systemd-system`.
- `state`: `not-installed`, `stopped`, `starting`, `running`, `stopping`, or
  `error`.
- `pid`: integer when running, otherwise `null`.
- `enabledAtLogin`: boolean. For `systemd-system`, this is always `false`.
- `version`: node binary version.
- `configPath`: absolute base config path.
- `dataPath`: absolute data root path.
- `logMode`: `file`, `journald`, or `stdout`.
- `keyBackend`: identity KeyProvider backend kind.
- `identityReady`: whether the node identity is ready for signing.
- `nodeDid`: node DID, or `null` if identity is not ready.

### 3.4 `tinycloud node status`

Returns the live control-plane status.

Contract:

- It maps to `GET /v1/status`.
- In `--json` mode, it emits the exact `/v1/status` response body.
- It is the runtime view, not the service-manager view.

### 3.5 `tinycloud node logs`

Returns the live log tail.

Contract:

- It maps to `GET /v1/logs/tail`.
- Default tail size is `200` lines.
- In `--json` mode, it emits the exact `/v1/logs/tail` response body.

### 3.6 `tinycloud node doctor`

Returns a health report synthesized from local files and control endpoints.

Sources:

- `service status --json` for manager and install state.
- `GET /v1/status` for live node state.
- `GET /v1/identity` for public identity readiness.
- `GET /v1/config` for config and overlay checks.
- Local filesystem checks for config/data paths and token file permissions.

Suggested output shape:

```json
{
  "contractVersion": "1.0.0",
  "ok": true,
  "checks": [
    { "name": "service", "status": "pass" },
    { "name": "control", "status": "pass" },
    { "name": "identity", "status": "pass" },
    { "name": "config", "status": "pass" }
  ],
  "warnings": []
}
```

### 3.7 `tinycloud node key backup`

Creates a recoverable backup bundle of the node key material.

Contract:

- The backup bundle is local and opaque.
- It MUST NOT print raw private key bytes.
- The default destination is under `dataPath/backups/`.
- The CLI returns metadata JSON on success.

Suggested success JSON:

```json
{
  "contractVersion": "1.0.0",
  "backupPath": "/Users/me/Library/Application Support/TinyCloud Node/backups/node-key-2026-07-02.bundle",
  "keyBackend": "macos-keychain",
  "nodeDid": "did:key:z6Mk..."
}
```

### 3.8 `tinycloud node key export`

Exports public identity material only.

Contract:

- It maps to `GET /v1/identity`.
- It MUST never expose the private key.
- In `--json` mode, it emits the exact `/v1/identity` response body.

## 4. Platform Paths

The node has a config root and a data root. The control runtime files live under
the data root.

| Platform / manager | Config root | Data root | Logs |
|---|---|---|---|
| macOS `launchd-user` / `homebrew-launchagent` | `~/Library/Application Support/TinyCloud Node/` (`tinycloud.toml` inside) | `~/Library/Application Support/TinyCloud Node/` | `~/Library/Logs/TinyCloud Node/` |
| Linux `systemd-user` | `$XDG_CONFIG_HOME/tinycloud-node/` or `~/.config/tinycloud-node/` | `$XDG_DATA_HOME/tinycloud-node/` or `~/.local/share/tinycloud-node/` | journald |
| Linux `systemd-system` | `/etc/tinycloud-node/` | `/var/lib/tinycloud-node/` | journald |

### Config loading order

The current config loading behavior remains, with one runtime overlay added for
the control plane:

1. Built-in defaults from `Config::default()`.
2. Base config file from `--config <path>` or the platform default `tinycloud.toml`.
3. Runtime overlay file at `dataPath/runtime/config.override.toml`.
4. `TINYCLOUD_` env vars, with `__` nesting preferred and legacy `_` still
   accepted.

Important:

- Env vars always win over files.
- Secret material is never sourced from env vars in the desktop/service flow.
- `tinycloud.toml` remains the base config file name regardless of platform.

## 5. Security Invariants

- The control plane MUST never bind a non-loopback address.
- The token file MUST be mode `0600`.
- The runtime directory SHOULD be mode `0700`.
- Private keys MUST NOT be placed in env vars.
- Private keys MUST NOT appear in control API responses, CLI JSON, logs, or
  doctor output.
- The app requests actions and the node signs internally. The desktop app and
  CLI never handle raw private keys.
- `PATCH /v1/config` cannot mutate key material, storage roots, or binding
  endpoints.

## 6. Key Material

### KeyProvider abstraction

The node identity key is owned by a KeyProvider abstraction. The backend kind
is public metadata and is surfaced as `keyBackend` in status and identity
responses.

Backends:

- `macos-keychain`: stores the identity secret in the user's login keychain.
  When iCloud Keychain is enabled by the user, the item can sync with the rest
  of their Apple devices.
- `encrypted-file`: stores the identity secret in an encrypted file under the
  data root for Linux and headless deployments.

### First run

If no node identity exists yet:

1. Generate a new node keypair.
2. Persist it through the selected KeyProvider.
3. Derive the node DID from the public key.
4. Mark `identityReady` true once the key can sign.

The node DID is stable for a given KeyProvider-backed identity.

### Backup and export UX

- `node key export` is public-only. It returns the node DID and backend kind,
  and it maps directly to `GET /v1/identity`.
- `node key backup` produces a recoverable sealed bundle. It is the recovery
  artifact, not the public export.

The backup bundle MUST be restorable without exposing plaintext private keys to
the CLI.

## 7. Non-goals

- No big-bang migration away from Rocket for the public API.
- No UDS requirement in v1.
- No private-key exposure through env vars.
- No attempt to make the control plane public or remotely reachable.
