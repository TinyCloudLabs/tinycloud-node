# TC-75: Node Control Plane v1

Status: Draft

Scope: TC-58 Stage A

Consumers: TC-76 CLI layer, TC-77 KeyProvider, TC-78 control API

Control contract version for this spec: `1.0.0`

## 0. Purpose

This document defines the local node control plane for `tinycloud-node` and the
JSON contract that the CLI and desktop app will use.

It does not migrate the public TinyCloud API away from Rocket yet. The public
server stays on Rocket 0.5 for now; the control plane is a separate local-only
surface.

## 1. Transport Decision

### Decision

Use loopback HTTP plus a token file, with a separate control listener.

The control listener MUST bind only to loopback (`127.0.0.1` or `::1`). It
MUST authenticate every request with `Authorization: Bearer <token>`, where the
token is stored in a local file. User installs keep that file mode `0600`;
`systemd-system` installs may use `0640 root:tinycloud` so root or the
`tinycloud` group can read it.

### Why this option

| Option | Verdict | Why |
|---|---|---|
| Loopback HTTP + token file | Chosen | Cross-platform, easy for the CLI and desktop app to discover, and simple to secure locally. |
| Unix domain socket | Rejected for v1 | Good on Unix, but not worth the discovery and portability cost here. |
| Mount control routes into Rocket | Rejected for v1 | Couples the local control surface to the public API and makes future transport changes harder. |

### Rocket 0.5 reality check

Rocket 0.5 still expects TCP/IP listeners. Rocket's own v0.5 release notes say
pluggable listeners and Unix domain sockets are next-major work, so UDS is not a
native Rocket 0.5 deployment target. A Rocket-hosted control plane would either
stay on TCP loopback or require extra listener plumbing that Rocket does not
provide today.

### Why a separate axum listener

axum is the better control-plane host than adding these routes to Rocket:

- `axum::serve` takes a supplied listener and stays deliberately minimal.
- The control API is JSON-only, local-only, and state-light.
- A separate listener keeps the public Rocket API unchanged for now.
- If v2 ever switches the local transport to UDS, that change stays isolated to
  the control plane instead of forcing a Rocket migration.

### Runtime files

The node owns the following local-only runtime files under `dataPath/runtime/`:

- `dataPath/runtime/control.json`
- `dataPath/runtime/control.token`
- `dataPath/runtime/config.override.toml`

The CLI-owned install manifest lives at `${configRoot}/service.json`:

- macOS: `~/Library/Application Support/TinyCloud Node/service.json`
- Linux user: `$XDG_CONFIG_HOME/tinycloud-node/service.json` or
  `~/.config/tinycloud-node/service.json`
- Linux system: `/etc/tinycloud-node/service.json`

The control listener chooses an available loopback port at startup and records
it in `control.json`. The token file is generated on startup, stored only on
disk, and MUST remain mode `0600` for user installs; `systemd-system` installs
may use `0640 root:tinycloud` so the documented group-read access path works.

Example `service.json`:

```json
{
  "contractVersion": "1.0.0",
  "profile": "macos-user",
  "platform": "macos",
  "manager": "launchd-user",
  "version": "1.4.2",
  "configPath": "/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml",
  "dataPath": "/Users/me/Library/Application Support/TinyCloud Node/",
  "logMode": "file",
  "keyBackend": "macos-keychain"
}
```

Example `control.json`:

```json
{
  "contractVersion": "1.0.0",
  "host": "127.0.0.1",
  "port": 49152,
  "pid": 12345,
  "tokenPath": "/Users/me/Library/Application Support/TinyCloud Node/runtime/control.token"
}
```

`service.json` is the CLI-owned bootstrap install manifest used by the CLI to
report service state even when the node is stopped. `tinycloud node service
install` writes it and `uninstall` removes it; the node never writes it.
`control.json` is the discovery file for the live control listener. Both files
are local-only, and node-owned runtime files stay under `dataPath/runtime/`.

`service.json` fields:

- `contractVersion`: semver string for the CLI/control contract.
- `profile`: install profile identifier used by the CLI.
- `platform`: `macos` or `linux`.
- `manager`: `homebrew-launchagent`, `launchd-user`, `systemd-user`, or
  `systemd-system`.
- `version`: node binary version when known.
- `configPath`: absolute base config path.
- `dataPath`: absolute data root path.
- `logMode`: `file`, `journald`, or `stdout`.
- `keyBackend`: `macos-keychain` or `encrypted-file`.

`control.json` fields:

- `contractVersion`: semver string for the CLI/control contract.
- `host`: loopback host bound by the live control listener.
- `port`: loopback TCP port bound by the live control listener.
- `pid`: process ID of the live node, when known.
- `tokenPath`: absolute path to the bearer token file.

## 2. Control API v1

### Common rules

- Base path: `/v1`
- All JSON uses lowerCamelCase field names.
- Every successful response includes `contractVersion`.
- The token is sent as `Authorization: Bearer <token>`.
- The control plane never exposes private keys, passphrases, recovery seeds, or
  secret env-var values.
- `GET /v1/config` and `PATCH /v1/config` return a public projection of the
  effective config, not a verbatim serialization of the internal `Config`
  struct. Secret-bearing fields are omitted entirely.
- All paths in responses are absolute after resolution.
- All byte sizes in JSON are exact byte counts, serialized as JSON numbers.

### Compatibility model

There are two independent version axes:

| Axis | Field | Compatibility rule |
|---|---|---|
| Control contract | `contractVersion` | Same major version only. A client may talk to a server with the same major and a greater or equal minor/patch version if it ignores unknown fields and still finds every field it needs. A major mismatch is a hard incompatibility for mutating commands. |
| Public API SDK | `publicProtocolVersion` | Exact integer match for the existing public Rocket API protocol. |

Additional rules:

1. Clients MUST ignore unknown response fields.
2. Clients MUST fail a command if a field they require is absent or has an
   incompatible type.
3. `appVersion` and `version` are informational and are not compatibility keys.
4. The desktop app may still use service-manager-only commands when the control
   contract is incompatible, but it MUST not issue control mutations across a
   major contract mismatch.
5. `publicProtocolVersion` gates only the existing public Rocket API. It is
   independent from the control contract version and can be checked separately by
   SDK consumers.

### Error shape

Non-2xx responses use this JSON shape:

```json
{
  "contractVersion": "1.0.0",
  "error": {
    "code": "invalid_request",
    "message": "field 'storage.limitBytes' must be a positive integer",
    "details": {}
  }
}
```

Suggested error codes:

- `invalid_token`
- `invalid_request`
- `incompatible_contract`
- `not_found`
- `conflict`
- `internal_error`

`details` is optional and may be an empty object.

### Shared enums

- `keyBackend`: `macos-keychain`, `encrypted-file`, `static`, `dstack`. Legacy
  `Static{secret}`/`TINYCLOUD_KEYS_SECRET` sources report `static` (`doctor`
  emits a deprecation warning) and TEE deployments report `dstack`.
- `logMode`: `file`, `journald`, `stdout`
- `platform`: `macos`, `linux`
- `manager`: `homebrew-launchagent`, `launchd-user`, `systemd-user`, `systemd-system`
- `state` for `service status`: `not-installed`, `stopped`, `starting`, `running`, `stopping`, `error`
- `state` for `GET /v1/status`: `starting`, `running`, `stopping`
- `error` is reserved for future control-plane use and is not emitted by v1

### 2.1 `GET /v1/version`

Purpose: report the control contract version, the running binary version, and
the public protocol version.

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

Field definitions:

- `contractVersion`: semver string for the control contract.
- `appVersion`: `CARGO_PKG_VERSION` for the running node binary.
- `publicProtocolVersion`: the current public TinyCloud protocol version.
- `identityReady`: `true` when the node can sign with its identity key.
- `keyBackend`: public KeyProvider kind, or `null` before the backend has been
  initialized.
- `nodeDid`: public DID for the node identity, or `null` if the identity is not
  ready.

### 2.2 `GET /v1/identity`

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

Field definitions:

- `contractVersion`: semver string for the control contract.
- `identityReady`: `true` when the KeyProvider can sign.
- `keyBackend`: public KeyProvider kind, or `null` before the backend has been
  initialized.
- `nodeDid`: public DID for the node identity, or `null` if the identity has
  not been generated yet.

This endpoint MUST never expose private key material or recovery material.

### 2.3 `GET /v1/status`

Purpose: report the live runtime view of the node process.

Response:

```json
{
  "contractVersion": "1.0.0",
  "state": "running",
  "pid": 12345,
  "version": "1.4.2",
  "publicApi": {
    "address": "127.0.0.1",
    "port": 8081
  },
  "configPath": "/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml",
  "dataPath": "/Users/me/Library/Application Support/TinyCloud Node/",
  "logMode": "file",
  "keyBackend": "macos-keychain",
  "identityReady": true,
  "nodeDid": "did:key:z6Mk..."
}
```

Field definitions:

- `contractVersion`: semver string for the control contract.
- `state`: live runtime state of the node process. `starting` means the node is
  booting but not yet ready, `running` means the control plane is serving, and
  `stopping` means shutdown is in progress. `error` is reserved and is not
  emitted by v1.
- `pid`: the running process ID.
- `version`: node binary version.
- `publicApi`: live Rocket bind address and port.
- `publicApi.address`: v0 binds `127.0.0.1` by default.
- `publicApi.port`: v0 binds `8081` by default.
- `configPath`: absolute path to the base config file in use.
- `dataPath`: absolute path to the data root in use.
- `logMode`: `file`, `journald`, or `stdout`.
- `keyBackend`: public KeyProvider kind, or `null` during very early startup.
- `identityReady`: whether the node can sign internally.
- `nodeDid`: public DID for the node identity, or `null` if identity is not
  ready.

### 2.4 `GET /v1/config`

Purpose: return the effective public config snapshot, with secret-bearing fields
omitted.

The snapshot is the normalized result of:

1. built-in defaults,
2. the base config file from `--config <path>` or the platform default
   `tinycloud.toml`,
3. the runtime overlay at `dataPath/runtime/config.override.toml`,
4. `TINYCLOUD_` environment variables, with `__` nesting preferred and legacy
   `_` still accepted.

Environment variables always win over files. This endpoint reports the
effective runtime configuration; it does not claim that the running process has
hot-reloaded every field.

Response:

```json
{
  "contractVersion": "1.0.0",
  "baseConfigPath": "/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml",
  "overlayPath": "/Users/me/Library/Application Support/TinyCloud Node/runtime/config.override.toml",
  "config": {
    "log": {
      "format": "text",
      "tracing": {
        "enabled": false,
        "traceHeader": "TinyCloud-Trace-Id"
      }
    },
    "storage": {
      "dataDir": "/Users/me/Library/Application Support/TinyCloud Node/",
      "blocks": {
        "type": "local",
        "path": "/Users/me/Library/Application Support/TinyCloud Node/blocks"
      },
      "staging": "memory",
      "database": {
        "backendKind": "sqlite",
        "path": "/Users/me/Library/Application Support/TinyCloud Node/caps.db"
      },
      "sql": {
        "path": "/Users/me/Library/Application Support/TinyCloud Node/sql",
        "memoryThresholdBytes": 10485760
      },
      "duckdb": {
        "path": "/Users/me/Library/Application Support/TinyCloud Node/duckdb",
        "memoryThresholdBytes": 10485760,
        "idleTimeoutSeconds": 300,
        "maxMemoryPerConnection": "128MiB"
      }
    },
    "spaces": {
      "allowlistUrl": null
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
    "publicApi": {
      "address": "127.0.0.1",
      "port": 8081
    },
    "telemetry": {
      "enabled": false
    },
    "prometheus": {
      "port": 8001
    },
    "cors": false,
    "keyProvider": {
      "backend": "macos-keychain"
    },
    "tee": {
      "mode": "auto",
      "attestation": false
    },
    "publicSpaces": {
      "rateLimitPerMinute": 60,
      "rateLimitBurst": 10,
      "storageLimitBytes": 10485760
    }
  }
}
```

Schema notes:

- Every path field in the snapshot is absolute.
- `baseConfigPath` is the absolute path to the base config file selected by
  `--config` or the platform default.
- `overlayPath` is the absolute path to `dataPath/runtime/config.override.toml`.
- `keyProvider.backend` is read-only, derived public metadata. It is not the
  raw on-disk key configuration.
- `keyProvider.backend` is derived from the effective legacy `keys` source:
  explicit `Static{secret}` or `TINYCLOUD_KEYS_SECRET` wins for backward
  compatibility, but that path is deprecated for desktop installs and `doctor`
  warns; `Auto` selects `macos-keychain` on macOS and `encrypted-file` on
  Linux. Legacy `keys = Dstack` remains reserved for TEE deployments and is
  not chosen by new desktop installs.
- `storage.database` is a public descriptor only. It never returns a raw DSN,
  credentials, or query parameters. For SQLite, `path` is the absolute file
  path; for MySQL/Postgres, `path` is `null`.
- Secret-bearing fields are omitted, not masked with fake placeholder strings.

Top-level `config` fields:

- `log`
- `storage`
- `spaces`
- `hooks`
- `publicApi`
- `telemetry`
- `prometheus`
- `cors`
- `keyProvider`
- `tee`
- `publicSpaces`

`log`:

- `format`: `text` or `json`
- `tracing.enabled`: boolean
- `tracing.traceHeader`: string

`storage`:

- `dataDir`: absolute path string
- `blocks`: block store object
- `staging`: `memory` or `file-system`
- `database.backendKind`: `sqlite`, `mysql`, `postgres`, or `other`
- `database.path`: absolute path string for file-backed SQLite, otherwise
  `null`
- `limitBytes`: integer or `null`
- `sql.path`: absolute path string
- `sql.memoryThresholdBytes`: integer
- `duckdb.path`: absolute path string
- `duckdb.memoryThresholdBytes`: integer
- `duckdb.idleTimeoutSeconds`: integer
- `duckdb.maxMemoryPerConnection`: raw string preserved from config

`storage.blocks`:

- If local:
  - `type`: `local`
  - `path`: absolute path string
- If S3:
  - `type`: `s3`
  - `bucket`: string
  - `endpoint`: string or `null`

`spaces`:

- `allowlistUrl`: string or `null`

`hooks`:

- `maxTicketTtlSeconds`
- `maxScopesPerTicket`
- `maxActiveSseStreams`
- `sseBroadcastCapacity`
- `maxWebhookSubscriptionsPerSpace`
- `webhookTimeoutSeconds`
- `webhookMaxAttempts`

`publicApi`:

- `address`: bind address; v0 defaults to `127.0.0.1`.
- `port`: bind port; v0 defaults to `8081`.

`telemetry`:

- `enabled`

`prometheus`:

- `port`

`keyProvider`:

- `backend`: `macos-keychain`, `encrypted-file`, `static`, or `dstack`. Legacy
  `Static{secret}`/`TINYCLOUD_KEYS_SECRET` sources report `static` (`doctor`
  emits a deprecation warning) and TEE deployments report `dstack`.

`tee`:

- `mode`: `auto`, `dstack`, or `off`
- `attestation`: boolean

`publicSpaces`:

- `rateLimitPerMinute`
- `rateLimitBurst`
- `storageLimitBytes`

### 2.5 `PATCH /v1/config`

Purpose: persist a safe config overlay.

The request body is a partial update document with a strict whitelist. Omitted
fields are unchanged. `null` resets a whitelisted field to its built-in default;
for `storage.limitBytes`, `null` clears the limit entirely. TOML has no native
`null`, so on disk the runtime overlay stores a cleared `storage.limitBytes` as
`0`; that stored `0` is the null-clear sentinel and is never a real zero-byte
quota.

Allowed fields:

- `cors`
- `log.format`
- `log.tracing.enabled`
- `storage.limitBytes`
- `publicSpaces.rateLimitPerMinute`
- `publicSpaces.rateLimitBurst`
- `publicSpaces.storageLimitBytes`
- `hooks.maxTicketTtlSeconds`
- `hooks.maxScopesPerTicket`
- `hooks.maxActiveSseStreams`
- `hooks.sseBroadcastCapacity`
- `hooks.maxWebhookSubscriptionsPerSpace`
- `hooks.webhookTimeoutSeconds`
- `hooks.webhookMaxAttempts`

Disallowed fields include, at minimum:

- `storage.dataDir`
- `storage.blocks`
- `storage.database`
- `storage.sql`
- `storage.duckdb`
- `publicApi.address`
- `publicApi.port`
- `prometheus.port`
- `telemetry.enabled`
- `keyProvider.backend`
- `tee.mode`
- `tee.attestation`

Request example:

```json
{
  "cors": false,
  "storage": {
    "limitBytes": 20971520
  },
  "publicSpaces": {
    "rateLimitPerMinute": 120
  }
}
```

Response:

```json
{
  "contractVersion": "1.0.0",
  "baseConfigPath": "/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml",
  "overlayPath": "/Users/me/Library/Application Support/TinyCloud Node/runtime/config.override.toml",
  "restartRequired": true,
  "appliedPaths": [
    "cors",
    "storage.limitBytes",
    "publicSpaces.rateLimitPerMinute"
  ],
  "config": {
    "...": "full public snapshot after the overlay is written"
  }
}
```

Field definitions:

- `baseConfigPath`: absolute path to the base config file selected by the CLI
  or platform default.
- `overlayPath`: absolute path to `dataPath/runtime/config.override.toml`.
- `restartRequired`: `true` when the patch changes overlay state for a field
  that requires restart, or when it changes the effective config for at least
  one requested restart-required field. Fields masked by a higher-precedence
  env var can still set this to `true` even when `appliedPaths` is empty,
  because the overlay changed even though the effective value did not.
- `appliedPaths`: canonical leaf paths that actually changed effective value.
  Fields masked by a higher-precedence env var are excluded; the response's
  effective `config` snapshot still reflects the env-masked value.
- `config`: the full effective public snapshot after the overlay write.

Invalid, unsafe, or unknown fields MUST be rejected with `400 invalid_request`.

### 2.6 `GET /v1/logs/tail`

Purpose: return the newest node logs in structured JSON.

Query params:

- `lines`: optional integer, default `200`, max `2000`
- `cursor`: optional opaque tail cursor
- `since`: optional RFC3339 timestamp

If both `cursor` and `since` are provided, `cursor` wins.

Response:

```json
{
  "contractVersion": "1.0.0",
  "source": "file",
  "cursor": "f:8388608:1234567",
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

Field definitions:

- `source`: `file`, `journald`, or `stdout`. In v1, all three are served from
  the node's in-memory ring buffer.
- `cursor`: opaque cursor for the newest returned entry, or `null` if there are
  no entries
- `entries`: ordered oldest-to-newest within the returned slice

- Native byte-offset and journald cursor formats are reserved for a future
  version; v1 serves all sources from the node's in-memory ring buffer.
- `cursor` values are opaque and process-lifetime scoped. If a cursor is
  stale, malformed, or has fallen out of the ring buffer, the server restarts
  from the newest tail window instead of erroring.
- Launchd/systemd stdout and stderr redirection remain the durable log sink on
  disk or in the journal; `/v1/logs/tail` does not read those sources directly
  in v1.

Log entry fields:

- `timestamp`: RFC3339 timestamp
- `level`: `TRACE`, `DEBUG`, `INFO`, `WARN`, or `ERROR`
- `target`: tracing target string
- `message`: rendered log message
- `fields`: optional object of extra structured log fields

`stdout` mode behavior:

- The node keeps an in-memory ring buffer of the most recent 2000 structured
  log entries.
- The buffer is not persisted across restarts.
- `cursor` values are valid only for the current process lifetime.
- If a cursor has fallen out of the buffer, the server returns the newest
  available window instead of erroring.

## 3. CLI Contract

All JSON-emitting CLI commands must pass through the exact control endpoint body
or a local file result. The CLI may add human formatting outside JSON mode, but
it MUST NOT reshape the JSON contract.

### Source map

| CLI command | Source |
|---|---|
| `tinycloud serve --config <path>` | Base config file plus runtime overlay and env vars |
| `tinycloud node service install` | Service manager + `service.json` manifest |
| `tinycloud node service start|stop|restart` | Service manager |
| `tinycloud node service status --json` | Service manager + `service.json` + `control.json` + `control.token` + local config file + `GET /v1/version` + `GET /v1/status` + `GET /v1/identity` |
| `tinycloud node service uninstall` | Service manager + `service.json` manifest + runtime files |
| `tinycloud node status` | `service.json` + `control.json` + `control.token` + `GET /v1/status` |
| `tinycloud node logs` | `service.json` + `control.json` + `control.token` + `GET /v1/logs/tail` |
| `tinycloud node doctor` | `service.json` + `control.json` + `control.token` + `GET /v1/status` + `GET /v1/identity` + `GET /v1/config` + local filesystem checks |
| `tinycloud node key backup` | KeyProvider store + local backup bundle path |
| `tinycloud node key export` | `service.json` + `control.json` + `control.token` + `GET /v1/identity` |

### Control discovery

Any command that talks to the live control API MUST discover the node in this
order:

1. Locate the CLI-owned `service.json` manifest for the installed profile at
   the well-known platform path.
2. Read `service.json` to learn `profile`, `dataPath`, `configPath`, `logMode`,
   `keyBackend`, `platform`, `manager`, and the fallback `contractVersion`.
3. Read `dataPath/runtime/control.json` to obtain the loopback `host`, `port`,
   `pid`, and `tokenPath`.
4. Read the token file at `tokenPath` and send it as `Authorization: Bearer <token>`.

If any discovery file is missing or unreadable, the command MUST fail locally
rather than guessing at a host, port, or token.

### 3.1 `tinycloud serve --config <path>`

Starts the public Rocket server and the separate local control listener.

Rules:

- `--config <path>` selects the base config file.
- If `--config` is omitted, the platform default `configRoot/tinycloud.toml`
  path is used.
- The node writes runtime files under `dataPath/runtime/`.
- The public API remains on Rocket 0.5.
- The control listener is separate, local-only, and never binds a non-loopback
  address.
- `serve` is the only command that starts a foreground node process directly;
  the service-manager commands wrap it for installation and lifetime control.

### 3.2 `tinycloud node service install|start|stop|restart|status --json|uninstall`

This is the host integration layer.

Manager selection:

- macOS: `launchd-user` by default.
- macOS managed by Homebrew services: `homebrew-launchagent`.
- Linux user: `systemd-user`.
- Linux system: `systemd-system`.

Command behavior:

- `install` writes the service definition, writes `service.json` at the fixed
  well-known platform manifest path outside `dataPath/runtime/`, and enables
  the service.
- `start` launches the node.
- `stop` stops the node.
- `restart` stops and starts the node.
- `status` reports the merged service status object.
- `uninstall` disables and removes the service definition, the CLI-owned
  `service.json` manifest, and the runtime control files.

`install` must also write `service.json` with the exact install profile used by
the node, including the chosen `profile`, `configPath`, `dataPath`, `manager`,
`logMode`, and `keyBackend`.

The runtime control files that uninstall removes are:

- `dataPath/runtime/control.json`
- `dataPath/runtime/control.token`
- `dataPath/runtime/config.override.toml`

`status --json` MUST emit the exact schema in section 3.3.

### 3.3 Exact `service status --json` output shape

```json
{
  "contractVersion": "1.0.0",
  "profile": "macos-user",
  "platform": "macos",
  "manager": "launchd-user",
  "state": "running",
  "pid": 12345,
  "enabledAtLogin": true,
  "version": "1.4.2",
  "publicApi": {
    "address": "127.0.0.1",
    "port": 8081
  },
  "configPath": "/Users/me/Library/Application Support/TinyCloud Node/tinycloud.toml",
  "dataPath": "/Users/me/Library/Application Support/TinyCloud Node/",
  "logMode": "file",
  "keyBackend": "macos-keychain",
  "identityReady": true,
  "nodeDid": "did:key:z6Mk..."
}
```

Field contract:

- `contractVersion`: semver string for the CLI/control contract. It should match
  the live `/v1/version` contract when the control API is reachable.
- `profile`: install profile identifier: `macos-user`, `linux-user`, or
  `linux-system`.
- `platform`: `macos` or `linux`.
- `manager`: `homebrew-launchagent`, `launchd-user`, `systemd-user`, or
  `systemd-system`.
- `state`: `not-installed`, `stopped`, `starting`, `running`, `stopping`, or
  `error`.
- The service manager only reports `running` with a pid, `stopped`, or
  `not-installed`.
- `starting` means the manager reports `running` with a pid, the control probe
  is not yet succeeding, and the process age is under 30 seconds.
- `running` means the manager reports `running` with a pid and the control
  probe succeeds.
- `stopping` is only reported when `/v1/status` says graceful shutdown is in
  progress.
- `error` means the manager reports `running` but the control probe still fails
  after 30 seconds, or the live control API reports an unrecoverable failure.
- `pid`: integer when running, otherwise `null`.
- `enabledAtLogin`: boolean. For `systemd-system`, this is always `false`.
- `version`: node binary version when known, otherwise `null`.
- `publicApi`: live Rocket bind address and port. v0 defaults to
  `127.0.0.1:8081`.
- `configPath`: absolute base config path.
- `dataPath`: absolute data root path.
- `logMode`: `file`, `journald`, `stdout`, or `null` if the install metadata is
  unavailable. `file` is the normal mode for macOS user installs and Linux
  user installs, `journald` is the normal mode for Linux system installs, and
  `stdout` is only used for foreground `serve` runs or debug profiles.
- `keyBackend`: identity KeyProvider backend kind, or `null` if the install
  metadata is unavailable.
- `identityReady`: whether the node identity is ready for signing.
- `nodeDid`: node DID, or `null` if identity is not ready.

Source mapping:

- `profile`, `platform`, `manager`, `configPath`, `dataPath`, `logMode`, and
  `keyBackend` come from `service.json` when installed, otherwise from the
  CLI's platform default target.
- `publicApi` comes from the live control API when reachable, otherwise from
  the config file identified by `service.json`, otherwise from the CLI's
  built-in platform defaults.
- `contractVersion` comes from `GET /v1/version` when reachable, otherwise from
  `service.json`, otherwise from the CLI's built-in control contract version.
- `state`, `pid`, and `enabledAtLogin` come from the service manager. The
  manager only reports `running` with a pid, `stopped`, or `not-installed`; the
  CLI derives `starting` and `error` using the control probe and a 30-second
  process-age grace window. If the live control API explicitly reports
  `stopping`, that state is preserved.
- `version`, `identityReady`, and `nodeDid` come from the control API when
  reachable.
- If the control API is unreachable, `identityReady` is `false`, `nodeDid` is
  `null`, and `version` falls back to `service.json` if available.

`state` is therefore manager-first, with live control health used as a
consistency check instead of a separate source of truth.

TC-78 resolves the v0 transition for the node control plane: the CLI now reads
live control health, identity, and version data from the local control API when
the node is serving. During the initial 30-second grace window, nodes that do
not expose the control listener may still surface `controlApi: "unavailable"`;
if the probe is still failing after 30 seconds, the CLI escalates the service
state to `error` instead of leaving the failure masked.

### 3.4 `tinycloud node status`

Returns the live control-plane status.

Contract:

- It maps to `GET /v1/status` after the CLI has discovered `control.json` and
  the bearer token.
- In `--json` mode, it emits the exact `/v1/status` response body.
- It is the runtime view, not the service-manager view.
- If discovery fails or the control API is unreachable, the command fails
  locally instead of fabricating a status object.

### 3.5 `tinycloud node logs`

Returns the live log tail.

Contract:

- It maps to `GET /v1/logs/tail` after the CLI has discovered `control.json`
  and the bearer token.
- Default tail size is `200` lines.
- In `--json` mode, it emits the exact `/v1/logs/tail` response body.
- When the node is running in `stdout` log mode, tailing is best-effort and
  comes from the in-memory ring buffer described above.
- If discovery fails or the control API is unreachable, the command fails
  locally instead of guessing.

### 3.6 `tinycloud node doctor`

Returns a health report synthesized from local files and control endpoints.

Sources:

- `service status --json` for manager and install state.
- `GET /v1/status` for live node state.
- `GET /v1/identity` for public identity readiness.
- `GET /v1/config` for config, overlay, and public API bind checks.
- Local filesystem checks for config/data paths, runtime files, and token file
  permissions.
- `doctor` must use the public config snapshot only; it must not read or echo a
  raw DSN or any private key material.

On v0 installs, `doctor` MUST fail if the effective `publicApi.address` is not
loopback.

On desktop installs, `doctor` SHOULD warn if the effective key source is the
legacy `Static{secret}` or `TINYCLOUD_KEYS_SECRET` path.

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

Each check status is `pass`, `warn`, or `fail`.

`doctor` may include extra check details, but it MUST keep the fields above.

### 3.7 `tinycloud node key backup`

Creates a recoverable backup bundle of the node key material.

Contract:

- The backup bundle is local and opaque.
- It MUST NOT print raw private key bytes.
- The command links the KeyProvider library in-process, reads the local
  KeyProvider store directly, and does not require the live control listener.
- It is the explicit documented trust boundary: the CLI may hold secret
  material in memory only long enough to seal the export bundle, and it never
  transmits that material over the control API.
- The default destination is under `dataPath/backups/`.
- The bundle supports a passphrase-wrapped outer layer, and `backup` requires
  the user to supply a passphrase in v1.
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

If the node identity is not ready yet, `backup` MUST fail instead of inventing a
bundle.

The bundle format itself is intentionally opaque in v1, but it is versioned so
future `key restore` support can be added without breaking existing bundles.

### 3.8 `tinycloud node key export`

Exports public identity material only.

Contract:

- It maps to `GET /v1/identity` after the CLI has discovered `control.json`
  and the bearer token.
- It MUST never expose the private key.
- In `--json` mode, it emits the exact `/v1/identity` response body.

### 3.9 `tinycloud node link` (v1-link)

`link` subcommands integrate the node with the tinycloud.link name+cert
service so LAN clients can reach the node over browser-trusted HTTPS at
`https://<name>.local.tinycloud.link[:<port>]`. Adding the link module does
not change the localhost-only public API listener — the LAN TLS listener is
only bound when link is explicitly enabled.

Verified first-run ordering: `link enable` derives the node's `did:key` from
an existing node identity and fails with "node identity is not ready" if none
exists yet. On a brand-new install the identity is only generated on a node's
first `serve` boot, so the real first-run order is `serve` (first boot
generates the identity) → `link enable` → restart `serve` so it picks up the
LAN TLS listener from the state written by `enable`. Running `link enable`
before the node has ever been served fails outright.

Commands:

- `tinycloud node link enable <name> [--service-url <url>] [--bind <addr:port>]`
- `tinycloud node link disable`
- `tinycloud node link status [--json]`
- `tinycloud node link renew`

`enable` behavior (v1-link):

- Links the KeyProvider library in-process (same trust boundary as `node key
  backup` — see §3.7) to derive the node's `did:key` and Ed25519 signing
  keypair. Private key material is used only long enough to sign the service
  payloads and never transits the control API.
- Enumerates the host's private-range LAN IPs (RFC1918 IPv4, ULA `fc00::/7`,
  IPv4 link-local `169.254.0.0/16`; public and loopback addresses are
  excluded) and caps the set at 8 addresses. RFC1918/ULA addresses are
  preferred over IPv4 link-local when truncating to the cap. IPv6 link-local
  (`fe80::/10`) addresses are excluded from published records entirely: they
  require a zone/scope ID to be reachable, which a plain AAAA record can't
  carry.
- `PUT /v1/names/:name` on the link service with a signed claim payload and
  a monotonically increasing `sequence` persisted at
  `dataPath/link/state.json`.
- Generates a fresh RSA-2048 keypair + PKCS#10 CSR whose CN and single
  dNSName SAN are both exactly `<name>.local.tinycloud.link` (RSA, not ECDSA,
  because the service parses submitted CSRs with `node-forge`, which only
  understands RSA `SubjectPublicKeyInfo`s). Sends the CSR via
  `POST /v1/certs/:name`. Stores the private key and returned cert chain
  under `dataPath/link/tls/{key,cert}.pem` with mode `0600`.
- Writes `dataPath/link/state.json` (mode `0600`) with `{name, serviceUrl,
  sequence, lastLanIps, certNotAfter, bind}`. The LAN listener activates on
  next `serve` (re)start if it isn't already running; if it is running (an
  earlier `enable`/`renew` already started it), the renewed cert is
  hot-reloaded into the running listener in place — see "Cert hot-reload"
  below.

`disable` behavior (v1-link):

- Signs `DELETE /v1/names/:name` with the next sequence and removes the
  `dataPath/link/` directory regardless of whether the service call
  succeeded. Keeping local state after a failed delete would wedge the node
  under a name/cert it no longer controls on the service side, so cleanup
  always happens; a genuine service-side failure is still surfaced as an
  error to the caller after cleanup runs.

`renew` behavior (v1-link):

- If the current LAN IP set differs from `lastLanIps` in `state.json`,
  re-claims the name (`PUT`) so DNS points at the current addresses.
- Requests a fresh cert (`POST`), stores the new key + cert chain, and
  refreshes `certNotAfter`.

Auto-renew (v1-link):

- `serve` starts a background task alongside the Rocket app that wakes daily,
  re-claims when the LAN IP set changes, and issues a fresh cert when the
  stored `certNotAfter` is less than 30 days away.

Cert hot-reload (v1-link):

- The LAN TLS listener's `rustls::ServerConfig` is backed by a custom
  `ResolvesServerCert` (`link::proxy::LinkCertResolver`) rather than a single
  static cert. After the auto-renew loop (or a foreground `link renew`
  while `serve` is already running) writes a new key/cert pair to
  `dataPath/link/tls/`, it calls the resolver's `update` to swap the served
  cert in place. Only TLS handshakes that start after the swap see the new
  cert; already-established connections are unaffected. No listener restart
  and no dropped connections.

Sequence and error handling (v1-link):

- Every signed action consumes `state.json`'s next sequence value and
  persists it *before* the network round-trip, not after a successful
  response. The service commits its own sequence bump as soon as the
  underlying write lands — for `POST /v1/certs/:name` specifically, this
  happens before the ACME round-trip (see `server.ts`) — so a client that
  only persists on success can end up behind the service's record if a later
  step fails. Persisting first mirrors the service's ordering and closes
  that gap.
- If the service still returns a stale-sequence 409 (e.g. `state.json` was
  restored from a backup), the client resyncs by jumping the local sequence
  forward and retrying once. `GET /v1/names/:name` does not expose the
  service's stored sequence, so this is a best-effort recovery, not an exact
  resync; a second failure is surfaced to the caller.
- 409 responses are disambiguated by the service's JSON error body rather
  than treated as one generic conflict: "name already claimed by a different
  subject" surfaces as a name-conflict error naming the conflicting name and
  does not modify local state; "stale record sequence" surfaces as a
  stale-sequence error and triggers the resync-and-retry above.
- A 429 rate-limited response surfaces the `Retry-After` header value to the
  caller and to the logs.
- `enable`/`disable`/`renew` hold an advisory lock over `state.json` for
  their duration, so the CLI and the in-process auto-renew loop can't race
  on the sequence counter.

`link status --json` and `service status --json` return the following extra
fields (v1-link, all optional):

```json
{
  "linkName": "mynode",
  "localUrl": "https://mynode.local.tinycloud.link:8443",
  "certNotAfter": "2027-06-01T00:00:00Z",
  "linkListener": "running",
  "linkListenerError": "address already in use (os error 48)"
}
```

`localUrl` omits the port when it is 443. `linkListener` is one of `disabled`
(link is not enabled), `stopped` (state.json exists but `serve` is not
running the listener, or the listener's last bind attempt failed), or
`running` (LAN TLS terminator is bound and accepting connections).
`service status --json` derives this from an on-disk listener-state marker
`serve` writes after its actual bind attempt
(`dataPath/link/listener-state.json`), not merely from whether the node
process is up — a bind failure (bad address, port in use, permission denied)
inside an otherwise-running node process is reported as `stopped`, with
`linkListenerError` set to the bind error. `link status --json` (run from a
separate CLI invocation, not from inside `serve`) cannot observe the running
listener and always reports `stopped` when link is enabled.

`--service-url` defaults to `https://api.tinycloud.link` and is intended for
staging, self-hosted, or air-gapped deployments. `--bind` defaults to
`0.0.0.0:8443`.

## 4. Platform Paths

The node has a config root, a data root, and a logs root. The runtime files live
under the data root.

| Platform / manager | Config root | Data root | Logs root |
|---|---|---|---|
| macOS `launchd-user` / `homebrew-launchagent` | `~/Library/Application Support/TinyCloud Node/` (`tinycloud.toml` inside) | `~/Library/Application Support/TinyCloud Node/` | `~/Library/Logs/TinyCloud Node/` |
| Linux `systemd-user` | `$XDG_CONFIG_HOME/tinycloud-node/` or `~/.config/tinycloud-node/` | `$XDG_DATA_HOME/tinycloud-node/` or `~/.local/share/tinycloud-node/` | `$XDG_STATE_HOME/tinycloud-node/` or `~/.local/state/tinycloud-node/` |
| Linux `systemd-system` | `/etc/tinycloud-node/` | `/var/lib/tinycloud-node/` | journald |

`configPath` is always `${configRoot}/tinycloud.toml`. `dataPath` is the root
that owns `runtime/`, logs metadata, backups, and other node-managed files. On
macOS, the config root and data root are the same directory; on Linux user and
system installs, they are separate roots.

The CLI-owned service manifest lives at the fixed install path
`${configRoot}/service.json` on every platform. It is install metadata, not
runtime state; the node never writes this file, and `service install` owns it
while `uninstall` removes it.

For `systemd-system` installs, control commands require either root or
membership in the `tinycloud` group because `control.token` is group-readable
(`0640 root:tinycloud`). Reading `journald` tails requires membership in the
`systemd-journal` group.

For local development and smoke tests, `TINYCLOUD_NODE_CONFIG_ROOT` may
override the macOS application-support root so the CLI-owned manifest,
LaunchAgent plist, and paired node roots can be redirected away from the real
home directory. Production installs should not depend on this escape hatch.
It exists only as a test/dev escape hatch for this stage so macOS validation
can run without touching `~/Library`.

### Config loading order

The node control plane keeps the existing config layering, with one runtime
overlay added for the control plane:

1. Built-in defaults from `Config::default()`.
2. Base config file from `--config <path>` or the platform default
   `configRoot/tinycloud.toml`.
3. Runtime overlay file at `dataPath/runtime/config.override.toml`.
4. `TINYCLOUD_` env vars, with `__` nesting preferred and legacy `_` still
   accepted.

Important:

- Env vars always win over files.
- The control plane never edits the base config file.
- The control overlay is the only file the node writes for config patches.
- `tinycloud.toml` remains the base config file name by convention.

## 5. Security Invariants

- The control plane MUST never bind a non-loopback address.
- The token file MUST be mode `0600` for user installs; `systemd-system`
  installs MAY use `0640 root:tinycloud` as documented in Section 4.
- The runtime directory MUST be mode `0700` for user installs and `0750
  root:tinycloud` for `systemd-system` installs.
- The token MUST not be passed through env vars or command-line arguments.
- Private key material MUST never be transmitted over the control API, printed,
  written unencrypted, or passed through env vars. `node key backup` is the
  only explicit documented trust boundary for this rule: it links the
  KeyProvider library in-process and holds secret material in memory only long
  enough to seal the export bundle.
- Private keys MUST NOT appear in control API responses, CLI JSON, logs, or
  doctor output.
- Secret-bearing config values MUST be omitted, not redacted with fake
  placeholder strings.
- The app requests actions and the node signs internally.
- `PATCH /v1/config` cannot mutate key material, storage roots, or binding
  endpoints.

## 6. Key Material

### KeyProvider abstraction

The node identity key is owned by a KeyProvider abstraction. The backend kind
is public metadata and is surfaced as `keyBackend` in status, identity, and
service status responses.

Backends:

- `macos-keychain`: stores the identity secret in the user's login keychain.
  The item is created with `kSecAttrSynchronizable=true` (iCloud Keychain sync
  enabled) and `kSecAttrAccessibleAfterFirstUnlock`. LaunchAgent runs in the
  user session, so login-keychain access works without extra privilege.
- `encrypted-file`: stores the identity secret in `dataPath/keys/identity.key.enc`.
  The file is owned by the service user and mode `0600`. The payload is sealed
  with an age-style envelope or XChaCha20-Poly1305. The raw file key is 32
  random bytes wrapped by a machine-scoped KEK derived with scrypt from a
  locally stored random secret at `dataPath/keys/kek.secret` (also mode
  `0600`). This protects against casual copying and backup leakage, not root
  compromise.

TC-77 amendment: macOS `macos-keychain` now uses a two-tier insert strategy.
The node first writes to the data-protection keychain with sync enabled and
`kSecAttrAccessibleAfterFirstUnlock`. If an unentitled binary returns
`errSecMissingEntitlement` (`-34018`), it falls back to the classic login
keychain without `kSecUseDataProtectionKeychain` or
`kSecAttrSynchronizable`. Reads must resolve either tier, and duplicate-item
updates must delete and re-add within the tier they are updating so pre-fix
items migrate to the correct attributes. This keeps iCloud Keychain sync for
the signed desktop app while letting the plain CLI bootstrap a usable local
identity.

Desktop-managed installs write `[global.keys] type = "provider"` in the
bootstrap config as the supported opt-in for this provider-backed path; that
naming deviation is now part of the contract.

Legacy source precedence:

- Explicit `keys = Static{secret}` or `TINYCLOUD_KEYS_SECRET` wins for backward
  compatibility, but that path is deprecated for desktop installs and `doctor`
  warns.
- `keys = Auto` selects `macos-keychain` on macOS and `encrypted-file` on
  Linux.
- `keys = Dstack` remains the TEE-backed legacy path when that deployment mode
  is selected; new desktop installs do not choose it.

Default selection:

- New macOS desktop installs default to `Auto`, which resolves to
  `macos-keychain`.
- New Linux user and system installs default to `Auto`, which resolves to
  `encrypted-file`.

### First run

If no node identity exists yet:

1. Generate a new node keypair.
2. Persist it through the selected KeyProvider.
3. Derive the node DID from the public key.
4. Mark `identityReady` true once the backend can sign.

The node DID is stable for a given KeyProvider-backed identity.

### Backup and export UX

- `node key export` is public-only. It returns the node DID and backend kind,
  and it maps directly to `GET /v1/identity`.
- `node key backup` produces a versioned, passphrase-wrapped sealed bundle. It
  is the in-process trust boundary and the recovery artifact, not the public
  export.
- `node key restore` is deferred until post-v0.

## 7. Non-goals

- No big-bang migration away from Rocket for the public API.
- No UDS requirement in v1.
- No remote or public control plane.
- No secret-bearing env vars in the node control contract.
- No live hot-reload guarantee for config patches in v1.
