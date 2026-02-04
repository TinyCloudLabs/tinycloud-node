![TinyCloud Protocol header](/docs/tinycloudheader.png)

[![](https://img.shields.io/badge/License-EGPL--1.5-green)](https://github.com/TinyCloudLabs/tinycloud-node/blob/main/LICENSE.md)
[![](https://img.shields.io/badge/Version-1.0.0-blue)](https://github.com/TinyCloudLabs/tinycloud-node/releases)

# TinyCloud Node

TinyCloud Node is the server component of the TinyCloud Protocol — a framework for creating interoperable software applications where users retain full sovereignty over their data. It provides a decentralized or user-controlled "cloud" that can serve as the backend for multiple apps, allowing users to maintain control over their data without ceding ownership or privacy to third parties.

TinyCloud Node hosts user data spaces, processes delegations, and serves the KV storage API. It is a descendant of [Kepler](https://github.com/spruceid/kepler) and is architected as a decentralized storage system that uses DIDs and Authorization Capabilities to define TinyCloud Spaces, where your data lives and who has access.

## Protocol Version

TinyCloud Node v1.0.0 introduces a protocol version system for SDK-node compatibility. The node exposes a public `/version` endpoint:

```
GET /version
```

```json
{
  "protocol": 1,
  "version": "1.0.0",
  "features": ["kv", "delegation", "sharing"]
}
```

The SDK checks this endpoint during sign-in and requires an exact protocol version match. This ensures clients and servers are always running compatible versions.

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/version` | No | Protocol version and feature discovery |
| `POST` | `/invoke` | Yes | Execute KV operations (get, put, list, delete) |
| `POST` | `/delegate` | Yes | Create capability delegations |
| `GET` | `/peer/generate/<space>` | No | Generate space host key pair |
| `GET` | `/healthz` | No | Health check |

## Quickstart

To run TinyCloud Protocol locally you will need the latest version of [rust](https://rustup.rs).


You will need to create a directory for TinyCloud Protocol to store data in:
```bash
mkdir data
```

Within this directory, create one more directories `blocks` and a database file `caps.db`:
```bash
mkdir data/blocks
touch data/caps.db
```

To setup local data storage you can also run `./scripts/init-tinycloud-data.sh`

You will then need to set the environment variables to point to those directories:
```bash
export TINYCLOUD_STORAGE_BLOCKS_PATH="data/blocks"
export TINYCLOUD_STORAGE_DATABASE="data/caps.db"
```

Finally you can run TinyCloud Protocol using `cargo`:
```bash
cargo build
cargo run
```


## Configuration

TinyCloud Protocol instances are configured by the [tinycloud.toml](tinycloud.toml) configuration file, or via environment variables. You can either modify them in this file, or specify them through environment variable using the prefix `TINYCLOUD_`.

The following common options are available:

| Option              | env var                      | description                                                                |
|:--------------------|:-----------------------------|:---------------------------------------------------------------------------|
| log_level           | TINYCLOUD_LOG_LEVEL           | Set the level of logging output, options are "normal", "debug"             |
| address             | TINYCLOUD_ADDRESS             | Set the listening address of the TinyCloud Protocol instance                           |
| port                | TINYCLOUD_PORT                | Set the listening TCP port for the TinyCloud Protocol instance                         |
| storage.blocks.type | TINYCLOUD_STORAGE_BLOCKS_TYPE | Set the mode of block storage, options are "Local" and "S3"                |
| storage.limit        | TINYCLOUD_STORAGE_LIMIT        | Set a maximum limit on storage available to Spaces hosted on this instance. Limits are written as strings, e.g. `10 MiB`, `100 GiB`                                                                           |
| storage.database    | TINYCLOUD_STORAGE_DATABASE    | Set the location of the SQL database                                       |
| storage.staging     | TINYCLOUD_STORAGE_STAGING     | Set the mode of content staging, options are "Memory" and "FileSystem"     |
| keys.type           | TINYCLOUD_KEYS_TYPE           | Set the type of host key store, options are "Static"                       |
| spaces.allowlist    | TINYCLOUD_SPACES_ALLOWLIST    | Set the URL of an allowlist service for gating the creation of Space Peers |

### Database Config

The SQL database can be configured with `storage.database` or the `TINYCLOUD_STORAGE_DATABASE` environment variable. It supports Sqlite, MySQL and PostgresSQL. For example:

| Type     | Example                                       | Description                                                                         |
|:---------|:----------------------------------------------|:------------------------------------------------------------------------------------|
| Sqlite   | "sqlite:./tinycloud/caps.db"                     | Set TinyCloud Protocol to use a local Sqlite file at the relative path `./tinycloud/caps.db`       |
| MySQL    | "mysql://root:root@localhost:3306/example"    | Use the MySQL instance deployed at `localhost:3306`, with database name `example`   |
| Postgres | "postgres://root:root@localhost:5432/example" | Use the Postgres instance deployed at `localhost:5432` with database name `example` |

This will default to an in-memory Sqlite database (i.e. `sqlite::memory:`).

#### Migrations

TinyCloud Protocol will automatically apply the relevant migrations to your chosen SQL database. Use caution if you are sharing this database with another application.

### Staging Config

TinyCloud Protocol will temporarily stage files it receives before writing them. It can do this in memory or in temporary files. This can be configured by setting `storage.staging` to `Memory` or `FileSystem`. Default is `Memory`.

### Storage Config

Storage can be configured for Blocks depending on it's `type`.

#### Local Storage

When `storage.blocks.type` is `Local`, the local filesystem will be used for application content storage. The following config option will become available:

| Option               | env var                       | description                                                    |
|:---------------------|:------------------------------|:---------------------------------------------------------------|
| storage.blocks.path  | TINYCLOUD_STORAGE_BLOCKS_PATH  | Set the path of the block storage                              |

#### AWS Storage

When `storage.blocks.type` is `S3` the instance will use the S3 AWS service for application storage. The following config options will become available:

| Option               | env var                       | description                                                    |
|:---------------------|:------------------------------|:---------------------------------------------------------------|
| storage.blocks.type  | TINYCLOUD_STORAGE_BLOCKS_TYPE  | Set the mode of block storage, options are "Local" and "S3"    |
| storage.blocks.bucket  | TINYCLOUD_STORAGE_BLOCKS_BUCKET  | Set the name of the S3 bucket    |
| storage.blocks.endpoint  | TINYCLOUD_STORAGE_BLOCKS_ENDPOINT  | Set the URL of the S3 store    |

Additionally, the following environment variables must be present: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_DEFAULT_REGION`.

### Keys Config

TinyCloud Protocol hosts require key pairs to provide replication. The `keys` config fields specify how a TinyCloud Protocol instance generates and stores these key pairs.

#### Static Secret Derivation

When `keys.type` is `Static` the instance will use an array of bytes as a static secret from which it will derive key pairs on a per-Space basis. The following config options will be available:

| Option      | env var              | description                                                                  |
|:------------|:---------------------|:-----------------------------------------------------------------------------|
| keys.secret | TINYCLOUD_KEYS_SECRET | Unpadded base64Url-encoded byte string from which key pairs will be derived. |

The secret MUST contain at least 32 bytes of entropy (either randomly generated or derived in a cryptographically secure way). It is STRONGLY RECOMMENDED that the secret be given via environment variables and NOT in the `tinycloud.toml` config file. Additionally it is STRONGLY RECOMMENDED that the secret be backed up in a secure place if used in production. Loss of the secret will result in total loss of function for the TinyCloud Protocol instance.

## Running

TinyCloud Protocol instances can be started via command line, e.g.:

``` sh
TINYCLOUD_PORT=8001 tinycloud
```

If the TinyCloud Protocol instance is not able to find or establish a connection to the configured storage, the instance will terminate.

## Usage

TinyCloud Protocol is most easily used via the TinyCloud Protocol SDK. See the example DApps and tutorials for detailed information.
