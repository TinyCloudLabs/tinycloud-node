# TinyCloud Protocol Development Guidelines

## Project Overview

TinyCloud is a decentralized, user-controlled cloud framework enabling data sovereignty and privacy-preserving storage. Users retain full control over their data with fine-grained access permissions through capability-based security.

**Core Concepts:**
- **Orbits**: User-owned data storage spaces that can be self-hosted or managed
- **Capabilities**: UCAN/CACAO-based tokens defining who can access data and how
- **DIDs**: Decentralized Identifiers for authentication without centralized authority

## Build Commands

```bash
# Build
cargo build                              # Debug build
cargo build --release                    # Production build

# Run
cargo run                                # Run locally (default port 8000)

# Test
cargo test                               # Run all tests
cargo test module_name                   # Test specific module
cargo test test_name -- --nocapture      # Single test with output

# Load Testing
k6 run --vus 10 --duration 30s test/load/k6/json_put.js
```

## Linting & Formatting

```bash
cargo clippy -- -D warnings              # Lint with warnings as errors
cargo fmt                                # Format code
cargo fmt -- --check                     # Check formatting without modifying
```

**Always run before committing:**
```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
```

## Project Structure

```
tinycloud-node/
├── src/                          # Main HTTP server (Rocket-based)
│   ├── main.rs                   # Server bootstrap, Prometheus metrics
│   ├── lib.rs                    # Application setup, route mounting
│   ├── routes/                   # API endpoint handlers
│   │   └── mod.rs                # /invoke, /delegate, /peer/generate, /healthz
│   ├── auth_guards.rs            # Request guards for authorization headers
│   ├── authorization.rs          # Auth header parsing and verification
│   ├── config.rs                 # Configuration structures
│   ├── prometheus.rs             # Metrics exposition
│   ├── tracing.rs                # Distributed tracing setup
│   └── storage/                  # Storage backend implementations
│
├── tinycloud-core/               # Core database layer (OrbitDatabase)
│   └── src/
│       ├── db.rs                 # Main database abstraction
│       ├── events/               # Event types (Delegation, Invocation, Revocation)
│       ├── models/               # Database entity definitions
│       ├── storage/              # Storage trait definitions and implementations
│       ├── types/                # Ability, Resource, Caveats, Metadata
│       ├── migrations/           # Database schema migrations
│       ├── hash.rs               # Content hashing (Blake2b, Blake3)
│       ├── keys.rs               # Cryptographic key management
│       └── manifest.rs           # Orbit manifest handling
│
├── tinycloud-lib/                # Shared authorization library
│   └── src/
│       ├── authorization.rs      # TinyCloudDelegation, Invocation, Revocation
│       ├── resource.rs           # TinyCloud resource URIs and paths
│       └── resolver.rs           # DID resolution
│
├── tinycloud-sdk-rs/             # Rust SDK for client applications
├── tinycloud-sdk-wasm/           # WebAssembly SDK bindings for browsers
│
├── siwe/                         # EIP-4361 Sign-In with Ethereum
├── siwe-recap/                   # EIP-5573 SIWE ReCap capability delegation
├── cacao/                        # CAIP-74 Chain-Agnostic Object Capability
│
├── test/load/                    # Load testing infrastructure
│   ├── k6/                       # k6 test scripts
│   └── signer/                   # Signing utility for test capabilities
│
└── .github/workflows/            # CI/CD pipelines
```

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/invoke` | Execute KV operations (list, get, put, delete, metadata) | Yes |
| `POST` | `/delegate` | Create capability delegations | Yes |
| `GET` | `/peer/generate/<orbit>` | Generate orbit host key pair | No |
| `GET` | `/healthz` | Health check | No |
| `OPTIONS` | `/*` | CORS preflight | No |

**Authorization Header Format:**
```
Authorization: <base64url-encoded-UCAN-or-CACAO>
```

**KV Capabilities:**
- `kv/list` - List keys in an orbit
- `kv/get` - Read a value
- `kv/put` - Write a value
- `kv/delete` - Remove a value
- `kv/metadata` - Get value metadata

## Authentication Architecture

TinyCloud uses a three-layer capability-based authentication:

1. **UCAN (User-Controlled Authorization Network)**: JWT-like tokens encoding capabilities with delegation chains
2. **CACAO (Chain-Agnostic Capability Object)**: IPLD-encoded capabilities with SIWE signatures
3. **SIWE (Sign-In with Ethereum)**: EIP-4361 signature verification for Ethereum wallets

**Request Flow:**
```
Request → Authorization Header → Parse (UCAN/CACAO) → Verify Signature →
Validate Capability → Check Resource Permission → Execute Operation
```

## Configuration

### Configuration File (`tinycloud.toml`)

```toml
[global]
log_level = "debug"              # Logging verbosity: trace, debug, info, warn, error
port = 8000                       # HTTP server port
cors = true                       # Enable CORS headers

[global.storage]
database = "sqlite:./tinycloud/caps.db?mode=rwc"  # Database URL
staging = "FileSystem"            # Staging mode: Memory or FileSystem
limit = "10 MiB"                  # Optional storage quota per orbit

[global.storage.blocks]
type = "Local"                    # Block storage: Local or S3
path = "./tinycloud/blocks"       # Local filesystem path

[global.keys]
type = "Static"                   # Key derivation type
secret = "<base64url-32+bytes>"   # Secret for key derivation

[global.orbits]
# allowlist = "http://localhost:10000"  # Optional orbit allowlist service
```

### Environment Variables

All use the `TINYCLOUD_` prefix:

| Variable | Description | Example |
|----------|-------------|---------|
| `TINYCLOUD_LOG_LEVEL` | Log verbosity | `debug` |
| `TINYCLOUD_PORT` | Server port | `8000` |
| `TINYCLOUD_STORAGE_DATABASE` | Database URL | `sqlite:./tinycloud/caps.db` |
| `TINYCLOUD_STORAGE_BLOCKS_TYPE` | Block storage backend | `Local`, `S3` |
| `TINYCLOUD_STORAGE_BLOCKS_PATH` | Local block path | `./tinycloud/blocks` |
| `TINYCLOUD_STORAGE_BLOCKS_BUCKET` | S3 bucket name | `my-bucket` |
| `TINYCLOUD_STORAGE_BLOCKS_ENDPOINT` | S3 endpoint | `https://s3.amazonaws.com` |
| `TINYCLOUD_STORAGE_LIMIT` | Storage quota | `10 MiB` |
| `TINYCLOUD_KEYS_SECRET` | Key derivation secret | Base64URL string |
| `TINYCLOUD_ORBITS_ALLOWLIST` | Allowlist endpoint | `http://localhost:10000` |

### Database Support

- **SQLite**: `sqlite:./path/to/db.db?mode=rwc`
- **PostgreSQL**: `postgres://user:pass@host:port/dbname`
- **MySQL**: `mysql://user:pass@host:port/dbname`

## Code Style Guidelines

### Naming Conventions
- `snake_case` for functions, variables, and module names
- `CamelCase` for types, traits, and enums
- `SCREAMING_SNAKE_CASE` for constants

### Error Handling
- Prefer `Result<T, E>` and `Option<T>` over `unwrap()`/`expect()` in production code
- Use `?` operator for error propagation
- Define domain-specific error types with `thiserror`

### Import Organization
```rust
// 1. Standard library
use std::collections::HashMap;

// 2. External crates
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};

// 3. Local modules
use crate::config::Config;
use crate::storage::Storage;
```

### Documentation
- Document all public interfaces with rustdoc comments (`///`)
- Include examples in doc comments for complex functions
- Use `#[doc(hidden)]` for internal APIs that shouldn't be in docs

### Security
- Validate inputs at API boundaries
- Never log sensitive data (keys, tokens, credentials)
- Use constant-time comparison for cryptographic values

## Key Dependencies

| Category | Crate | Purpose |
|----------|-------|---------|
| Web Framework | `rocket` | HTTP server, JSON handling |
| Database | `sea-orm` | Async ORM with migrations |
| Crypto | `k256` | ECDSA secp256k1 (Ethereum) |
| Serialization | `serde`, `serde_json` | Data serialization |
| IPLD | `serde_ipld_dagcbor`, `ipld-core` | Content-addressed data |
| Async | `tokio` | Async runtime |
| Cloud | `aws-sdk-s3` | S3 storage backend |
| P2P | `libp2p` | Peer-to-peer networking |
| Observability | `tracing`, `prometheus` | Logging and metrics |

## Testing

### Test Structure
- **Unit tests**: Inline in source files (`#[cfg(test)]` modules)
- **Integration tests**: `test/` directory
- **Load tests**: `test/load/k6/` with k6 scripts

### Load Testing

```bash
# Start the signer service (generates test capabilities)
cd test/load/signer && cargo run

# Run k6 tests
k6 run --vus 10 --duration 30s test/load/k6/json_put.js
k6 run --vus 10 --duration 30s test/load/k6/json_get.js
k6 run --vus 5 --duration 60s test/load/k6/many_orbits.js
```

### CI/CD Workflows

1. **rust.yml**: Runs on push/PR to main
   - Builds all workspace crates
   - Runs tests (excludes WASM)
   - Runs clippy and fmt checks

2. **docker.yml**: Docker image builds
   - Builds on all branches
   - Publishes to `ghcr.io` on main/tags

## Local Development Setup

```bash
# 1. Create required directories and files
mkdir -p tinycloud/blocks
touch tinycloud/caps.db

# 2. Create configuration (optional - uses defaults)
cat > tinycloud.toml << 'EOF'
[global]
log_level = "debug"
port = 8000
cors = true

[global.storage]
database = "sqlite:./tinycloud/caps.db?mode=rwc"
staging = "FileSystem"

[global.storage.blocks]
type = "Local"
path = "./tinycloud/blocks"

[global.keys]
type = "Static"
secret = "YOUR_32_BYTE_BASE64URL_SECRET_HERE"
EOF

# 3. Build and run
cargo build
cargo run
```

## Docker Deployment

```bash
# Build image
docker build -t tinycloud:latest .

# Run container
docker run -d \
  -p 8000:8000 \
  -p 8001:8001 \
  -v $(pwd)/tinycloud:/app/tinycloud \
  -e TINYCLOUD_STORAGE_DATABASE="sqlite:./tinycloud/caps.db?mode=rwc" \
  tinycloud:latest
```

**Exposed Ports:**
- `8000`: HTTP API
- `8001`: Prometheus metrics
- `8081`: Relay (P2P)

## Troubleshooting

### Common Issues

**Database connection errors:**
- Ensure the SQLite file exists: `touch tinycloud/caps.db`
- Check database URL format includes `?mode=rwc` for SQLite

**Block storage errors:**
- Ensure blocks directory exists: `mkdir -p tinycloud/blocks`
- Check file permissions

**Authorization failures:**
- Verify UCAN/CACAO token format
- Check token expiration timestamps
- Ensure DID in capability matches request issuer

### Debug Logging

Set log level for verbose output:
```bash
TINYCLOUD_LOG_LEVEL=trace cargo run
```
