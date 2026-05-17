# Agent Development Notes

This document gives coding agents enough local context to work on TinyCloud Node without guessing
about repo boundaries, test expectations, or cross-repo API impact.

## Project Context

TinyCloud Node is the Rust server for the TinyCloud Protocol. It hosts user-owned data spaces,
verifies capability-based authorization, and exposes the node API used by TinyCloud SDK clients.

Important concepts:

- Spaces are user-owned namespaces addressed through TinyCloud resource identifiers.
- Authorization is capability based. Requests carry UCAN/CACAO/SIWE-derived authorization that
  grants specific abilities such as KV, SQL, DuckDB, delegation, hooks, and signed URL access.
- The HTTP server lives in `tinycloud-node-server` and is built on Rocket.
- Core storage, migrations, authorization-adjacent models, SQL, DuckDB, hooks, and database logic
  live primarily in `tinycloud-core`.
- `tinycloud-auth` contains shared authorization/resource types used by the node and SDK tooling.
- `tinycloud-sdk-rs` and `tinycloud-sdk-wasm` are Rust/WASM SDK crates in this repo, but the main
  JavaScript/TypeScript SDK lives in a separate repository.
- Local config comes from `tinycloud.toml` plus `TINYCLOUD_` and `ROCKET_` environment variables.
  Prefer canonical nested env vars with double underscores, such as `TINYCLOUD_STORAGE__DATADIR`.

Storage is protocol-critical. Treat data durability, key derivation, capability checks, and
cross-client compatibility as production concerns, not demo behavior.

## Related Repositories

- `TinyCloudLabs/js-sdk`
  - Local path in the tinycloud-dev workspace: `repositories/js-sdk`.
  - Contains the TypeScript SDK packages, node SDK, web SDK, examples, and SDK integration tests.
  - Use this repo to validate TinyCloud Node API behavior from the client path that apps actually use.
- `TinyCloudLabs/openkey`
  - Local path in the tinycloud-dev workspace: `repositories/openkey`.
  - Related authentication/product repo that depends on TinyCloud/OpenKey integration behavior.
  - When auth, SIWE, passkey, session, or client-facing identity behavior changes, check whether
    OpenKey needs matching changes or regression tests.

If a TinyCloud Node change alters public behavior, request/response shapes, capabilities, endpoint
semantics, auth flows, error codes, or feature discovery, assume the SDK may need a matching change.

## Build And Testing

Common Rust checks:

```bash
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

Focused package checks:

```bash
cargo test -p tinycloud-core
cargo test -p tinycloud-node
```

Run the node locally for SDK integration tests:

```bash
TINYCLOUD_STORAGE__DATADIR="$(mktemp -d)/data" \
ROCKET_ADDRESS=127.0.0.1 \
ROCKET_PORT=9000 \
cargo run -p tinycloud-node --bin tinycloud
```

Then run the SDK node test suite from `TinyCloudLabs/js-sdk`:

```bash
cd ../js-sdk/tests/node-sdk
TC_TEST_SERVER=http://127.0.0.1:9000 bun test
```

When testing changes to TinyCloud Node, run the SDK node test suite as well as the Rust tests. This
is required for behavior that affects API compatibility, auth, KV, SQL, DuckDB, hooks, signed URLs,
delegation, feature discovery, storage persistence, or errors returned to clients.

API/interface changes should have a corresponding SDK PR. Write tests against the SDK node path.
Web SDK coverage is optional for some changes, but recommended when the behavior is reachable from
browser clients.

For persistence-sensitive work, add a restart/cold-cache check:

1. Start TinyCloud Node with a fresh `TINYCLOUD_STORAGE__DATADIR`.
2. Write data through the SDK.
3. Stop the node.
4. Remove only local cache directories relevant to the feature under test.
5. Restart against the same durable database.
6. Query through the SDK and confirm the data is still present.

## Debugging

Health and feature discovery:

```bash
curl -fsS http://127.0.0.1:9000/info
curl -fsS http://127.0.0.1:9000/version
curl -fsS http://127.0.0.1:9000/healthz
```

Configuration debugging:

- Check `tinycloud.toml` first, then environment overrides.
- Prefer fresh temp data directories for local tests so existing `data/` contents do not hide bugs.
- Do not commit generated local data under `data/`, `target/`, SDK `node_modules/`, or test output.
- If storage behavior is involved, inspect the configured `storage.database` rather than only the
  local SQL/DuckDB/cache files.

Auth and capability debugging:

- Verify the SDK client is signed in and using the expected host, prefix, DID, and space id.
- Confirm the requested TinyCloud ability matches the service path being exercised.
- For delegation bugs, test both the owner path and delegated access path.
- Never print or commit real private keys, production tokens, deploy keys, or secrets.

Server debugging:

- Use `RUST_LOG`/Rocket log settings when route or storage behavior is unclear.
- Keep server, SDK test, and browser/API logs separate so request failures can be tied to one layer.
- If a test only fails after a restart, validate that the node is using the same durable database
  and that local cache directories were intentionally cleared.

## Additional Context

- Keep changes narrow. Do not refactor adjacent protocol or auth code unless it is required for the
  issue being solved.
- Public API changes need compatibility thinking: SDK behavior, deployed node behavior, feature
  flags, migrations, and error surfaces should move together.
- Database migrations must be safe for existing deployed nodes. Add tests or manual verification for
  migration behavior when schema changes are involved.
- Storage changes must preserve user data across deploys, restarts, and local cache loss.
- Deployment/release changes should not assume Docker Compose is the production path. TinyCloud
  deploys from GHCR images unless the issue explicitly says otherwise.
- When agent-facing context changes, update this document's additional notes and append a concise
  entry to `agent.changelog.md` so future agents can see what changed and why.
- Linear issue context matters. Leave concise implementation, testing, and handoff notes on the
  issue when an agent completes meaningful work.
- PR descriptions should list cross-repo dependencies, SDK PRs, migration implications, and exact
  verification commands.
