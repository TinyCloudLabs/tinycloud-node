# TinyCloud Protocol Development Guidelines

## Build Commands
- Build project: `cargo build`
- Run project: `cargo run`
- Run single test: `cargo test test_name -- --nocapture`
- Run tests in a module: `cargo test module_name`
- Load testing: `k6 run --vus 10 --duration 30s test/load/k6/json_put.js`

## Linting & Formatting
- Run clippy: `cargo clippy -- -D warnings`
- Format code: `cargo fmt`

## Code Style Guidelines
- Use Rust's standard naming conventions (snake_case for functions/variables, CamelCase for types)
- Prefer Result/Option over unwrap/expect in production code
- Group imports by std, external crates, then local modules
- Document public interfaces with rustdoc comments
- Use strong typing with Rust's type system
- Validate inputs at API boundaries

## Project Structure
- Core functionality in tinycloud-core/
  - Database models and storage in tinycloud-core/src/models/ and tinycloud-core/src/storage/
  - Event handling in tinycloud-core/src/events/
  - Type definitions in tinycloud-core/src/types/
- HTTP server in src/
  - API routes in src/routes/
  - Authentication guards in src/auth_guards.rs
  - Storage implementations in src/storage/
- SDK Libraries
  - Core SDK in tinycloud-sdk/
  - WebAssembly bindings in tinycloud-sdk-wasm/
- Shared Libraries
  - Common types and utilities in tinycloud-lib/

## Configuration
- Main configuration file: `tinycloud.toml`
- Environment variables use the `TINYCLOUD_` prefix
- Local development database defaults to SQLite
- See README.md for complete configuration options

## Testing
- Unit tests within module files
- Integration tests in the test/ directory
- Load testing scripts in test/load/k6/
- Sample signing utilities in test/load/signer/
