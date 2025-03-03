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
- HTTP server in src/
- SDKs in tinycloud-sdk/ and tinycloud-sdk-wasm/

## Migration Notes
This project was forked from the archived Kepler protocol. The following changes were made:
1. Renamed all references from "Kepler" to "TinyCloud Protocol"
2. Renamed the crate `kepler` to `tinycloud`
3. Renamed the crate `kepler-core` to `tinycloud-core`
4. Renamed the crate `kepler-lib` to `tinycloud-lib`
5. Renamed the crate `kepler-sdk` to `tinycloud-sdk`
6. Renamed the crate `kepler-sdk-wasm` to `tinycloud-sdk-wasm`
7. Renamed all imports from `kepler_*` to `tinycloud_*`
8. Renamed types and modules:
   - `KeplerDelegation` → `TinyCloudDelegation`
   - `KeplerInvocation` → `TinyCloudInvocation`
   - `KeplerRevocation` → `TinyCloudRevocation`
9. Changed environment variables from `KEPLER_*` to `TINYCLOUD_*`
10. Renamed configuration file from `kepler.toml` to `tinycloud.toml`