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
- SDKs in sdk/ and sdk-wasm/