# Changesets (Rust Workspace)

This project uses a hybrid approach: changesets for tracking changes, with a custom script to apply them to multiple `Cargo.toml` files.

## Crate Groups

| Group/Alias | Crates Affected |
|-------------|-----------------|
| `core` or `tinycloud-node` | tinycloud, tinycloud-core, tinycloud-lib |
| `sdk` | tinycloud-sdk-rs, tinycloud-sdk-wasm |
| Individual names | siwe, siwe-recap, cacaos |

## Workflow

### 1. Add a changeset when making changes

```bash
bun changeset
# or manually create .changeset/my-change.md
```

**Examples:**

```markdown
---
"core": patch
---

Fixed a bug in the delegation validation
```

```markdown
---
"sdk": minor
"siwe": patch
---

Added new delegation helper functions
Fixed SIWE message parsing edge case
```

```markdown
---
"tinycloud-sdk-wasm": patch
---

Fixed WASM initialization in static methods
```

### 2. Apply changesets to release

```bash
bun run version
```

This will:
- Read all `.changeset/*.md` files
- Resolve groups to individual crates
- Update each affected `Cargo.toml`
- Generate `CHANGELOG.md` entry
- Delete processed changeset files

### 3. Commit and tag

```bash
git add -A
git commit -m "chore: release"
git push
```

## Version Types

- `patch` - Bug fixes (0.0.X)
- `minor` - New features, non-breaking (0.X.0)
- `major` - Breaking changes (X.0.0)

## Multiple Changesets

You can have multiple changeset files. When applied:
- All descriptions are combined into a single CHANGELOG entry
- If a crate is bumped multiple times, the highest bump wins (major > minor > patch)

## Available Packages

| Package Name | Cargo.toml Path |
|--------------|-----------------|
| `tinycloud` | `./Cargo.toml` |
| `tinycloud-core` | `./tinycloud-core/Cargo.toml` |
| `tinycloud-lib` | `./tinycloud-lib/Cargo.toml` |
| `tinycloud-sdk-rs` | `./tinycloud-sdk-rs/Cargo.toml` |
| `tinycloud-sdk-wasm` | `./tinycloud-sdk-wasm/Cargo.toml` |
| `siwe` | `./siwe/Cargo.toml` |
| `siwe-recap` | `./siwe-recap/Cargo.toml` |
| `cacaos` | `./cacao/Cargo.toml` |
