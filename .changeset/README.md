# Changesets (Rust Hybrid)

This project uses a hybrid approach: changesets for tracking changes, with a custom script to apply them to `Cargo.toml`.

## Workflow

### 1. Add a changeset when making changes

```bash
bun changeset
# or manually create a file in .changeset/
```

Example changeset file (`.changeset/my-change.md`):

```markdown
---
"tinycloud-node": patch
---

Fixed a bug in the authentication flow
```

### 2. Apply changesets to release

```bash
bun run version
```

This will:
- Read all `.changeset/*.md` files
- Determine the version bump (highest of patch/minor/major wins)
- Update `Cargo.toml` version
- Generate `CHANGELOG.md` entry
- Delete processed changeset files

### 3. Commit and tag

```bash
git add -A
git commit -m "chore: release vX.Y.Z"
git tag vX.Y.Z
git push && git push --tags
```

## Version Types

- `patch` - Bug fixes, small improvements (0.0.X)
- `minor` - New features, non-breaking changes (0.X.0)
- `major` - Breaking changes (X.0.0)

## Multiple Changesets

You can have multiple changeset files. When `bun run version` is called:
- All descriptions are combined into a single CHANGELOG entry
- The highest bump type wins (major > minor > patch)
