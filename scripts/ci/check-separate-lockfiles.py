#!/usr/bin/env python3
"""Check that every separate Cargo workspace's lockfile is current for the
workspace crates it uses by path (TC-887).

Some workspaces (test/w5-policy-runtime-node-e2e, test/m1-realdata-e2e,
test/load/signer) are excluded from the main workspace and carry their own
Cargo.lock. When a workspace crate such as tinycloud-core gains a dependency
or a dependency feature, the main Cargo.lock is updated by the build, but
those lockfiles are not, and `cargo ... --locked` then fails in them. CI
cannot run a `--locked` resolve of w5 (it depends on a private repository),
so this check needs no network. For every in-repo crate a separate lockfile
records (per `cargo metadata --no-deps` of the main workspace):
- each normal, non-optional dependency must appear in its lockfile entry;
- each feature it requests on a dependency that, in the main Cargo.lock,
  pulls in a package (e.g. `aes` feature `zeroize`) must pull in that package
  in the separate lockfile too.
Workspaces that CI can resolve are also checked with `cargo metadata
--locked` in the `lockfiles` job.

Usage: scripts/ci/check-separate-lockfiles.py   (from the repository root)
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SKIP_DIRS = {"target", "node_modules", ".git"}


def lock_entries(path):
    """Yield (name, has_source, dependency names) for each [[package]]."""
    for block in path.read_text().split("[[package]]")[1:]:
        name = re.search(r'^name = "(.*)"$', block, re.M).group(1)
        has_source = re.search(r"^source = ", block, re.M) is not None
        deps = []
        if "dependencies = [" in block:
            body = block.split("dependencies = [", 1)[1].split("]", 1)[0]
            deps = re.findall(r'"([^" ]+)', body)
        yield name, has_source, deps


def path_packages(path):
    """In-repo (source-less) package name -> its dependency names."""
    return {n: set(d) for n, has_source, d in lock_entries(path) if not has_source}


def all_packages(path):
    """Package name -> dependency names, merged over every entry of that name."""
    merged = {}
    for name, _, deps in lock_entries(path):
        merged.setdefault(name, set()).update(deps)
    return merged


def workspace():
    """In-repo crates (name -> (normal deps, {dep: features})) and member dirs."""
    meta = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--no-deps", "--offline", "--format-version", "1"],
            cwd=ROOT,
        )
    )
    crates = {}
    for pkg in meta["packages"]:
        normal = [d for d in pkg["dependencies"] if d["kind"] is None]
        crates[pkg["name"]] = (
            sorted({d["name"] for d in normal if not d["optional"]}),
            {d["name"]: d["features"] for d in normal if d["features"]},
        )
    members = {
        pathlib.Path(pkg["manifest_path"]).parent
        for pkg in meta["packages"]
        if pkg["id"] in meta["workspace_members"]
    }
    return crates, members


def separate_lockfiles(members):
    for lock in sorted(ROOT.rglob("Cargo.lock")):
        rel = lock.relative_to(ROOT)
        if rel == pathlib.Path("Cargo.lock") or SKIP_DIRS & set(rel.parts):
            continue
        if lock.parent in members:
            # A main-workspace member's leftover lockfile: cargo never reads it.
            continue
        yield lock


def main():
    crates, members = workspace()
    root_all = all_packages(ROOT / "Cargo.lock")
    failures, checked = [], 0
    for lock in separate_lockfiles(members):
        rel = lock.relative_to(ROOT)
        recorded = path_packages(lock)
        everything = all_packages(lock)
        for name, (needed, features) in crates.items():
            if name not in recorded:
                continue
            checked += 1
            missing = [d for d in needed if d not in recorded[name]]
            if missing:
                failures.append(f"{rel}: {name} is missing {', '.join(missing)}")
            for dep, wanted in features.items():
                for feature in wanted:
                    if feature in root_all.get(dep, ()) and feature not in everything.get(dep, ()):
                        failures.append(
                            f"{rel}: {dep} lacks {feature} (feature `{feature}` requested by {name})"
                        )
    for f in failures:
        print(f"stale lockfile: {f}", file=sys.stderr)
    if failures:
        print(
            "Refresh each listed lockfile, e.g. "
            "`cargo update -p <crate> --manifest-path <dir>/Cargo.toml`.",
            file=sys.stderr,
        )
        return 1
    print(f"separate lockfiles current ({checked} in-repo crate entries checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
