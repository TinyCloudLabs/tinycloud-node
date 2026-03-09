#!/usr/bin/env node

/**
 * Custom version script for changesets + Cargo.toml.
 *
 * 1. Reads .changeset/*.md files to determine bump type (major/minor/patch)
 * 2. Bumps version in all Cargo.toml files
 * 3. Updates CHANGELOG.md
 * 4. Removes consumed changeset files
 */

import { readFileSync, writeFileSync, readdirSync, unlinkSync } from "fs";
import { join } from "path";

const ROOT = process.cwd();
const CHANGESET_DIR = join(ROOT, ".changeset");
const CHANGELOG_PATH = join(ROOT, "CHANGELOG.md");

// Cargo.toml files to update (workspace root + sub-crates)
const CARGO_TOMLS = [
  "Cargo.toml",
  "tinycloud-core/Cargo.toml",
  "tinycloud-lib/Cargo.toml",
  "tinycloud-sdk-rs/Cargo.toml",
  "tinycloud-sdk-wasm/Cargo.toml",
].map((p) => join(ROOT, p));

function parseVersion(version) {
  const [major, minor, patch] = version.split(".").map(Number);
  return { major, minor, patch };
}

function bumpVersion(version, type) {
  const v = parseVersion(version);
  switch (type) {
    case "major":
      return `${v.major + 1}.0.0`;
    case "minor":
      return `${v.major}.${v.minor + 1}.0`;
    case "patch":
      return `${v.major}.${v.minor}.${v.patch + 1}`;
    default:
      throw new Error(`Unknown bump type: ${type}`);
  }
}

function getCurrentVersion() {
  const cargo = readFileSync(join(ROOT, "Cargo.toml"), "utf8");
  const match = cargo.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error("Could not find version in root Cargo.toml");
  return match[1];
}

function getChangesets() {
  const files = readdirSync(CHANGESET_DIR).filter(
    (f) => f.endsWith(".md") && f !== "README.md"
  );

  const changesets = [];
  for (const file of files) {
    const content = readFileSync(join(CHANGESET_DIR, file), "utf8");
    const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
    if (!frontmatterMatch) continue;

    // Determine highest bump type from frontmatter
    const frontmatter = frontmatterMatch[1];
    const summary = frontmatterMatch[2].trim();
    let bumpType = "patch";
    if (frontmatter.includes("major")) bumpType = "major";
    else if (frontmatter.includes("minor")) bumpType = "minor";

    changesets.push({ file, bumpType, summary });
  }

  return changesets;
}

function updateCargoToml(path, oldVersion, newVersion) {
  try {
    let content = readFileSync(path, "utf8");
    // Only replace the package version, not dependency versions
    content = content.replace(
      /^(version\s*=\s*)"[^"]+"/m,
      `$1"${newVersion}"`
    );
    writeFileSync(path, content);
    console.log(`  Updated ${path}`);
  } catch {
    // File may not exist (e.g. sdk crates not in all builds)
  }
}

function updateChangelog(version, entries) {
  const date = new Date().toISOString().split("T")[0];
  const newEntry = `## [${version}] - ${date}\n\n${entries.map((e) => `- ${e}`).join("\n")}\n\n`;

  let changelog = "";
  try {
    changelog = readFileSync(CHANGELOG_PATH, "utf8");
  } catch {
    changelog = "# Changelog\n\n";
  }

  // Insert after the header
  const headerEnd = changelog.indexOf("\n\n") + 2;
  changelog =
    changelog.slice(0, headerEnd) + newEntry + changelog.slice(headerEnd);
  writeFileSync(CHANGELOG_PATH, changelog);
  console.log(`  Updated CHANGELOG.md`);
}

// Main
const changesets = getChangesets();
if (changesets.length === 0) {
  console.log("No changesets found, nothing to version.");
  process.exit(0);
}

// Determine highest bump type across all changesets
const bumpPriority = { major: 3, minor: 2, patch: 1 };
const highestBump = changesets.reduce(
  (acc, cs) =>
    bumpPriority[cs.bumpType] > bumpPriority[acc] ? cs.bumpType : acc,
  "patch"
);

const currentVersion = getCurrentVersion();
const newVersion = bumpVersion(currentVersion, highestBump);

console.log(`Bumping ${currentVersion} → ${newVersion} (${highestBump})`);

// Update all Cargo.toml files
for (const cargoPath of CARGO_TOMLS) {
  updateCargoToml(cargoPath, currentVersion, newVersion);
}

// Update CHANGELOG
const summaries = changesets.map((cs) => cs.summary);
updateChangelog(newVersion, summaries);

// Remove consumed changeset files
for (const cs of changesets) {
  const path = join(CHANGESET_DIR, cs.file);
  unlinkSync(path);
  console.log(`  Removed ${cs.file}`);
}

console.log(`\nDone. Version is now ${newVersion}`);
