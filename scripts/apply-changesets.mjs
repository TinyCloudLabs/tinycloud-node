#!/usr/bin/env node
/**
 * Hybrid Changesets for Rust
 *
 * Reads .changeset/*.md files and applies version bumps to Cargo.toml
 * Generates CHANGELOG.md entries
 *
 * Usage: node scripts/apply-changesets.mjs
 */

import { readFileSync, writeFileSync, readdirSync, unlinkSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Get the directory where the script is located, then go up to project root
const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const CHANGESET_DIR = join(ROOT, '.changeset');
const CARGO_TOML = join(ROOT, 'Cargo.toml');
const CHANGELOG = join(ROOT, 'CHANGELOG.md');

// Parse a changeset file
function parseChangeset(content) {
  const lines = content.split('\n');
  const frontmatterEnd = lines.indexOf('---', 1);

  if (frontmatterEnd === -1) return null;

  const frontmatter = lines.slice(1, frontmatterEnd).join('\n');
  const description = lines.slice(frontmatterEnd + 1).join('\n').trim();

  // Parse "package-name": bump-type
  const bumpMatch = frontmatter.match(/"([^"]+)":\s*(major|minor|patch)/);
  if (!bumpMatch) return null;

  return {
    package: bumpMatch[1],
    bump: bumpMatch[2],
    description
  };
}

// Parse version from Cargo.toml
function parseCargoVersion(content) {
  const match = content.match(/^version\s*=\s*"([^"]+)"/m);
  return match ? match[1] : null;
}

// Bump version string
function bumpVersion(version, type) {
  const [major, minor, patch] = version.split('.').map(Number);

  switch (type) {
    case 'major':
      return `${major + 1}.0.0`;
    case 'minor':
      return `${major}.${minor + 1}.0`;
    case 'patch':
      return `${major}.${minor}.${patch + 1}`;
    default:
      return version;
  }
}

// Get highest priority bump
function getHighestBump(bumps) {
  if (bumps.includes('major')) return 'major';
  if (bumps.includes('minor')) return 'minor';
  if (bumps.includes('patch')) return 'patch';
  return null;
}

// Main
function main() {
  // Find all changeset files
  const files = readdirSync(CHANGESET_DIR)
    .filter(f => f.endsWith('.md') && f !== 'README.md');

  if (files.length === 0) {
    console.log('No changesets to apply');
    return;
  }

  // Parse all changesets
  const changesets = [];
  for (const file of files) {
    const content = readFileSync(join(CHANGESET_DIR, file), 'utf-8');
    const parsed = parseChangeset(content);
    if (parsed) {
      changesets.push({ ...parsed, file });
    }
  }

  if (changesets.length === 0) {
    console.log('No valid changesets found');
    return;
  }

  // Determine version bump
  const bumps = changesets.map(c => c.bump);
  const highestBump = getHighestBump(bumps);

  // Read and update Cargo.toml
  const cargoContent = readFileSync(CARGO_TOML, 'utf-8');
  const currentVersion = parseCargoVersion(cargoContent);

  if (!currentVersion) {
    console.error('Could not parse version from Cargo.toml');
    process.exit(1);
  }

  const newVersion = bumpVersion(currentVersion, highestBump);
  const newCargoContent = cargoContent.replace(
    /^(version\s*=\s*")([^"]+)(")/m,
    `$1${newVersion}$3`
  );

  console.log(`Version: ${currentVersion} → ${newVersion} (${highestBump})`);

  // Generate changelog entry
  const date = new Date().toISOString().split('T')[0];
  const changelogEntry = `## [${newVersion}] - ${date}

${changesets.map(c => c.description).join('\n\n')}

`;

  // Update CHANGELOG.md
  let changelogContent = '';
  if (existsSync(CHANGELOG)) {
    changelogContent = readFileSync(CHANGELOG, 'utf-8');
    // Insert after header
    const headerEnd = changelogContent.indexOf('\n\n');
    if (headerEnd !== -1) {
      changelogContent =
        changelogContent.slice(0, headerEnd + 2) +
        changelogEntry +
        changelogContent.slice(headerEnd + 2);
    } else {
      changelogContent = changelogEntry + changelogContent;
    }
  } else {
    changelogContent = `# Changelog

All notable changes to this project will be documented in this file.

${changelogEntry}`;
  }

  // Write files
  writeFileSync(CARGO_TOML, newCargoContent);
  writeFileSync(CHANGELOG, changelogContent);

  // Delete processed changesets
  for (const cs of changesets) {
    unlinkSync(join(CHANGESET_DIR, cs.file));
    console.log(`Deleted: .changeset/${cs.file}`);
  }

  console.log(`\nUpdated Cargo.toml to version ${newVersion}`);
  console.log('Updated CHANGELOG.md');
  console.log('\nNext steps:');
  console.log('  1. Review the changes');
  console.log('  2. Commit: git add -A && git commit -m "chore: release v' + newVersion + '"');
  console.log('  3. Tag: git tag v' + newVersion);
  console.log('  4. Push: git push && git push --tags');
}

main();
