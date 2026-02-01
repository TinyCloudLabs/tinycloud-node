#!/usr/bin/env node
/**
 * Hybrid Changesets for Rust Workspaces
 *
 * Reads .changeset/*.md files and applies version bumps to Cargo.toml files
 * Supports grouped versioning for related crates
 *
 * Usage: node scripts/apply-changesets.mjs
 *
 * Groups:
 *   - "core" or "tinycloud-core" → tinycloud, tinycloud-core, tinycloud-lib
 *   - "sdk" → tinycloud-sdk-rs, tinycloud-sdk-wasm
 *   - Individual crate names for independent versioning
 */

import { readFileSync, writeFileSync, readdirSync, unlinkSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const CHANGESET_DIR = join(ROOT, '.changeset');
const CHANGELOG = join(ROOT, 'CHANGELOG.md');

// Crate groups - bumping a group bumps all members together
const GROUPS = {
  'core': ['tinycloud', 'tinycloud-core', 'tinycloud-lib'],
  'sdk': ['tinycloud-sdk-rs', 'tinycloud-sdk-wasm'],
};

// Aliases for convenience
const ALIASES = {
  'tinycloud-node': 'core',  // Main package name maps to core group
};

// All known crates and their Cargo.toml paths (relative to ROOT)
const CRATES = {
  'tinycloud': 'Cargo.toml',
  'tinycloud-core': 'tinycloud-core/Cargo.toml',
  'tinycloud-lib': 'tinycloud-lib/Cargo.toml',
  'tinycloud-sdk-rs': 'tinycloud-sdk-rs/Cargo.toml',
  'tinycloud-sdk-wasm': 'tinycloud-sdk-wasm/Cargo.toml',
  'siwe': 'siwe/Cargo.toml',
  'siwe-recap': 'siwe-recap/Cargo.toml',
  'cacaos': 'cacao/Cargo.toml',
};

// Parse a changeset file - supports multiple packages
function parseChangeset(content) {
  const lines = content.split('\n');
  const frontmatterStart = lines.indexOf('---');
  const frontmatterEnd = lines.indexOf('---', frontmatterStart + 1);

  if (frontmatterStart === -1 || frontmatterEnd === -1) return null;

  const frontmatter = lines.slice(frontmatterStart + 1, frontmatterEnd).join('\n');
  const description = lines.slice(frontmatterEnd + 1).join('\n').trim();

  // Parse all "package-name": bump-type entries
  const bumps = [];
  const bumpRegex = /"([^"]+)":\s*(major|minor|patch)/g;
  let match;
  while ((match = bumpRegex.exec(frontmatter)) !== null) {
    bumps.push({ package: match[1], bump: match[2] });
  }

  if (bumps.length === 0) return null;

  return { bumps, description };
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
    case 'major': return `${major + 1}.0.0`;
    case 'minor': return `${major}.${minor + 1}.0`;
    case 'patch': return `${major}.${minor}.${patch + 1}`;
    default: return version;
  }
}

// Get highest priority bump
function getHighestBump(bumps) {
  if (bumps.includes('major')) return 'major';
  if (bumps.includes('minor')) return 'minor';
  if (bumps.includes('patch')) return 'patch';
  return null;
}

// Resolve package name to list of crates
function resolveCrates(packageName) {
  // Check aliases first
  const resolved = ALIASES[packageName] || packageName;

  // Check if it's a group
  if (GROUPS[resolved]) {
    return GROUPS[resolved];
  }

  // Check if it's an individual crate
  if (CRATES[resolved]) {
    return [resolved];
  }

  console.warn(`Warning: Unknown package "${packageName}", skipping`);
  return [];
}

// Update a Cargo.toml file
function updateCargoToml(crateName, newVersion) {
  const tomlPath = join(ROOT, CRATES[crateName]);

  if (!existsSync(tomlPath)) {
    console.warn(`Warning: ${tomlPath} not found`);
    return false;
  }

  const content = readFileSync(tomlPath, 'utf-8');
  const currentVersion = parseCargoVersion(content);

  if (!currentVersion) {
    console.warn(`Warning: Could not parse version from ${tomlPath}`);
    return false;
  }

  const newContent = content.replace(
    /^(version\s*=\s*")([^"]+)(")/m,
    `$1${newVersion}$3`
  );

  writeFileSync(tomlPath, newContent);
  console.log(`  ${crateName}: ${currentVersion} → ${newVersion}`);
  return true;
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

  // Parse all changesets and collect bumps by crate
  const crateBumps = new Map(); // crate -> [bump types]
  const descriptions = [];

  for (const file of files) {
    const content = readFileSync(join(CHANGESET_DIR, file), 'utf-8');
    const parsed = parseChangeset(content);

    if (!parsed) {
      console.warn(`Warning: Could not parse ${file}`);
      continue;
    }

    descriptions.push(parsed.description);

    for (const { package: pkg, bump } of parsed.bumps) {
      const crates = resolveCrates(pkg);
      for (const crate of crates) {
        if (!crateBumps.has(crate)) {
          crateBumps.set(crate, []);
        }
        crateBumps.get(crate).push(bump);
      }
    }
  }

  if (crateBumps.size === 0) {
    console.log('No valid bumps found in changesets');
    return;
  }

  // Calculate new versions and update Cargo.toml files
  console.log('\nUpdating versions:');
  const versionUpdates = [];

  for (const [crate, bumps] of crateBumps) {
    const tomlPath = join(ROOT, CRATES[crate]);
    if (!existsSync(tomlPath)) continue;

    const content = readFileSync(tomlPath, 'utf-8');
    const currentVersion = parseCargoVersion(content);
    const highestBump = getHighestBump(bumps);
    const newVersion = bumpVersion(currentVersion, highestBump);

    updateCargoToml(crate, newVersion);
    versionUpdates.push({ crate, from: currentVersion, to: newVersion, bump: highestBump });
  }

  // Generate changelog entry
  const date = new Date().toISOString().split('T')[0];
  const versionSummary = versionUpdates
    .map(v => `${v.crate} ${v.to}`)
    .join(', ');

  const changelogEntry = `## [${date}] ${versionSummary}

${descriptions.join('\n\n')}

`;

  // Update CHANGELOG.md
  let changelogContent = '';
  if (existsSync(CHANGELOG)) {
    changelogContent = readFileSync(CHANGELOG, 'utf-8');
    const headerMatch = changelogContent.match(/^(# Changelog\n+(?:.*?\n+)?)/);
    if (headerMatch) {
      changelogContent =
        headerMatch[1] +
        changelogEntry +
        changelogContent.slice(headerMatch[1].length);
    } else {
      changelogContent = changelogEntry + changelogContent;
    }
  } else {
    changelogContent = `# Changelog

All notable changes to this project will be documented in this file.

${changelogEntry}`;
  }

  writeFileSync(CHANGELOG, changelogContent);
  console.log('\nUpdated CHANGELOG.md');

  // Delete processed changesets
  console.log('\nDeleted changesets:');
  for (const file of files) {
    unlinkSync(join(CHANGESET_DIR, file));
    console.log(`  .changeset/${file}`);
  }

  // Summary
  console.log('\n--- Summary ---');
  for (const v of versionUpdates) {
    console.log(`${v.crate}: ${v.from} → ${v.to} (${v.bump})`);
  }

  console.log('\nNext steps:');
  console.log('  1. Review the changes: git diff');
  console.log('  2. Commit: git add -A && git commit -m "chore: release"');
  console.log('  3. Tag (optional): git tag v<version>');
  console.log('  4. Push: git push && git push --tags');
}

main();
