#!/bin/sh

# TinyCloud Directory Initialization Script
#
# Creates the runtime data directory structure. Honors DATA_DIR env var
# (default: ./data) to match the `datadir` config in tinycloud.toml.
#
# Structure created:
#   $DATA_DIR/                   - Root data directory
#   $DATA_DIR/blocks/            - Content block storage
#   $DATA_DIR/sql/               - SQL service storage
#   $DATA_DIR/duckdb/            - DuckDB service storage
#   $DATA_DIR/caps.db            - SQLite capability database
#   $DATA_DIR/.gitignore         - Ignores all contents
#
# Idempotent — safe to run multiple times.
# Called during Docker builds and local setup.

set -e

DATA_DIR="${DATA_DIR:-./data}"

echo "Initializing TinyCloud data directory: $DATA_DIR"

mkdir -p "$DATA_DIR/blocks"
mkdir -p "$DATA_DIR/sql"
mkdir -p "$DATA_DIR/duckdb"

if [ ! -f "$DATA_DIR/caps.db" ]; then
    touch "$DATA_DIR/caps.db"
fi

if [ ! -f "$DATA_DIR/.gitignore" ]; then
    echo "*" > "$DATA_DIR/.gitignore"
elif [ "$(cat "$DATA_DIR/.gitignore")" != "*" ]; then
    echo "*" > "$DATA_DIR/.gitignore"
fi

echo "Data directory ready: $DATA_DIR"
echo "  blocks/  sql/  duckdb/  caps.db  .gitignore"
