#!/bin/bash
# Reset tinycloud-node data directory
# Clears caps.db and blocks/ while preserving .gitignore

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/../data"

echo "Resetting data in: $DATA_DIR"

# Remove database
if [ -f "$DATA_DIR/caps.db" ]; then
    rm "$DATA_DIR/caps.db"
    echo "  Removed caps.db"
fi

# Clear blocks directory
if [ -d "$DATA_DIR/blocks" ]; then
    rm -rf "$DATA_DIR/blocks"
    mkdir -p "$DATA_DIR/blocks"
    echo "  Cleared blocks/"
fi

echo "Done. Data directory reset."
