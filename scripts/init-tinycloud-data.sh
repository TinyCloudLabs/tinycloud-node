#!/bin/sh

# TinyCloud Directory Initialization Script
#
# This script ensures the TinyCloud runtime directory structure exists with the proper files:
# - ./data/                      - Main TinyCloud data directory
# - ./data/blocks/               - Directory for storing content blocks
# - ./data/caps.db               - SQLite database for capability tokens
# - ./data/.gitignore            - Git ignore file set to "*" to ignore all contents
#
# The script is idempotent - it can be run multiple times safely and will only
# create missing files/directories without affecting existing ones.
#
# This script is called during Docker image builds to ensure the runtime
# environment has the proper directory structure.

set -e

echo "Initializing TinyCloud directory structure..."

# Create the main data directory if it doesn't exist
if [ ! -d "./data" ]; then
    echo "Creating ./data directory..."
    mkdir -p "./data"
fi

# Create the blocks directory if it doesn't exist
if [ ! -d "./data/blocks" ]; then
    echo "Creating ./data/blocks directory..."
    mkdir -p "./data/blocks"
fi

# Create caps.db if it doesn't exist
if [ ! -f "./data/caps.db" ]; then
    echo "Creating ./data/caps.db..."
    touch "./data/caps.db"
fi

# Create .gitignore with "*" if it doesn't exist
if [ ! -f "./data/.gitignore" ]; then
    echo "Creating ./data/.gitignore..."
    echo "*" > "./data/.gitignore"
elif [ "$(cat ./data/.gitignore)" != "*" ]; then
    echo "Updating ./data/.gitignore to contain '*'..."
    echo "*" > "./data/.gitignore"
fi

echo "TinyCloud directory structure initialized successfully!"
echo "Created/verified:"
echo "  - ./data/"
echo "  - ./data/blocks/"
echo "  - ./data/caps.db"
echo "  - ./data/.gitignore (contains '*')"
