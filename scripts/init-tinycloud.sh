#!/bin/sh

# TinyCloud Directory Initialization Script
#
# This script ensures the TinyCloud runtime directory structure exists with the proper files:
# - ./tinycloud/                 - Main TinyCloud data directory
# - ./tinycloud/blocks/          - Directory for storing content blocks
# - ./tinycloud/caps.db          - SQLite database for capability tokens
# - ./tinycloud/.gitignore       - Git ignore file set to "*" to ignore all contents
#
# The script is idempotent - it can be run multiple times safely and will only
# create missing files/directories without affecting existing ones.
#
# This script is called during Docker image builds to ensure the runtime
# environment has the proper directory structure.

set -e

echo "Initializing TinyCloud directory structure..."

# Create the main tinycloud directory if it doesn't exist
if [ ! -d "./tinycloud" ]; then
    echo "Creating ./tinycloud directory..."
    mkdir -p ./tinycloud
fi

# Create the blocks directory if it doesn't exist
if [ ! -d "./tinycloud/blocks" ]; then
    echo "Creating ./tinycloud/blocks directory..."
    mkdir -p ./tinycloud/blocks
fi

# Create caps.db if it doesn't exist
if [ ! -f "./tinycloud/caps.db" ]; then
    echo "Creating ./tinycloud/caps.db..."
    touch ./tinycloud/caps.db
fi

# Create .gitignore with "*" if it doesn't exist
if [ ! -f "./tinycloud/.gitignore" ]; then
    echo "Creating ./tinycloud/.gitignore..."
    echo "*" > ./tinycloud/.gitignore
fi

echo "TinyCloud directory structure initialized successfully!"
echo "Created/verified:"
echo "  - ./tinycloud/"
echo "  - ./tinycloud/blocks/"
echo "  - ./tinycloud/caps.db"
echo "  - ./tinycloud/.gitignore"
