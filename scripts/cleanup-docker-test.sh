#!/bin/sh

# TinyCloud Docker Test Cleanup Script
#
# This script cleans up Docker resources created by the local test script.
# It removes the test container and optionally the test image.

set -e

CONTAINER_NAME="tinycloud-test"
IMAGE_NAME="tinycloud:local-test"

echo "🧹 Cleaning up TinyCloud Docker test resources..."

# Stop and remove container
if docker ps -a --filter "name=$CONTAINER_NAME" --format "{{.Names}}" | grep -q "^$CONTAINER_NAME$"; then
    echo "🛑 Stopping and removing container: $CONTAINER_NAME"
    docker rm -f $CONTAINER_NAME
else
    echo "ℹ️  Container $CONTAINER_NAME not found"
fi

# Ask if user wants to remove the image
if docker images --filter "reference=$IMAGE_NAME" --format "{{.Repository}}:{{.Tag}}" | grep -q "^$IMAGE_NAME$"; then
    echo ""
    printf "🗑️  Remove Docker image $IMAGE_NAME? [y/N]: "
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY])
            echo "🗑️  Removing Docker image: $IMAGE_NAME"
            docker rmi $IMAGE_NAME
            ;;
        *)
            echo "ℹ️  Keeping Docker image: $IMAGE_NAME"
            ;;
    esac
else
    echo "ℹ️  Image $IMAGE_NAME not found"
fi

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "🐳 Remaining TinyCloud Docker resources:"
docker images --filter "reference=tinycloud*" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}"
echo ""
docker ps -a --filter "name=tinycloud*" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "No TinyCloud containers found"
