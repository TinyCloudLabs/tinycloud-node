#!/bin/sh

# TinyCloud Local Docker Test Script
#
# This script builds and runs the TinyCloud Docker image locally for testing.
# It uses local filesystem storage (no external dependencies like S3 or Postgres).
# The container will be accessible at http://localhost:8000

set -e

CONTAINER_NAME="tinycloud-node"
IMAGE_NAME="tinycloudlabs:tincloud-node-simple"

# Detect platform architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        PLATFORM="linux/amd64"
        ;;
    arm64|aarch64)
        PLATFORM="linux/arm64"
        ;;
    *)
        echo "⚠️  Unknown architecture: $ARCH, defaulting to linux/amd64"
        PLATFORM="linux/amd64"
        ;;
esac
echo "🔧 Detected platform: $PLATFORM"

echo "🐳 Building TinyCloud Docker image..."
docker build -t $IMAGE_NAME .

echo "🔍 Verifying image was built..."
if ! docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "^$IMAGE_NAME$"; then
    echo "❌ Image $IMAGE_NAME not found locally!"
    echo "Available images:"
    docker images | head -10
    exit 1
fi
echo "✅ Image $IMAGE_NAME found locally"

echo "🧹 Cleaning up any existing test container..."
docker rm -f $CONTAINER_NAME 2>/dev/null || true

echo "🚀 Starting TinyCloud container..."
docker run -d \
    --name $CONTAINER_NAME \
    --platform $PLATFORM \
    -p 8000:8000 \
    -p 8001:8001 \
    -p 8081:8081 \
    -e RUST_LOG=debug \
    -e TINYCLOUD_LOG_LEVEL=debug \
    --pull never \
    $IMAGE_NAME

echo "⏳ Waiting for TinyCloud to start..."
sleep 5

echo "📊 Container status:"
docker ps --filter "name=$CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "📝 Container logs (last 20 lines):"
docker logs --tail 20 $CONTAINER_NAME

echo ""
echo "🔍 Testing TinyCloud health endpoint..."
for i in 1 2 3 4 5; do
    if curl -s -f http://localhost:8000/healthz > /dev/null 2>&1; then
        echo "✅ Health check passed!"
        break
    else
        echo "⏳ Health check attempt $i/5 failed, retrying in 2 seconds..."
        sleep 2
    fi
    if [ $i -eq 5 ]; then
        echo "❌ Health check failed after 5 attempts"
        echo "📝 Recent container logs:"
        docker logs --tail 10 $CONTAINER_NAME
        exit 1
    fi
done

echo ""
echo "🧪 Running basic API tests..."
echo "Health endpoint: $(curl -s http://localhost:8000/healthz -w "HTTP %{http_code}")"

# Test if there are any other endpoints we can safely test
if curl -s -f http://localhost:8000/ > /dev/null 2>&1; then
    echo "Root endpoint: $(curl -s http://localhost:8000/ -w "HTTP %{http_code}")"
fi

echo ""
echo "🌐 TinyCloud is running at:"
echo "  - Main API: http://localhost:8000"
echo "  - Health check: http://localhost:8000/healthz"
echo "  - Port 8001: http://localhost:8001"
echo "  - Port 8081: http://localhost:8081"
echo ""
echo "🔍 Manual test commands:"
echo "  curl http://localhost:8000/healthz"
echo "  curl -v http://localhost:8000/"
echo ""
echo "🛑 To stop the container:"
echo "  docker stop $CONTAINER_NAME"
echo ""
echo "📋 To view logs:"
echo "  docker logs -f $CONTAINER_NAME"
echo ""
echo "🗑️ To remove the container:"
echo "  docker rm -f $CONTAINER_NAME"
