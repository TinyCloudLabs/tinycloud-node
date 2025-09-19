#!/bin/bash

# Script to set up TinyCloud development environment with cloud resources

set -e

echo "🚀 Setting up TinyCloud development environment..."
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI is not installed. Please install it first:"
    echo "   https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit 1
fi

# Check if AWS credentials are configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS credentials not configured. Please run 'aws configure' first."
    exit 1
fi

echo "✅ AWS CLI configured"

# Check required environment variables or prompt for them
if [ -z "$TINYCLOUD_AWS_ACCESS_KEY_ID" ]; then
    echo ""
    echo "📝 Please provide AWS credentials for TinyCloud development:"
    echo "   (These should have S3 and RDS permissions)"
    echo ""
    read -p "AWS Access Key ID: " TINYCLOUD_AWS_ACCESS_KEY_ID
fi

if [ -z "$TINYCLOUD_AWS_SECRET_ACCESS_KEY" ]; then
    read -s -p "AWS Secret Access Key: " TINYCLOUD_AWS_SECRET_ACCESS_KEY
    echo ""
fi

# Validate credential format
if [[ ! $TINYCLOUD_AWS_ACCESS_KEY_ID =~ ^AKIA[A-Z0-9]{16}$ ]]; then
    echo "⚠️  Warning: Access Key ID doesn't match expected format (AKIA...)"
fi

if [ ${#TINYCLOUD_AWS_SECRET_ACCESS_KEY} -ne 40 ]; then
    echo "⚠️  Warning: Secret Access Key should be 40 characters long"
fi

echo ""
echo "🔐 Setting up SST secrets for dev stage..."

# Generate a secure key for TinyCloud
TINYCLOUD_KEYS_SECRET=$(openssl rand -base64 32)

# Set SST secrets
npx sst secret set TINYCLOUD_KEYS_SECRET "$TINYCLOUD_KEYS_SECRET" --stage dev
npx sst secret set AWS_ACCESS_KEY_ID "$TINYCLOUD_AWS_ACCESS_KEY_ID" --stage dev
npx sst secret set AWS_SECRET_ACCESS_KEY "$TINYCLOUD_AWS_SECRET_ACCESS_KEY" --stage dev

echo "✅ SST secrets configured"

# Test the credentials
echo ""
echo "🧪 Testing AWS credentials..."
if AWS_ACCESS_KEY_ID="$TINYCLOUD_AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$TINYCLOUD_AWS_SECRET_ACCESS_KEY" aws s3 ls > /dev/null 2>&1; then
    echo "✅ AWS credentials working"
else
    echo "❌ AWS credentials test failed. Please check your credentials."
    exit 1
fi

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Run 'bun run dev' or 'npx sst dev'"
echo "  2. Wait for AWS resources to deploy"
echo "  3. TinyCloud will start locally connected to cloud resources"
echo ""
echo "Your local server will be at: http://localhost:8000"
echo "All data will be stored in AWS S3 and Aurora database."