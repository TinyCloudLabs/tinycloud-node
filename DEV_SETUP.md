# TinyCloud Cloud-Connected Development

## Overview

**TinyCloud `sst dev` runs your code locally while connecting to REAL AWS resources** - S3 buckets, Aurora database, etc. This gives you:
- ⚡ Fast local development with hot reload
- ☁️ Real cloud storage and database 
- 🔧 Production-like environment for testing

## Quick Start

### 1. Set up AWS credentials (one time)

**Easy setup with script:**
```bash
# Run the setup script (will prompt for AWS credentials)
bun run dev:setup
```

**Manual setup:**
```bash
# Create AWS IAM user with these policies:
# - AmazonS3FullAccess (or specific bucket permissions)  
# - AmazonRDSFullAccess (or specific database permissions)

# Then set the secrets in SST:
npx sst secret set AWS_ACCESS_KEY_ID "AKIA..." --stage dev
npx sst secret set AWS_SECRET_ACCESS_KEY "your-secret-key" --stage dev
npx sst secret set TINYCLOUD_KEYS_SECRET "$(openssl rand -base64 32)" --stage dev
```

### 2. Start cloud-connected development

```bash
# This deploys AWS resources and runs TinyCloud locally
bun run dev
# OR
npx sst dev
```

**What happens:**
1. 🚀 **Deploys** S3 bucket + Aurora database to AWS (dev stage)
2. 🏠 **Runs** TinyCloud locally with `cargo run` 
3. 🔗 **Connects** local app to cloud resources via environment variables
4. 🔄 **Auto-reloads** when you change Rust code

## How Cloud-Connected Dev Works

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Your Machine  │    │   AWS Cloud     │    │   SST Magic     │
│                 │    │                 │    │                 │
│ cargo run       │◄──►│ S3 Bucket       │◄──►│ Environment     │
│ (localhost:8000)│    │ Aurora Database │    │ Variables       │
│ Hot Reload ⚡   │    │ (dev stage)     │    │ Auto-Injection  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

**Storage is 100% in AWS:**
- 📦 **All data** stored in AWS S3 bucket (`tinycloud-dev-blockstorage-xyz`)
- 🗄️ **Database** runs on Aurora Serverless in AWS
- 🔑 **Authentication** uses your AWS credentials

## Development URL

Your local TinyCloud server runs at:
- `http://localhost:8000` (local code, cloud storage)

## Environment Variables (Auto-Injected)

SST automatically provides these to your local `cargo run`:
```bash
# Storage Configuration (CLOUD RESOURCES)
TINYCLOUD_STORAGE_BLOCKS_TYPE=S3
TINYCLOUD_STORAGE_BLOCKS_BUCKET=tinycloud-dev-blockstorage-xyz
TINYCLOUD_STORAGE_DATABASE=postgres://...amazonaws.com:5432/tinycloud

# AWS Credentials (YOUR CREDENTIALS)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1

# Development Settings
TINYCLOUD_LOG_LEVEL=debug
RUST_LOG=tinycloud=debug,info
RUST_BACKTRACE=1
```

## Pure Local Development (Optional)

If you want to run completely locally without AWS:

```bash
# Set up local storage directories
mkdir -p tinycloud/blocks
touch tinycloud/caps.db

# Run with local environment variables
export TINYCLOUD_STORAGE_BLOCKS_PATH="tinycloud/blocks"
export TINYCLOUD_STORAGE_DATABASE="sqlite:tinycloud/caps.db"
export TINYCLOUD_STORAGE_BLOCKS_TYPE="Local"
export TINYCLOUD_KEYS_SECRET="$(openssl rand -base64 32)"

cargo run
```

## Troubleshooting

### "InvalidToken" or AWS credential errors
```bash
# 1. Check if secrets are set
npx sst secret list --stage dev

# 2. Verify credential format
npx sst secret get AWS_ACCESS_KEY_ID --stage dev
# Should be ~20 chars starting with AKIA

# 3. Test credentials manually
AWS_ACCESS_KEY_ID="your-key" AWS_SECRET_ACCESS_KEY="your-secret" aws s3 ls

# 4. Re-generate and reset credentials if needed
```

### Local app not connecting to cloud resources
```bash
# 1. Check SST deployment status
npx sst dev --verbose

# 2. Verify environment variables are injected
# Look for logs showing S3 bucket name and database connection
```

### Database connection issues
```bash
# Check if Aurora database is running
npx sst console --stage dev
# Look for database status in AWS console
```

## Debugging Tools

- **SST Console**: `npx sst console --stage dev` (view AWS resources)
- **Local Logs**: Cargo output in your terminal (debug level enabled)
- **AWS Console**: Check S3 bucket and Aurora database directly
- **Environment Check**: `env | grep TINYCLOUD` (verify env vars)

## Cleanup Development Resources

```bash
# Remove ALL dev stage resources (S3, database, etc.)
npx sst remove --stage dev
```

⚠️ **Warning**: This deletes your dev S3 bucket and database permanently!