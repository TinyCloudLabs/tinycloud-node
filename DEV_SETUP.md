# TinyCloud Local Development with SST

## Quick Start

To run TinyCloud locally with cloud resources:

```bash
# Set up development secrets (one time setup)
npx sst secret set TINYCLOUD_KEYS_SECRET "$(openssl rand -base64 32)" --stage dev
npx sst secret set AWS_ACCESS_KEY_ID "your-dev-aws-access-key" --stage dev
npx sst secret set AWS_SECRET_ACCESS_KEY "your-dev-aws-secret-key" --stage dev

# Start local development
bun run dev
# OR
npx sst dev
```

This will:
1. Deploy cloud resources (S3 bucket, Aurora database) to AWS 
2. Start TinyCloud locally on your machine with `cargo run`
3. Connect your local app to the cloud resources
4. Auto-reload when you change Rust source files

## How It Works

When you run `sst dev`:

- **Cloud Resources**: Database and S3 bucket are deployed to AWS (dev stage)
- **Local App**: TinyCloud runs locally with `cargo run`
- **Environment**: SST automatically injects environment variables to connect to cloud resources
- **Hot Reload**: Changes to `src/`, `Cargo.toml`, or `Cargo.lock` trigger auto-restart

## Local Development URL

Your local TinyCloud will be available at:
- `http://localhost:8000` (direct to your local server)

## Environment Variables

SST automatically sets these when running locally:
```bash
TINYCLOUD_LOG_LEVEL=debug
TINYCLOUD_STORAGE_BLOCKS_TYPE=S3
TINYCLOUD_STORAGE_BLOCKS_BUCKET=<dev-bucket-name>
TINYCLOUD_STORAGE_DATABASE=<dev-database-connection-string>
TINYCLOUD_KEYS_SECRET=<your-dev-secret>
AWS_ACCESS_KEY_ID=<your-aws-key>
AWS_SECRET_ACCESS_KEY=<your-aws-secret>
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

## Debugging

- **View SST console**: `npx sst console --stage dev`
- **Check logs**: Cargo output appears directly in your terminal
- **Database access**: Use the connection string from SST console
- **S3 bucket**: Check the bucket name in SST console

## Cleanup Development Resources

```bash
npx sst remove --stage dev
```

This removes the dev database and S3 bucket but keeps your local code unchanged.