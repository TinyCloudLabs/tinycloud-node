# Tinycloud Load Tests

## Installation

https://k6.io/docs/getting-started/installation/

## Setup

Make sure the [signer](../signer) is running (`cargo run`).

### Test with the filesystem
Run Kepler with:
```bash
RUST_LOG=warn cargo run
```

### Test with the DynamoDB/S3 backend
Run an AWS local stack with:
```bash
docker-compose up -d localstack ../
```

Then run Tinycloud with:
```bash
RUST_LOG=warn TINYCLOUD_STORAGE_BLOCKS_BUCKET="tinycloud-blocks" TINYCLOUD_STORAGE_BLOCKS_DYNAMODB_TABLE="tinycloud-pinstore" TINYCLOUD_STORAGE_BLOCKS_TYPE=S3 TINYCLOUD_STORAGE_BLOCKS_ENDPOINT="http://localhost:4566" TINYCLOUD_STORAGE_BLOCKS_DYNAMODB_ENDPOINT="http://localhost:4566" TINYCLOUD_STORAGE_INDEXES_TYPE=DynamoDB TINYCLOUD_STORAGE_INDEXES_TABLE="tinycloud-indexing" TINYCLOUD_STORAGE_INDEXES_ENDPOINT="http://localhost:4566" AWS_ACCESS_KEY_ID="test" AWS_SECRET_ACCESS_KEY="test" AWS_DEFAULT_REGION="us-east-1" cargo run
```

## Usage

```bash
k6 run --vus 10 --duration 30s json_put.js
```
